import concurrent.futures
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings
from backend.db import connect
from backend.security import digest, now, passwords, uid

PASSWORD = 'correct horse battery staple'


@pytest.fixture
def env(tmp_path):
    settings = Settings(database=str(tmp_path / 'auth.db'), storage=str(tmp_path / 'private'), registration=True, owner_username='administrator')
    client = TestClient(create_app(settings), base_url='https://testserver')
    with connect(settings) as db:
        user, admin = uid(), uid()
        for identifier, name, role in [(user, 'alice', 'user'), (admin, 'administrator', 'admin')]:
            db.execute('INSERT INTO users(id,username,password_hash,role,subscription_until,created_at) VALUES(?,?,?,?,?,?)',
                       (identifier, name, passwords.hash(PASSWORD), role, now() + 3600, now()))
        db.execute('INSERT INTO permissions VALUES(?,?)', (user, 'premium'))
        db.execute('INSERT INTO variables VALUES(?,?,?,?,?)', ('flag', 'premium_feature', None, 'enabled', 'premium'))
        db.execute('INSERT INTO variables VALUES(?,?,?,?,?)', ('secret', 'secret', None, 'hidden', 'secret'))
        db.execute('INSERT INTO files VALUES(?,?,?,?,?)', ('protected-file', 'payload.bin', 'premium', 1, 10000))
        db.execute('INSERT INTO files VALUES(?,?,?,?,?)', ('secret-file', 'secret.bin', 'secret', 1, 10000))
    Path(settings.storage, 'payload.bin').write_bytes(b'private\x00payload')
    Path(settings.storage, 'secret.bin').write_bytes(b'secret')
    return client, settings, user


def login(client, admin=False, hardware=None):
    body = {'username': 'administrator' if admin else 'alice', 'password': PASSWORD}
    if hardware:
        body['hardware_id'] = hardware
    r = client.post('/v1/admin/login' if admin else '/v1/login', json=body)
    assert r.status_code == 200, r.text
    return r.json()


def bearer(tokens, hardware=None):
    headers = {'Authorization': 'Bearer ' + tokens['access_token']}
    if hardware:
        headers['X-Hardware-ID'] = hardware
    return headers


def test_wrong_password_and_unknown_user_are_identical(env):
    c, _, _ = env
    responses = [c.post('/v1/login', json={'username': name, 'password': 'incorrect password'})
                 for name in ['alice', 'nonexistent']]
    assert all(r.status_code == 401 for r in responses)
    assert responses[0].json() == responses[1].json()
    assert c.get('/v1/variables/premium_feature').status_code == 401


def test_registration_never_creates_session_and_rejects_roles(env):
    c, s, _ = env
    body = {'username': 'new-user', 'password': PASSWORD}
    r = c.post('/v1/register', json=body)
    assert r.status_code == 201 and 'access_token' not in r.json()
    assert c.post('/v1/register', json=body).status_code == 409
    assert c.post('/v1/register', json={**body, 'role': 'admin'}).status_code == 422
    assert c.post('/v1/register', json={'username': 'other', 'password': ''}).status_code == 422
    with connect(s) as db:
        assert db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 0
    t = c.post('/v1/login', json=body).json()
    assert c.get('/v1/variables/premium_feature', headers=bearer(t)).status_code == 403


def test_valid_and_unauthorized_resources(env):
    c, _, _ = env
    h = bearer(login(c))
    assert c.get('/v1/session', headers=h).status_code == 200
    assert c.get('/v1/variables/premium_feature', headers=h).json()['value'] == 'enabled'
    r = c.get('/v1/files/protected-file/content', headers=h)
    assert r.content == b'private\x00payload'
    assert r.headers['cache-control'] == 'no-store'
    for path in ['/v1/variables/secret', '/v1/variables/missing', '/v1/files/secret-file/content',
                 '/v1/files/missing/content', '/v1/admin/users']:
        r = c.get(path, headers=h)
        assert r.status_code == 403 and b'hidden' not in r.content


@pytest.mark.parametrize('condition', ['access', 'session', 'password', 'revoked', 'suspended', 'subscription', 'permission'])
def test_current_records_enforced_every_request(env, condition):
    c, s, user = env
    h = bearer(login(c))
    with connect(s) as db:
        if condition == 'access':
            db.execute('UPDATE access_tokens SET expires_at=?', (now() - 1,))
        elif condition == 'session':
            db.execute('UPDATE sessions SET expires_at=?', (now() - 1,))
        elif condition == 'password':
            db.execute('UPDATE users SET password_until=? WHERE id=?', (now() - 1, user))
        elif condition in ('revoked', 'suspended'):
            db.execute('UPDATE users SET status=? WHERE id=?', (condition, user))
        elif condition == 'subscription':
            db.execute('UPDATE users SET subscription_until=0 WHERE id=?', (user,))
        else:
            db.execute('DELETE FROM permissions WHERE user_id=?', (user,))
    for path in ['/v1/variables/premium_feature', '/v1/files/protected-file/content']:
        assert c.get(path, headers=h).status_code in (401, 403)


def test_password_expired_login_fails(env):
    c, s, user = env
    with connect(s) as db:
        db.execute('UPDATE users SET password_until=? WHERE id=?', (now() - 1, user))
    assert c.post('/v1/login', json={'username': 'alice', 'password': PASSWORD}).status_code == 401


def test_refresh_rotation_replay_revokes_family(env):
    c, _, _ = env
    old = login(c)
    new = c.post('/v1/refresh', json={'refresh_token': old['refresh_token']}).json()
    assert new['success'] and old['refresh_token'] != new['refresh_token']
    assert c.get('/v1/session', headers=bearer(old)).status_code == 401
    assert c.get('/v1/session', headers=bearer(new)).status_code == 200
    assert c.post('/v1/refresh', json={'refresh_token': old['refresh_token']}).status_code == 401
    assert c.get('/v1/session', headers=bearer(new)).status_code == 401
    assert c.post('/v1/refresh', json={'refresh_token': new['refresh_token']}).status_code == 401


def test_concurrent_refresh_has_single_winner_and_revokes(env):
    c, _, _ = env
    old = login(c)
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(c.post, '/v1/refresh', json={'refresh_token': old['refresh_token']}) for _ in range(2)]
        results = [f.result() for f in futures]
    assert sorted(r.status_code for r in results) == [200, 401]
    winner = next(r.json() for r in results if r.status_code == 200)
    assert c.get('/v1/session', headers=bearer(winner)).status_code == 401


def test_logout_and_admin_revoke(env):
    c, _, user = env
    t = login(c)
    assert c.post('/v1/logout', headers=bearer(t)).status_code == 200
    assert c.get('/v1/session', headers=bearer(t)).status_code == 401
    assert c.post('/v1/refresh', json={'refresh_token': t['refresh_token']}).status_code == 401
    t = login(c)
    admin = bearer(login(c, admin=True))
    assert c.get('/v1/session', headers=admin).status_code == 403
    assert c.post(f'/v1/admin/users/{user}/revoke-sessions', headers=admin).status_code == 200
    assert c.get('/v1/session', headers=bearer(t)).status_code == 401
    assert c.post('/v1/admin/logout', headers=admin).status_code == 200
    assert c.get('/v1/admin/users', headers=admin).status_code == 401


def test_license_binding_expiry_and_revocation(env):
    c, s, user = env
    admin = bearer(login(c, admin=True))
    r = c.post('/v1/admin/licenses', headers=admin,
               json={'days': 1, 'permission': 'secret', 'hardware_bound': True})
    lic = r.json()
    no_hardware = bearer(login(c))
    assert c.post('/v1/licenses/activate', headers=no_hardware, json={'key': lic['key']}).status_code == 403
    hardware = 'hardware-device-one'
    t = login(c, hardware=hardware)
    h = bearer(t, hardware)
    assert c.get('/v1/session', headers=bearer(t)).status_code == 403
    assert c.post('/v1/licenses/activate', headers=h, json={'key': lic['key']}).status_code == 200
    assert c.get('/v1/variables/secret', headers=h).status_code == 200
    assert c.get('/v1/variables/secret', headers=no_hardware).status_code == 403
    assert c.post('/v1/refresh', json={'refresh_token': t['refresh_token'], 'hardware_id': 'different-hardware'}).status_code == 403
    assert c.delete('/v1/admin/licenses/' + lic['id'], headers=admin).status_code == 200
    assert c.get('/v1/variables/secret', headers=h).status_code == 403
    with connect(s) as db:
        db.execute('UPDATE licenses SET revoked=0,expires_at=?', (now() - 1,))
    assert c.get('/v1/files/secret-file/content', headers=h).status_code == 403


def test_admin_management_and_scope(env):
    c, _, user = env
    h = bearer(login(c, admin=True))
    created = c.post('/v1/admin/users', headers=h, json={'username': 'managed', 'password': PASSWORD})
    assert created.status_code == 201
    assert c.get('/v1/admin/users', headers=h).json()['users']
    assert c.put(f'/v1/admin/users/{user}', headers=h,
                 json={'status': 'active', 'subscription_until': now() + 2000}).status_code == 200
    assert c.put(f'/v1/admin/users/{user}/permissions', headers=h,
                 json={'permission': 'secret', 'allowed': True}).status_code == 200
    v = {'name': 'premium_feature', 'user_id': user, 'value': 'personal', 'permission': 'premium'}
    assert c.put('/v1/admin/variables/personal', headers=h, json=v).status_code == 200
    t = bearer(login(c))
    assert c.get('/v1/variables/premium_feature', headers=t).json()['value'] == 'personal'
    assert c.delete('/v1/admin/variables/personal', headers=h).status_code == 200
    assert c.get('/v1/variables/premium_feature', headers=t).json()['value'] == 'enabled'
    meta = {'storage_name': 'payload.bin', 'permission': 'premium', 'enabled': False, 'max_bytes': 10000}
    assert c.put('/v1/admin/files/protected-file', headers=h, json=meta).status_code == 200
    assert c.get('/v1/files/protected-file/content', headers=t).status_code == 403
    assert c.put('/v1/admin/files/bad', headers=h, json={**meta, 'storage_name': '..'}).status_code == 422
    assert c.get('/v1/admin/audit', headers=h).json()['events']


def test_throttling_and_redacted_audit(env):
    c, s, _ = env
    for _ in range(10):
        assert c.post('/v1/login', json={'username': 'alice', 'password': 'wrong password'}).status_code == 401
    assert c.post('/v1/login', json={'username': 'alice', 'password': PASSWORD}).status_code == 429
    with connect(s) as db:
        logs = str([tuple(r) for r in db.execute('SELECT * FROM audit_logs')])
    assert PASSWORD not in logs and 'wrong password' not in logs
    assert 'login' in logs and 'rate_limit' in logs


def test_https_input_and_injection(env):
    c, s, _ = env
    insecure = TestClient(create_app(s), base_url='http://testserver')
    assert insecure.post('/v1/login', json={'username': 'alice', 'password': PASSWORD}).status_code == 400
    assert c.post('/v1/login', json={'username': "' OR 1=1 --", 'password': PASSWORD}).status_code == 422
    assert c.post('/v1/login', content=b'x' * 32769).status_code == 413
    h = bearer(login(c))
    assert c.get('/v1/variables/%27%20OR%201=1--', headers=h).status_code == 403
    assert c.get('/v1/session', headers={'Authorization': 'Bearer fake'}).status_code == 401
    missing = c.get('/nonexistent')
    assert missing.status_code == 404 and missing.json()['success'] is False


def test_disabled_registration_and_db_failure_fail_closed(tmp_path):
    settings = Settings(database=str(tmp_path / 'auth.db'), storage=str(tmp_path / 'private'))
    c = TestClient(create_app(settings), base_url='https://testserver', raise_server_exceptions=False)
    assert c.post('/v1/register', json={'username': 'alice', 'password': PASSWORD}).status_code == 403
    with connect(settings) as db:
        db.execute('DROP TABLE access_tokens')
    r = c.get('/v1/session', headers={'Authorization': 'Bearer ' + 'x' * 43})
    assert r.status_code == 500 and r.json() == {'success': False, 'error': 'server_error'}


def test_admin_suspension_revokes_even_after_reactivation(env):
    c, _, user = env
    old = login(c)
    admin = bearer(login(c, admin=True))
    assert c.put(f'/v1/admin/users/{user}', headers=admin, json={
        'status': 'suspended', 'subscription_until': now() + 3600}).status_code == 200
    assert c.get('/v1/files/protected-file/content', headers=bearer(old)).status_code == 401
    assert c.put(f'/v1/admin/users/{user}', headers=admin, json={
        'status': 'active', 'subscription_until': now() + 3600}).status_code == 200
    assert c.get('/v1/session', headers=bearer(old)).status_code == 401
    assert c.get('/v1/session', headers=bearer(login(c))).status_code == 200


def test_license_cannot_be_claimed_by_second_account_and_secrets_not_logged(env):
    c, s, _ = env
    admin_token = login(c, admin=True)
    lic = c.post('/v1/admin/licenses', headers=bearer(admin_token), json={
        'days': 1, 'permission': 'secret'}).json()
    token = login(c)
    assert c.post('/v1/licenses/activate', headers=bearer(token), json={'key': lic['key']}).status_code == 200
    c.post('/v1/register', json={'username': 'second', 'password': PASSWORD}).raise_for_status()
    second = c.post('/v1/login', json={'username': 'second', 'password': PASSWORD}).json()
    assert c.post('/v1/licenses/activate', headers=bearer(second), json={'key': lic['key']}).status_code == 403
    assert c.get('/v1/variables/secret', headers=bearer(second)).status_code == 403
    with connect(s) as db:
        logs = str([tuple(r) for r in db.execute('SELECT * FROM audit_logs')])
        stored_key = db.execute('SELECT key_hash FROM licenses').fetchone()[0]
    assert stored_key == digest(lic['key'])
    for secret in [lic['key'], token['access_token'], token['refresh_token'], admin_token['access_token'], PASSWORD]:
        assert secret not in logs
