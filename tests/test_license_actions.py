from backend.db import connect
from backend.security import now
from test_security import env, login, bearer


def issue(client, admin, **values):
    result = client.post('/v1/admin/licenses', headers=admin, json={'days': 1, **values})
    result.raise_for_status()
    return result.json()


def test_hwid_reset_keeps_owner_and_requires_reactivation(env):
    client, settings, user = env
    admin = bearer(login(client, admin=True))
    license = issue(client, admin, hardware_bound=True, permission='secret')
    old = login(client, hardware='original-device-id')
    original = bearer(old, 'original-device-id')
    assert client.post('/v1/licenses/activate', headers=original, json={'key': license['key']}).status_code == 200
    assert client.get('/v1/variables/secret', headers=original).status_code == 200
    result = client.post(f"/v1/admin/licenses/{license['id']}/reset-hwid", headers=admin)
    assert result.status_code == 200
    with connect(settings) as db:
        row = db.execute('SELECT * FROM licenses WHERE id=?', (license['id'],)).fetchone()
        assert row['user_id'] == user and row['hardware_hash'] is None and row['hardware_bound'] == 1
        assert db.execute("SELECT 1 FROM audit_logs WHERE event='admin.license.hwid_reset' AND target=?", (license['id'],)).fetchone()
    assert client.get('/v1/session', headers=original).status_code == 401
    assert client.post('/v1/refresh', json={'refresh_token': old['refresh_token'], 'hardware_id': 'original-device-id'}).status_code == 401
    replacement = bearer(login(client, hardware='replacement-device'), 'replacement-device')
    assert client.get('/v1/variables/secret', headers=replacement).status_code == 403
    assert client.post('/v1/licenses/activate', headers=replacement, json={'key': license['key']}).status_code == 200
    assert client.get('/v1/variables/secret', headers=replacement).status_code == 200
    old_login = bearer(login(client, hardware='original-device-id'), 'original-device-id')
    assert client.post('/v1/licenses/activate', headers=old_login, json={'key': license['key']}).status_code == 403
    assert client.get('/v1/admin/session', headers=admin).status_code == 200


def test_add_days_updates_license_and_assigned_subscription(env):
    client, settings, user = env
    admin = bearer(login(client, admin=True))
    license = issue(client, admin)
    headers = bearer(login(client))
    client.post('/v1/licenses/activate', headers=headers, json={'key': license['key']}).raise_for_status()
    with connect(settings) as db:
        original = db.execute('SELECT expires_at FROM licenses WHERE id=?', (license['id'],)).fetchone()[0]
    result = client.post(f"/v1/admin/licenses/{license['id']}/extend", headers=admin, json={'days': 3})
    assert result.status_code == 200 and result.json()['expires_at'] == original + 3 * 86400
    with connect(settings) as db:
        assert db.execute('SELECT subscription_until FROM users WHERE id=?', (user,)).fetchone()[0] == result.json()['expires_at']
        db.execute('UPDATE licenses SET expires_at=? WHERE id=?', (now() - 86400, license['id']))
        db.execute('UPDATE users SET subscription_until=0 WHERE id=?', (user,))
    before = now()
    renewed = client.post(f"/v1/admin/licenses/{license['id']}/extend", headers=admin, json={'days': 1})
    assert before + 86400 <= renewed.json()['expires_at'] <= now() + 86400
    with connect(settings) as db:
        assert db.execute('SELECT subscription_until FROM users WHERE id=?', (user,)).fetchone()[0] == renewed.json()['expires_at']
        assert db.execute("SELECT COUNT(*) FROM audit_logs WHERE event='admin.license.extend'").fetchone()[0] == 2


def test_license_actions_are_admin_only_and_validate_state(env):
    client, settings, _ = env
    admin = bearer(login(client, admin=True))
    ordinary = bearer(login(client))
    license = issue(client, admin, hardware_bound=True)
    base = f"/v1/admin/licenses/{license['id']}"
    for suffix, body in [('extend', {'days': 1}), ('reset-hwid', {})]:
        assert client.post(base + '/' + suffix, json=body).status_code == 401
        assert client.post(base + '/' + suffix, json=body, headers=ordinary).status_code == 403
        assert client.post('/v1/admin/licenses/missing/' + suffix, json=body, headers=admin).status_code == 404
    for invalid in [0, -1, 1000, 1.5, True, '1', None]:
        assert client.post(base + '/extend', headers=admin, json={'days': invalid}).status_code == 422
    unbound = issue(client, admin)
    assert client.post(f"/v1/admin/licenses/{unbound['id']}/reset-hwid", headers=admin).status_code == 409
    assert client.post(base + '/reset-hwid', headers=admin).status_code == 200
    client.delete(base, headers=admin).raise_for_status()
    for suffix, body in [('extend', {'days': 1}), ('reset-hwid', {})]:
        assert client.post(base + '/' + suffix, json=body, headers=admin).status_code == 409
