import re
from pathlib import Path
from fastapi.testclient import TestClient

from backend.db import connect
from backend.security import digest, now, uid
from test_security import env, login, bearer


def test_novyx_keys_are_visible_only_to_admin_and_encrypted_at_rest(env):
    client, settings, _ = env
    admin = bearer(login(client, admin=True))
    result = client.post('/v1/admin/licenses', headers=admin, json={'days': 1}).json()
    assert re.fullmatch(r'NOVYX-[A-Z0-9]{6}-[A-Z0-9]{6}', result['key'])
    with connect(settings) as db:
        row = db.execute('SELECT * FROM licenses WHERE id=?', (result['id'],)).fetchone()
        assert row['key_hash'] == digest(result['key'])
        assert result['key'] not in row['key_ciphertext']
        assert result['key'] not in str([tuple(r) for r in db.execute('SELECT * FROM audit_logs')])
        legacy = uid()
        db.execute('INSERT INTO licenses(id,key_hash,expires_at,permission) VALUES(?,?,?,?)',
                   (legacy, digest('old-unrecoverable-license-key-value'), now()+86400, 'premium'))
    rows = client.get('/v1/admin/licenses', headers=admin).json()['licenses']
    assert next(row for row in rows if row['id'] == result['id'])['key'] == result['key']
    assert next(row for row in rows if row['id'] == legacy)['key'] is None
    ordinary = bearer(login(client))
    assert client.get('/v1/admin/licenses', headers=ordinary).status_code == 403
    assert client.get('/v1/admin/licenses').status_code == 401
    assert client.post('/v1/licenses/activate', headers=ordinary, json={'key': result['key']}).status_code == 200


def test_delete_user_cleans_access_and_preserves_audit(env):
    client, settings, user = env
    admin = bearer(login(client, admin=True))
    token = login(client)
    license = client.post('/v1/admin/licenses', headers=admin, json={'days': 1}).json()
    client.post('/v1/licenses/activate', headers=bearer(token), json={'key': license['key']}).raise_for_status()
    with connect(settings) as db:
        db.execute('INSERT INTO variables VALUES(?,?,?,?,?)', ('personal','personal',user,'value','premium'))
    assert client.delete(f'/v1/admin/users/{user}', headers=bearer(token)).status_code == 403
    assert client.delete(f'/v1/admin/users/{user}').status_code == 401
    assert client.delete(f'/v1/admin/users/{user}', headers=admin).status_code == 200
    assert client.get('/v1/session', headers=bearer(token)).status_code == 401
    assert client.post('/v1/refresh', json={'refresh_token':token['refresh_token']}).status_code == 401
    with connect(settings) as db:
        assert db.execute('SELECT 1 FROM users WHERE id=?',(user,)).fetchone() is None
        assert db.execute('SELECT 1 FROM variables WHERE user_id=?',(user,)).fetchone() is None
        assert db.execute('SELECT 1 FROM permissions WHERE user_id=?',(user,)).fetchone() is None
        row = db.execute('SELECT * FROM licenses WHERE id=?',(license['id'],)).fetchone()
        assert row['revoked'] == 1 and row['user_id'] is None
        assert db.execute("SELECT 1 FROM audit_logs WHERE event='admin.user.delete' AND target=?",(user,)).fetchone()
    assert client.delete(f'/v1/admin/users/{user}', headers=admin).status_code == 404
    me = client.get('/v1/admin/session', headers=admin).json()['user_id']
    assert client.delete(f'/v1/admin/users/{me}', headers=admin).status_code == 409


def test_logo_branding_and_theme_assets(env):
    client, _, _ = env
    html = client.get('/').text
    assert 'NOVYX' in html and 'Sentinel' not in html
    for route in ['/assets/novyx.svg','/assets/theme.js','/assets/theme.css']:
        assert client.get(route).status_code == 200


def test_lost_display_key_fails_closed_without_replacing_it(env):
    original, settings, _ = env
    client = TestClient(original.app,base_url='https://testserver',raise_server_exceptions=False)
    admin = bearer(login(client,admin=True))
    client.post('/v1/admin/licenses',headers=admin,json={'days':1}).raise_for_status()
    keyfile = Path(settings.database + '.license-key')
    saved = keyfile.read_bytes()
    keyfile.unlink()
    assert client.get('/v1/admin/licenses',headers=admin).status_code == 500
    assert not keyfile.exists()
    assert client.post('/v1/admin/licenses',headers=admin,json={'days':1}).status_code == 500
    assert not keyfile.exists()
    keyfile.write_bytes(saved)
    assert client.get('/v1/admin/licenses',headers=admin).status_code == 200
