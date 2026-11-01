from backend.db import connect
from backend.security import now
from test_security import env, login, bearer


def test_freeze_blocks_key_and_preserves_license_and_subscription_time(env):
    client, settings, user = env
    admin = bearer(login(client, admin=True))
    headers = bearer(login(client))
    license = client.post('/v1/admin/licenses', headers=admin,
                          json={'days': 1, 'permission': 'secret'}).json()
    base = f"/v1/admin/licenses/{license['id']}"
    assert client.post('/v1/licenses/activate', headers=headers, json={'key': license['key']}).status_code == 200
    assert client.post(base + '/freeze', headers=headers).status_code == 403
    assert client.post(base + '/freeze', headers=admin).json()['frozen'] is True
    assert client.get('/v1/variables/secret', headers=headers).status_code == 403
    assert client.post('/v1/licenses/activate', headers=headers, json={'key': license['key']}).status_code == 403
    listed = client.get('/v1/admin/licenses', headers=admin).json()['licenses']
    assert next(row for row in listed if row['id'] == license['id'])['frozen_at'] is not None
    with connect(settings) as db:
        expiry = db.execute('SELECT expires_at FROM licenses WHERE id=?', (license['id'],)).fetchone()[0]
        subscription = db.execute('SELECT subscription_until FROM users WHERE id=?', (user,)).fetchone()[0]
        frozen_at = now() - 3600
        db.execute('UPDATE licenses SET frozen_at=? WHERE id=?', (frozen_at, license['id']))
        db.execute('UPDATE users SET frozen_at=? WHERE id=?', (frozen_at, user))
    assert client.post(base + '/freeze', headers=admin).json()['frozen'] is False
    with connect(settings) as db:
        row = db.execute('SELECT * FROM licenses WHERE id=?', (license['id'],)).fetchone()
        assert row['frozen_at'] is None
        assert 3600 <= row['expires_at'] - expiry <= 3605
        account = db.execute('SELECT * FROM users WHERE id=?', (user,)).fetchone()
        assert account['frozen_at'] is None
        assert 3600 <= account['subscription_until'] - subscription <= 3605
    assert client.get('/v1/variables/secret', headers=headers).status_code == 200


def test_multiple_frozen_keys_keep_subscription_paused(env):
    client, settings, user = env
    admin = bearer(login(client, admin=True))
    keys = [client.post('/v1/admin/licenses', headers=admin, json={'days': 1}).json() for _ in range(2)]
    with connect(settings) as db:
        for key in keys:
            db.execute('UPDATE licenses SET user_id=? WHERE id=?', (user, key['id']))
    for key in keys:
        assert client.post(f"/v1/admin/licenses/{key['id']}/freeze", headers=admin).json()['frozen']
    for index, key in enumerate(keys):
        assert client.post(f"/v1/admin/licenses/{key['id']}/freeze", headers=admin).json()['frozen'] is False
        with connect(settings) as db:
            paused = db.execute('SELECT frozen_at FROM users WHERE id=?', (user,)).fetchone()[0]
            assert (paused is not None) == (index == 0)
