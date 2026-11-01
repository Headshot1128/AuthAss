import backend.app as app_module
import backend.security as security
from backend.db import connect
from test_security import env, login, bearer


def test_duration_bounds_are_enforced_by_server(env):
    client, settings, _ = env
    headers = bearer(login(client, admin=True))
    for value in [0, -1, 1000, 1.5, '1', True, None]:
        assert client.post('/v1/admin/licenses', headers=headers, json={'days': value}).status_code == 422
    for days in [1, 999]:
        before = security.now()
        result = client.post('/v1/admin/licenses', headers=headers, json={'days': days})
        assert result.status_code == 201
        with connect(settings) as db:
            license = db.execute('SELECT * FROM licenses WHERE id=?', (result.json()['id'],)).fetchone()
        assert before + days * 86400 <= license['expires_at'] <= security.now() + days * 86400
        assert license['permission'] == 'premium'
    assert client.post('/v1/admin/licenses', headers=headers, json={'expires_at': 9999999999}).status_code == 422


def test_license_expires_at_exact_deadline_without_cleanup_job(env, monkeypatch):
    client, settings, user = env
    created = security.now()
    clock = [created]
    monkeypatch.setattr(app_module, 'now', lambda: clock[0])
    monkeypatch.setattr(security, 'now', lambda: clock[0])
    admin = bearer(login(client, admin=True))
    claimed = client.post('/v1/admin/licenses', headers=admin, json={'days': 1}).json()
    unclaimed = client.post('/v1/admin/licenses', headers=admin, json={'days': 1}).json()
    with connect(settings) as db:
        db.execute('DELETE FROM permissions WHERE user_id=?', (user,))
    headers = bearer(login(client))
    assert client.post('/v1/licenses/activate', headers=headers, json={'key': claimed['key']}).status_code == 200
    with connect(settings) as db:
        # A longer subscription cannot keep an expired license permission alive.
        db.execute('UPDATE users SET subscription_until=? WHERE id=?', (created + 10 * 86400, user))
    clock[0] = created + 86400 - 1
    headers = bearer(login(client))
    assert client.get('/v1/variables/premium_feature', headers=headers).status_code == 200
    assert client.get('/v1/files/protected-file/content', headers=headers).status_code == 200
    clock[0] += 1
    assert client.get('/v1/variables/premium_feature', headers=headers).status_code == 403
    assert client.get('/v1/files/protected-file/content', headers=headers).status_code == 403
    for key in [claimed['key'], unclaimed['key']]:
        assert client.post('/v1/licenses/activate', headers=headers, json={'key': key}).status_code == 403
    current_admin = bearer(login(client, admin=True))
    assert client.get('/v1/admin/overview', headers=current_admin).json()['counts']['licenses'] == 0
