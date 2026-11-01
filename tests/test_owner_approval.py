from backend.db import connect
from backend.security import now
from test_security import env, login, bearer, PASSWORD


def test_only_owner_can_approve_new_website_users(env):
    client, settings, _ = env
    owner = bearer(login(client, admin=True))
    credentials = {'username':'pending-user','password':PASSWORD}
    new = client.post('/v1/admin/users',headers=owner,json=credentials).json()['id']
    response = client.post('/v1/admin/login',json=credentials)
    assert response.status_code == 403 and response.json()['error'] == 'website_approval_required'
    with connect(settings) as db:
        assert db.execute('SELECT COUNT(*) FROM sessions WHERE user_id=?',(new,)).fetchone()[0] == 0
    approved = {'status':'active','subscription_until':0,'web_access':True}
    client.put(f'/v1/admin/users/{new}',headers=owner,json=approved).raise_for_status()
    member = client.post('/v1/admin/login',json=credentials).json()
    headers = bearer(member)
    assert client.get('/v1/admin/session',headers=headers).json()['is_owner'] is False
    assert client.get('/v1/admin/overview',headers=headers).status_code == 200
    assert client.get('/v1/admin/users',headers=headers).status_code == 403
    assert client.post('/v1/admin/users',headers=headers,json={'username':'escalation','password':PASSWORD}).status_code == 403
    assert client.put(f'/v1/admin/users/{new}',headers=headers,json=approved).status_code == 403
    assert client.put(f'/v1/admin/users/{new}/permissions',headers=headers,json={'permission':'owner','allowed':True}).status_code == 403
    assert client.delete(f'/v1/admin/users/{new}',headers=headers).status_code == 403
    client.put(f'/v1/admin/users/{new}',headers=owner,json={**approved,'web_access':False}).raise_for_status()
    assert client.get('/v1/admin/overview',headers=headers).status_code == 401
    assert client.post('/v1/refresh',json={'refresh_token':member['refresh_token']}).status_code == 401


def test_unapproved_existing_admin_sessions_are_denied(env):
    client, settings, _ = env
    owner = bearer(login(client,admin=True))
    member_id = client.post('/v1/admin/users',headers=owner,json={'username':'existing-admin','password':PASSWORD}).json()['id']
    client.put(f'/v1/admin/users/{member_id}',headers=owner,json={'status':'active','subscription_until':0,'web_access':True}).raise_for_status()
    member = client.post('/v1/admin/login',json={'username':'existing-admin','password':PASSWORD}).json()
    with connect(settings) as db:
        db.execute('UPDATE users SET web_approved=0 WHERE id=?',(member_id,))
    assert client.get('/v1/admin/licenses',headers=bearer(member)).status_code == 401
    assert client.post('/v1/refresh',json={'refresh_token':member['refresh_token']}).status_code == 401
    me = client.get('/v1/admin/session',headers=owner).json()
    assert me['is_owner'] is True


def test_public_registration_cannot_claim_reserved_owner(env):
    client, _, _ = env
    assert client.post('/v1/register',json={'username':'administrator','password':PASSWORD}).status_code == 409
