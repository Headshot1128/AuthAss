import sqlite3
from pathlib import Path

from backend.config import Settings, prepare
from backend.db import connect, migrate
from backend.security import now, passwords
from test_security import env, login, bearer, PASSWORD


def test_created_accounts_can_login_to_website_but_not_sdk(env):
    client, settings, _ = env
    admin = bearer(login(client, admin=True))
    credentials = {'username':'website-user','password':PASSWORD}
    created = client.post('/v1/admin/users', headers=admin, json=credentials)
    assert created.status_code == 201
    assert client.post('/v1/admin/login', json=credentials).status_code == 403
    client.put('/v1/admin/users/'+created.json()['id'], headers=admin, json={'status':'active','subscription_until':0,'web_access':True}).raise_for_status()
    web = client.post('/v1/admin/login', json=credentials)
    assert web.status_code == 200
    headers = bearer(web.json())
    assert client.get('/v1/admin/overview', headers=headers).status_code == 200
    assert client.get('/v1/session', headers=headers).status_code == 403
    assert client.post('/v1/login', json=credentials).status_code == 401
    with connect(settings) as db:
        user = db.execute('SELECT role,console_only FROM users WHERE id=?', (created.json()['id'],)).fetchone()
        assert user['role'] == 'admin' and user['console_only'] == 1


def test_existing_user_can_be_granted_and_removed_website_access(env):
    client, _, user = env
    admin = bearer(login(client, admin=True))
    old = login(client)
    credentials = {'username':'alice','password':PASSWORD}
    assert client.post('/v1/admin/login', json=credentials).status_code == 401
    body = {'status':'active','subscription_until':now()+86400,'web_access':True}
    assert client.put(f'/v1/admin/users/{user}',headers=admin,json=body).status_code == 200
    assert client.get('/v1/session',headers=bearer(old)).status_code == 401
    assert client.post('/v1/refresh',json={'refresh_token':old['refresh_token']}).status_code == 401
    assert client.post('/v1/login',json=credentials).status_code == 401
    web = client.post('/v1/admin/login',json=credentials)
    assert web.status_code == 200
    headers = bearer(web.json())
    assert client.get('/v1/admin/users',headers=headers).status_code == 403
    assert client.get('/v1/admin/overview',headers=headers).status_code == 200
    assert client.put(f'/v1/admin/users/{user}',headers=admin,json={**body,'web_access':False}).status_code == 200
    assert client.get('/v1/admin/users',headers=headers).status_code == 401
    assert client.post('/v1/refresh',json={'refresh_token':web.json()['refresh_token']}).status_code == 401
    assert client.post('/v1/admin/login',json=credentials).status_code == 401
    assert client.post('/v1/login',json=credentials).status_code == 401


def test_web_access_changes_require_admin_and_preserve_own_access(env):
    client, _, user = env
    ordinary = bearer(login(client))
    body = {'status':'active','subscription_until':0,'web_access':True}
    assert client.put(f'/v1/admin/users/{user}',headers=ordinary,json=body).status_code == 403
    admin = bearer(login(client,admin=True))
    me = client.get('/v1/admin/session',headers=admin).json()['user_id']
    assert client.put(f'/v1/admin/users/{me}',headers=admin,json={**body,'web_access':False}).status_code == 409
    assert client.get('/v1/admin/session',headers=admin).status_code == 200


def test_migration_preserves_users_and_restricts_existing_admins(tmp_path):
    settings = Settings(database=str(tmp_path/'old.db'),storage=str(tmp_path/'private'))
    prepare(settings)
    with sqlite3.connect(settings.database) as db:
        db.executescript(Path('backend/migrations/001_initial.sql').read_text())
        for name, role in [('original-admin','admin'),('ordinary-user','user')]:
            db.execute('INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                       (name,name,passwords.hash(PASSWORD),role,now()))
        db.execute("INSERT INTO sessions VALUES('old-client','original-admin','client',9999999999,0,NULL)")
        db.execute("INSERT INTO sessions VALUES('old-admin','original-admin','admin',9999999999,0,NULL)")
    migrate(settings)
    migrate(settings)  # repeat startup must be safe
    with connect(settings) as db:
        assert db.execute("SELECT console_only FROM users WHERE id='original-admin'").fetchone()[0] == 1
        assert db.execute("SELECT console_only FROM users WHERE id='ordinary-user'").fetchone()[0] == 0
        assert db.execute("SELECT revoked FROM sessions WHERE id='old-client'").fetchone()[0] == 1
        assert db.execute("SELECT revoked FROM sessions WHERE id='old-admin'").fetchone()[0] == 0
