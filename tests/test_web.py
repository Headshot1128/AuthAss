from test_security import env, login, bearer


def test_web_shell_and_security_headers(env):
    client, _, _ = env
    for route in ['/', '/admin']:
        response = client.get(route)
        assert response.status_code == 200
        assert 'text/html' in response.headers['content-type']
        assert 'id="login-form"' in response.text
        assert 'id="console"' in response.text
        assert "script-src 'self'" in response.headers['content-security-policy']
        assert "frame-ancestors 'none'" in response.headers['content-security-policy']
        assert response.headers['cache-control'] == 'no-store'
        assert response.headers['referrer-policy'] == 'no-referrer'
    for asset in ['app.js','app.css','fonts.css','mark.svg']:
        assert client.get('/assets/' + asset).status_code == 200
    assert client.get('/assets/../app.py').status_code == 404
    assert client.get('/data/auth.db').status_code == 404


def test_admin_dashboard_reads_require_admin_audience(env):
    client, _, user = env
    routes = ['/v1/admin/session','/v1/admin/overview','/v1/admin/licenses',
              '/v1/admin/variables','/v1/admin/files',f'/v1/admin/users/{user}/permissions']
    ordinary = bearer(login(client))
    for route in routes:
        assert client.get(route).status_code == 401
        assert client.get(route,headers=ordinary).status_code == 403
    admin = bearer(login(client,admin=True))
    for route in routes:
        assert client.get(route,headers=admin).status_code == 200
    assert client.get('/v1/admin/session',headers=admin).json()['username'] == 'administrator'
    data = client.get('/v1/admin/overview',headers=admin).json()
    assert data['counts'] == {'users':2,'subscribers':2,'licenses':0,'files':2}
    assert len(data['recent']) <= 8
    assert client.get(f'/v1/admin/users/{user}/permissions',headers=admin).json()['permissions'] == ['premium']


def test_dashboard_collections_redact_secrets_and_support_pagination(env):
    client, _, _ = env
    admin = bearer(login(client,admin=True))
    license = client.post('/v1/admin/licenses',headers=admin,
                          json={'days':999}).json()
    response = client.get('/v1/admin/licenses',headers=admin)
    assert len(response.json()['licenses']) == 1
    assert license['key'] == response.json()['licenses'][0]['key']
    for forbidden in ['key_hash','hardware_hash','password_hash','access_token','refresh_token']:
        assert forbidden not in response.text
    assert client.get('/v1/admin/licenses?offset=100',headers=admin).json()['licenses'] == []
    files = client.get('/v1/admin/files',headers=admin).json()['files']
    assert {row['id'] for row in files} == {'protected-file','secret-file'}
    variables = client.get('/v1/admin/variables',headers=admin).json()['variables']
    assert {row['name'] for row in variables} == {'premium_feature','secret'}
    logs = client.get('/v1/admin/audit?recent=true',headers=admin).json()['events']
    assert [row['id'] for row in logs] == sorted((row['id'] for row in logs),reverse=True)
    assert client.get('/v1/admin/audit?recent=true&offset=100000',headers=admin).json()['events'] == []
    client.post('/v1/admin/logout',headers=admin).raise_for_status()
    assert client.get('/v1/admin/overview',headers=admin).status_code == 401
