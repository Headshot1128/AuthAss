"""One-time authorized hosted owner recovery; credentials arrive only on stdin."""
import json
import sys
import time
import httpx


def main():
    config = json.loads(sys.stdin.readline())
    if config['url'] not in ('https://novyx.online', 'https://novyx-authorization.epicmaple8.chatgpt.site'):
        raise ValueError('Unexpected recovery destination')
    headers = {'User-Agent': 'NOVYX-Owner-Recovery/1.0'}
    if config.get('bypass'):
        headers['OAI-Sites-Authorization'] = 'Bearer ' + config['bypass']
    with httpx.Client(base_url=config['url'], headers=headers, timeout=60,
                      follow_redirects=False, trust_env=False) as client:
        result = client.post('/_maintenance/owner-password',
            headers={'x-owner-recovery-token':config['token']},
            json={key:config[key] for key in ('username', 'user_id', 'password')})
        print('Owner recovery HTTP status:',result.status_code,flush=True)
        result.raise_for_status()
        data = result.json()
        assert data.get('success') and data.get('user_id') == config['user_id']
        started = time.perf_counter()
        result = client.post('/v1/admin/login',json={key:config[key] for key in ('username','password')})
        result.raise_for_status()
        credentials = result.json()
        assert credentials.get('success') and credentials.get('access_token')
        elapsed = round((time.perf_counter()-started)*1000)
        bearer = {'Authorization':'Bearer '+credentials['access_token']}
        result = client.get('/v1/admin/session',headers=bearer)
        result.raise_for_status()
        assert result.json().get('user_id') == config['user_id']
        assert result.json().get('is_owner') is True
        result = client.post('/v1/admin/logout',headers=bearer,json={})
        result.raise_for_status()
        assert client.get('/v1/admin/session',headers=bearer).status_code == 401
        print(json.dumps({'reset':True,'sign_in_verified':True,'username':config['username'],
                          'login_ms':elapsed,'verification_session_logged_out':True}),flush=True)


if __name__ == '__main__':
    main()
