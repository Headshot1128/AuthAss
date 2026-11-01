"""Test hosted verification delivery to the provider's simulated recipient."""
import json
import sys
import httpx
import secrets

config=json.loads(sys.stdin.readline())
with httpx.Client(base_url='https://novyx.online',timeout=30,trust_env=False,follow_redirects=False) as client:
    result=client.post('/v1/admin/login',json={'username':'gerry2.0','password':config['password']})
    print('Sign-in status:',result.status_code,flush=True)
    result.raise_for_status()
    token=result.json()['access_token']
    headers={'Authorization':'Bearer '+token}
    user_id=None
    probe_headers=None
    try:
        username='mail-check-'+secrets.token_hex(5)
        password=secrets.token_urlsafe(24)
        result=client.post('/v1/admin/users',headers=headers,json={'username':username,'password':password,'account_type':'website'})
        result.raise_for_status();user_id=result.json()['id']
        result=client.put('/v1/admin/users/'+user_id,headers=headers,json={'status':'active','subscription_until':0,'web_access':True})
        result.raise_for_status()
        result=client.post('/v1/admin/login',json={'username':username,'password':password})
        result.raise_for_status();probe_headers={'Authorization':'Bearer '+result.json()['access_token']}
        result=client.post('/v1/admin/account/email',headers=probe_headers,json={'email':'delivered@resend.dev','password':password})
        print(json.dumps({'delivery_status':result.status_code,'result':result.json()}),flush=True)
    finally:
        if probe_headers:
            client.post('/v1/admin/logout',headers=probe_headers,json={})
        if user_id:
            result=client.delete('/v1/admin/users/'+user_id,headers=headers)
            print('Disposable probe account deleted:',result.status_code==200,flush=True)
        result=client.post('/v1/admin/logout',headers=headers,json={})
        print('Probe signed out:',result.status_code==200,flush=True)
