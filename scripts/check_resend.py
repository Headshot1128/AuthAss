"""Probe the configured sender using Resend's official simulated recipient."""
import json
import sys
import httpx

config=json.loads(sys.stdin.readline())
with httpx.Client(timeout=20,trust_env=False,follow_redirects=False) as client:
    client.headers.pop('User-Agent',None)
    response=client.post('https://api.resend.com/emails',headers={'Authorization':'Bearer '+config['key']},json={
        'from':'NOVYX <accounts@auth.novyx.online>', 'to':['delivered@resend.dev'],
        'subject':'NOVYX email configuration check','text':'Configuration diagnostic using the Resend simulated delivery recipient.'})
    data=response.json()
    print(json.dumps({'status':response.status_code,'name':data.get('name'),'message':data.get('message'),'accepted':bool(data.get('id'))}))
