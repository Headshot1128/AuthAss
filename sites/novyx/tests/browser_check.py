"""Local built-Worker browser smoke test. Uses only a disposable preview owner."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
from websockets.sync.client import connect

def main():
    output=Path('data/sites-browser-check');output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='sites-browser-',dir='data') as profile:
        browser=subprocess.Popen([r'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe','--headless=new','--disable-gpu','--no-first-run','--disable-background-networking','--remote-debugging-port=0',f'--user-data-dir={Path(profile).resolve()}','about:blank'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            active=Path(profile)/'DevToolsActivePort';deadline=time.monotonic()+20
            while not active.exists() and time.monotonic()<deadline:time.sleep(.1)
            port=int(active.read_text().splitlines()[0]);opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f'http://127.0.0.1:{port}/json/list') as response:page=next(p for p in json.load(response) if p['type']=='page')
            with connect(page['webSocketDebuggerUrl'],max_size=10*1024*1024) as ws:
                serial=0;errors=[];network=[];member_name='worker-member-'+str(int(time.time()))
                def command(method,params=None):
                    nonlocal serial
                    serial+=1;current=serial;ws.send(json.dumps(dict(id=current,method=method,params=params or {})))
                    while True:
                        result=json.loads(ws.recv(timeout=30))
                        if result.get('method')=='Runtime.exceptionThrown':errors.append(result['params'])
                        if result.get('method')=='Network.responseReceived' and '/v1/' in result['params']['response']['url']:
                            network.append((result['params']['requestId'],result['params']['response']['url'],result['params']['response']['status']))
                        if result.get('id')==current:
                            assert 'error' not in result,result
                            return result.get('result',{})
                def evaluate(source):
                    source=source.replace('worker-member',member_name)
                    result=command('Runtime.evaluate',dict(expression=source,returnByValue=True,awaitPromise=True));assert 'exceptionDetails' not in result,result
                    return result.get('result',{}).get('value')
                def wait(source):
                    deadline=time.monotonic()+20
                    while time.monotonic()<deadline:
                        if evaluate(source):return
                        time.sleep(.1)
                    print('Browser diagnostic:',evaluate("JSON.stringify({loginError:document.querySelector('#login-error')?.textContent,pageError:document.querySelector('#page-error')?.textContent,consoleHidden:document.querySelector('#console').hidden,content:document.querySelector('#page-content').textContent.slice(0,200)})"))
                    print('Runtime errors:',errors)
                    for request_id,url,status in network[-6:]:
                        try:
                            raw=command('Network.getResponseBody',dict(requestId=request_id))['body'];body=json.loads(raw)
                            print('API diagnostic:',url,status,dict(success=body.get('success'),error=body.get('error'),access_length=len(body.get('access_token','')),refresh_length=len(body.get('refresh_token','')),expires_at=body.get('expires_at'),browser_time=evaluate('Math.floor(Date.now()/1000)')))
                        except Exception:
                            if status==503:
                                try:print('Runtime 503:',command('Network.getResponseBody',dict(requestId=request_id))['body'][:1200])
                                except Exception:pass
                    raise AssertionError(source)
                def click(selector):evaluate('document.querySelector('+json.dumps(selector)+').click()')
                def fill(selector,value):evaluate('(document.querySelector(\'#modal[open]\') || document).querySelector('+json.dumps(selector)+').value='+json.dumps(value))
                command('Page.enable');command('Runtime.enable');command('Network.enable');command('Emulation.setDeviceMetricsOverride',dict(width=1440,height=1000,deviceScaleFactor=1,mobile=False))
                command('Page.navigate',dict(url='http://127.0.0.1:8787/'));wait("typeof api==='function' && !!document.querySelector('#login-form')")
                fill('#username','browser-admin');fill('#password','temporary browser test password');evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!!document.querySelector('.stats-grid')")
                assert evaluate("document.querySelector('.profile small').textContent==='Owner'")
                click('.nav-item[data-view=users]');wait("!!document.querySelector('#table-rows')")
                click('#page-action');fill('[name=username]','worker-member');fill('[name=password]','temporary member password');evaluate("document.querySelector('#modal-form').requestSubmit()")
                wait("!document.querySelector('#modal').open && document.querySelector('#table-rows').textContent.includes('worker-member')")
                assert evaluate("document.querySelector('#table-rows').textContent.includes('Not approved')")
                evaluate("[...document.querySelectorAll('#table-rows tr')].find(r=>r.textContent.includes('worker-member')).querySelector('[data-row-action=permissions]').click()")
                click('[name=web_access]');evaluate("document.querySelector('#modal-form').requestSubmit()")
                wait("!document.querySelector('#modal').open && document.querySelector('#table-rows').textContent.includes('Approved')")
                click('#page-action');fill('[name=account_type]','application');evaluate("document.querySelector('#modal [name=account_type]').dispatchEvent(new Event('change'))");fill('[name=username]','worker-member-app');fill('[name=password]','x');evaluate("document.querySelector('#modal-form').requestSubmit()")
                wait("!document.querySelector('#modal').open && document.querySelector('#table-rows').textContent.includes('worker-member-app')")
                assert evaluate("[...document.querySelectorAll('#table-rows tr')].find(r=>r.textContent.includes('worker-member-app')).textContent.includes('EXE only')")
                assert evaluate("![...document.querySelectorAll('#table-rows tr')].find(r=>r.textContent.includes('worker-member-app')).querySelector('[data-row-action=permissions]')")
                evaluate("[...document.querySelectorAll('#table-rows tr')].find(r=>r.textContent.includes('worker-member-app')).querySelector('[data-row-action=edit]').click()")
                assert evaluate("!document.querySelector('#modal [name=web_access]')")
                evaluate("document.querySelector('#modal-form').requestSubmit()")
                wait("!document.querySelector('#modal').open")
                assert evaluate("(async()=>{const r=await fetch('/v1/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'worker-member-app',password:'x'})});const b=await r.json();if(!b.access_token)return false;await fetch('/v1/logout',{method:'POST',headers:{Authorization:'Bearer '+b.access_token}});return r.status===200;})()")
                click('.nav-item[data-view=licenses]');wait("!!document.querySelector('#table-rows')")
                click('#page-action');fill('[name=days]',1);evaluate("document.querySelector('#modal-form').requestSubmit()")
                wait("!!document.querySelector('#new-license-key')")
                assert evaluate("/^NOVYX-[A-Z0-9]{6}-[A-Z0-9]{6}$/.test(document.querySelector('#new-license-key').textContent)")
                click('#modal-form [type=submit]');wait("!document.querySelector('#modal').open")
                click('#console .theme-toggle')
                shot=command('Page.captureScreenshot',dict(format='png'));(output/'licenses.png').write_bytes(base64.b64decode(shot['data']))
                click('#logout');wait("!document.querySelector('#login-screen').hidden")
                fill('#username','worker-member');fill('#password','temporary member password');evaluate("document.querySelector('#login-form').requestSubmit()")
                # A local Wrangler hot restart can cancel an in-flight POST. It must
                # fail closed; exercise a deliberate second sign-in, never a silent retry.
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    if evaluate("!!document.querySelector('.stats-grid') || !document.querySelector('#login-error').hidden"):break
                    time.sleep(.1)
                if evaluate("!document.querySelector('#login-error').hidden"):
                    print('Preview rejected a sign-in during a Worker restart; retrying explicitly.')
                    time.sleep(1)
                    fill('#password','temporary member password');evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!!document.querySelector('.stats-grid')")
                assert evaluate("document.querySelector('.nav-item[data-view=users]').hidden")
                command('Emulation.setDeviceMetricsOverride',dict(width=390,height=844,deviceScaleFactor=1,mobile=True))
                assert evaluate('document.documentElement.scrollWidth<=innerWidth')
                assert not errors,errors
                print('Built Worker browser checks passed: owner login, website approval, application creation/login/isolation, license creation, themes, approved-member isolation, mobile.')
        finally:
            browser.terminate();browser.wait(timeout=10);time.sleep(1)

if __name__=='__main__':main()
