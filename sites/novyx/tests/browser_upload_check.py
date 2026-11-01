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
                evaluate("(async()=>{const user=await api('/v1/admin/users','POST',{username:'worker-member',password:'temporary member password'});await api('/v1/admin/users/'+user.id,'PUT',{status:'active',subscription_until:0,web_access:true});})()")
                click('#logout');wait("!document.querySelector('#login-screen').hidden")
                fill('#username','worker-member');fill('#password','temporary member password');evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!!document.querySelector('.stats-grid') || !document.querySelector('#login-error').hidden")
                if evaluate("!document.querySelector('#login-error').hidden"):
                    time.sleep(1)
                    fill('#password','temporary member password');evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!!document.querySelector('.stats-grid')")
                assert evaluate("document.querySelector('.profile small').textContent==='Website user'")
                click('.nav-item[data-view=files]');wait("!!document.querySelector('#table-rows')")
                before=evaluate("records.length")
                assert evaluate("!document.querySelector('#page-action').hidden")
                click('#page-action');wait("!!document.querySelector('#field-upload')")
                doc=command('DOM.getDocument')
                node=command('DOM.querySelector',dict(nodeId=doc['root']['nodeId'],selector='#field-upload'))['nodeId']
                command('DOM.setFileInputFiles',dict(nodeId=node,files=[str(Path(__file__).resolve())]))
                evaluate("document.querySelector('#modal-form').requestSubmit()")
                wait("document.querySelector('#modal-title')?.textContent==='Your file is ready' || !!document.querySelector('#modal-error:not([hidden])')")
                print('Upload result:',evaluate("JSON.stringify({title:document.querySelector('#modal-title')?.textContent,error:document.querySelector('#modal-error')?.textContent,count:records.length,modalOpen:document.querySelector('#modal').open})"))
                assert evaluate("document.querySelector('#modal-title')?.textContent==='Your file is ready'")
                time.sleep(.3)
                assert evaluate("!!document.querySelector('#modal textarea')?.value.includes('auth.downloadfile(')")
                assert evaluate("records.length") == before+1
                click('#modal-form [type=submit]');wait("!document.querySelector('#modal').open")
                evaluate("document.querySelector('[data-row-action=download-code]').click()")
                wait("!!document.querySelector('#modal textarea')")
                assert not errors,errors
                print('Browser upload and generated C++ code checks passed.')
        finally:
            browser.terminate();browser.wait(timeout=10);time.sleep(1)

if __name__=='__main__':main()
