"""Real-browser UI check against disposable API fixtures; never touches live data."""
import base64
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import urllib.request
from websockets.sync.client import connect

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parents[1] / 'build/reseller-ui'
MOCK = r"""
localStorage.setItem('novyx-theme','dark');
const realFetch=window.fetch.bind(window);window.fixtureCalls=[];
let partnerCreated=false,keys=[];
window.fetch=async(input,options={})=>{
 const url=new URL(typeof input==='string'?input:input.url,location.href);
 if(!url.pathname.startsWith('/v1/'))return realFetch(input,options);
 const path=url.pathname,method=options.method||'GET',body=options.body?JSON.parse(options.body):{};
 window.fixtureCalls.push({path,method,body});
 const reply=(value,status=200)=>new Response(JSON.stringify({success:status<400,...value}),{status,headers:{'Content-Type':'application/json'}});
 const app='11111111-1111-4111-8111-111111111111';
 if(path.endsWith('/resume'))return reply({error:'authentication_required'},401);
 if(path.endsWith('/login'))return reply({access_token:'a'.repeat(43),refresh_token:'r'.repeat(64),expires_at:Math.floor(Date.now()/1000)+300,user:{username:body.username,user_id:body.username,is_owner:body.username==='owner',role:body.username==='partner'?'reseller':'admin'}});
 if(path.endsWith('/logout'))return reply({});
 if(path.endsWith('/applications'))return reply({applications:[{id:app,name:'External',status:'active'}],default_application_id:app});
 if(path.endsWith('/overview'))return reply({counts:{users:1284,subscribers:946,licenses:2371,files:12},recent:[{id:21,event:'reseller.license.create',outcome:'allowed',actor_id:'reseller',target:'license',timestamp:Math.floor(Date.now()/1000)-90},{id:20,event:'login',outcome:'allowed',actor_id:'customer',timestamp:Math.floor(Date.now()/1000)-180}]});
 if(path.endsWith('/resellers')){
  if(method==='POST'){partnerCreated=true;return reply({id:'partner'},201);}
  return reply({resellers:partnerCreated?[{id:'partner',username:'partner',status:'active',max_days:30,created_at:Math.floor(Date.now()/1000)}]:[]});
 }
 if(path.endsWith('/reseller/licenses')){
  if(method==='POST'){const key={id:'key-'+(keys.length+1),key:'NOVYX-ABCDEF-GHIJKL',expires_at:Math.floor(Date.now()/1000)+86400*body.days,revoked:0,hardware_bound:1};keys.push(key);return reply({...key,license:key},201);}
  const snapshot=keys.map(key=>({...key}));if(window.fixtureReadDelay)await new Promise(resolve=>setTimeout(resolve,window.fixtureReadDelay));return reply({reseller_licenses:snapshot,max_days:30});
 }
 if(path.endsWith('/reseller/reset-hwid'))return reply({username:body.username,message:'HWID reset. The next login binds the new SID.'});
 return reply({error:'permission_denied'},403);
};
"""


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), partial(QuietHandler, directory=str(ROOT / 'web')))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='reseller-browser-', dir=OUTPUT) as profile:
        browser = subprocess.Popen([
            r'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe',
            '--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking',
            '--remote-debugging-port=0', f'--user-data-dir={profile}', 'about:blank',
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            active = Path(profile) / 'DevToolsActivePort'
            deadline = time.monotonic() + 20
            while not active.exists() and time.monotonic() < deadline:
                time.sleep(.1)
            port = int(active.read_text().splitlines()[0])
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f'http://127.0.0.1:{port}/json/list') as response:
                page = next(p for p in json.load(response) if p['type'] == 'page')
            with connect(page['webSocketDebuggerUrl'], max_size=12*1024*1024) as ws:
                serial = 0
                errors = []
                def command(method, params=None):
                    nonlocal serial
                    serial += 1
                    current = serial
                    ws.send(json.dumps(dict(id=current, method=method, params=params or {})))
                    while True:
                        result = json.loads(ws.recv(timeout=30))
                        if result.get('method') == 'Runtime.exceptionThrown':
                            errors.append(result['params'])
                        if result.get('id') == current:
                            assert 'error' not in result, result
                            return result.get('result', {})
                def evaluate(source):
                    result = command('Runtime.evaluate', dict(expression=source, returnByValue=True, awaitPromise=True))
                    assert 'exceptionDetails' not in result, result
                    return result.get('result', {}).get('value')
                def wait(source):
                    deadline = time.monotonic() + 12
                    while time.monotonic() < deadline:
                        if evaluate(source):
                            return
                        time.sleep(.1)
                    raise AssertionError((source, errors, evaluate("document.body.innerText.slice(-1000)")))
                def click(selector):
                    evaluate(f'document.querySelector({json.dumps(selector)}).click()')
                def fill(selector, value):
                    evaluate(f'document.querySelector({json.dumps(selector)}).value={json.dumps(value)}')
                def screenshot(name):
                    result = command('Page.captureScreenshot', {'format':'png'})
                    (OUTPUT / name).write_bytes(base64.b64decode(result['data']))
                def login(username):
                    fill('#username', username)
                    fill('#password', 'fixture-password-123')
                    click('#login-form [type=submit]')
                    wait("!document.querySelector('#console').hidden && document.querySelector('#page-content').getAttribute('aria-busy')!=='true'")
                command('Runtime.enable')
                command('Page.enable')
                command('Emulation.setDeviceMetricsOverride', {'width':1440,'height':1040,'deviceScaleFactor':1,'mobile':False})
                command('Page.addScriptToEvaluateOnNewDocument', {'source':MOCK})
                command('Page.navigate', {'url':f'http://127.0.0.1:{server.server_port}/'})
                wait("document.querySelector('#login-form [type=submit]')?.textContent==='Sign in'")
                screenshot('login-desktop.png')
                login('owner')
                screenshot('admin-overview.png')
                command('Emulation.setDeviceMetricsOverride', {'width':1280,'height':600,'deviceScaleFactor':1,'mobile':False})
                evaluate("document.querySelector('#sidebar').scrollTop=document.querySelector('#sidebar').scrollHeight")
                assert evaluate("(()=>{const r=document.querySelector('#logout').getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight&&r.right<=document.querySelector('#sidebar').getBoundingClientRect().right})()"), 'Sign out unreachable on short screen'
                screenshot('sidebar-short-screen.png')
                command('Emulation.setDeviceMetricsOverride', {'width':1440,'height':1040,'deviceScaleFactor':1,'mobile':False})
                evaluate("document.querySelector('#sidebar').scrollTop=0")
                click('#page-action')
                wait("document.querySelector('#modal').open")
                assert evaluate("Array.from(document.querySelector('#field-account_type').options).some(o=>o.value==='reseller'&&o.text==='Reseller account')")
                evaluate("document.querySelector('#field-account_type').value='reseller';document.querySelector('#field-account_type').dispatchEvent(new Event('change'))")
                assert evaluate("!document.querySelector('#reseller-create-options').hidden && !document.querySelector('#field-max_days').disabled")
                fill('#field-username', 'partner')
                fill('#field-password', 'fixture-password-123')
                click('#modal-form [type=submit]')
                wait("!document.querySelector('#modal').open && document.querySelector('#table-rows')?.textContent.includes('partner')")
                screenshot('admin-resellers.png')
                click('#logout')
                wait("document.querySelector('#console').hidden")
                login('partner')
                assert evaluate("Array.from(document.querySelectorAll('.nav-item')).filter(n=>!n.hidden).map(n=>n.dataset.view)") == ['reseller_licenses','reseller_hwid']
                wait("!!document.querySelector('#quick-license-form')")
                before_reads=evaluate("fixtureCalls.filter(c=>c.path.endsWith('/reseller/licenses')&&c.method==='GET').length")
                click('[data-duration="7"]')
                click('#quick-license-form [type=submit]')
                wait("!document.querySelector('#quick-license-result').hidden && document.querySelector('#table-rows').textContent.includes('NOVYX-')")
                assert evaluate("document.querySelector('#issued-license-key').value==='NOVYX-ABCDEF-GHIJKL'")
                assert evaluate("fixtureCalls.filter(c=>c.path.endsWith('/reseller/licenses')&&c.method==='GET').length")==before_reads, 'Creating a key must not reload the list'
                assert evaluate("document.querySelector('.table-toolbar h2 span').textContent==='1'")
                screenshot('reseller-licenses.png')
                command('Emulation.setDeviceMetricsOverride', {'width':390,'height':844,'deviceScaleFactor':1,'mobile':True})
                assert evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile license desk overflows'
                screenshot('reseller-licenses-mobile.png')
                command('Emulation.setDeviceMetricsOverride', {'width':1440,'height':1040,'deviceScaleFactor':1,'mobile':False})
                click('[data-view=reseller_hwid]')
                click('[data-view=reseller_licenses]')
                wait("document.querySelector('#page-content').getAttribute('aria-busy')!=='true' && !!document.querySelector('#quick-license-form')")
                click('[data-view=reseller_hwid]')
                evaluate('window.fixtureReadDelay=700')
                click('[data-view=reseller_licenses]')
                wait("!!document.querySelector('#quick-license-form')")
                fill('#quick-license-days','7')
                click('#quick-license-form [type=submit]')
                wait("!document.querySelector('#quick-license-result').hidden")
                wait("document.querySelector('#page-content').getAttribute('aria-busy')!=='true'")
                assert evaluate("document.querySelectorAll('#table-rows tr').length===2 && document.querySelector('#quick-license-days').value==='7' && !document.querySelector('#quick-license-result').hidden"), 'Slow cached read overwrote the new key or form'
                evaluate('window.fixtureReadDelay=0')
                click('[data-view=reseller_hwid]')
                wait("!!document.querySelector('#reseller-hwid-form')")
                fill('#reset-username', 'customer')
                before_reset_calls=evaluate('fixtureCalls.length')
                click('#reseller-hwid-form [type=submit]')
                wait("!document.querySelector('#hwid-reset-confirmation').hidden")
                click('#confirm-hwid-reset')
                wait("!document.querySelector('#reset-feedback').hidden")
                assert evaluate("fixtureCalls.some(c=>c.path.endsWith('/reseller/reset-hwid')&&c.body.username==='customer')")
                assert evaluate("fixtureCalls.slice("+str(before_reset_calls)+").filter(c=>c.method==='GET').length===0"), 'HWID reset must not trigger a page reload'
                screenshot('reseller-hwid.png')
                command('Emulation.setDeviceMetricsOverride', {'width':390,'height':844,'deviceScaleFactor':1,'mobile':True})
                assert evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile page overflows'
                screenshot('reseller-mobile.png')
                assert not errors, errors
                print('Browser checks passed: admin reseller creation, role navigation, license issuance, HWID reset, mobile layout.')
                print(OUTPUT)
        finally:
            browser.terminate()
            browser.wait(timeout=10)
            server.shutdown()


if __name__ == '__main__':
    main()
