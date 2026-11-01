"""Exercise the built panel against the disposable local Worker on port 8791."""
from pathlib import Path
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

from websockets.sync.client import connect
from backend.security import passwords


def main():
    root = Path(__file__).resolve().parents[1]
    base = 'http://127.0.0.1:8791'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    password = 'bootstrap disposable test password'
    timestamp = int(time.time())
    snapshot = dict(users=[dict(id='bootstrap-owner', username='gerry2.0',
        password_hash=passwords.hash(password), status='active', role='admin',
        subscription_until=0, password_until=None, created_at=timestamp,
        console_only=1, web_approved=0)], licenses=[], permissions=[], variables=[], files=[], audit_logs=[])
    try:
        check = urllib.request.Request(base + '/v1/admin/login',
            data=json.dumps(dict(username='gerry2.0',password=password)).encode(),
            headers={'Content-Type':'application/json'})
        with opener.open(check) as response:
            assert json.load(response)['success']
    except urllib.error.HTTPError as error:
        if error.code != 401: raise
        request = urllib.request.Request(base + '/_migration/import', data=json.dumps(snapshot).encode(),
            headers={'Content-Type':'application/json', 'x-migration-token':'bootstrap-disposable-test'})
        with opener.open(request) as response:
            assert json.load(response)['success']
    output = root / 'build/bootstrap-browser-check'
    def local_api(path, body, token='',method='POST'):
        request=urllib.request.Request(base+path,method=method,data=json.dumps(body).encode(),headers={'Content-Type':'application/json',**({'Authorization':'Bearer '+token} if token else {})})
        with opener.open(request) as response: return json.load(response)
    owner=local_api('/v1/admin/login',dict(username='gerry2.0',password=password))
    test_key=local_api('/v1/admin/licenses',dict(days=1,hardware_bound=True),owner['access_token'])['key']
    customer='qa-directory-'+str(timestamp)
    local_api('/v1/register',dict(username=customer,password=password,license_key=test_key,hardware_id='local-directory-test-device'))
    staff='qa-staff-'+str(timestamp)
    staff_id=local_api('/v1/admin/users',dict(username=staff,password=password,account_type='website'),owner['access_token'])['id']
    local_api('/v1/admin/users/'+staff_id,dict(status='active',subscription_until=0,web_access=True),owner['access_token'],'PUT')
    output.mkdir(exist_ok=True)
    browser_path = os.environ.get('BROWSER_EXE', r'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe')
    with tempfile.TemporaryDirectory(dir=root / 'build', prefix='bootstrap-browser-',ignore_cleanup_errors=True) as folder:
        profile = Path(folder)
        browser = subprocess.Popen([browser_path,'--headless=new','--disable-gpu','--no-first-run',
            '--no-default-browser-check','--disable-background-networking','--no-proxy-server','--remote-debugging-port=0',
            f'--user-data-dir={profile}','about:blank'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        try:
            deadline = time.monotonic() + 20
            while not (profile / 'DevToolsActivePort').exists() and time.monotonic() < deadline:
                time.sleep(.1)
            port = int((profile / 'DevToolsActivePort').read_text().splitlines()[0])
            with opener.open(f'http://127.0.0.1:{port}/json/list') as response:
                page = next(item for item in json.load(response) if item['type'] == 'page')
            with connect(page['webSocketDebuggerUrl'], max_size=12*1024*1024) as ws:
                counter, errors, requests, failed_requests = 0, [], [], []
                def command(method, params=None):
                    nonlocal counter
                    counter += 1
                    ws.send(json.dumps(dict(id=counter,method=method,params=params or {})))
                    while True:
                        message = json.loads(ws.recv(timeout=30))
                        if message.get('method') == 'Runtime.exceptionThrown': errors.append(message['params'])
                        if message.get('method') == 'Network.requestWillBeSent':
                            requests.append(message['params']['request']['url'])
                        if message.get('method') == 'Network.responseReceived' and message['params']['response']['status']>=500:
                            failed_requests.append(message['params']['requestId'])
                        if message.get('id') == counter:
                            assert 'error' not in message, message
                            return message.get('result',{})
                def evaluate(expression):
                    result = command('Runtime.evaluate',dict(expression=expression,returnByValue=True,awaitPromise=True))
                    assert 'exceptionDetails' not in result, result
                    return result.get('result',{}).get('value')
                def wait(expression):
                    deadline = time.monotonic()+30
                    while time.monotonic()<deadline:
                        if evaluate(expression): return
                        time.sleep(.1)
                    for identifier in failed_requests:
                        print('Failed preview response:',command('Network.getResponseBody',dict(requestId=identifier)))
                    raise AssertionError((expression,evaluate('document.body.innerText')))
                def choose(path):
                    document = command('DOM.getDocument')
                    node = command('DOM.querySelector',dict(nodeId=document['root']['nodeId'],selector='#bootstrap-file'))
                    command('DOM.setFileInputFiles',dict(nodeId=node['nodeId'],files=[str(path)]))
                command('Page.enable'); command('Runtime.enable'); command('Network.enable')
                command('Browser.setDownloadBehavior',dict(behavior='allow',downloadPath=str(output)))
                command('Emulation.setDeviceMetricsOverride',dict(width=1440,height=1000,deviceScaleFactor=1,mobile=False))
                command('Page.navigate',dict(url=base))
                wait("!!document.querySelector('#login-form')")
                wait("!document.querySelector('#login-form [type=submit]').disabled")
                for width,height in [(1440,1000),(390,844)]:
                    command('Emulation.setDeviceMetricsOverride',dict(width=width,height=height,deviceScaleFactor=1,mobile=width<700))
                    assert evaluate("(()=>{const link=document.querySelector('#forgot-password').getBoundingClientRect(),label=document.querySelector('label[for=password]').getBoundingClientRect(),input=document.querySelector('#password').getBoundingClientRect();return Math.abs(link.right-input.right)<2&&Math.abs((link.top+link.bottom)-(label.top+label.bottom))<2&&document.documentElement.scrollWidth<=innerWidth;})()")
                    image=command('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False))
                    (output/f'login-{width}.png').write_bytes(base64.b64decode(image['data']))
                command('Emulation.setDeviceMetricsOverride',dict(width=1440,height=1000,deviceScaleFactor=1,mobile=False))
                evaluate("document.querySelector('#forgot-password').click()")
                evaluate("document.querySelector('#modal [name=email]').value='recovery@example.test'")
                evaluate("document.querySelector('#modal-form').requestSubmit()")
                wait("!document.querySelector('#modal-error').hidden")
                assert 'not available yet' in evaluate("document.querySelector('#modal-error').textContent")
                evaluate("document.querySelector('#modal').close()")
                evaluate("document.querySelector('#username').value='gerry2.0'")
                evaluate(f"document.querySelector('#password').value={json.dumps(password)}")
                started = time.perf_counter()
                evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!!document.querySelector('.stats-grid')")
                print('Browser sign-in to dashboard:',round((time.perf_counter()-started)*1000),'ms')
                assert not any('/v1/admin/session' in url for url in requests), requests
                evaluate("document.querySelector('[data-view=account]').click()")
                wait("!!document.querySelector('#account-email-form')")
                assert evaluate("document.querySelector('#account-email-form [type=submit]').disabled")
                assert 'No verified recovery email' in evaluate("document.querySelector('#page-content').textContent")
                screenshot=command('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False))
                (output/'account-email.png').write_bytes(base64.b64decode(screenshot['data']))
                # Create two products through the real admin forms.
                def click(selector): evaluate(f'document.querySelector({json.dumps(selector)}).click()')
                def fill(selector,value): evaluate(f'document.querySelector({json.dumps(selector)}).value={json.dumps(value)}')
                def submit(): evaluate("document.querySelector('#modal-form').requestSubmit()")
                def page(view):
                    click(f'[data-view={view}]')
                    wait(f"document.querySelector('#page-title').textContent==={json.dumps({'applications':'Applications','users':'Users','website_users':'Website accounts'}[view])} && document.querySelector('#page-content').getAttribute('aria-busy')===null")
                def switch(app):
                    evaluate(f"(()=>{{const s=document.querySelector('#application-selector');s.value={json.dumps(app)};s.dispatchEvent(new Event('change',{{bubbles:true}}));}})()")
                    wait("document.querySelector('#page-content').getAttribute('aria-busy')===null")
                def create_app(name):
                    page('applications');click('#page-action');fill('#modal [name=name]',name);submit()
                    wait("!document.querySelector('#modal').open && document.querySelector('#page-content').getAttribute('aria-busy')===null")
                    return evaluate("document.querySelector('#application-selector').value")
                app_a=create_app('External QA')
                page('users');click('#page-action');fill('#modal [name=account_type]','application')
                evaluate("document.querySelector('#modal [name=account_type]').dispatchEvent(new Event('change'))")
                fill('#modal [name=username]','qa-customer');fill('#modal [name=password]','local application test password');submit()
                wait("!document.querySelector('#modal').open && document.querySelector('#table-rows')?.textContent.includes('qa-customer')")
                click('[data-row-action=ban-user]');submit()
                wait("!document.querySelector('#modal').open && !!document.querySelector('[data-row-action=unban-user]')")
                assert evaluate("document.querySelector('#table-rows').textContent.includes('Banned')")
                click('[data-row-action=unban-user]');submit()
                wait("!document.querySelector('#modal').open && !!document.querySelector('[data-row-action=ban-user]')")
                click('[data-command=lookup-user]');fill('#modal [name=username]','qa-customer');submit()
                wait("!!document.querySelector('[data-user-operation=reset-hwid]')")
                click('[data-user-operation=reset-hwid]');submit()
                wait("!document.querySelector('#modal').open && document.querySelector('#page-content').getAttribute('aria-busy')===null")
                app_b=create_app('Spoofer QA');assert app_b!=app_a
                page('users');assert not evaluate("document.querySelector('#table-rows').textContent.includes('qa-customer')")
                switch(app_a);assert evaluate("document.querySelector('#table-rows').textContent.includes('qa-customer')")
                page('applications')
                image=command('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False))
                (output/'applications.png').write_bytes(base64.b64decode(image['data']))
                switch('00000000-0000-4000-8000-000000000001')
                page('website_users')
                assert 'gerry2.0' in evaluate("document.querySelector('#table-rows').textContent")
                assert customer not in evaluate("document.querySelector('#table-rows').textContent")
                print('Applications, isolated Users view, username lookup, Ban/Unban and Reset HWID forms: passed')
                # Exercise page switching on a deliberately slow connection.
                command('Network.emulateNetworkConditions',dict(offline=False,latency=450,downloadThroughput=10000000,uploadThroughput=10000000))
                evaluate("document.querySelector('[data-view=users]').click()")
                assert evaluate("!!document.querySelector('[data-loading-view=users]')")
                wait("document.querySelector('#page-content').getAttribute('aria-busy')===null && !!document.querySelector('#table-rows')")
                directory_text=evaluate("document.querySelector('#table-rows').textContent")
                assert customer in directory_text and test_key in directory_text and 'gerry2.0' not in directory_text
                evaluate("document.querySelector('[data-view=licenses]').click()")
                wait("document.querySelector('#page-content').getAttribute('aria-busy')===null && document.querySelector('#page-title').textContent==='Licenses'")
                cached = evaluate("(() => {const start=performance.now();document.querySelector('[data-view=users]').click();return {ms:performance.now()-start,visible:document.querySelector('#table-rows')?.textContent.includes("+json.dumps(customer)+"),updating:document.querySelector('#page-description').textContent.includes('Updating')};})()")
                assert cached['visible'] and cached['updating'], cached
                print('Cached Users view visible:',round(cached['ms'],1),'ms with 450 ms simulated network latency')
                image = command('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False))
                (output/'navigation.png').write_bytes(base64.b64decode(image['data']))
                evaluate("['variables','users','licenses'].forEach(view=>document.querySelector('[data-view='+view+']').click())")
                wait("document.querySelector('#page-title').textContent==='Licenses' && document.querySelector('#page-content').getAttribute('aria-busy')===null")
                assert evaluate("document.querySelector('#table-data thead').textContent.includes('License')")
                assert evaluate("!document.querySelector('#console').hidden && document.querySelector('#page-error').hidden")
                command('Network.emulateNetworkConditions',dict(offline=False,latency=0,downloadThroughput=-1,uploadThroughput=-1))
                evaluate("document.querySelector('[data-view=bootstrapper]').click()")
                wait("!!document.querySelector('#bootstrap-form')")
                evaluate("document.querySelector('#bootstrap-sdk').click()")
                wait("document.querySelector('#bootstrap-sdk-status').textContent.startsWith('SDK ready')")
                choose(root / 'README.md')
                evaluate("document.querySelector('#bootstrap-form').requestSubmit()")
                wait("!document.querySelector('#bootstrap-error').hidden")
                assert 'Windows executable' in evaluate("document.querySelector('#bootstrap-error').textContent")
                choose(root / 'build/embedded/novyx_dll_example.exe')
                evaluate("document.querySelector('#bootstrap-form').requestSubmit()")
                wait("!document.querySelector('#bootstrap-result').hidden || !document.querySelector('#bootstrap-error').hidden")
                if evaluate("!document.querySelector('#bootstrap-error').hidden"):
                    raise AssertionError(evaluate("document.querySelector('#bootstrap-error').textContent"))
                assert evaluate("document.querySelector('#bootstrap-error').hidden")
                screenshot = command('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False))
                (output/'desktop.png').write_bytes(base64.b64decode(screenshot['data']))
                command('Emulation.setDeviceMetricsOverride',dict(width=390,height=844,deviceScaleFactor=1,mobile=True))
                assert evaluate('document.documentElement.scrollWidth<=window.innerWidth')
                screenshot = command('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False))
                (output/'mobile.png').write_bytes(base64.b64decode(screenshot['data']))
                # Session-local page snapshots must never survive sign-out.
                evaluate("document.querySelector('#logout').click()")
                wait("!document.querySelector('#login-screen').hidden")
                evaluate("document.querySelector('#username').value='gerry2.0'")
                evaluate("document.querySelector('#remember-session').checked=true")
                evaluate(f"document.querySelector('#password').value={json.dumps(password)}")
                evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!!document.querySelector('.stats-grid') || !document.querySelector('#login-error').hidden")
                if not evaluate("!!document.querySelector('.stats-grid')"):
                    # Wrangler explicitly rejects non-idempotent requests during
                    # local reloads. Simulate a fresh user sign-in only for that
                    # exact development response; never retry a token refresh.
                    assert failed_requests
                    failure=command('Network.getResponseBody',dict(requestId=failed_requests[-1]))
                    assert failure.get('body','').startswith('Your worker restarted mid-request.'),failure
                    print('Local Wrangler reloaded; entering a fresh sign-in for the session-clear check')
                    evaluate(f"document.querySelector('#password').value={json.dumps(password)}")
                    evaluate("document.querySelector('#login-form').requestSubmit()")
                    wait("!!document.querySelector('.stats-grid')")
                command('Network.emulateNetworkConditions',dict(offline=False,latency=450,downloadThroughput=10000000,uploadThroughput=10000000))
                evaluate("document.querySelector('[data-view=users]').click()")
                assert evaluate("!!document.querySelector('[data-loading-view=users]') && !document.querySelector('#table-rows')")
                wait("document.querySelector('#page-content').getAttribute('aria-busy')===null && !!document.querySelector('#table-rows')")
                command('Network.emulateNetworkConditions',dict(offline=False,latency=0,downloadThroughput=-1,uploadThroughput=-1))
                command('Page.reload')
                wait("!!document.querySelector('.stats-grid')")
                assert evaluate("!document.cookie.includes('novyx-remember')")
                print('Stay signed in restores the dashboard after reload; cookie is hidden from JavaScript: passed')
                evaluate("document.querySelector('#logout').click()")
                wait("!document.querySelector('#login-screen').hidden")
                command('Page.reload')
                wait("!!document.querySelector('#login-form') && !document.querySelector('#login-form [type=submit]').disabled")
                assert evaluate("document.querySelector('#console').hidden")
                assert not errors, errors
                for action in ['verify-email','reset-password']:
                    command('Page.navigate',dict(url=base+'/#action='+action+'&token='+'a'*64))
                    wait("!!document.querySelector('#modal')?.open")
                    assert evaluate("location.hash===''"), 'Recovery token must be removed from the address bar'
                    if action=='reset-password':
                        evaluate("document.querySelector('#modal [name=password]').value='test reset password'")
                        evaluate("document.querySelector('#modal [name=confirm]').value='test reset password'")
                    evaluate("document.querySelector('#modal-form').requestSubmit()")
                    wait("!document.querySelector('#modal-error').hidden")
                    assert 'expired' in evaluate("document.querySelector('#modal-error').textContent")
                assert not errors,errors
                print('Recovery forms, disabled delivery state, cleared link fragments and invalid-link handling: passed')
                command('Page.navigate',dict(url=base+'/?staff-check=1'))
                wait("!!document.querySelector('#login-form') && !document.querySelector('#login-form [type=submit]').disabled")
                evaluate('document.querySelector("#username").value='+json.dumps(staff))
                evaluate('document.querySelector("#password").value='+json.dumps(password))
                evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!!document.querySelector('.stats-grid')")
                page('users')
                assert evaluate("document.querySelector('#page-action').hidden && document.querySelector('[data-view=website_users]').hidden")
                assert evaluate("!!document.querySelector('[data-command=lookup-user]') && !!document.querySelector('[data-row-action=edit]') && !!document.querySelector('[data-row-action=reset-user-hwid]') && !!document.querySelector('[data-row-action=ban-user]') && !!document.querySelector('[data-row-action=delete-user]')")
                assert 'Read only' not in evaluate("document.querySelector('#table-rows').textContent")
                def staff_action(action):
                    evaluate("Array.from(document.querySelectorAll('#table-rows tr')).find(row=>row.textContent.includes("+json.dumps(customer)+")).querySelector('[data-row-action="+action+"]').click()")
                    submit()
                    wait("!document.querySelector('#modal').open && document.querySelector('#page-content').getAttribute('aria-busy')===null")
                for action in ['edit','reset-user-hwid','ban-user','unban-user']:
                    staff_action(action)
                image=command('Page.captureScreenshot',dict(format='png',captureBeyondViewport=False))
                (output/'staff-customer-actions.png').write_bytes(base64.b64decode(image['data']))
                staff_action('delete-user')
                assert customer not in evaluate("document.querySelector('#table-rows').textContent")
                click('#logout');wait("!document.querySelector('#login-screen').hidden")
                print('Website user: Manage, Reset HWID, Ban/Unban and Delete work; Create user and Website accounts hidden: passed')
            downloaded = output/'novyx_dll_example-bootstrap.exe'
            deadline = time.monotonic()+15
            while not downloaded.exists() and time.monotonic()<deadline: time.sleep(.1)
            template = (root/'build/embedded/novyx_bootstrap.exe').read_bytes()
            application = (root/'build/embedded/novyx_dll_example.exe').read_bytes()
            expected = template + application + b'NVXPKG01' + len(application).to_bytes(8,'little') + len(template).to_bytes(8,'little')
            assert hashlib.sha256(downloaded.read_bytes()).digest() == hashlib.sha256(expected).digest()
            sdk = output/'novyx-bootstrap-sdk.zip'
            assert sdk.read_bytes() == (root/'sites/novyx/public/bootstrap/novyx-bootstrap-sdk.zip').read_bytes()
            result = subprocess.run([str(downloaded),'https://novyx.online','invalid-mode'],capture_output=True,text=True,timeout=20)
            assert result.returncode == 1 and 'Unknown mode.' in result.stderr
            print('Browser login, invalid-EXE rejection, SDK link, packaging, download bytes, EXE launch, mobile layout: passed')
        finally:
            browser.terminate()
            browser.wait(timeout=15)


if __name__ == '__main__':
    main()
