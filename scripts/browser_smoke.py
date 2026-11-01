"""Optional local Chromium smoke test, against a disposable database only.

Set BROWSER_EXE to a Chromium/Chrome/Brave executable. Requires websockets and
the development certificate created by scripts/dev_certificate.py.
"""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request

import uvicorn
from websockets.sync.client import connect as websocket_connect

from backend.app import create_app
from backend.config import Settings
from backend.db import connect
from backend.security import now, passwords, uid


def main():
    browser_path = os.environ.get('BROWSER_EXE', r'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe')
    certificate = Path('data/tls/localhost-cert.pem').resolve()
    private_key = Path('data/tls/localhost-key.pem').resolve()
    assert certificate.exists() and private_key.exists()
    screenshots = Path('data/browser-check')
    screenshots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='web-smoke-', dir='data') as temporary:
        root = Path(temporary).resolve()
        settings = Settings(database=str(root / 'test.db'), storage=str(root / 'private'), owner_username='browser-admin')
        app = create_app(settings)
        password = 'temporary browser test password'
        admin_id = uid()
        with connect(settings) as db:
            db.execute("INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,'admin',?)",
                       (admin_id,'browser-admin',passwords.hash(password),now()))
        (root / 'private' / 'demo.bin').write_bytes(b'test payload')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            port = sock.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,
            ssl_certfile=str(certificate),ssl_keyfile=str(private_key),log_level='error',access_log=False))
        thread = threading.Thread(target=server.run,daemon=True)
        thread.start()
        browser = None
        try:
            deadline = time.monotonic()+15
            while not server.started and time.monotonic()<deadline:
                time.sleep(.1)
            assert server.started
            profile = root / 'browser'
            browser = subprocess.Popen([browser_path,'--headless=new','--disable-gpu','--no-first-run',
                '--no-default-browser-check','--disable-background-networking','--ignore-certificate-errors',
                '--remote-debugging-port=0',f'--user-data-dir={profile}','about:blank'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            active_port = profile / 'DevToolsActivePort'
            deadline = time.monotonic()+20
            while not active_port.exists() and time.monotonic()<deadline:
                time.sleep(.1)
            assert active_port.exists(), 'Browser did not expose its local debugging port'
            debug_port = int(active_port.read_text().splitlines()[0])
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f'http://127.0.0.1:{debug_port}/json/list') as response:
                page = next(item for item in json.load(response) if item['type'] == 'page')
            errors = []
            with websocket_connect(page['webSocketDebuggerUrl'],max_size=10*1024*1024) as ws:
                counter = 0

                def command(method, params=None):
                    nonlocal counter
                    counter += 1
                    identifier = counter
                    ws.send(json.dumps({'id':identifier,'method':method,'params':params or {}}))
                    while True:
                        message = json.loads(ws.recv(timeout=20))
                        if message.get('method') == 'Runtime.exceptionThrown':
                            errors.append(message['params'])
                        if message.get('id') == identifier:
                            assert 'error' not in message, message
                            return message.get('result',{})

                def evaluate(expression):
                    result = command('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True})
                    assert 'exceptionDetails' not in result, result
                    return result.get('result',{}).get('value')

                def wait(expression):
                    deadline = time.monotonic()+15
                    while time.monotonic()<deadline:
                        if evaluate(expression):
                            return
                        time.sleep(.1)
                    print('Browser diagnostic:',evaluate("JSON.stringify({modal:document.querySelector('#modal').open,error:document.querySelector('#modal-error')?.textContent,loginError:document.querySelector('#login-error')?.textContent,fields:[...document.querySelectorAll('#modal-form input')].map(e=>({name:e.name,valid:e.validity.valid,message:e.validationMessage})),rows:document.querySelector('#table-rows')?.textContent})"))
                    failed = command('Page.captureScreenshot',{'format':'png'})
                    (screenshots / 'failure.png').write_bytes(base64.b64decode(failed['data']))
                    print('Runtime errors:',errors)
                    raise AssertionError(f'Timed out waiting for {expression}')

                def fill(selector,value):
                    evaluate(f"(() => {{ const scope = document.querySelector('#modal[open]') || document; scope.querySelector({json.dumps(selector)}).value={json.dumps(value)}; }})()")

                def click(selector):
                    evaluate(f'document.querySelector({json.dumps(selector)}).click()')

                def submit():
                    evaluate("document.querySelector('#modal-form').requestSubmit()")

                command('Page.enable'); command('Runtime.enable')
                command('Emulation.setDeviceMetricsOverride',{'width':1440,'height':1000,'deviceScaleFactor':1,'mobile':False})
                command('Page.navigate',{'url':f'https://localhost:{port}/'})
                wait("!!document.querySelector('#login-form') && typeof api === 'function'")
                assert evaluate("document.title.includes('NOVYX')")
                if evaluate("document.documentElement.dataset.theme==='dark'"):
                    click('#login-screen .theme-toggle')
                image = command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':False})
                (screenshots / 'login.png').write_bytes(base64.b64decode(image['data']))
                click('#login-screen .theme-toggle')
                assert evaluate("document.documentElement.dataset.theme==='dark'")
                command('Page.reload')
                wait("!!document.querySelector('#login-form') && typeof api === 'function'")
                assert evaluate("document.documentElement.dataset.theme==='dark'")
                image = command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':False})
                (screenshots / 'login-dark.png').write_bytes(base64.b64decode(image['data']))
                click('#login-screen .theme-toggle')
                fill('#username','browser-admin'); fill('#password','incorrect password')
                evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!document.querySelector('#login-error').hidden")
                assert evaluate("document.querySelector('#console').hidden")
                fill('#password',password)
                evaluate("document.querySelector('#login-form').requestSubmit()")
                wait("!document.querySelector('#console').hidden && !!document.querySelector('.stats-grid')")
                assert evaluate("document.querySelector('.stat-number').textContent") == '1'
                image = command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':False})
                (screenshots / 'overview.png').write_bytes(base64.b64decode(image['data']))
                click('#console .theme-toggle')
                assert evaluate("document.documentElement.dataset.theme==='dark'")
                image = command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':False})
                (screenshots / 'overview-dark.png').write_bytes(base64.b64decode(image['data']))
                click('#console .theme-toggle')
                click('.nav-item[data-view="users"]')
                wait("!!document.querySelector('#table-rows')")
                assert evaluate("document.querySelector('[data-row-action=copyid]')===null && document.querySelector('[data-row-action=sessions]')===null")
                click('#page-action')
                fill('[name=username]','web-created'); fill('[name=password]',password); submit()
                wait("!document.querySelector('#modal').open && document.querySelector('#table-rows').textContent.includes('web-created')")
                with connect(settings) as db:
                    created = db.execute("SELECT id FROM users WHERE username='web-created'").fetchone()['id']
                    account = db.execute('SELECT role,console_only FROM users WHERE id=?',(created,)).fetchone()
                    assert account['role'] == 'admin' and account['console_only'] == 1
                click(f'[data-row-action="edit"][data-id="{created}"]')
                assert evaluate("!document.querySelector('[name=web_access]').checked")
                assert evaluate("document.querySelector('[name=subscription]')===null")
                submit()
                wait("!document.querySelector('#modal').open")
                click(f'[data-row-action="permissions"][data-id="{created}"]')
                wait("!!document.querySelector('[name=web_access]')")
                click('[name=web_access]'); submit()
                wait("!document.querySelector('#modal').open")
                with connect(settings) as db:
                    assert db.execute('SELECT web_approved FROM users WHERE id=?',(created,)).fetchone()[0] == 1
                click(f'[data-row-action="delete-user"][data-id="{created}"]'); submit()
                wait("!document.querySelector('#modal').open && !document.querySelector('#table-rows').textContent.includes('web-created')")
                with connect(settings) as db:
                    assert db.execute('SELECT 1 FROM users WHERE id=?',(created,)).fetchone() is None
                click('.nav-item[data-view="licenses"]'); wait("document.querySelector('#page-title').textContent==='Licenses' && !!document.querySelector('#table-rows')")
                click('#page-action')
                assert evaluate("document.querySelector('#modal [name=permission]')===null")
                fill('[name=days]',1); click('[name=hardware]'); submit()
                wait("!!document.querySelector('#new-license-key')")
                assert evaluate("/^NOVYX-[A-Z0-9]{6}-[A-Z0-9]{6}$/.test(document.querySelector('#new-license-key').textContent)")
                click('#modal-form [type=submit]'); wait("!document.querySelector('#modal').open")
                assert evaluate("/^NOVYX-[A-Z0-9]{6}-[A-Z0-9]{6}$/.test(document.querySelector('.license-key').textContent)")
                with connect(settings) as db:
                    previous_expiry = db.execute('SELECT expires_at FROM licenses').fetchone()[0]
                click('[data-row-action=extend]'); fill('[name=days]',1); submit()
                wait("!document.querySelector('#modal').open && !!document.querySelector('[data-row-action=extend]')")
                with connect(settings) as db:
                    assert db.execute('SELECT expires_at FROM licenses').fetchone()[0] == previous_expiry + 86400
                click('[data-row-action=reset-hwid]'); submit()
                wait("!document.querySelector('#modal').open && !!document.querySelector('[data-row-action=revoke]')")
                click('[data-row-action=revoke]'); submit(); wait("!document.querySelector('#modal').open && document.querySelector('#table-rows').textContent.includes('Revoked')")
                click('.nav-item[data-view="variables"]'); wait("document.querySelector('#page-title').textContent==='Variables' && !!document.querySelector('#table-rows')")
                click('#page-action'); fill('[name=name]','web_feature'); fill('[name=value]','<img src=x onerror=alert(1)>'); fill('[name=permission]','premium'); submit()
                wait("!document.querySelector('#modal').open && document.querySelector('#table-rows').textContent.includes('web_feature')")
                assert evaluate("document.querySelector('#table-rows').querySelector('img')===null")
                click('.nav-item[data-view="files"]'); wait("document.querySelector('#page-title').textContent==='Protected files' && !!document.querySelector('#table-rows')")
                click('#page-action'); fill('[name=id]','web-file'); fill('[name=storage]','demo.bin'); fill('[name=permission]','premium'); submit()
                wait("!document.querySelector('#modal').open && document.querySelector('#table-rows').textContent.includes('web-file')")
                click('.nav-item[data-view="audit"]'); wait("document.querySelector('#page-title').textContent==='Activity log' && !!document.querySelector('#table-rows')")
                assert evaluate("document.querySelector('#table-rows').textContent.includes('file update')")
                click('.nav-item[data-view="overview"]'); wait("!!document.querySelector('.stats-grid')")
                command('Emulation.setDeviceMetricsOverride',{'width':390,'height':844,'deviceScaleFactor':1,'mobile':True})
                assert evaluate('document.documentElement.scrollWidth <= innerWidth'), 'Mobile viewport overflows'
                image = command('Page.captureScreenshot',{'format':'png','captureBeyondViewport':False})
                (screenshots / 'mobile.png').write_bytes(base64.b64decode(image['data']))
                click('#menu-toggle'); assert evaluate("document.querySelector('#sidebar').classList.contains('open')")
                # Refresh expires server-side; the next browser request must rotate and recover.
                with connect(settings) as db:
                    db.execute('UPDATE access_tokens SET expires_at=?',(now()-1,))
                click('#refresh'); wait("!!document.querySelector('.stats-grid')")
                with connect(settings) as db:
                    assert db.execute('SELECT COUNT(*) FROM refresh_tokens WHERE used=1').fetchone()[0] == 1
                    db.execute('UPDATE sessions SET revoked=1')
                click('#refresh'); wait("!document.querySelector('#login-screen').hidden")
                assert evaluate("document.querySelector('#console').hidden")
                assert not errors, errors
                print('Browser checks passed: rejected login, dashboard, website-only user creation, access controls, permissions, licenses, variables/XSS, files, audit, mobile, refresh, revocation.')
                print('Screenshots: data/browser-check/')
        finally:
            if browser:
                browser.terminate()
                try:
                    browser.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    browser.kill(); browser.wait(timeout=10)
            server.should_exit = True
            thread.join(timeout=10)
            # Chromium subprocesses may need a moment to close the temporary profile.
            time.sleep(1)


if __name__ == '__main__':
    main()
