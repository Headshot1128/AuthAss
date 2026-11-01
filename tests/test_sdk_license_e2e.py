"""Execute the shipped EXE against a disposable TLS server and license records."""
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import replace

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.app import create_app
from backend.db import connect
from backend.security import now
from test_security import env, login, bearer, PASSWORD


@pytest.mark.skipif(not os.getenv('SDK_EXAMPLE_BINARY'), reason='Set SDK_EXAMPLE_BINARY to run the compiled example')
def test_example_without_arguments_shows_prompts_and_waits_to_close(tmp_path):
    binary = str(Path(os.environ['SDK_EXAMPLE_BINARY']).resolve())
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith('AUTH_')}
    result = subprocess.run([binary], input='2\n\n\n\n\n', capture_output=True, text=True,
                            cwd=tmp_path, env=clean_env, timeout=10)
    assert result.returncode == 1
    assert 'Connecting to https://novyx.online' in result.stdout
    assert '1. Login' in result.stdout and '2. Register key' in result.stdout
    assert 'Username:' in result.stdout and 'Password (visible):' in result.stdout
    assert 'License key:' in result.stdout
    assert 'Hardware ID (' not in result.stdout
    assert 'Press Enter to close' in result.stdout
    assert 'required' in result.stderr


@pytest.mark.skipif(not os.getenv('SDK_EXAMPLE_BINARY'), reason='Set SDK_EXAMPLE_BINARY to run the compiled license example')
def test_example_license_controls_real_variable_and_file(env, tmp_path):
    client, settings, user = env
    file_id = str(uuid.uuid4())
    with connect(settings) as db:
        db.execute('DELETE FROM permissions WHERE user_id=?', (user,))
        db.execute('UPDATE users SET subscription_until=0 WHERE id=?', (user,))
        db.execute("UPDATE files SET id=? WHERE id='protected-file'", (file_id,))
    issued = client.post('/v1/admin/licenses', headers=bearer(login(client, admin=True)),
                         json={'days': 1, 'hardware_bound': True}).json()
    assert issued['key'].startswith('NOVYX-')

    # Trust only this disposable server certificate, never disable verification.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                   .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(replace(settings, registration=False)), host='127.0.0.1', port=port,
                            ssl_certfile=str(cert_path), ssl_keyfile=str(key_path), log_level='error', access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    binary = str(Path(os.environ['SDK_EXAMPLE_BINARY']).resolve())
    process_env = {k: v for k, v in os.environ.items() if not k.startswith('AUTH_')}
    process_env.update(AUTH_USERNAME='alice', AUTH_PASSWORD=PASSWORD, AUTH_LICENSE_KEY=issued['key'],
                       AUTH_FILE_ID=file_id, AUTH_VARIABLE_NAME='premium_feature',
                       AUTH_HARDWARE_ID='example-original-device', AUTH_CA_BUNDLE=str(cert_path))

    def run(label, expected, message, mode=None, input_text=None, **overrides):
        folder = tmp_path / label
        folder.mkdir()
        args = [binary, f'https://localhost:{port}'] + ([mode] if mode else [])
        result = subprocess.run(args, env={**process_env, **overrides},
                                cwd=folder, input=input_text, capture_output=True, text=True, timeout=45)
        assert result.returncode == expected, result.stdout + result.stderr
        assert message in result.stdout + result.stderr
        output = folder / overrides.get('AUTH_DOWNLOAD_PATH', 'protected-download.bin')
        if expected == 0:
            assert output.read_bytes() == b'private\x00payload'
        else:
            assert not output.exists()

    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started
        run('invalid-key', 1, 'License activation denied', AUTH_LICENSE_KEY='NOVYX-INVALID-INVALID')
        run('valid-key', 0, 'Saved file to')
        run('missing-file-id', 1, 'Set AUTH_FILE_ID', AUTH_FILE_ID='')
        run('unknown-file-id', 1, 'Download denied', AUTH_FILE_ID=str(uuid.uuid4()))
        run('custom-output', 0, 'release.bin', AUTH_DOWNLOAD_PATH='release.bin')
        run('wrong-device', 1, 'License activation denied', AUTH_HARDWARE_ID='example-different-device')
        with connect(settings) as db:
            db.execute("UPDATE files SET permission='secret' WHERE storage_name='payload.bin'")
        run('file-permission', 1, 'Download denied')
        with connect(settings) as db:
            db.execute("UPDATE files SET permission='premium' WHERE storage_name='payload.bin'")
            db.execute("UPDATE variables SET permission='secret' WHERE id='flag'")
        run('variable-permission', 1, 'Protected variable denied')
        run('download-without-variable', 0, 'Saved file to', AUTH_VARIABLE_NAME='')
        with connect(settings) as db:
            db.execute("UPDATE variables SET permission='premium' WHERE id='flag'")
            db.execute('UPDATE licenses SET revoked=1 WHERE id=?', (issued['id'],))
        run('revoked-key', 1, 'License activation denied')
        with connect(settings) as db:
            db.execute('UPDATE licenses SET revoked=0, expires_at=? WHERE id=?', (now() - 1, issued['id']))
        run('expired-key', 1, 'License activation denied')
        fresh = client.post('/v1/admin/licenses', headers=bearer(login(client, admin=True)),
                            json={'days': 1}).json()
        run('register-key', 0, 'License activated and bound to this computer', mode='register',
            AUTH_USERNAME='exe-registered', AUTH_LICENSE_KEY=fresh['key'])
        # Login subsequently needs no key; the license entitlement is persisted.
        run('registered-login', 0, 'Login successful', AUTH_USERNAME='exe-registered', AUTH_LICENSE_KEY='')
        run('registered-other-device', 1, 'Protected variable denied', AUTH_USERNAME='exe-registered',
            AUTH_LICENSE_KEY='', AUTH_HARDWARE_ID='different-registered-device')
        run('reused-registration-key', 1, 'Registration denied', mode='register',
            AUTH_USERNAME='second-registered', AUTH_LICENSE_KEY=fresh['key'])
        menu_key = client.post('/v1/admin/licenses', headers=bearer(login(client, admin=True)),
                               json={'days': 1}).json()['key']
        run('menu-register', 0, 'License activated and bound to this computer', mode='interactive',
            input_text=f'2\nmenu-registered\nx\n{menu_key}\n{file_id}\n\n\n',
            AUTH_USERNAME='', AUTH_PASSWORD='', AUTH_LICENSE_KEY='', AUTH_HARDWARE_ID='', AUTH_FILE_ID='')
        run('menu-login', 0, 'Login successful', mode='interactive',
            input_text='1\nmenu-registered\nx\n\n',
            AUTH_USERNAME='', AUTH_PASSWORD='', AUTH_LICENSE_KEY='', AUTH_HARDWARE_ID='')
        long_key = client.post('/v1/admin/licenses', headers=bearer(login(client, admin=True)),
                               json={'days': 1}).json()['key']
        run('long-password-register', 0, 'License activated and bound to this computer', mode='register',
            AUTH_USERNAME='long-password-user', AUTH_PASSWORD='p' * 257, AUTH_LICENSE_KEY=long_key)
        run('long-password-login', 0, 'Login successful', AUTH_USERNAME='long-password-user',
            AUTH_PASSWORD='p' * 257, AUTH_LICENSE_KEY='')
    finally:
        server.should_exit = True
        thread.join(timeout=10)
