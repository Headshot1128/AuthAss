"""Real TLS integration, enabled when a compiled SDK probe is available."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time

import pytest
import uvicorn

from backend.app import create_app
from test_security import env  # shared seeded database fixture


@pytest.mark.skipif(not os.getenv('SDK_E2E_BINARY'), reason='Build SDK and set SDK_E2E_BINARY to enable real TLS integration')
def test_cpp_sdk_over_tls(env, tmp_path):
    _, settings, _ = env
    if not shutil.which('openssl'):
        pytest.fail('openssl is required for the TLS integration test')
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                   check=True, capture_output=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host='127.0.0.1', port=port,
                            ssl_certfile=str(cert), ssl_keyfile=str(key), log_level='error', access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert server.started
        subprocess.run([str(Path(os.environ['SDK_E2E_BINARY']).resolve()), f'https://localhost:{port}', str(cert)],
                       check=True, timeout=60)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
