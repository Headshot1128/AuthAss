"""Recoverable administrator-only license display; lookup still uses token hashes."""
import os
import secrets
import string
from pathlib import Path
from cryptography.fernet import Fernet


def cipher(settings, create=False):
    path = Path(settings.license_key_file or settings.database + '.license-key')
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        if not create:
            raise FileNotFoundError('License display encryption key is unavailable')
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(Fernet.generate_key())
    return Fernet(path.read_bytes())


def generate():
    alphabet = string.ascii_uppercase + string.digits
    return 'NOVYX-' + '-'.join(''.join(secrets.choice(alphabet) for _ in range(6)) for _ in range(2))
