import hashlib
import secrets
import time
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

passwords = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
DUMMY = passwords.hash(secrets.token_urlsafe(32))


def now():
    return int(time.time())


def uid():
    return str(uuid.uuid4())


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def verify(encoded, password):
    try:
        return passwords.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


def audit(db, event, outcome, actor=None, target=None):
    db.execute('INSERT INTO audit_logs(timestamp,actor_id,event,target,outcome) VALUES(?,?,?,?,?)',
               (now(), actor, event, target, outcome))


def issue(db, settings, session_id):
    access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    session = db.execute('SELECT expires_at FROM sessions WHERE id=?', (session_id,)).fetchone()
    expiry = min(now() + settings.access_seconds, session['expires_at'])
    db.execute('INSERT INTO access_tokens VALUES(?,?,?)', (digest(access), session_id, expiry))
    db.execute('INSERT INTO refresh_tokens(hash,session_id) VALUES(?,?)', (digest(refresh), session_id))
    return dict(success=True, access_token=access, refresh_token=refresh, expires_at=expiry)
