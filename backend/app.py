from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings, prepare
from .db import connect, migrate
from .security import DUMMY, audit, digest, issue, now, passwords, uid, verify
from .license_keys import cipher, generate


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')


class Credentials(Input):
    username: str = Field(pattern=r'^[A-Za-z0-9_.-]{3,64}$')
    password: str = Field(min_length=12, max_length=128)
    hardware_id: str | None = Field(default=None, min_length=16, max_length=256)


class ApplicationCredentials(Credentials):
    password: str = Field(min_length=1)


class Registration(ApplicationCredentials):
    license_key: str | None = Field(default=None, min_length=19, max_length=256)


class Refresh(Input):
    refresh_token: str = Field(min_length=32, max_length=256)
    hardware_id: str | None = Field(default=None, min_length=16, max_length=256)


class Activation(Input):
    key: str = Field(min_length=19, max_length=256)


class UserUpdate(Input):
    status: Literal['active', 'suspended', 'revoked']
    subscription_until: int = Field(ge=0)
    password_until: int | None = Field(default=None, ge=0)
    web_access: bool | None = None


class Permission(Input):
    permission: str = Field(pattern=r'^[a-zA-Z0-9_.:-]{1,100}$')
    allowed: bool


class LicenseCreate(Input):
    days: int = Field(default=30, ge=1, le=999, strict=True)
    permission: str = Field(default='premium', pattern=r'^[a-zA-Z0-9_.:-]{1,100}$')
    hardware_bound: bool = False


class LicenseExtension(Input):
    days: int = Field(ge=1, le=999, strict=True)


class Variable(Input):
    name: str = Field(pattern=r'^[a-zA-Z0-9_.-]{1,100}$')
    user_id: str | None = None
    value: str = Field(max_length=16384)
    permission: str = Field(pattern=r'^[a-zA-Z0-9_.:-]{1,100}$')


class FileMetadata(Input):
    storage_name: str = Field(pattern=r'^[a-zA-Z0-9_.-]{1,128}$')
    permission: str = Field(pattern=r'^[a-zA-Z0-9_.:-]{1,100}$')
    enabled: bool = True
    max_bytes: int = Field(gt=0, le=1024 * 1024 * 1024)


def deny(code, status=401):
    raise HTTPException(status, code)


def website_allowed(user, settings):
    return user['role'] == 'admin' and (user['username'] in (settings.owner_username, 'slights1', 'admin') or user['web_approved'])


def owner_authenticated(db, request):
    user = authenticated(db, request, 'admin')
    if user['username'] != request.app.state.settings.owner_username:
        deny('owner_required', 403)
    return user


def throttle(db, bucket, limit, seconds=60):
    bucket = digest(bucket)
    t = now()
    db.execute('DELETE FROM rate_limits WHERE window_start<?', (t - 86400,))
    row = db.execute('SELECT * FROM rate_limits WHERE bucket=?', (bucket,)).fetchone()
    if row and row['window_start'] > t - seconds:
        if row['count'] >= limit:
            audit(db, 'rate_limit', 'denied')
            deny('rate_limited', 429)
        db.execute('UPDATE rate_limits SET count=count+1 WHERE bucket=?', (bucket,))
    else:
        db.execute('INSERT OR REPLACE INTO rate_limits VALUES(?,?,1)', (bucket, t))


def authenticated(db, request, audience='client', count_request=True):
    header = request.headers.get('authorization', '')
    if not header.startswith('Bearer ') or len(header) > 512:
        deny('authentication_required')
    row = db.execute('''SELECT u.*, s.id AS session_id, s.revoked, s.audience,
        s.expires_at AS session_expiry, s.hardware_hash, a.expires_at AS access_expiry
        FROM access_tokens a JOIN sessions s ON a.session_id=s.id
        JOIN users u ON s.user_id=u.id WHERE a.hash=?''', (digest(header[7:]),)).fetchone()
    if not row:
        deny('invalid_token')
    if row['status'] != 'active' or row['revoked']:
        deny('revoked')
    if min(row['session_expiry'], row['access_expiry']) <= now():
        deny('expired')
    if row['password_until'] is not None and row['password_until'] <= now():
        deny('expired')
    if row['audience'] != audience or (audience == 'admin' and row['role'] != 'admin'):
        deny('permission_denied', 403)
    if audience == 'admin' and not website_allowed(row, request.app.state.settings):
        deny('website_approval_required', 401)
    if audience == 'client' and (row['console_only'] or row['role'] == 'admin'):
        deny('permission_denied', 403)
    if row['hardware_hash'] and digest(request.headers.get('x-hardware-id', '')) != row['hardware_hash']:
        deny('hardware_mismatch', 403)
    if count_request:
        throttle(db, 'session:' + row['session_id'], 120)
    return row


def entitled(db, user, permission):
    if user['frozen_at'] is not None:
        deny('subscription_frozen', 403)
    if user['subscription_until'] <= now():
        deny('subscription_expired', 403)
    allowed = db.execute('SELECT 1 FROM permissions WHERE user_id=? AND permission=?',
                         (user['id'], permission)).fetchone()
    licensed = db.execute('''SELECT 1 FROM licenses WHERE user_id=? AND permission=?
        AND revoked=0 AND frozen_at IS NULL AND expires_at>? AND (hardware_bound=0 OR hardware_hash=?)''',
                          (user['id'], permission, now(), user['hardware_hash'])).fetchone()
    if not allowed and not licensed:
        deny('permission_denied', 403)


def create_app(settings=None):
    settings = settings or Settings.environment()
    prepare(settings)
    migrate(settings)
    if settings.owner_password:
        with connect(settings) as db:
            user = db.execute('SELECT id FROM users WHERE username=?', (settings.owner_username,)).fetchone()
            if not user:
                identifier = uid()
                db.execute("INSERT INTO users(id,username,password_hash,role,console_only,web_approved,created_at) VALUES(?,?,?,'admin',1,1,?)",
                           (identifier, settings.owner_username, passwords.hash(settings.owner_password), now()))
                audit(db, 'system.bootstrap-owner', 'allowed', target=identifier)
            else:
                db.execute("UPDATE users SET password_hash=?,role='admin',console_only=1,web_approved=1,status='active',password_until=NULL WHERE id=?",
                           (passwords.hash(settings.owner_password), user['id']))
                audit(db, 'system.sync-owner', 'allowed', target=user['id'])
    app = FastAPI(title='Secure Authorization', version='1.0.0', docs_url=None, redoc_url=None)
    app.state.settings = settings

    @app.exception_handler(StarletteHTTPException)
    async def expected_error(request, exc):
        return JSONResponse({'success': False, 'error': exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        # Never reflect validation inputs, which can include passwords and tokens.
        return JSONResponse({'success': False, 'error': 'invalid_request'}, status_code=422)

    @app.exception_handler(Exception)
    async def unexpected_error(request, exc):
        return JSONResponse({'success': False, 'error': 'server_error'}, status_code=500)

    @app.middleware('http')
    async def boundary(request, call_next):
        if settings.require_https and request.url.scheme != 'https':
            return JSONResponse({'success': False, 'error': 'https_required'}, status_code=400)
        # Buffer bounded JSON requests before parsing, including chunked bodies.
        size = 0
        chunks = []
        async for chunk in request.stream():
            size += len(chunk)
            if size > 32768:
                return JSONResponse({'success': False, 'error': 'request_too_large'}, status_code=413)
            chunks.append(chunk)
        request._body = b''.join(chunks)
        response = await call_next(request)
        if response.status_code >= 400:
            with connect(settings) as db:
                audit(db, 'request.denied', str(response.status_code))
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['X-Frame-Options'] = 'DENY'
        return response

    def login(body, request, audience):
        with connect(settings) as db:
            peer = request.client.host if request.client else 'unknown'
            throttle(db, 'login-ip:' + peer, settings.rate_limit)
            throttle(db, 'login-user:' + body.username.lower(), 10, 300)
            user = db.execute('SELECT * FROM users WHERE username=?', (body.username.lower(),)).fetchone()
            valid = verify(user['password_hash'] if user else DUMMY, body.password)
            if (not valid or not user or user['status'] != 'active'
                or (user['password_until'] is not None and user['password_until'] <= now())
                or (audience == 'admin' and user['role'] != 'admin')):
                audit(db, 'login', 'denied')
                deny('invalid_credentials')
            if audience == 'client' and (user['console_only'] or user['role'] == 'admin'):
                audit(db, 'login', 'denied')
                deny('invalid_credentials')
            if audience == 'admin' and not website_allowed(user, settings):
                audit(db, 'login.approval_required', 'denied', user['id'])
                deny('website_approval_required', 403)
            if passwords.check_needs_rehash(user['password_hash']):
                db.execute('UPDATE users SET password_hash=? WHERE id=?', (passwords.hash(body.password), user['id']))
            sid = uid()
            db.execute('INSERT INTO sessions VALUES(?,?,?,?,0,?)',
                       (sid, user['id'], audience, now() + settings.session_seconds,
                        digest(body.hardware_id) if body.hardware_id else None))
            audit(db, 'login', 'allowed', user['id'])
            return issue(db, settings, sid)

    @app.post('/v1/register', status_code=201)
    def register(body: Registration, request: Request):
        with connect(settings) as db:
            throttle(db, 'register:' + (request.client.host if request.client else 'unknown'), 5, 300)
            if not body.license_key and not settings.registration:
                deny('registration_disabled', 403)
            name = body.username.lower()
            if name == settings.owner_username:
                deny('registration_failed', 409)
            if db.execute('SELECT 1 FROM users WHERE username=?', (name,)).fetchone():
                audit(db, 'registration', 'denied')
                deny('registration_failed', 409)
            identifier = uid()
            if body.license_key:
                if not body.hardware_id:
                    deny('hardware_required', 422)
                license = db.execute('SELECT * FROM licenses WHERE key_hash=?', (digest(body.license_key),)).fetchone()
                if not license or license['revoked'] or license['frozen_at'] is not None or license['expires_at'] <= now() or license['user_id'] or license['hardware_hash']:
                    deny('invalid_license', 403)
                db.execute('INSERT INTO users(id,username,password_hash,created_at,subscription_until) VALUES(?,?,?,?,?)',
                           (identifier, name, passwords.hash(body.password), now(), license['expires_at']))
                db.execute('UPDATE licenses SET user_id=?,hardware_bound=1,hardware_hash=? WHERE id=?',
                           (identifier, digest(body.hardware_id), license['id']))
                audit(db, 'registration', 'allowed', identifier)
                audit(db, 'activation', 'allowed', identifier, license['id'])
                return {'success': True}
            db.execute('INSERT INTO users(id,username,password_hash,created_at) VALUES(?,?,?,?)',
                       (identifier, name, passwords.hash(body.password), now()))
            audit(db, 'registration', 'allowed', identifier)
            # Registration deliberately does not create a session.
            return {'success': True}

    @app.post('/v1/login')
    def user_login(body: ApplicationCredentials, request: Request):
        return login(body, request, 'client')

    @app.post('/v1/admin/login')
    def admin_login(body: Credentials, request: Request):
        return login(body, request, 'admin')

    @app.post('/v1/refresh')
    def refresh(body: Refresh, request: Request):
        with connect(settings) as db:
            throttle(db, 'refresh:' + (request.client.host if request.client else 'unknown'), 60)
            row = db.execute('''SELECT r.used, s.*, u.status, u.password_until, u.role, u.console_only, u.username, u.web_approved FROM refresh_tokens r
                JOIN sessions s ON r.session_id=s.id JOIN users u ON s.user_id=u.id WHERE r.hash=?''',
                             (digest(body.refresh_token),)).fetchone()
            if not row:
                deny('invalid_token')
            if row['used']:
                db.execute('UPDATE sessions SET revoked=1 WHERE id=?', (row['id'],))
                audit(db, 'refresh_replay', 'revoked', row['user_id'])
                deny('revoked')
            if row['revoked'] or row['status'] != 'active':
                deny('revoked')
            if ((row['audience'] == 'client' and (row['console_only'] or row['role'] == 'admin'))
                or (row['audience'] == 'admin' and not website_allowed(row, settings))):
                db.execute('UPDATE sessions SET revoked=1 WHERE id=?', (row['id'],))
                deny('revoked')
            if row['expires_at'] <= now() or (row['password_until'] is not None and row['password_until'] <= now()):
                deny('expired')
            if row['hardware_hash'] and digest(body.hardware_id or '') != row['hardware_hash']:
                deny('hardware_mismatch', 403)
            db.execute('UPDATE refresh_tokens SET used=1 WHERE hash=?', (digest(body.refresh_token),))
            db.execute('DELETE FROM access_tokens WHERE session_id=?', (row['id'],))
            audit(db, 'refresh', 'allowed', row['user_id'])
            return issue(db, settings, row['id'])

    @app.get('/v1/session')
    def session(request: Request):
        with connect(settings) as db:
            user = authenticated(db, request)
            return {'success': True, 'user_id': user['id'], 'subscription_until': user['subscription_until']}

    @app.post('/v1/logout')
    def logout(request: Request):
        with connect(settings) as db:
            user = authenticated(db, request)
            db.execute('UPDATE sessions SET revoked=1 WHERE id=?', (user['session_id'],))
            audit(db, 'logout', 'allowed', user['id'])
            return {'success': True}

    @app.post('/v1/admin/logout')
    def admin_logout(request: Request):
        with connect(settings) as db:
            user = authenticated(db, request, 'admin')
            db.execute('UPDATE sessions SET revoked=1 WHERE id=?', (user['session_id'],))
            audit(db, 'admin.logout', 'allowed', user['id'])
            return {'success': True}

    @app.post('/v1/licenses/activate')
    def activate(body: Activation, request: Request):
        with connect(settings) as db:
            user = authenticated(db, request)
            throttle(db, 'activation:' + user['id'], 10, 300)
            lic = db.execute('SELECT * FROM licenses WHERE key_hash=?', (digest(body.key),)).fetchone()
            if (not lic or lic['revoked'] or lic['frozen_at'] is not None or lic['expires_at'] <= now()
                or (lic['user_id'] is not None and lic['user_id'] != user['id'])
                or (lic['hardware_bound'] and not user['hardware_hash'])
                or (lic['hardware_hash'] and lic['hardware_hash'] != user['hardware_hash'])):
                audit(db, 'activation', 'denied', user['id'])
                deny('invalid_license', 403)
            db.execute('UPDATE licenses SET user_id=?,hardware_hash=? WHERE id=?',
                       (user['id'], user['hardware_hash'] if lic['hardware_bound'] else None, lic['id']))
            db.execute('UPDATE users SET subscription_until=MAX(subscription_until,?) WHERE id=?',
                       (lic['expires_at'], user['id']))
            audit(db, 'activation', 'allowed', user['id'], lic['id'])
            return {'success': True}

    @app.get('/v1/variables/{name}')
    def variable(name: str, request: Request):
        with connect(settings) as db:
            user = authenticated(db, request)
            row = db.execute('''SELECT * FROM variables WHERE name=? AND (user_id=? OR user_id IS NULL)
                ORDER BY user_id IS NULL LIMIT 1''', (name, user['id'])).fetchone()
            try:
                if not row:
                    deny('permission_denied', 403)
                entitled(db, user, row['permission'])
            except HTTPException:
                audit(db, 'variable', 'denied', user['id'])
                raise
            audit(db, 'variable', 'allowed', user['id'], row['id'])
            return {'success': True, 'value': row['value']}

    @app.get('/v1/files/{file_id}/content')
    def download(file_id: str, request: Request):
        # Authenticated streaming: no bearer credentials or permanent storage URLs in links.
        with connect(settings) as db:
            user = authenticated(db, request)
            row = db.execute('SELECT * FROM files WHERE id=? AND enabled=1', (file_id,)).fetchone()
            try:
                if not row:
                    deny('permission_denied', 403)
                entitled(db, user, row['permission'])
            except HTTPException:
                audit(db, 'download', 'denied', user['id'])
                raise
            root = Path(settings.storage).resolve()
            path = (root / row['storage_name']).resolve()
            if path.parent != root or not path.is_file():
                deny('file_unavailable', 404)
            handle = path.open('rb')
            import os
            length = os.fstat(handle.fileno()).st_size
            if length > row['max_bytes']:
                handle.close()
                deny('file_unavailable', 404)
            audit(db, 'download', 'allowed', user['id'], file_id)
            sid, user_id, permission = user['session_id'], user['id'], row['permission']

        def stream():
            try:
                while True:
                    # Recheck entitlement and session even during long transfers.
                    with connect(settings) as db:
                        current = authenticated(db, request, count_request=False)
                        if current['session_id'] != sid or current['id'] != user_id:
                            return
                        entitled(db, current, permission)
                        active = db.execute('SELECT enabled,permission FROM files WHERE id=?', (file_id,)).fetchone()
                        if not active or not active['enabled'] or active['permission'] != permission:
                            return
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        return
                    yield chunk
            except HTTPException:
                return  # Content-Length mismatch makes the client reject a truncated transfer.
            finally:
                handle.close()
        return StreamingResponse(stream(), media_type='application/octet-stream',
                                 headers={'Content-Length': str(length), 'Content-Disposition': 'attachment'})

    @app.get('/v1/admin/users')
    def list_users(request: Request, offset: int = 0):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            rows = db.execute('SELECT id,username,status,role,console_only,web_approved,subscription_until,password_until FROM users ORDER BY id LIMIT 100 OFFSET ?',
                              (max(0, offset),)).fetchall()
            audit(db, 'admin.users.list', 'allowed', admin['id'])
            return {'success': True, 'users': [{**dict(r), 'is_owner': r['username'] == settings.owner_username} for r in rows]}

    @app.get('/v1/admin/session')
    def admin_session(request: Request):
        with connect(settings) as db:
            user = authenticated(db, request, 'admin')
            return {'success': True, 'username': user['username'], 'user_id': user['id'], 'is_owner': user['username'] == settings.owner_username}

    @app.get('/v1/admin/overview')
    def overview(request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            counts = {
                'users': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
                'subscribers': db.execute("SELECT COUNT(*) FROM users WHERE status='active' AND subscription_until>?", (now(),)).fetchone()[0],
                'licenses': db.execute('SELECT COUNT(*) FROM licenses WHERE revoked=0 AND expires_at>?', (now(),)).fetchone()[0],
                'files': db.execute('SELECT COUNT(*) FROM files WHERE enabled=1').fetchone()[0],
            }
            recent = db.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 8').fetchall()
            audit(db, 'admin.overview.read', 'allowed', admin['id'])
            return {'success': True, 'counts': counts, 'recent': [dict(r) for r in recent]}

    @app.get('/v1/admin/licenses')
    def list_licenses(request: Request, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            rows = db.execute('''SELECT l.id,l.expires_at,l.permission,l.hardware_bound,l.user_id,l.revoked,l.frozen_at,l.key_ciphertext,
                u.username FROM licenses l LEFT JOIN users u ON l.user_id=u.id
                ORDER BY l.id LIMIT 100 OFFSET ?''', (max(0, offset),)).fetchall()
            audit(db, 'admin.licenses.list', 'allowed', admin['id'])
            licenses = []
            for row in rows:
                item = dict(row)
                encrypted = item.pop('key_ciphertext')
                item['key'] = cipher(settings).decrypt(encrypted.encode()).decode() if encrypted else None
                licenses.append(item)
            return {'success': True, 'licenses': licenses}

    @app.get('/v1/admin/variables')
    def list_variables(request: Request, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            rows = db.execute('SELECT * FROM variables ORDER BY name,id LIMIT 100 OFFSET ?', (max(0, offset),)).fetchall()
            audit(db, 'admin.variables.list', 'allowed', admin['id'])
            return {'success': True, 'variables': [dict(r) for r in rows]}

    @app.get('/v1/admin/files')
    def list_files(request: Request, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            rows = db.execute('SELECT * FROM files ORDER BY id LIMIT 100 OFFSET ?', (max(0, offset),)).fetchall()
            audit(db, 'admin.files.list', 'allowed', admin['id'])
            return {'success': True, 'files': [dict(r) for r in rows]}

    @app.get('/v1/admin/users/{user_id}/permissions')
    def list_permissions(user_id: str, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            rows = db.execute('SELECT permission FROM permissions WHERE user_id=? ORDER BY permission', (user_id,)).fetchall()
            audit(db, 'admin.permissions.list', 'allowed', admin['id'], user_id)
            return {'success': True, 'permissions': [r['permission'] for r in rows]}

    @app.post('/v1/admin/users', status_code=201)
    def create_user(body: Credentials, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            if db.execute('SELECT 1 FROM users WHERE username=?', (body.username.lower(),)).fetchone():
                deny('user_exists', 409)
            identifier = uid()
            db.execute("INSERT INTO users(id,username,password_hash,role,console_only,created_at) VALUES(?,?,?,'admin',1,?)",
                       (identifier, body.username.lower(), passwords.hash(body.password), now()))
            audit(db, 'admin.user.create', 'allowed', admin['id'], identifier)
            return {'success': True, 'id': identifier}

    @app.delete('/v1/admin/users/{user_id}')
    def delete_user(user_id: str, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            if user_id == admin['id']:
                deny('cannot_delete_own_account', 409)
            if not db.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone():
                deny('not_found', 404)
            db.execute('DELETE FROM access_tokens WHERE session_id IN (SELECT id FROM sessions WHERE user_id=?)', (user_id,))
            db.execute('DELETE FROM refresh_tokens WHERE session_id IN (SELECT id FROM sessions WHERE user_id=?)', (user_id,))
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
            db.execute('DELETE FROM permissions WHERE user_id=?', (user_id,))
            db.execute('DELETE FROM variables WHERE user_id=?', (user_id,))
            db.execute('UPDATE licenses SET revoked=1,user_id=NULL,hardware_hash=NULL WHERE user_id=?', (user_id,))
            db.execute('DELETE FROM users WHERE id=?', (user_id,))
            audit(db, 'admin.user.delete', 'allowed', admin['id'], user_id)
            return {'success': True}

    @app.put('/v1/admin/users/{user_id}')
    def update_user(user_id: str, body: UserUpdate, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            if not db.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone():
                deny('not_found', 404)
            if user_id == admin['id'] and (body.web_access is False or body.status != 'active'):
                deny('cannot_disable_own_access', 409)
            db.execute('UPDATE users SET status=?,subscription_until=?,password_until=? WHERE id=?',
                       (body.status, body.subscription_until, body.password_until, user_id))
            if body.web_access is not None:
                role = 'admin' if body.web_access else 'user'
                prior = db.execute('SELECT role,console_only FROM users WHERE id=?', (user_id,)).fetchone()
                approval = 1 if body.web_access else 0
                old_approval = db.execute('SELECT web_approved FROM users WHERE id=?', (user_id,)).fetchone()[0]
                db.execute('UPDATE users SET role=?,console_only=1,web_approved=? WHERE id=?', (role, approval, user_id))
                if prior['role'] != role or not prior['console_only'] or old_approval != approval:
                    db.execute('UPDATE sessions SET revoked=1 WHERE user_id=?', (user_id,))
                audit(db, 'admin.user.web_access', 'allowed', admin['id'], user_id)
            if body.status != 'active':
                db.execute('UPDATE sessions SET revoked=1 WHERE user_id=?', (user_id,))
            audit(db, 'admin.user.update', 'allowed', admin['id'], user_id)
            return {'success': True}

    @app.post('/v1/admin/users/{user_id}/revoke-sessions')
    def revoke_sessions(user_id: str, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            db.execute('UPDATE sessions SET revoked=1 WHERE user_id=?', (user_id,))
            audit(db, 'admin.sessions.revoke', 'allowed', admin['id'], user_id)
            return {'success': True}

    @app.put('/v1/admin/users/{user_id}/permissions')
    def permission(user_id: str, body: Permission, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            if not db.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone():
                deny('not_found', 404)
            if body.allowed:
                db.execute('INSERT OR IGNORE INTO permissions VALUES(?,?)', (user_id, body.permission))
            else:
                db.execute('DELETE FROM permissions WHERE user_id=? AND permission=?', (user_id, body.permission))
            audit(db, 'admin.permission.update', 'allowed', admin['id'], user_id)
            return {'success': True}

    @app.post('/v1/admin/licenses', status_code=201)
    def create_license(body: LicenseCreate, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            identifier, key = uid(), generate()
            while db.execute('SELECT 1 FROM licenses WHERE key_hash=?', (digest(key),)).fetchone():
                key = generate()
            has_encrypted_keys = db.execute('SELECT 1 FROM licenses WHERE key_ciphertext IS NOT NULL LIMIT 1').fetchone()
            encrypted = cipher(settings, create=not has_encrypted_keys).encrypt(key.encode()).decode()
            db.execute('INSERT INTO licenses(id,key_hash,expires_at,permission,hardware_bound,key_ciphertext) VALUES(?,?,?,?,?,?)',
                       (identifier, digest(key), now() + body.days * 86400, body.permission, body.hardware_bound, encrypted))
            audit(db, 'admin.license.create', 'allowed', admin['id'], identifier)
            return {'success': True, 'id': identifier, 'key': key}

    @app.post('/v1/admin/licenses/{license_id}/reset-hwid')
    def reset_license_hwid(license_id: str, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            license = db.execute('SELECT * FROM licenses WHERE id=?', (license_id,)).fetchone()
            if not license:
                deny('not_found', 404)
            if license['revoked']:
                deny('license_revoked', 409)
            if not license['hardware_bound']:
                deny('hardware_binding_disabled', 409)
            db.execute('UPDATE licenses SET hardware_hash=NULL WHERE id=?', (license_id,))
            if license['user_id']:
                db.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND audience='client'", (license['user_id'],))
            audit(db, 'admin.license.hwid_reset', 'allowed', admin['id'], license_id)
            return {'success': True}

    @app.post('/v1/admin/licenses/{license_id}/freeze')
    def freeze_license(license_id: str, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            license = db.execute('SELECT * FROM licenses WHERE id=?', (license_id,)).fetchone()
            if not license:
                deny('not_found', 404)
            if license['revoked']:
                deny('license_revoked', 409)
            timestamp = now()
            frozen = license['frozen_at'] is None
            if frozen:
                db.execute('UPDATE licenses SET frozen_at=? WHERE id=?', (timestamp, license_id))
                if license['user_id']:
                    db.execute('UPDATE users SET frozen_at=COALESCE(frozen_at,?) WHERE id=?', (timestamp, license['user_id']))
            else:
                db.execute('UPDATE licenses SET expires_at=expires_at+?,frozen_at=NULL WHERE id=?', (timestamp-license['frozen_at'], license_id))
                if license['user_id'] and not db.execute('SELECT 1 FROM licenses WHERE user_id=? AND frozen_at IS NOT NULL AND revoked=0', (license['user_id'],)).fetchone():
                    db.execute('UPDATE users SET subscription_until=subscription_until+?-COALESCE(frozen_at,?),frozen_at=NULL WHERE id=?', (timestamp, timestamp, license['user_id']))
            audit(db, 'admin.license.freeze' if frozen else 'admin.license.unfreeze', 'allowed', admin['id'], license_id)
            return {'success': True, 'frozen': frozen}

    @app.post('/v1/admin/licenses/{license_id}/extend')
    def extend_license(license_id: str, body: LicenseExtension, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            license = db.execute('SELECT * FROM licenses WHERE id=?', (license_id,)).fetchone()
            if not license:
                deny('not_found', 404)
            if license['revoked']:
                deny('license_revoked', 409)
            expiry = max(license['frozen_at'] if license['frozen_at'] is not None else now(), license['expires_at']) + body.days * 86400
            db.execute('UPDATE licenses SET expires_at=? WHERE id=?', (expiry, license_id))
            if license['user_id']:
                db.execute('UPDATE users SET subscription_until=MAX(subscription_until,?) WHERE id=?',
                           (expiry, license['user_id']))
            audit(db, 'admin.license.extend', 'allowed', admin['id'], license_id)
            return {'success': True, 'expires_at': expiry}

    @app.delete('/v1/admin/licenses/{license_id}')
    def revoke_license(license_id: str, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            license = db.execute('SELECT * FROM licenses WHERE id=?', (license_id,)).fetchone()
            db.execute('UPDATE licenses SET revoked=1,frozen_at=NULL WHERE id=?', (license_id,))
            if license and license['user_id'] and license['frozen_at'] is not None:
                if not db.execute('SELECT 1 FROM licenses WHERE user_id=? AND frozen_at IS NOT NULL AND revoked=0', (license['user_id'],)).fetchone():
                    db.execute('UPDATE users SET subscription_until=subscription_until+?-COALESCE(frozen_at,?),frozen_at=NULL WHERE id=?', (now(), now(), license['user_id']))
            audit(db, 'admin.license.revoke', 'allowed', admin['id'], license_id)
            return {'success': True}

    @app.put('/v1/admin/variables/{variable_id}')
    def set_variable(variable_id: str, body: Variable, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            if body.user_id and not db.execute('SELECT 1 FROM users WHERE id=?', (body.user_id,)).fetchone():
                deny('not_found', 404)
            collision = db.execute('SELECT id FROM variables WHERE name=? AND user_id IS ? AND id<>?',
                                   (body.name, body.user_id, variable_id)).fetchone()
            if collision:
                deny('variable_exists', 409)
            db.execute('''INSERT INTO variables VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,user_id=excluded.user_id,value=excluded.value,permission=excluded.permission''',
                       (variable_id, body.name, body.user_id, body.value, body.permission))
            audit(db, 'admin.variable.update', 'allowed', admin['id'], variable_id)
            return {'success': True}

    @app.put('/v1/admin/files/{file_id}')
    def set_file(file_id: str, body: FileMetadata, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            root = Path(settings.storage).resolve()
            path = (root / body.storage_name).resolve()
            if path.parent != root or not path.is_file() or path.stat().st_size > body.max_bytes:
                deny('invalid_storage_file', 422)
            if db.execute('SELECT 1 FROM files WHERE storage_name=? AND id<>?', (body.storage_name, file_id)).fetchone():
                deny('file_exists', 409)
            db.execute('''INSERT INTO files VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                storage_name=excluded.storage_name,permission=excluded.permission,
                enabled=excluded.enabled,max_bytes=excluded.max_bytes''',
                       (file_id, body.storage_name, body.permission, body.enabled, body.max_bytes))
            audit(db, 'admin.file.update', 'allowed', admin['id'], file_id)
            return {'success': True}

    @app.delete('/v1/admin/variables/{variable_id}')
    def delete_variable(variable_id: str, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            db.execute('DELETE FROM variables WHERE id=?', (variable_id,))
            audit(db, 'admin.variable.delete', 'allowed', admin['id'], variable_id)
            return {'success': True}

    @app.get('/v1/admin/audit')
    def logs(request: Request, after: int = 0, recent: bool = False, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            if recent:
                rows = db.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100 OFFSET ?', (max(0, offset),)).fetchall()
            else:
                rows = db.execute('SELECT * FROM audit_logs WHERE id>? ORDER BY id LIMIT 100', (after,)).fetchall()
            audit(db, 'admin.audit.read', 'allowed', admin['id'])
            return {'success': True, 'events': [dict(r) for r in rows]}

    web = Path(__file__).parent / 'web'
    app.mount('/assets', StaticFiles(directory=web / 'assets'), name='web-assets')

    @app.get('/', include_in_schema=False)
    @app.get('/admin', include_in_schema=False)
    def dashboard():
        # The shell is public; every data read and write still requires an admin session.
        return FileResponse(web / 'index.html')

    return app
