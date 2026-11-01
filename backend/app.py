import json
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import Settings, prepare
from .db import connect, migrate
from .security import DUMMY, audit, digest, issue, now, passwords, uid, verify
from .license_keys import cipher, generate

DEFAULT_APPLICATION = '00000000-0000-4000-8000-000000000001'


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


class ApplicationCreate(Input):
    name: str = Field(min_length=1, max_length=64)


class ApplicationUpdate(Input):
    name: str = Field(min_length=1, max_length=64)
    status: Literal['active', 'disabled']


class ResellerCreate(Input):
    username: str = Field(pattern=r'^[A-Za-z0-9_.-]{3,64}$')
    password: str = Field(min_length=12, max_length=128)
    max_days: int = Field(default=30, ge=1, le=999)


class ResellerUpdate(Input):
    status: Literal['active', 'suspended']
    max_days: int = Field(ge=1, le=999)


class ResellerLicenseCreate(Input):
    days: int = Field(ge=1, le=999)


class ResellerHwidReset(Input):
    username: str = Field(pattern=r'^[A-Za-z0-9_.-]{3,64}$')


def deny(code, status=401):
    raise HTTPException(status, code)


def website_allowed(user, settings):
    return (user['role'] == 'admin' and (user['username'] in (settings.owner_username, 'slights1', 'admin') or user['web_approved'])) or \
           (user['role'] == 'reseller' and user['web_approved'])


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


# Reseller-allowed admin paths.
RESELLER_ALLOWED_PATHS = {
    ('GET', '/v1/admin/session'),
    ('POST', '/v1/admin/logout'),
    ('GET', '/v1/admin/applications'),
    ('GET', '/v1/admin/reseller/licenses'),
    ('POST', '/v1/admin/reseller/licenses'),
    ('POST', '/v1/admin/reseller/reset-hwid'),
}


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
    if row['audience'] != audience or (audience == 'admin' and row['role'] not in ('admin', 'reseller')):
        deny('permission_denied', 403)
    if audience == 'admin' and not website_allowed(row, request.app.state.settings):
        deny('website_approval_required', 401)
    if audience == 'admin' and row['role'] == 'reseller':
        method = request.method
        path = request.url.path
        if (method, path) not in RESELLER_ALLOWED_PATHS:
            deny('permission_denied', 403)
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


def get_application_id(request):
    """Extract and return the application_id from query params, defaulting to DEFAULT_APPLICATION."""
    return request.query_params.get('application_id', DEFAULT_APPLICATION)


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
        scheme = request.headers.get('x-forwarded-proto', request.url.scheme)
        if settings.require_https and scheme != 'https':
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
                or (audience == 'admin' and user['role'] not in ('admin', 'reseller'))):
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

    # ── Admin: Session ────────────────────────────────────────────────

    @app.get('/v1/admin/session')
    def admin_session(request: Request):
        with connect(settings) as db:
            user = authenticated(db, request, 'admin')
            return {'success': True, 'username': user['username'], 'user_id': user['id'],
                    'is_owner': user['username'] == settings.owner_username, 'role': user['role']}

    # ── Admin: Overview ───────────────────────────────────────────────

    @app.get('/v1/admin/overview')
    def overview(request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            counts = {
                'users': db.execute("SELECT COUNT(*) FROM users WHERE application_id=? AND console_only=0 AND role='user'", (app_id,)).fetchone()[0],
                'subscribers': db.execute("SELECT COUNT(*) FROM users WHERE application_id=? AND status='active' AND subscription_until>?", (app_id, now())).fetchone()[0],
                'licenses': db.execute('SELECT COUNT(*) FROM licenses WHERE application_id=? AND revoked=0 AND expires_at>?', (app_id, now())).fetchone()[0],
                'files': db.execute('SELECT COUNT(*) FROM files WHERE application_id=? AND enabled=1', (app_id,)).fetchone()[0],
            }
            recent = db.execute('SELECT * FROM audit_logs WHERE application_id=? ORDER BY id DESC LIMIT 8', (app_id,)).fetchall()
            audit(db, 'admin.overview.read', 'allowed', admin['id'])
            return {'success': True, 'counts': counts, 'recent': [dict(r) for r in recent]}

    # ── Admin: Users ──────────────────────────────────────────────────

    @app.get('/v1/admin/users')
    def list_users(request: Request, offset: int = 0, scope: str = 'application'):
        with connect(settings) as db:
            app_id = get_application_id(request)
            if scope == 'website':
                admin = owner_authenticated(db, request)
                rows = db.execute("SELECT id,username,status,role,console_only,web_approved,subscription_until,password_until FROM users WHERE console_only=1 OR role='admin' ORDER BY id LIMIT 100 OFFSET ?",
                                  (max(0, offset),)).fetchall()
                audit(db, 'admin.website_users.list', 'allowed', admin['id'])
                return {'success': True, 'users': [{**dict(r), 'is_owner': r['username'] == settings.owner_username} for r in rows]}
            else:
                admin = authenticated(db, request, 'admin')
                rows = db.execute("SELECT id,username,status,role,console_only,web_approved,subscription_until,password_until FROM users WHERE application_id=? AND console_only=0 AND role='user' ORDER BY username,id LIMIT 100 OFFSET ?",
                                  (app_id, max(0, offset))).fetchall()
                audit(db, 'admin.users.list', 'allowed', admin['id'])
                return {'success': True, 'users': [{**dict(r), 'is_owner': r['username'] == settings.owner_username} for r in rows]}

    @app.post('/v1/admin/users', status_code=201)
    def create_user(body: Credentials, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            if db.execute('SELECT 1 FROM users WHERE username=?', (body.username.lower(),)).fetchone():
                deny('user_exists', 409)
            identifier = uid()
            db.execute("INSERT INTO users(id,username,password_hash,role,console_only,created_at,application_id) VALUES(?,?,?,'admin',1,?,?)",
                       (identifier, body.username.lower(), passwords.hash(body.password), now(), DEFAULT_APPLICATION))
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

    @app.get('/v1/admin/users/{user_id}/permissions')
    def list_permissions(user_id: str, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            rows = db.execute('SELECT permission FROM permissions WHERE user_id=? ORDER BY permission', (user_id,)).fetchall()
            audit(db, 'admin.permissions.list', 'allowed', admin['id'], user_id)
            return {'success': True, 'permissions': [r['permission'] for r in rows]}

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

    # ── Admin: Licenses ───────────────────────────────────────────────

    @app.get('/v1/admin/licenses')
    def list_licenses(request: Request, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            rows = db.execute('''SELECT l.id,l.expires_at,l.permission,l.hardware_bound,l.user_id,l.revoked,l.frozen_at,l.key_ciphertext,
                u.username FROM licenses l LEFT JOIN users u ON l.user_id=u.id
                WHERE l.application_id=? ORDER BY l.id LIMIT 100 OFFSET ?''', (app_id, max(0, offset))).fetchall()
            audit(db, 'admin.licenses.list', 'allowed', admin['id'])
            licenses = []
            for row in rows:
                item = dict(row)
                encrypted = item.pop('key_ciphertext')
                item['key'] = cipher(settings).decrypt(encrypted.encode()).decode() if encrypted else None
                licenses.append(item)
            return {'success': True, 'licenses': licenses}

    @app.post('/v1/admin/licenses', status_code=201)
    def create_license(body: LicenseCreate, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            identifier, key = uid(), generate()
            while db.execute('SELECT 1 FROM licenses WHERE key_hash=?', (digest(key),)).fetchone():
                key = generate()
            has_encrypted_keys = db.execute('SELECT 1 FROM licenses WHERE key_ciphertext IS NOT NULL LIMIT 1').fetchone()
            encrypted = cipher(settings, create=not has_encrypted_keys).encrypt(key.encode()).decode()
            db.execute('INSERT INTO licenses(id,key_hash,expires_at,permission,hardware_bound,key_ciphertext,application_id) VALUES(?,?,?,?,?,?,?)',
                       (identifier, digest(key), now() + body.days * 86400, body.permission, body.hardware_bound, encrypted, app_id))
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

    # ── Admin: Variables ──────────────────────────────────────────────

    @app.get('/v1/admin/variables')
    def list_variables(request: Request, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            rows = db.execute('SELECT * FROM variables WHERE application_id=? ORDER BY name,id LIMIT 100 OFFSET ?', (app_id, max(0, offset))).fetchall()
            audit(db, 'admin.variables.list', 'allowed', admin['id'])
            return {'success': True, 'variables': [dict(r) for r in rows]}

    @app.put('/v1/admin/variables/{variable_id}')
    def set_variable(variable_id: str, body: Variable, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            if body.user_id and not db.execute('SELECT 1 FROM users WHERE id=?', (body.user_id,)).fetchone():
                deny('not_found', 404)
            collision = db.execute('SELECT id FROM variables WHERE name=? AND user_id IS ? AND id<>?',
                                   (body.name, body.user_id, variable_id)).fetchone()
            if collision:
                deny('variable_exists', 409)
            db.execute('''INSERT INTO variables(id,name,user_id,value,permission,application_id) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,user_id=excluded.user_id,value=excluded.value,permission=excluded.permission''',
                       (variable_id, body.name, body.user_id, body.value, body.permission, app_id))
            audit(db, 'admin.variable.update', 'allowed', admin['id'], variable_id)
            return {'success': True}

    @app.delete('/v1/admin/variables/{variable_id}')
    def delete_variable(variable_id: str, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            db.execute('DELETE FROM variables WHERE id=?', (variable_id,))
            audit(db, 'admin.variable.delete', 'allowed', admin['id'], variable_id)
            return {'success': True}

    # ── Admin: Files ──────────────────────────────────────────────────

    @app.get('/v1/admin/files')
    def list_files(request: Request, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            rows = db.execute('SELECT * FROM files WHERE application_id=? ORDER BY id LIMIT 100 OFFSET ?', (app_id, max(0, offset))).fetchall()
            audit(db, 'admin.files.list', 'allowed', admin['id'])
            return {'success': True, 'files': [dict(r) for r in rows]}

    @app.put('/v1/admin/files/{file_id}')
    def set_file(file_id: str, body: FileMetadata, request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            root = Path(settings.storage).resolve()
            path = (root / body.storage_name).resolve()
            if path.parent != root or not path.is_file() or path.stat().st_size > body.max_bytes:
                deny('invalid_storage_file', 422)
            if db.execute('SELECT 1 FROM files WHERE storage_name=? AND id<>?', (body.storage_name, file_id)).fetchone():
                deny('file_exists', 409)
            db.execute('''INSERT INTO files(id,storage_name,permission,enabled,max_bytes,application_id) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                storage_name=excluded.storage_name,permission=excluded.permission,
                enabled=excluded.enabled,max_bytes=excluded.max_bytes''',
                       (file_id, body.storage_name, body.permission, body.enabled, body.max_bytes, app_id))
            audit(db, 'admin.file.update', 'allowed', admin['id'], file_id)
            return {'success': True}

    # ── Admin: Audit ──────────────────────────────────────────────────

    @app.get('/v1/admin/audit')
    def logs(request: Request, after: int = 0, recent: bool = False, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            if recent:
                rows = db.execute('SELECT * FROM audit_logs WHERE application_id=? ORDER BY id DESC LIMIT 100 OFFSET ?', (app_id, max(0, offset))).fetchall()
            else:
                rows = db.execute('SELECT * FROM audit_logs WHERE application_id=? AND id>? ORDER BY id LIMIT 100', (app_id, after)).fetchall()
            audit(db, 'admin.audit.read', 'allowed', admin['id'])
            return {'success': True, 'events': [dict(r) for r in rows]}

    # ── Admin: Applications ───────────────────────────────────────────

    @app.get('/v1/admin/applications')
    def list_applications(request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            if admin['role'] == 'reseller':
                app_id = admin['application_id'] if admin['application_id'] else DEFAULT_APPLICATION
                rows = db.execute('SELECT * FROM applications WHERE id=?', (app_id,)).fetchall()
                return {'success': True, 'applications': [dict(r) for r in rows], 'default_application_id': app_id}
            rows = db.execute('SELECT * FROM applications ORDER BY created_at,id').fetchall()
            return {'success': True, 'applications': [dict(r) for r in rows], 'default_application_id': DEFAULT_APPLICATION}

    @app.post('/v1/admin/applications', status_code=201)
    def create_application(body: ApplicationCreate, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            app_id = uid()
            db.execute("INSERT INTO applications(id,name,status,created_at) VALUES(?,?,'active',?)",
                       (app_id, body.name.strip(), now()))
            audit(db, 'admin.application.create', 'allowed', admin['id'], app_id)
            return {'success': True, 'id': app_id, 'name': body.name.strip(), 'status': 'active'}

    @app.put('/v1/admin/applications/{application_id}')
    def update_application(application_id: str, body: ApplicationUpdate, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            if not db.execute('SELECT 1 FROM applications WHERE id=?', (application_id,)).fetchone():
                deny('not_found', 404)
            db.execute('UPDATE applications SET name=?,status=? WHERE id=?',
                       (body.name.strip(), body.status, application_id))
            if body.status == 'disabled':
                db.execute("UPDATE sessions SET revoked=1 WHERE audience='client' AND user_id IN (SELECT id FROM users WHERE application_id=? AND console_only=0 AND role='user')",
                           (application_id,))
            audit(db, 'admin.application.update', 'allowed', admin['id'], application_id)
            return {'success': True}

    # ── Admin: Resellers ──────────────────────────────────────────────

    @app.get('/v1/admin/resellers')
    def list_resellers(request: Request, offset: int = 0):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            app_id = get_application_id(request)
            rows = db.execute("SELECT u.id,u.username,u.status,u.created_at,r.max_days FROM users u JOIN reseller_profiles r ON r.user_id=u.id WHERE u.application_id=? AND u.role='reseller' ORDER BY u.username LIMIT 100 OFFSET ?",
                              (app_id, max(0, offset))).fetchall()
            return {'success': True, 'resellers': [dict(r) for r in rows]}

    @app.post('/v1/admin/resellers', status_code=201)
    def create_reseller(body: ResellerCreate, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            app_id = get_application_id(request)
            username = body.username.lower()
            if username == settings.owner_username or db.execute('SELECT 1 FROM users WHERE username=? AND console_only=1', (username,)).fetchone():
                deny('user_exists', 409)
            identifier = uid()
            db.execute("INSERT INTO users(id,username,password_hash,role,console_only,web_approved,created_at,application_id) VALUES(?,?,?,'reseller',1,1,?,?)",
                       (identifier, username, passwords.hash(body.password), now(), app_id))
            db.execute('INSERT INTO reseller_profiles(user_id,max_days) VALUES(?,?)',
                       (identifier, body.max_days))
            audit(db, 'admin.reseller.create', 'allowed', admin['id'], identifier)
            return {'success': True, 'id': identifier, 'username': username}

    @app.put('/v1/admin/resellers/{reseller_id}')
    def update_reseller(reseller_id: str, body: ResellerUpdate, request: Request):
        with connect(settings) as db:
            admin = owner_authenticated(db, request)
            app_id = get_application_id(request)
            if not db.execute("SELECT 1 FROM users WHERE id=? AND application_id=? AND role='reseller'", (reseller_id, app_id)).fetchone():
                deny('not_found', 404)
            db.execute('UPDATE users SET status=? WHERE id=?', (body.status, reseller_id))
            db.execute('UPDATE reseller_profiles SET max_days=? WHERE user_id=?', (body.max_days, reseller_id))
            db.execute('UPDATE sessions SET revoked=1 WHERE user_id=?', (reseller_id,))
            audit(db, 'admin.reseller.update', 'allowed', admin['id'], reseller_id)
            return {'success': True}

    # ── Reseller: Own Endpoints ───────────────────────────────────────

    @app.get('/v1/admin/reseller/licenses')
    def reseller_list_licenses(request: Request, offset: int = 0):
        with connect(settings) as db:
            user = authenticated(db, request, 'admin')
            if user['role'] != 'reseller':
                deny('permission_denied', 403)
            app_id = user['application_id'] if user['application_id'] else DEFAULT_APPLICATION
            profile = db.execute('SELECT max_days FROM reseller_profiles WHERE user_id=?', (user['id'],)).fetchone()
            if not profile:
                deny('permission_denied', 403)
            rows = db.execute('''SELECT l.id,l.expires_at,l.hardware_bound,l.revoked,l.key_ciphertext,c.username
                FROM licenses l LEFT JOIN users c ON c.id=l.user_id
                WHERE l.application_id=? AND l.reseller_id=? ORDER BY l.id DESC LIMIT 100 OFFSET ?''',
                              (app_id, user['id'], max(0, offset))).fetchall()
            licenses = []
            for row in rows:
                item = dict(row)
                encrypted = item.pop('key_ciphertext')
                item['key'] = cipher(settings).decrypt(encrypted.encode()).decode() if encrypted else None
                licenses.append(item)
            return {'success': True, 'reseller_licenses': licenses, 'max_days': profile['max_days']}

    @app.post('/v1/admin/reseller/licenses', status_code=201)
    def reseller_create_license(body: ResellerLicenseCreate, request: Request):
        with connect(settings) as db:
            user = authenticated(db, request, 'admin')
            if user['role'] != 'reseller':
                deny('permission_denied', 403)
            app_id = user['application_id'] if user['application_id'] else DEFAULT_APPLICATION
            profile = db.execute('SELECT max_days FROM reseller_profiles WHERE user_id=?', (user['id'],)).fetchone()
            if not profile:
                deny('permission_denied', 403)
            if body.days > profile['max_days']:
                deny('invalid_request', 422)
            identifier, key = uid(), generate()
            while db.execute('SELECT 1 FROM licenses WHERE key_hash=?', (digest(key),)).fetchone():
                key = generate()
            expires_at = now() + body.days * 86400
            has_encrypted_keys = db.execute('SELECT 1 FROM licenses WHERE key_ciphertext IS NOT NULL LIMIT 1').fetchone()
            encrypted = cipher(settings, create=not has_encrypted_keys).encrypt(key.encode()).decode()
            db.execute("INSERT INTO licenses(id,key_hash,expires_at,permission,hardware_bound,key_ciphertext,application_id,reseller_id) VALUES(?,?,?,'premium',1,?,?,?)",
                       (identifier, digest(key), expires_at, encrypted, app_id, user['id']))
            audit(db, 'reseller.license.create', 'allowed', user['id'], identifier)
            return {'success': True, 'id': identifier, 'key': key,
                    'license': {'id': identifier, 'key': key, 'expires_at': expires_at, 'hardware_bound': 1, 'revoked': 0, 'username': None}}

    @app.post('/v1/admin/reseller/reset-hwid')
    def reseller_reset_hwid(body: ResellerHwidReset, request: Request):
        with connect(settings) as db:
            user = authenticated(db, request, 'admin')
            if user['role'] != 'reseller':
                deny('permission_denied', 403)
            app_id = user['application_id'] if user['application_id'] else DEFAULT_APPLICATION
            profile = db.execute('SELECT max_days FROM reseller_profiles WHERE user_id=?', (user['id'],)).fetchone()
            if not profile:
                deny('permission_denied', 403)
            customer = db.execute("SELECT id,username FROM users WHERE application_id=? AND username=? AND console_only=0 AND role='user'",
                                  (app_id, body.username.lower())).fetchone()
            if not customer:
                deny('not_found', 404)
            db.execute('UPDATE users SET hardware_hash=NULL WHERE id=?', (customer['id'],))
            db.execute('UPDATE licenses SET hardware_hash=NULL WHERE user_id=? AND application_id=?', (customer['id'], app_id))
            db.execute('UPDATE sessions SET revoked=1 WHERE user_id=?', (customer['id'],))
            audit(db, 'reseller.user.hwid_reset', 'allowed', user['id'], customer['id'])
            return {'success': True, 'username': customer['username'],
                    'message': 'HWID reset. The next successful login binds the new Windows account SID.'}

    # ── Admin: Bootstrapper ──────────────────────────────────────────

    @app.get('/v1/admin/bootstrapper')
    def bootstrapper_manifest(request: Request):
        with connect(settings) as db:
            authenticated(db, request, 'admin')
            manifest = {
                'sdk_url': '/v1/admin/bootstrapper/sdk',
                'template_url': '/v1/admin/bootstrapper/template',
                'template_sha256': '1e30e0696b3ec5aa3d156e6388a8cfd302ac60f705a164e2ae4ee60c91ecfe2e',
                'template_bytes': 5553664,
                'max_bytes': 67108864,
                'sdk_version': 1,
            }
            return {'success': True, **manifest}

    @app.get('/v1/admin/bootstrapper/template')
    def bootstrapper_template(request: Request):
        with connect(settings) as db:
            authenticated(db, request, 'admin')
            template_path = Path(__file__).parent / 'web' / 'bootstrap' / 'novyx-template.bin'
            if not template_path.is_file():
                deny('server_error', 503)
            return Response(content=template_path.read_bytes(), media_type='application/vnd.novyx.asset')

    @app.get('/v1/admin/bootstrapper/sdk')
    def bootstrapper_sdk(request: Request):
        with connect(settings) as db:
            authenticated(db, request, 'admin')
            sdk_path = Path(__file__).parent / 'web' / 'bootstrap' / 'novyx-bootstrap-sdk.zip'
            if not sdk_path.is_file():
                deny('server_error', 503)
            return Response(content=sdk_path.read_bytes(), media_type='application/vnd.novyx.asset')

    @app.post('/v1/admin/bootstrapper')
    def bootstrapper_validate(request: Request):
        with connect(settings) as db:
            admin = authenticated(db, request, 'admin')
            audit(db, 'admin.bootstrapper.package', 'allowed', admin['id'])
            return {'success': True}

    # ── Static Web ────────────────────────────────────────────────────

    web = Path(__file__).parent / 'web'
    app.mount('/assets', StaticFiles(directory=web / 'assets'), name='web-assets')

    @app.get('/', include_in_schema=False)
    @app.get('/admin', include_in_schema=False)
    def dashboard():
        # The shell is public; every data read and write still requires an admin session.
        return FileResponse(web / 'index.html')

    return app
