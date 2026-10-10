"""Opt-in, single-owner OAuth service. Mount ``routes`` in the connector app.

All credentials live below a private root independent of the connector store.
Request handlers never log request contents or expose exception details.
"""
import base64
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import getpass
from getpass import GetPassWarning
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import math
import time
import warnings
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from .auth import fetch_json, https_url
from .core import Rejected

ACCESS_SECONDS = 600
REFRESH_SECONDS = 90 * 86400
SCOPES = ['herdr:observe', 'herdr:control']
HEADERS = {'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
           'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
           'Referrer-Policy': 'no-referrer'}


def hidden_input(prompt, getpass=getpass.getpass):
    """Refuse secret entry if terminal echo cannot be disabled."""
    with warnings.catch_warnings():
        warnings.simplefilter('error', GetPassWarning)
        try:
            return getpass(prompt)
        except GetPassWarning:
            raise Rejected('hidden_input_unavailable_use_a_real_terminal') from None


def ask_new_password(getpass=getpass.getpass, say=print):
    """Collect the owner credential without exposing either entry."""
    for _ in range(3):
        first = hidden_input('New sign-in password: ', getpass=getpass)
        second = hidden_input('Repeat sign-in password: ', getpass=getpass)
        if len(first) < 8:
            say('Password must contain at least 8 characters; try again.')
        elif len(first) > 1024:
            say('Password must contain at most 1024 characters; try again.')
        elif first != second:
            say('Passwords do not match; try again.')
        else:
            return first
    raise Rejected('password_not_set')


@dataclass(frozen=True)
class Settings:
    allowed_hosts: tuple = ('https://chatgpt.com',)
    dcr_max_clients: int = 100
    dcr_ttl: int = 86400
    cimd_ttl: int = 300
    login_ip_limit: int = 5
    login_global_limit: int = 50
    login_window: int = 300
    login_backoff: int = 1


def _private_fd(path, flags, mode=0o600, *, directory=False):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, mode)
    try:
        info = os.fstat(fd)
        valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not valid or info.st_uid != os.getuid():
            raise Rejected('invalid_signin_storage')
        wanted = 0o700 if directory else 0o600
        if stat.S_IMODE(info.st_mode) != wanted:
            os.fchmod(fd, wanted)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _private_root(root):
    root = Path(root).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = _private_fd(root, os.O_RDONLY | os.O_DIRECTORY, directory=True)
    os.close(fd)
    # Check every existing credential, including unused/legacy private keys.
    for path in root.iterdir():
        if path.name in {'oauth.sqlite3', 'lock', 'subject', 'keys.json', 'password.json'} or path.suffix == '.pem':
            fd = _private_fd(path, os.O_RDONLY)
            os.close(fd)
    return root


def signin_root(config):
    return _private_root(Path(config).absolute().parent / 'signin')


def _create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _read(path):
    fd = _private_fd(path, os.O_RDONLY)
    with os.fdopen(fd, 'rb') as stream:
        return stream.read()


def _atomic(path, data):
    temp = path.with_name('.' + path.name + '.' + secrets.token_hex(16))
    try:
        _create(temp, data)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


@contextmanager
def _lock(root):
    root = _private_root(root)
    fd = _private_fd(root / 'lock', os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield root
    finally:
        os.close(fd)


def _new_key(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kid = hashlib.sha256(public).hexdigest()
    _create(root / (kid + '.pem'), key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, alg='RS256', use='sig')
    return {'kid': kid, 'jwk': jwk}


@contextmanager
def _db(root):
    path = _private_root(root) / 'oauth.sqlite3'
    # Refuse symlinks before SQLite opens the private-directory entry.
    fd = _private_fd(path, os.O_RDWR | os.O_CREAT)
    os.close(fd)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('BEGIN IMMEDIATE')
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _prune_keys(root, keys, now):
    expired = [row for row in keys['old'] if row['expires'] <= now]
    if expired:
        keys['old'] = [row for row in keys['old'] if row['expires'] > now]
        _atomic(root / 'keys.json', json.dumps(keys).encode())
        for row in expired:
            (root / (row['jwk']['kid'] + '.pem')).unlink(missing_ok=True)
    return keys


def initialize(root, *, now=None):
    with _lock(root) as root:
        subject = root / 'subject'
        if not subject.exists():
            _create(subject, secrets.token_urlsafe(32).encode())
        manifest = root / 'keys.json'
        if not manifest.exists():
            _atomic(manifest, json.dumps({'current': _new_key(root), 'old': []}).encode())
        keys = _prune_keys(root, json.loads(_read(manifest)), time.time() if now is None else now)
        result = {'subject': _read(subject).decode(), 'kid': keys['current']['kid']}
    with _db(root) as db:
        db.execute('CREATE TABLE IF NOT EXISTS rows (kind TEXT, id TEXT, expires REAL, data TEXT, PRIMARY KEY(kind,id))')
        db.execute('CREATE TABLE IF NOT EXISTS attempts (ip TEXT PRIMARY KEY, start REAL, count INTEGER, next REAL)')
        rows = db.execute("SELECT id,expires,data FROM rows WHERE kind='refresh'").fetchall()
        families = {}
        for row in rows:
            data = json.loads(row['data'])
            if 'family' in data:
                created = data.get('created_at', row['expires'] - REFRESH_SECONDS)
                families[data['family']] = min(families.get(data['family'], created), created)
        for row in rows:
            data = json.loads(row['data'])
            if 'family' in data and 'created_at' not in data:
                data['created_at'] = families[data['family']]
                _put(db, 'refresh', row['id'], data['created_at'] + REFRESH_SECONDS, data)

    return result


def set_password(root, password):
    if not isinstance(password, str) or not 8 <= len(password) <= 1024:
        raise Rejected('password_length_required_8_to_1024')
    initialize(root)
    salt = secrets.token_bytes(32)
    record = {'salt': salt.hex(), 'n': 16384, 'r': 8, 'p': 1, 'dklen': 32}
    record['hash'] = hashlib.scrypt(password.encode(), salt=salt, n=record['n'], r=8, p=1, dklen=32).hex()
    # Match token issuance's database-before-key-lock order.
    with _db(root) as db:
        with _lock(root):
            _atomic(Path(root) / 'password.json', json.dumps(record).encode())
        db.execute('DELETE FROM attempts')


def reset_attempts(root):
    with _db(root) as db:
        db.execute('DELETE FROM attempts')


def has_password(root):
    return (Path(root) / 'password.json').is_file() and not (Path(root) / 'password.json').is_symlink()


def verify_password(root, password):
    if not isinstance(password, str) or len(password) > 1024 or not has_password(root):
        return False
    try:
        _private_root(root)
        record = json.loads(_read(Path(root) / 'password.json'))
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(record['salt']),
                                n=record['n'], r=record['r'], p=record['p'], dklen=record['dklen'])
        return hmac.compare_digest(digest, bytes.fromhex(record['hash']))
    except (ValueError, KeyError, OSError, TypeError):
        return False


def rotate_key(root, *, now=None):
    now = time.time() if now is None else now
    initialize(root, now=now)
    with _lock(root) as root:
        path = root / 'keys.json'
        keys = json.loads(_read(path))
        previous = keys['current']
        old = [row for row in keys['old'] if row['expires'] > now]
        old.append({'jwk': previous['jwk'], 'expires': now + ACCESS_SECONDS})
        current = _new_key(root)
        _atomic(path, json.dumps({'current': current, 'old': old}).encode())
        (root / (previous['kid'] + '.pem')).unlink()
        return current['kid']


def _strict_url(value):
    if (not isinstance(value, str) or len(value) > 2048 or '\\' in value
            or any(ord(c) < 33 or ord(c) == 127 or c.isspace() for c in value)):
        raise Rejected('invalid_signin_url')
    p = urlsplit(value)
    if (p.scheme != 'https' or not p.hostname or p.username is not None
            or p.password is not None or p.port == 0 or p.fragment):
        raise Rejected('invalid_signin_url')
    return p


def issuer_for(resource):
    p = _strict_url(resource)
    https_url(resource)
    return p.scheme + '://' + p.netloc


def jwks_url(issuer):
    return issuer + '/.well-known/jwks.json'


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _put(db, kind, ident, expires, data):
    db.execute('INSERT OR REPLACE INTO rows VALUES (?,?,?,?)', (kind, ident, expires, json.dumps(data)))


def _get(db, kind, ident):
    row = db.execute('SELECT data FROM rows WHERE kind=? AND id=?', (kind, ident)).fetchone()
    return json.loads(row['data']) if row else None


def _purge(db, now):
    db.execute('DELETE FROM rows WHERE expires<=?', (now,))
    db.execute('DELETE FROM attempts WHERE start<=?', (now - 86400,))


def _scheme(request):
    scheme = request.headers['authorization'].partition(' ')[0]
    return scheme if re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,32}", scheme) else 'Basic'


class _Service:
    def __init__(self, root, issuer, resource, fetch, clock, settings):
        if issuer_for(resource) != issuer:
            raise Rejected('signin_issuer_origin_required')
        self.root = Path(root)
        self.subject = initialize(root, now=clock())['subject']
        self.issuer, self.resource, self.fetch, self.clock = issuer, resource, fetch, clock
        self.settings = Settings(**settings) if isinstance(settings, dict) else settings or Settings()
        for field in ('dcr_max_clients', 'dcr_ttl', 'cimd_ttl', 'login_ip_limit', 'login_global_limit', 'login_window', 'login_backoff'):
            if not isinstance(getattr(self.settings, field), int) or getattr(self.settings, field) < 1:
                raise Rejected('invalid_signin_settings')
        self.origins = set()
        for origin in self.settings.allowed_hosts:
            p = _strict_url(origin)
            https_url(origin)
            if p.path not in ('', '/'):
                raise Rejected('invalid_signin_allowlist')
            self.origins.add((p.hostname, 443 if p.port is None else p.port))

    def allowed(self, value):
        if not isinstance(value, str):
            return False
        try:
            # Redirects may have queries; client documents use auth.fetch_json's stricter rules.
            p = _strict_url(value)
            return (p.hostname, 443 if p.port is None else p.port) in self.origins
        except (ValueError, TypeError, Rejected):
            return False

    def error(self, name, status=400, headers=None):
        return JSONResponse({'error': name}, status_code=status, headers=HEADERS | (headers or {}))

    def redirect(self, data, **values):
        p = urlsplit(data['redirect_uri'])
        query = parse_qs(p.query, keep_blank_values=True)
        query.update({k: [v] for k, v in values.items()})
        if 'state' in data:
            query['state'] = [data['state']]
        query['iss'] = [self.issuer]
        return RedirectResponse(urlunsplit((p.scheme, p.netloc, p.path, urlencode(query, doseq=True), '')),
                                status_code=302, headers=HEADERS)

    def page(self, txn, csrf, failed=False, status=200, wait=0):
        message = '<p>Sign-in unsuccessful. Please try again.</p>' if failed else ''
        if wait:
            message = f'<p>Please wait {wait} seconds before trying again.</p>'
        body = ('<!doctype html><html><head><title>Herdr sign-in</title></head><body><h1>Herdr sign-in</h1>' + message +
                '<form method="post" action="/login"><label>Password <input type="password" name="password" autocomplete="current-password" required></label>'
                '<label><input type="checkbox" name="control" value="yes">Also allow Herdr control</label>'
                '<input type="hidden" name="txn" value="' + html.escape(txn, quote=True) + '">'
                '<input type="hidden" name="csrf" value="' + html.escape(csrf, quote=True) + '">'
                '<button type="submit">Sign in</button></form></body></html>')
        return HTMLResponse(body, status_code=status, headers=HEADERS)

    async def form(self, request):
        if request.headers.get('content-type', '').split(';')[0] != 'application/x-www-form-urlencoded':
            raise Rejected('invalid_request')
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16384:
                raise Rejected('invalid_request')
        try:
            values = parse_qs(body.decode(), keep_blank_values=True, max_num_fields=32)
        except (ValueError, UnicodeError):
            raise Rejected('invalid_request') from None
        if any(len(v) != 1 for v in values.values()):
            raise Rejected('invalid_request')
        return {k: v[0] for k, v in values.items()}

    async def client(self, client_id, redirect):
        if not self.allowed(redirect):
            return False
        now = self.clock()
        cached = await run_in_threadpool(self.cached_client, client_id, now)
        if client_id.startswith('https://'):
            if not self.allowed(client_id):
                return False
            try:
                https_url(client_id)
                if cached is None:
                    doc = await self.fetch(client_id)
                    if not isinstance(doc, dict) or doc.get('client_id') != client_id:
                        return False
                    redirects = doc.get('redirect_uris')
                    if not isinstance(redirects, list) or not 1 <= len(redirects) <= 16 or not all(self.allowed(v) for v in redirects):
                        return False
                    if doc.get('token_endpoint_auth_method', 'none') != 'none':
                        return False
                    cached = {'redirect_uris': redirects}
                    await run_in_threadpool(self.cache_client, client_id, now, cached)
            except Exception:
                # Fetch failures are deliberately generic, including injected fetch exceptions.
                return False
        return bool(cached and redirect in cached['redirect_uris'])

    def cached_client(self, client_id, now):
        with _db(self.root) as db:
            _purge(db, now)
            return _get(db, 'client', client_id)

    def cache_client(self, client_id, now, cached):
        with _db(self.root) as db:
            _put(db, 'client', client_id, now + self.settings.cimd_ttl, cached)

    async def metadata(self, request):
        return JSONResponse({'issuer': self.issuer, 'authorization_endpoint': self.issuer + '/authorize',
            'token_endpoint': self.issuer + '/token', 'registration_endpoint': self.issuer + '/register',
            'revocation_endpoint': self.issuer + '/revoke', 'jwks_uri': jwks_url(self.issuer),
            'revocation_endpoint_auth_methods_supported': ['none'],
            'response_types_supported': ['code'], 'grant_types_supported': ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported': ['S256'], 'token_endpoint_auth_methods_supported': ['none'],
            'scopes_supported': SCOPES, 'client_id_metadata_document_supported': True,
            'authorization_response_iss_parameter_supported': True}, headers=HEADERS)

    async def jwks(self, request):
        return await run_in_threadpool(self.jwks_data)

    def jwks_data(self):
        keys = json.loads(_read(self.root / 'keys.json'))
        keys['old'] = [row for row in keys['old'] if row['expires'] > self.clock()]
        return JSONResponse({'keys': [keys['current']['jwk']] + [row['jwk'] for row in keys['old']]}, headers=HEADERS)

    async def register(self, request):
        try:
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 16384:
                    return self.error('invalid_client_metadata')
            doc = json.loads(body)
            redirects = doc.get('redirect_uris')
            grants = doc.get('grant_types', ['authorization_code'])
            responses = doc.get('response_types', ['code'])
            if (not isinstance(redirects, list) or not 1 <= len(redirects) <= 16
                    or not all(self.allowed(v) for v in redirects)):
                return self.error('invalid_redirect_uri')
            if (doc.get('token_endpoint_auth_method', 'none') != 'none'
                    or not isinstance(grants, list)
                    or not set(grants) <= {'authorization_code', 'refresh_token'}
                    or responses != ['code']):
                return self.error('invalid_client_metadata')
        except (ValueError, AttributeError, TypeError):
            return self.error('invalid_client_metadata')
        return await run_in_threadpool(self.register_client, redirects, grants, responses)

    def register_client(self, redirects, grants, responses):
        now = self.clock()
        with _db(self.root) as db:
            _purge(db, now)
            count = db.execute("SELECT count(*) FROM rows WHERE kind='client' AND id NOT LIKE 'https://%' ").fetchone()[0]
            if count >= self.settings.dcr_max_clients:
                return self.error('registration_limit', 429)
            ident = secrets.token_urlsafe(32)
            _put(db, 'client', ident, now + self.settings.dcr_ttl,
                 {'redirect_uris': redirects, 'grant_types': grants, 'response_types': responses})
        return JSONResponse({'client_id': ident, 'client_id_issued_at': int(now), 'redirect_uris': redirects,
                             'token_endpoint_auth_method': 'none', 'grant_types': grants,
                             'response_types': responses}, status_code=201, headers=HEADERS)

    async def authorize(self, request):
        if len(request.scope.get('query_string', b'')) > 16384:
            return self.error('invalid_request')
        data = dict(request.query_params)
        if not await self.client(data.get('client_id', ''), data.get('redirect_uri', '')):
            return HTMLResponse('Invalid client or redirect URI.', status_code=400, headers=HEADERS)
        if any(len(request.query_params.getlist(k)) != 1 for k in request.query_params):
            return self.redirect(data, error='invalid_request')
        error = None
        if data.get('resource') != self.resource:
            error = 'invalid_target'
        elif not data.get('response_type') or data.get('code_challenge_method') != 'S256' or not re.fullmatch(r'[A-Za-z0-9_-]{43}', data.get('code_challenge', '')):
            error = 'invalid_request'
        elif data['response_type'] != 'code':
            error = 'unsupported_response_type'
        elif not set(data.get('scope', '').split()) <= set(SCOPES):
            error = 'invalid_scope'
        if error:
            return self.redirect(data, error=error)
        return await run_in_threadpool(self.authorize_data, data)

    def authorize_data(self, data):
        txn, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        data['csrf_hash'] = _hash(csrf)
        with _db(self.root) as db:
            _purge(db, self.clock())
            _put(db, 'txn', _hash(txn), self.clock() + 600, data)
        return self.page(txn, csrf)

    def attempt(self, db, key, now):
        row = db.execute('SELECT * FROM attempts WHERE ip=?', (key,)).fetchone()
        if row and row['start'] + self.settings.login_window > now:
            return row['start'], row['count'], row['next']
        return now, 0, 0

    def limited(self, db, ip, now):
        wait = 0
        for key in ('ip:' + ip, 'global'):
            _, _, next_at = self.attempt(db, key, now)
            wait = max(wait, math.ceil(next_at - now))
        return max(0, wait)

    def failed(self, db, ip, now):
        for key, limit in (('ip:' + ip, self.settings.login_ip_limit), ('global', self.settings.login_global_limit)):
            start, count, _ = self.attempt(db, key, now)
            count += 1
            delay = 60 if count >= limit else min(60, self.settings.login_backoff * 2 ** min(count - 1, 6))
            next_at = now + delay
            db.execute('INSERT OR REPLACE INTO attempts VALUES (?,?,?,?)', (key, start, count, next_at))

    async def login(self, request):
        try:
            form = await self.form(request)
        except Rejected:
            return self.error('invalid_request')
        ip = request.client.host if request.client else 'unknown'
        # Keep the transaction and password check together in a worker: awaiting
        # scrypt with an open SQLite write transaction can block other handlers.
        return await run_in_threadpool(self.login_form, form, ip)

    def login_form(self, form, ip):
        now = self.clock()
        txn, csrf = form.get('txn', ''), form.get('csrf', '')
        with _db(self.root) as db:
            _purge(db, now)
            data = _get(db, 'txn', _hash(txn))
            if not data or not hmac.compare_digest(data['csrf_hash'], _hash(csrf)):
                return self.error('invalid_request')
            wait = self.limited(db, ip, now)
            if wait:
                return self.page(txn, csrf, True, 429, wait)
            if not verify_password(self.root, form.get('password', '')):
                self.failed(db, ip, now)
                return self.page(txn, csrf, True)
            db.execute('DELETE FROM attempts WHERE ip=?', ('ip:' + ip,))
            scope = 'herdr:observe'
            if form.get('control') == 'yes' and 'herdr:control' in data.get('scope', '').split():
                scope += ' herdr:control'
            data['scope'] = scope
            data.pop('csrf_hash')
            code = secrets.token_urlsafe(32)
            data['code_expires'] = now + 60
            _put(db, 'code', _hash(code), data['code_expires'], data)
            db.execute("DELETE FROM rows WHERE kind='txn' AND id=?", (_hash(txn),))
        return self.redirect(data, code=code)

    def issue(self, db, data, now, family=None):
        family = family or secrets.token_urlsafe(32)
        created_at = data.get('created_at', now)
        deadline = created_at + REFRESH_SECONDS
        refresh = secrets.token_urlsafe(48)
        _put(db, 'refresh', _hash(refresh), deadline,
             {'client_id': data['client_id'], 'scope': data['scope'], 'resource': self.resource, 'family': family, 'created_at': created_at, 'used': False})
        with _lock(self.root):
            keys = _prune_keys(self.root, json.loads(_read(self.root / 'keys.json')), now)
            current = keys['current']
            key = _read(self.root / (current['kid'] + '.pem'))
            access = jwt.encode({'iss': self.issuer, 'aud': self.resource, 'sub': self.subject,
                'client_id': data['client_id'], 'iat': int(now), 'exp': int(now) + ACCESS_SECONDS,
                'scope': data['scope']}, key, algorithm='RS256', headers={'kid': current['kid']})
        return JSONResponse({'access_token': access, 'token_type': 'Bearer', 'expires_in': ACCESS_SECONDS,
                             'refresh_token': refresh, 'scope': data['scope']}, headers=HEADERS)

    def revoke_family(self, db, family):
        # Consumed refresh hashes remain until expiry to detect replay.
        for row in db.execute("SELECT id,data FROM rows WHERE kind='refresh'").fetchall():
            data = json.loads(row['data'])
            if data['family'] == family:
                data['used'] = True
                db.execute("UPDATE rows SET data=? WHERE kind='refresh' AND id=?", (json.dumps(data), row['id']))

    async def token(self, request):
        try:
            form = await self.form(request)
        except Rejected:
            return self.error('invalid_request')
        if request.headers.get('authorization'):
            return self.error('invalid_client', 401, {'WWW-Authenticate': _scheme(request)})
        if form.get('client_secret'):
            return self.error('invalid_client')
        if form.get('resource') != self.resource:
            return self.error('invalid_target')
        return await run_in_threadpool(self.token_form, form)

    def token_form(self, form):
        now = self.clock()
        with _db(self.root) as db:
            _purge(db, now)
            grant = form.get('grant_type')
            if grant == 'authorization_code':
                ident = _hash(form.get('code', ''))
                data = _get(db, 'code', ident)
                verifier = form.get('code_verifier', '')
                if (not data or data['resource'] != self.resource or data['client_id'] != form.get('client_id') or ('redirect_uri' in form and data['redirect_uri'] != form['redirect_uri'])
                        or not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', verifier)
                        or not hmac.compare_digest(data['code_challenge'], base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('='))):
                    return self.error('invalid_grant')
                if data.get('family'):
                    self.revoke_family(db, data['family'])
                    return self.error('invalid_grant')
                if 'code_expires' not in data:
                    data['code_expires'] = db.execute("SELECT expires FROM rows WHERE kind='code' AND id=?", (ident,)).fetchone()[0]
                data['family'] = secrets.token_urlsafe(32)
                _put(db, 'code', ident, data['code_expires'] + ACCESS_SECONDS, data)
                return self.issue(db, data, now, data['family'])
            if grant == 'refresh_token':
                ident = _hash(form.get('refresh_token', ''))
                data = _get(db, 'refresh', ident)
                if not data or data['client_id'] != form.get('client_id') or data['resource'] != self.resource:
                    return self.error('invalid_grant')
                if data['used']:
                    self.revoke_family(db, data['family'])
                    return self.error('invalid_grant')
                requested = form.get('scope', data['scope'])
                if not set(requested.split()) <= set(data['scope'].split()):
                    return self.error('invalid_scope')
                data['used'] = True
                db.execute("UPDATE rows SET data=? WHERE kind='refresh' AND id=?", (json.dumps(data), ident))
                data['scope'] = requested
                return self.issue(db, data, now, data['family'])
        return self.error('unsupported_grant_type')

    async def revoke(self, request):
        try:
            form = await self.form(request)
        except Rejected:
            return self.error('invalid_request')
        if request.headers.get('authorization'):
            return self.error('invalid_client', 401, {'WWW-Authenticate': _scheme(request)})
        if form.get('client_secret'):
            return self.error('invalid_client')
        if not form.get('token'):
            return self.error('invalid_request')
        return await run_in_threadpool(self.revoke_form, form)

    def revoke_form(self, form):
        with _db(self.root) as db:
            _purge(db, self.clock())
            data = _get(db, 'refresh', _hash(form['token']))
            if data and data['client_id'] == form.get('client_id'):
                self.revoke_family(db, data['family'])
        return JSONResponse({}, headers=HEADERS)


def routes(root, *, issuer, resource, fetch=fetch_json, clock=time.time, settings=None):
    service = _Service(root, issuer, resource, fetch, clock, settings)
    return [Route('/.well-known/oauth-authorization-server', service.metadata),
            Route('/.well-known/jwks.json', service.jwks), Route('/authorize', service.authorize),
            Route('/login', service.login, methods=['POST']), Route('/token', service.token, methods=['POST']),
            Route('/register', service.register, methods=['POST']), Route('/revoke', service.revoke, methods=['POST'])]


def app(root, **kwargs):
    return Starlette(routes=routes(root, **kwargs))
