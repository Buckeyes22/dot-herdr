"""Offline OAuth contract and security tests for the built-in owner provider."""
import asyncio
import base64
from contextlib import closing
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx2
import jwt
from dot_herdr import auth, signin
from dot_herdr.core import Rejected

ISSUER = 'https://herdr.example'
RESOURCE = ISSUER + '/mcp'
CLIENT = 'https://chatgpt.com/oauth/client.json'
REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect'
OWNER_CREDENTIAL = 'test-only-owner-password'
VERIFIER = 'a' * 43
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip('=')


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'signin'

    def test_initialize_idempotent_private_opaque_and_separate(self):
        root = signin.signin_root(Path(self.temp.name) / 'config.toml')
        self.assertEqual(root, self.root)
        first = signin.initialize(root)
        self.assertEqual(signin.initialize(root), first)
        self.assertGreater(len(first['subject']), 30)
        self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
        for file in root.iterdir():
            self.assertEqual(os.stat(file).st_mode & 0o777, 0o600)
        key = signin.serialization.load_pem_private_key((root / (first['kid'] + '.pem')).read_bytes(), None)
        self.assertEqual(key.key_size, 3072)
        self.assertTrue((root / 'oauth.sqlite3').is_file())
        self.assertEqual(signin.issuer_for(RESOURCE), ISSUER)
        self.assertEqual(signin.jwks_url(ISSUER), ISSUER + '/.well-known/jwks.json')

    def test_password_hash_atomic_private_salt_and_boundaries(self):
        self.assertFalse(signin.has_password(self.root))
        for bad in ('', 'short', 'a' * 1025):
            with self.assertRaises(Rejected): signin.set_password(self.root, bad)
        signin.set_password(self.root, OWNER_CREDENTIAL)
        first = json.loads((self.root / 'password.json').read_text())
        self.assertTrue(signin.verify_password(self.root, OWNER_CREDENTIAL))
        self.assertFalse(signin.verify_password(self.root, 'wrong'))
        self.assertFalse(signin.verify_password(self.root, 'a' * 1025))
        signin.set_password(self.root, OWNER_CREDENTIAL)
        second = json.loads((self.root / 'password.json').read_text())
        self.assertNotEqual(first['salt'], second['salt'])
        self.assertEqual(first['n'], 16384)
        self.assertEqual(os.stat(self.root / 'password.json').st_mode & 0o777, 0o600)
        for file in self.root.iterdir(): self.assertNotIn(OWNER_CREDENTIAL.encode(), file.read_bytes())

    def test_symlink_key_and_subject_are_refused(self):
        self.root.mkdir()
        target = Path(self.temp.name) / 'elsewhere'
        target.write_text('do not overwrite')
        (self.root / 'subject').symlink_to(target)
        with self.assertRaises(OSError): signin.initialize(self.root)
        self.assertEqual(target.read_text(), 'do not overwrite')

    def test_initialize_repairs_existing_private_storage(self):
        signin.set_password(self.root, OWNER_CREDENTIAL)
        paths = list(self.root.iterdir())
        self.root.chmod(0o755)
        for path in paths:
            path.chmod(0o644)
        signin.initialize(self.root)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        for path in paths:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        (self.root / 'password.json').chmod(0o644)
        self.assertTrue(signin.verify_password(self.root, OWNER_CREDENTIAL))
        self.assertEqual((self.root / 'password.json').stat().st_mode & 0o777, 0o600)

    def test_nonregular_symlink_and_foreign_owned_storage_rejected(self):
        signin.set_password(self.root, OWNER_CREDENTIAL)
        paths = list(self.root.iterdir())
        for path in paths:
            with self.subTest(path=path.name):
                data = path.read_bytes()
                path.unlink()
                path.symlink_to(Path(self.temp.name) / 'missing')
                with self.assertRaises(OSError):
                    signin.initialize(self.root)
                path.unlink()
                os.mkfifo(path)
                with self.assertRaises(Rejected):
                    signin.initialize(self.root)
                path.unlink()
                path.write_bytes(data)
        original = signin.os.getuid
        with patch.object(signin.os, 'getuid', return_value=original() + 1):
            with self.assertRaises(Rejected):
                signin.initialize(self.root)
        signin.reset_attempts(self.root)



class OAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().set_debug(False)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'signin'
        signin.set_password(self.root, OWNER_CREDENTIAL)
        self.now = time.time()
        self.doc = {'client_id': CLIENT, 'redirect_uris': [REDIRECT]}
        self.fetched = []
        async def fetch(url):
            self.fetched.append(url)
            return self.doc
        self.fetch = fetch
        self.make_client()
        self.addAsyncCleanup(self.client.aclose)

    def make_client(self, settings=None, ip='192.0.2.1'):
        self.application = signin.app(self.root, issuer=ISSUER, resource=RESOURCE,
                                       fetch=self.fetch, clock=lambda: self.now, settings=settings)
        self.client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.application, client=(ip, 1234)), base_url=ISSUER)

    def query(self, **changes):
        return {k: v for k, v in (dict(client_id=CLIENT, redirect_uri=REDIRECT, response_type='code',
                    code_challenge=CHALLENGE, code_challenge_method='S256', resource=RESOURCE,
                    scope='herdr:observe herdr:control', state='state-value', **{}) | changes).items() if v is not None}

    async def authorize(self, **changes):
        response = await self.client.get('/authorize', params=self.query(**changes))
        if response.status_code != 200: return response, {}
        fields = dict(re.findall(r'name="(txn|csrf)" value="([^"]+)"', response.text))
        return response, fields

    async def code(self, control=True, **changes):
        _, fields = await self.authorize(**changes)
        fields['password'] = OWNER_CREDENTIAL
        if control: fields['control'] = 'yes'
        response = await self.client.post('/login', data=fields)
        self.assertEqual(response.status_code, 302)
        result = parse_qs(urlsplit(response.headers['location']).query, keep_blank_values=True)
        self.assertEqual(result['iss'], [ISSUER])
        if changes.get('state', 'state-value') is None:
            self.assertNotIn('state', result)
        else:
            self.assertEqual(result['state'], [changes.get('state', 'state-value')])
        return result['code'][0]

    async def exchange(self, code=None, **changes):
        code = code or await self.code()
        return await self.client.post('/token', data=dict(grant_type='authorization_code', code=code,
            client_id=CLIENT, redirect_uri=REDIRECT, code_verifier=VERIFIER, resource=RESOURCE) | changes)

    async def refresh(self, token, **changes):
        return await self.client.post('/token', data=dict(grant_type='refresh_token', refresh_token=token,
            client_id=CLIENT, resource=RESOURCE) | changes)

    async def test_metadata_and_connector_discovery(self):
        response = await self.client.get('/.well-known/oauth-authorization-server')
        doc = response.json()
        self.assertEqual(doc['issuer'], ISSUER)
        self.assertEqual(doc['scopes_supported'], signin.SCOPES)
        for key, path in [('authorization_endpoint', '/authorize'), ('token_endpoint', '/token'),
                          ('registration_endpoint', '/register'), ('revocation_endpoint', '/revoke'),
                          ('jwks_uri', '/.well-known/jwks.json')]: self.assertEqual(doc[key], ISSUER + path)
        self.assertEqual(doc['response_types_supported'], ['code'])
        self.assertEqual(doc['grant_types_supported'], ['authorization_code', 'refresh_token'])
        self.assertEqual(doc['code_challenge_methods_supported'], ['S256'])
        self.assertEqual(doc['token_endpoint_auth_methods_supported'], ['none'])
        self.assertTrue(doc['client_id_metadata_document_supported'])
        self.assertTrue(doc['authorization_response_iss_parameter_supported'])
        async def fetch(url): return (await self.client.get(url)).json()
        self.assertEqual((await auth.discover_provider(ISSUER, RESOURCE, fetch=fetch))['registration'], 'cimd')
        self.assertEqual({r.path for r in self.application.routes}, {'/.well-known/oauth-authorization-server',
            '/.well-known/jwks.json', '/authorize', '/login', '/token', '/register', '/revoke'})

    async def test_cimd_mismatch_rejected_without_redirect(self):
        self.doc['client_id'] = 'https://chatgpt.com/wrong'
        response, _ = await self.authorize()
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('location', response.headers)

    async def test_cimd_unlisted_redirect_rejected(self):
        response, _ = await self.authorize(redirect_uri='https://chatgpt.com/other')
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('location', response.headers)

    async def test_cimd_ssrf_never_fetched(self):
        for url in ('https://evil.example/client.json', 'https://chatgpt.com.evil.example/client.json',
                    'https://chatgpt.com:444/client.json', 'http://chatgpt.com/client.json'):
            response, _ = await self.authorize(client_id=url)
            self.assertEqual(response.status_code, 400)
        self.assertEqual(self.fetched, [])

    async def test_cimd_cache_expires(self):
        await self.authorize()
        await self.authorize()
        self.assertEqual(len(self.fetched), 1)
        self.now += 301
        self.doc['client_id'] = 'mismatch'
        response, _ = await self.authorize()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.fetched), 2)

    async def test_dcr_public_client_fallback_and_limits(self):
        await self.client.aclose()
        self.make_client({'dcr_max_clients': 1, 'dcr_ttl': 10})
        self.addAsyncCleanup(self.client.aclose)
        for doc in ({'redirect_uris': ['https://evil.example/callback']},
                    {'redirect_uris': [REDIRECT], 'token_endpoint_auth_method': 'client_secret_basic'}):
            self.assertEqual((await self.client.post('/register', json=doc)).status_code, 400)
        doc = {'redirect_uris': [REDIRECT], 'token_endpoint_auth_method': 'none'}
        registered = await self.client.post('/register', json=doc)
        self.assertEqual(registered.status_code, 201)
        client_id = registered.json()['client_id']
        response, _ = await self.authorize(client_id=client_id)
        self.assertEqual(response.status_code, 200)
        self.assertEqual((await self.client.post('/register', json=doc)).status_code, 429)
        self.now += 11
        response, _ = await self.authorize(client_id=client_id)
        self.assertEqual(response.status_code, 400)
        self.assertEqual((await self.client.post('/register', json=doc)).status_code, 201)
        self.assertEqual(self.fetched, [])

    async def test_authorization_errors_have_iss_and_state(self):
        for changes, error in [({'resource': RESOURCE + '/'}, 'invalid_target'),
            ({'code_challenge_method': 'plain'}, 'invalid_request'), ({'code_challenge': 'short'}, 'invalid_request'),
            ({'scope': 'offline_access'}, 'invalid_scope'), ({'response_type': 'token'}, 'unsupported_response_type')]:
            response, _ = await self.authorize(**changes)
            self.assertEqual(response.status_code, 302)
            query = parse_qs(urlsplit(response.headers['location']).query)
            self.assertEqual(query['error'], [error])
            self.assertEqual(query['iss'], [ISSUER])
            self.assertEqual(query['state'], ['state-value'])

    async def test_login_html_security_and_csrf_binding(self):
        response, fields = await self.authorize(state='<script>oops</script>')
        self.assertNotIn('<script>', response.text)
        self.assertEqual(response.text.count('type="password"'), 1)
        self.assertIn('Also allow Herdr control', response.text)
        for key, value in signin.HEADERS.items(): self.assertEqual(response.headers[key], value)
        _, other = await self.authorize()
        for csrf in ('wrong', other['csrf']):
            result = await self.client.post('/login', data=fields | {'csrf': csrf, 'password': OWNER_CREDENTIAL})
            self.assertEqual(result.status_code, 400)
        result = await self.client.post('/login', data=fields | {'password': 'bad'})
        self.assertEqual(result.status_code, 200)
        self.assertNotIn('bad', result.text)
        self.assertEqual((await self.client.get('/login')).status_code, 405)

    async def test_control_requires_both_request_and_checkbox(self):
        for control, scope, expected in [(False, 'herdr:observe herdr:control', 'herdr:observe'),
                                         (True, 'herdr:observe', 'herdr:observe'),
                                         (True, 'herdr:observe herdr:control', 'herdr:observe herdr:control')]:
            code = await self.code(control=control, scope=scope)
            response = await self.exchange(code)
            self.assertEqual(response.json()['scope'], expected)
            self.now += 100

    async def test_pkce_code_bindings_single_use_and_ttl(self):
        code = await self.code()
        for changes in ({'code_verifier': 'b' * 43}, {'client_id': 'other'}, {'redirect_uri': REDIRECT + '/other'}):
            self.assertEqual((await self.exchange(code, **changes)).json()['error'], 'invalid_grant')
        self.assertEqual((await self.exchange(code, resource=RESOURCE + '/other')).json()['error'], 'invalid_target')
        self.assertEqual((await self.exchange(code)).status_code, 200)
        self.assertEqual((await self.exchange(code)).json()['error'], 'invalid_grant')
        self.now += 100
        code = await self.code()
        self.now += 61
        self.assertEqual((await self.exchange(code)).json()['error'], 'invalid_grant')

    async def test_refresh_rotation_replay_revokes_family(self):
        original = (await self.exchange()).json()['refresh_token']
        second = await self.refresh(original)
        self.assertEqual(second.status_code, 200)
        rotated = second.json()['refresh_token']
        self.assertNotEqual(original, rotated)
        self.assertEqual((await self.refresh(original)).json()['error'], 'invalid_grant')
        self.assertEqual((await self.refresh(rotated)).json()['error'], 'invalid_grant')

    async def test_refresh_resource_client_scope_and_expiry(self):
        refresh = (await self.exchange()).json()['refresh_token']
        self.assertEqual((await self.refresh(refresh, resource='wrong')).json()['error'], 'invalid_target')
        self.assertEqual((await self.refresh(refresh, client_id='wrong')).json()['error'], 'invalid_grant')
        self.assertEqual((await self.refresh(refresh, scope='offline_access')).json()['error'], 'invalid_scope')
        reduced = (await self.refresh(refresh, scope='herdr:observe')).json()
        self.assertEqual(reduced['scope'], 'herdr:observe')
        self.now += signin.REFRESH_SECONDS + 1
        self.assertEqual((await self.refresh(reduced['refresh_token'])).json()['error'], 'invalid_grant')

    async def test_revocation_is_idempotent_and_client_bound(self):
        refresh = (await self.exchange()).json()['refresh_token']
        await self.client.post('/revoke', data={'token': refresh, 'client_id': 'wrong'})
        rotated = (await self.refresh(refresh)).json()['refresh_token']
        for token in (rotated, rotated, 'unknown'):
            self.assertEqual((await self.client.post('/revoke', data={'token': token, 'client_id': CLIENT})).status_code, 200)
        self.assertEqual((await self.refresh(rotated)).json()['error'], 'invalid_grant')

    async def test_rate_limit_backoff_and_forwarded_headers_ignored(self):
        await self.client.aclose()
        self.make_client({'login_ip_limit': 2, 'login_global_limit': 3, 'login_window': 100, 'login_backoff': 1})
        self.addAsyncCleanup(self.client.aclose)
        _, fields = await self.authorize()
        form = fields | {'password': 'wrong'}
        self.assertEqual((await self.client.post('/login', data=form)).status_code, 200)
        with patch.object(signin, 'verify_password', side_effect=AssertionError('backoff request verified')):
            self.assertEqual((await self.client.post('/login', data=form)).status_code, 429)
        self.now += 2
        self.assertEqual((await self.client.post('/login', data=form)).status_code, 200)
        self.now += 3
        self.assertEqual((await self.client.post('/login', data=form, headers={'X-Forwarded-For': 'different', 'CF-Connecting-IP': 'different'})).status_code, 429)
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.application, client=('192.0.2.2', 3)), base_url=ISSUER) as other:
            self.assertEqual((await other.post('/login', data=form)).status_code, 200)
            self.now += 5
            with patch.object(signin, 'verify_password', side_effect=AssertionError('limited request verified')):
                self.assertEqual((await other.post('/login', data=form)).status_code, 429)
        self.now += 101
        self.assertEqual((await self.client.post('/login', data=form)).status_code, 200)

    async def test_six_successful_logins_do_not_count_as_failures(self):
        for _ in range(6):
            await self.code()
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 0)

    async def test_success_clears_only_per_ip_failures(self):
        _, fields = await self.authorize()
        self.assertEqual((await self.client.post('/login', data=fields | {'password': 'wrong'})).status_code, 200)
        self.now += 2
        self.assertEqual((await self.client.post('/login', data=fields | {'password': OWNER_CREDENTIAL})).status_code, 302)
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT ip,count FROM attempts').fetchall(), [('global', 1)])
        _, fields = await self.authorize()
        await self.client.post('/login', data=fields | {'password': 'wrong'})
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db:
            self.assertEqual(dict(db.execute('SELECT ip,count FROM attempts')), {'global': 2, 'ip:192.0.2.1': 1})

    async def test_token_resource_is_required_for_both_grants(self):
        code = await self.code()
        form = dict(grant_type='authorization_code', code=code, client_id=CLIENT,
                    redirect_uri=REDIRECT, code_verifier=VERIFIER)
        self.assertEqual((await self.client.post('/token', data=form | {'resource': 'wrong'})).json()['error'], 'invalid_target')
        self.assertEqual((await self.client.post('/token', data=form)).json()['error'], 'invalid_target')
        response = await self.client.post('/token', data=form | {'resource': RESOURCE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(jwt.decode(response.json()['access_token'], options={'verify_signature': False})['aud'], RESOURCE)
        form = dict(grant_type='refresh_token', refresh_token=response.json()['refresh_token'], client_id=CLIENT)
        self.assertEqual((await self.client.post('/token', data=form | {'resource': 'wrong'})).json()['error'], 'invalid_target')
        self.assertEqual((await self.client.post('/token', data=form)).json()['error'], 'invalid_target')
        response = await self.client.post('/token', data=form | {'resource': RESOURCE})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(jwt.decode(response.json()['access_token'], options={'verify_signature': False})['aud'], RESOURCE)

    async def test_redirect_state_only_when_supplied(self):
        for state in (None, '', 'supplied-state'):
            await self.code(state=state)
            response, _ = await self.authorize(state=state, resource=None)
            query = parse_qs(urlsplit(response.headers['location']).query, keep_blank_values=True)
            self.assertEqual(query['iss'], [ISSUER])
            self.assertEqual(query['error'], ['invalid_target'])
            if state is None:
                self.assertNotIn('state', query)
            else:
                self.assertEqual(query['state'], [state])

    async def test_login_password_verification_keeps_event_loop_responsive(self):
        _, fields = await self.authorize()
        started, release = threading.Event(), threading.Event()
        loop_thread = threading.get_ident()
        original = signin.verify_password
        def verify(root, password):
            self.assertNotEqual(threading.get_ident(), loop_thread)
            started.set()
            if not release.wait(5):
                raise AssertionError('event loop did not release password worker')
            return original(root, password)
        with patch.object(signin, 'verify_password', side_effect=verify):
            login = asyncio.create_task(self.client.post('/login', data=fields | {'password': OWNER_CREDENTIAL}))
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 2))
                response = await asyncio.wait_for(self.client.get('/.well-known/oauth-authorization-server'), 1)
                self.assertEqual(response.status_code, 200)
            finally:
                release.set()
                response = await login
            self.assertEqual(response.status_code, 302)

    async def test_jwks_and_metadata_reads_leave_storage_unchanged(self):
        old = signin.initialize(self.root)['kid']
        new = signin.rotate_key(self.root, now=self.now)
        self.now += 600
        path = self.root / 'keys.json'
        before = path.stat()
        database = self.root / 'oauth.sqlite3'
        db_before = database.stat()
        for _ in range(2):
            response = await self.client.get('/.well-known/jwks.json')
            self.assertEqual([k['kid'] for k in response.json()['keys']], [new])
            await self.client.get('/.well-known/oauth-authorization-server')
        after = path.stat()
        self.assertEqual((after.st_mtime_ns, after.st_ino), (before.st_mtime_ns, before.st_ino))
        self.assertEqual(database.stat().st_mtime_ns, db_before.st_mtime_ns)
        self.assertEqual(json.loads(path.read_text())['old'][0]['jwk']['kid'], old)

    async def test_initialize_and_rotate_prune_expired_old_keys(self):
        for operation in ('initialize', 'rotate'):
            with self.subTest(operation=operation):
                old = json.loads((self.root / 'keys.json').read_text())['current']['kid']
                private = (self.root / (old + '.pem')).read_bytes()
                current = signin.rotate_key(self.root, now=self.now)
                # Also clean up any retained legacy old private key file.
                (self.root / (old + '.pem')).write_bytes(private)
                self.now += 600
                if operation == 'initialize':
                    self.assertEqual(signin.initialize(self.root, now=self.now)['kid'], current)
                else:
                    current = signin.rotate_key(self.root, now=self.now)
                manifest = json.loads((self.root / 'keys.json').read_text())
                self.assertNotIn(old, [k['jwk']['kid'] for k in manifest['old']])
                self.assertFalse((self.root / (old + '.pem')).exists())
                self.assertNotIn(old, [k['kid'] for k in (await self.client.get('/.well-known/jwks.json')).json()['keys']])
                token = (await self.exchange()).json()['access_token']
                self.assertEqual(jwt.get_unverified_header(token)['kid'], current)

    async def test_rotation_overlap_and_old_key_drop(self):
        old = signin.initialize(self.root)['kid']
        new = signin.rotate_key(self.root, now=self.now)
        self.assertNotEqual(new, old)
        self.assertEqual({k['kid'] for k in (await self.client.get('/.well-known/jwks.json')).json()['keys']}, {old, new})
        response = await self.exchange()
        self.assertEqual(jwt.get_unverified_header(response.json()['access_token'])['kid'], new)
        self.now += 600
        self.assertEqual([k['kid'] for k in (await self.client.get('/.well-known/jwks.json')).json()['keys']], [new])
        self.assertFalse((self.root / (old + '.pem')).exists())
        await self.exchange()
        self.assertEqual(json.loads((self.root / 'keys.json').read_text())['old'], [])

    async def test_expired_rows_purged_and_only_secret_hashes_stored(self):
        code = await self.code()
        response = await self.exchange(code)
        refresh = response.json()['refresh_token']
        _, fields = await self.authorize()
        await self.client.post('/register', json={'redirect_uris': [REDIRECT]})
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db, db:
            rows = db.execute('SELECT kind,id,data FROM rows').fetchall()
            text = repr(rows)
            for secret in (OWNER_CREDENTIAL, code, refresh, fields['txn'], fields['csrf']): self.assertNotIn(secret, text)
            for kind in ('code', 'txn', 'client', 'refresh'):
                db.execute('INSERT INTO rows VALUES (?,?,?,?)', (kind, 'expired', self.now - 1, '{}'))
        await self.authorize()
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db, db:
            self.assertEqual(db.execute("SELECT count(*) FROM rows WHERE id='expired'").fetchone()[0], 0)

    async def test_no_sensitive_values_in_logs_or_errors(self):
        with self.assertLogs(level=logging.INFO) as captured:
            logging.getLogger('signin-test').info('capture-start')
            response, fields = await self.authorize()
            self.now += 2
            code = await self.code()
            token = (await self.exchange(code)).json()
            bad = await self.client.post('/token', data={'resource': RESOURCE, 'grant_type': 'authorization_code', 'code': code}, headers={'Authorization': 'Bearer secret-header'})
            await self.client.post('/login', data=fields | {'password': OWNER_CREDENTIAL, 'csrf': 'wrong'})
        output = '\n'.join(captured.output) + bad.text
        for secret in (OWNER_CREDENTIAL, code, fields['csrf'], fields['txn'], token['access_token'], token['refresh_token'], 'secret-header'):
            self.assertNotIn(secret, output)

    async def test_full_flow_connector_verifier_and_adversarial_tokens(self):
        old_kid = signin.initialize(self.root)['kid']
        old_key = (self.root / (old_kid + '.pem')).read_bytes()
        token = (await self.exchange()).json()
        async def fetch(url): return (await self.client.get(url)).json()
        verifier = auth.JWTVerifier(ISSUER, RESOURCE, jwks_url=signin.jwks_url(ISSUER), fetch=fetch)
        verified = await verifier.verify_token(token['access_token'])
        self.assertEqual(verified.scopes, signin.SCOPES)
        self.assertEqual(verified.subject, signin.initialize(self.root)['subject'])
        claims = jwt.decode(token['access_token'], options={'verify_signature': False})
        self.assertEqual(claims['exp'] - claims['iat'], 600)
        self.assertEqual(claims['aud'], RESOURCE)
        pieces = token['access_token'].split('.')
        pieces[1] = base64.urlsafe_b64encode(json.dumps(claims | {'sub': 'tampered'}).encode()).decode().rstrip('=')
        self.assertIsNone(await verifier.verify_token('.'.join(pieces)))
        wrong = jwt.encode(claims | {'aud': 'wrong'}, old_key, algorithm='RS256', headers={'kid': old_kid})
        self.assertIsNone(await verifier.verify_token(wrong))
        refreshed = (await self.refresh(token['refresh_token'])).json()
        self.assertIsNotNone(await verifier.verify_token(refreshed['access_token']))
        signin.rotate_key(self.root, now=self.now)
        self.now += 601
        # Fresh verifier: existing connector caches may retain an old public key for 300s.
        verifier = auth.JWTVerifier(ISSUER, RESOURCE, jwks_url=signin.jwks_url(ISSUER), fetch=fetch)
        forged_late = jwt.encode(claims | {'iat': int(time.time()), 'exp': int(time.time()) + 600}, old_key,
                                algorithm='RS256', headers={'kid': old_kid})
        self.assertIsNone(await verifier.verify_token(forged_late))

    async def test_bounded_malformed_requests(self):
        self.assertEqual((await self.client.post('/register', content='x' * 17000)).status_code, 400)
        self.assertEqual((await self.client.post('/register', json=[])).status_code, 400)
        self.assertEqual((await self.client.post('/register', json={'redirect_uris': [{}]})).status_code, 400)
        self.assertEqual((await self.client.post('/token', json={})).status_code, 400)
        self.assertEqual((await self.client.post('/login', content='password=' + 'x' * 17000,
            headers={'Content-Type': 'application/x-www-form-urlencoded'})).status_code, 400)
        self.assertEqual((await self.client.post('/token', content='resource=a&resource=b',
            headers={'Content-Type': 'application/x-www-form-urlencoded'})).status_code, 400)

    async def test_concurrent_code_and_refresh_redemption(self):
        code = await self.code()
        results = await asyncio.gather(self.exchange(code), self.exchange(code))
        self.assertEqual(sorted(r.status_code for r in results), [200, 400])
        original = next(r.json()['refresh_token'] for r in results if r.status_code == 200)
        self.assertEqual((await self.refresh(original)).status_code, 400)
        original = (await self.exchange()).json()['refresh_token']
        results = await asyncio.gather(self.refresh(original), self.refresh(original))
        self.assertEqual(sorted(r.status_code for r in results), [200, 400])
        child = next(r.json()['refresh_token'] for r in results if r.status_code == 200)
        self.assertEqual((await self.refresh(child)).status_code, 400)

    async def test_custom_allowlist_and_default_fetch_contract(self):
        import inspect
        self.assertIs(inspect.signature(signin.routes).parameters['fetch'].default, auth.fetch_json)
        await self.client.aclose()
        self.make_client({'allowed_hosts': ('https://custom.example',)})
        self.addAsyncCleanup(self.client.aclose)
        doc = {'redirect_uris': ['https://custom.example/callback'], 'grant_types': ['authorization_code']}
        registered = await self.client.post('/register', json=doc)
        self.assertEqual(registered.status_code, 201)
        response, _ = await self.authorize(client_id=registered.json()['client_id'], redirect_uri=doc['redirect_uris'][0])
        self.assertEqual(response.status_code, 200)
        self.assertEqual((await self.client.post('/register', json={'redirect_uris': [REDIRECT]})).status_code, 400)

    async def test_expired_transaction_cannot_login(self):
        _, fields = await self.authorize()
        self.now += 601
        self.assertEqual((await self.client.post('/login', data=fields | {'password': OWNER_CREDENTIAL})).status_code, 400)

    async def test_owner_not_locked_out_by_remote_loopback_failures(self):
        fields = (await self.authorize())[1]
        for delay in (0, 2, 4, 8, 16):
            self.now += delay
            self.assertEqual((await self.client.post('/login', data=fields | {'password':'wrong'})).status_code, 200)
        blocked = await self.client.post('/login', data=fields | {'password': OWNER_CREDENTIAL})
        self.assertEqual(blocked.status_code, 429)
        self.assertIn('Please wait 60 seconds', blocked.text)
        signin.set_password(self.root, OWNER_CREDENTIAL)
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM attempts').fetchone()[0], 0)
        self.assertEqual((await self.client.post('/login', data=fields | {'password': OWNER_CREDENTIAL})).status_code, 302)
        # Fill the shared bucket again, and verify its backoff expires within 60s.
        fields = (await self.authorize())[1]
        for delay in (0, 2, 4, 8, 16):
            self.now += delay
            self.assertEqual((await self.client.post('/login', data=fields | {'password': 'wrong'})).status_code, 200)
        self.now += 61
        owner = (await self.authorize())[1]
        response = await self.client.post('/login', data=owner | {'password': OWNER_CREDENTIAL})
        self.assertEqual(response.status_code, 302, 'owner blocked for remainder of shared 300-second window')

    async def test_refresh_replay_retained_for_active_family(self):
        first = (await self.exchange()).json()['refresh_token']
        created = self.now
        self.now += 10
        second = (await self.refresh(first)).json()['refresh_token']
        self.now = created + signin.REFRESH_SECONDS - 1
        third = (await self.refresh(second)).json()['refresh_token']
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db:
            rows = db.execute("SELECT expires,data FROM rows WHERE kind='refresh'").fetchall()
        self.assertEqual(len(rows), 3)
        self.assertEqual({row[0] for row in rows}, {created + signin.REFRESH_SECONDS})
        self.assertEqual((await self.refresh(first)).status_code, 400)
        self.assertEqual((await self.refresh(third)).status_code, 400)
        # An unreplayed family also expires at its original deadline after rotation.
        token = (await self.exchange()).json()['refresh_token']
        self.now += signin.REFRESH_SECONDS - 1
        child = (await self.refresh(token)).json()['refresh_token']
        self.now += 1
        self.assertEqual((await self.refresh(child)).status_code, 400)

    async def test_token_requires_resource(self):
        code = await self.code()
        response = await self.client.post('/token', data=dict(grant_type='authorization_code', code=code,
            client_id=CLIENT, redirect_uri=REDIRECT, code_verifier=VERIFIER))
        self.assertEqual(response.status_code, 400, 'missing resource accepted by token endpoint')

    async def test_port_zero_is_not_default_https_origin(self):
        response = await self.client.post('/register', json={'redirect_uris':['https://chatgpt.com:0/callback']})
        self.assertEqual(response.status_code, 400, 'port 0 treated as port 443')

    async def test_redirect_rejects_empty_userinfo_and_backslash(self):
        for redirect in ('https://@chatgpt.com/callback', 'https://:@chatgpt.com/callback',
                         'https://chatgpt.com/\\callback', 'https://chatgpt.com/a b',
                         'https://chatgpt.com/a\t', 'https://chatgpt.com/a\n', 'https://chatgpt.com/a\x7f'):
            with self.subTest(redirect=redirect):
                response = await self.client.post('/register', json={'redirect_uris':[redirect]})
                self.assertEqual(response.status_code, 400, f'malformed URI accepted: {redirect!r}')

    async def test_sqlite_wait_does_not_block_event_loop(self):
        fields = (await self.authorize())[1]
        started, release = threading.Event(), threading.Event()
        original = signin.verify_password
        def verify(root, password):
            started.set()
            release.wait(3)
            return original(root, password)
        with patch.object(signin, 'verify_password', side_effect=verify):
            login = asyncio.create_task(self.client.post('/login', data=fields | {'password':OWNER_CREDENTIAL}))
            self.assertTrue(await asyncio.to_thread(started.wait, 2))
            # Cache hit contends with the login writer while the loop heartbeat runs.
            timer = threading.Timer(.5, release.set)
            timer.start()
            start = time.monotonic()
            authorize = asyncio.create_task(self.client.get('/authorize', params=dict(client_id=CLIENT, redirect_uri=REDIRECT)))
            await asyncio.sleep(.05)
            gap = time.monotonic() - start
            await login
            await authorize
            timer.join()
        self.assertLess(gap, .2, f'event loop stalled for {gap:.3f}s waiting for SQLite')

    async def test_revoke_requires_token_parameter(self):
        response = await self.client.post('/revoke', data={'client_id':CLIENT})
        self.assertEqual(response.status_code, 400, 'missing REQUIRED token accepted as successful revocation')
        self.assertEqual(response.json()['error'], 'invalid_request')
        self.assertEqual((await self.client.post('/revoke', data={'token': ''})).status_code, 400)
        self.assertEqual((await self.client.post('/revoke', data={'token': 'unknown'})).status_code, 200)

    async def test_consumed_authorization_code_revokes_grant(self):
        code = await self.code()
        token = (await self.exchange(code)).json()['refresh_token']
        self.assertEqual((await self.exchange(code)).status_code, 400)
        self.assertEqual((await self.refresh(token)).status_code, 400, 'code replay leaves issued refresh grant active')

    async def test_client_ids_and_configured_origins_rejected(self):
        for origin in ('https://chatgpt.com:0', 'https://@chatgpt.com', 'https://:@chatgpt.com',
                       'https://chatgpt.com/\\', 'https://chatgpt.com\t', 'https://chatgpt.com/a b'):
            with self.subTest(origin=origin):
                with self.assertRaises((Rejected, ValueError)):
                    signin.app(self.root, issuer=ISSUER, resource=RESOURCE, settings={'allowed_hosts': (origin,)})
                self.fetched.clear()
                response, _ = await self.authorize(client_id=origin + '/client.json')
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.fetched, [])

    async def test_code_tombstone_bindings_expiry_and_rotation(self):
        code = await self.code()
        first = (await self.exchange(code)).json()['refresh_token']
        child = (await self.refresh(first)).json()['refresh_token']
        for changes in ({'client_id': 'wrong'}, {'redirect_uri': REDIRECT + '/wrong'}, {'code_verifier': 'b' * 43}):
            self.assertEqual((await self.exchange(code, **changes)).status_code, 400)
        child = (await self.refresh(child)).json()['refresh_token']
        self.now += 61
        self.assertEqual((await self.exchange(code)).status_code, 400)
        self.assertEqual((await self.refresh(child)).status_code, 400)
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db:
            expiry = db.execute("SELECT expires FROM rows WHERE kind='code' AND id=?", (signin._hash(code),)).fetchone()[0]
        self.now = expiry
        await self.authorize()
        with closing(sqlite3.connect(self.root / 'oauth.sqlite3')) as db:
            self.assertIsNone(db.execute("SELECT id FROM rows WHERE kind='code' AND id=?", (signin._hash(code),)).fetchone())

    async def test_all_handler_storage_and_signing_run_in_workers(self):
        loop_thread = threading.get_ident()
        original_db, original_read, original_lock, original_sign = signin._db, signin._read, signin._lock, signin.jwt.encode
        def worker_call(function):
            def checked(*args, **kwargs):
                self.assertNotEqual(threading.get_ident(), loop_thread)
                return function(*args, **kwargs)
            return checked
        with patch.object(signin, '_db', side_effect=worker_call(original_db)), \
             patch.object(signin, '_read', side_effect=worker_call(original_read)), \
             patch.object(signin, '_lock', side_effect=worker_call(original_lock)), \
             patch.object(signin.jwt, 'encode', side_effect=worker_call(original_sign)):
            self.assertEqual((await self.client.get('/.well-known/jwks.json')).status_code, 200)
            self.assertEqual((await self.client.post('/register', json={'redirect_uris': [REDIRECT]})).status_code, 201)
            token = (await self.exchange()).json()['refresh_token']
            child = (await self.refresh(token)).json()['refresh_token']
            self.assertEqual((await self.client.post('/revoke', data={'token': child, 'client_id': CLIENT})).status_code, 200)
