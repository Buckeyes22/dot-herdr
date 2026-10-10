"""Mounted OAuth routes exercise the connector boundary and real verifier offline."""
import base64
import hashlib
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import AsyncMock, Mock, patch

import httpx2
from dot_herdr import auth, endpoint, runtime, signin
from dot_herdr.core import Store, Rejected

ISSUER = 'https://herdr.example'
RESOURCE = ISSUER + '/mcp'
REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect'
OWNER_CREDENTIAL = 'offline-owner-credential'
PKCE = 'v' * 43


class MountTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        signin.set_password(self.root / 'signin', OWNER_CREDENTIAL)
        self.store = Store(self.root / 'state.sqlite')
        self.addCleanup(self.store.close)
        self.fetched = []
        async def fetch(url):
            self.fetched.append(url)
            self.assertEqual(url, signin.jwks_url(ISSUER))
            return (await self.client.get('/.well-known/jwks.json')).json()
        self.verifier = auth.JWTVerifier(ISSUER, RESOURCE, jwks_url=signin.jwks_url(ISSUER), fetch=fetch)
        self.routes = signin.routes(self.root / 'signin', issuer=ISSUER, resource=RESOURCE)
        self.app = endpoint.build(self.store, None, None, self.verifier, ISSUER, RESOURCE,
                                  signin_routes=self.routes).streamable_http_app(json_response=True, stateless_http=True)
        self.client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.app), base_url=ISSUER)
        self.addAsyncCleanup(self.client.aclose)

    async def test_full_flow_and_mcp_uses_public_jwks_verifier(self):
        metadata = (await self.client.get('/.well-known/oauth-protected-resource/mcp')).json()
        self.assertEqual(metadata['authorization_servers'], [ISSUER])
        registration = await self.client.post('/register', json={'redirect_uris': [REDIRECT]},
                                              headers={'Origin': 'https://server.example'})
        self.assertEqual(registration.status_code, 201)
        ident = registration.json()['client_id']
        response = await self.client.get('/authorize', params=dict(client_id=ident, redirect_uri=REDIRECT,
            response_type='code', resource=RESOURCE, scope='herdr:observe', code_challenge_method='S256',
            code_challenge=base64.urlsafe_b64encode(hashlib.sha256(PKCE.encode()).digest()).decode().rstrip('=')))
        self.assertEqual(response.status_code, 200)
        fields = dict(re.findall(r'name="(txn|csrf)" value="([^"]+)"', response.text))
        fields['password'] = OWNER_CREDENTIAL
        response = await self.client.post('/login', data=fields, headers={'Origin': ISSUER})
        self.assertEqual(response.status_code, 302)
        code = parse_qs(urlsplit(response.headers['location']).query)['code'][0]
        response = await self.client.post('/token', data=dict(grant_type='authorization_code', code=code,
            client_id=ident, redirect_uri=REDIRECT, code_verifier=PKCE, resource=RESOURCE),
            headers={'Origin': 'https://server.example'})
        self.assertEqual(response.status_code, 200)
        token = response.json()['access_token']
        async with self.app.router.lifespan_context(self.app):
            response = await self.client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                'params': {'protocolVersion': endpoint.PROTOCOL, 'capabilities': {}, 'clientInfo': {'name': 'offline', 'version': '1'}}},
                headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json, text/event-stream'})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn('result', response.json())
            parts = token.split('.')
            parts[2] = ('A' if parts[2][0] != 'A' else 'B') + parts[2][1:]
            rejected = await self.client.post('/mcp', json={}, headers={'Authorization': 'Bearer ' + '.'.join(parts)})
            self.assertEqual(rejected.status_code, 401)
        self.assertEqual(self.fetched, [signin.jwks_url(ISSUER)])
        revoked = await self.client.post('/revoke', data={'token': 'offline-unknown', 'client_id': ident},
                                          headers={'Origin': 'https://server.example'})
        self.assertEqual(revoked.status_code, 200)

    async def test_signin_routes_never_call_mcp_bearer_verifier(self):
        with patch.object(self.verifier, 'verify_token', new_callable=AsyncMock) as verify:
            verify.side_effect = AssertionError('Sign-in entered the MCP verifier')
            for route in self.routes:
                with self.subTest(path=route.path):
                    method = 'POST' if 'POST' in route.methods else 'GET'
                    response = await self.client.request(method, route.path, headers={'Authorization': 'Bearer offline-marker'},
                                                         content=b'{}')
                    self.assertIn(response.status_code, (200, 201, 400))
            verify.assert_not_awaited()

    async def test_foreign_host_rejected_on_every_signin_path(self):
        for route in self.routes:
            with self.subTest(path=route.path):
                method = 'POST' if 'POST' in route.methods else 'GET'
                response = await self.client.request(method, route.path, headers={'Host': 'foreign.example'}, content=b'x=1')
                self.assertEqual(response.status_code, 421)

    async def test_login_origin_and_other_path_checks(self):
        for origin in ('https://foreign.example', 'http://127.0.0.1:8000', ''):
            response = await self.client.post('/login', data={}, headers={'Origin': origin})
            self.assertEqual(response.status_code, 403)
        for host in ('herdr.example', '127.0.0.1:8000'):
            response = await self.client.post('/login', data={}, headers={'Host': host})
            self.assertEqual(response.json(), {'error': 'invalid_request'})
        for path in ('/mcp', '/unknown'):
            response = await self.client.post(path, data={'a': 'b'})
            self.assertEqual(response.status_code, 400)
            response = await self.client.post(path, json={}, headers={'Origin': 'https://foreign.example'})
            self.assertEqual(response.status_code, 403)
            response = await self.client.post(path, json={}, headers={'Host': 'foreign.example'})
            self.assertEqual(response.status_code, 421)

    async def test_pairing_builder_mounts_public_signin(self):
        pairing = endpoint.PairingSession(ISSUER)
        app = endpoint.build_pairing(self.verifier, ISSUER, RESOURCE, pairing,
                                     signin_routes=self.routes).streamable_http_app()
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=ISSUER) as client:
            self.assertEqual((await client.get('/.well-known/jwks.json')).status_code, 200)
            self.assertEqual((await client.post('/login', data={})).json(), {'error': 'invalid_request'})


class RunMountTests(unittest.IsolatedAsyncioTestCase):
    async def test_builtin_run_initializes_and_refuses_missing_password(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'config.json'
            cfg = {'signin': 'builtin', 'issuer': ISSUER, 'resource': RESOURCE, 'jwks_url': signin.jwks_url(ISSUER),
                   'subjects': [], 'session_users': ['owner']}
            with patch('dot_herdr.runtime.placeholders', return_value=False), patch('dot_herdr.connections.exposure_for', return_value=None):
                with self.assertRaisesRegex(Rejected, 'builtin_signin_password_not_set_run_dot_herdr_signin_set_password'):
                    await runtime.run(config, cfg=cfg)
            self.assertTrue((signin.signin_root(config) / 'keys.json').is_file())

    async def test_run_builtin_mounts_and_external_keeps_verifier_and_build_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'config.json'
            signin.set_password(signin.signin_root(config), OWNER_CREDENTIAL)
            cfg = {'issuer': ISSUER, 'resource': RESOURCE, 'jwks_url': signin.jwks_url(ISSUER),
                   'subjects': [], 'session_users': ['owner'], 'socket': '/offline/source', 'store': str(Path(temp) / 'state.sqlite')}
            for builtin in (False, True):
                selected = dict(cfg, signin='builtin') if builtin else cfg
                verifier = Mock()
                with patch('dot_herdr.runtime.placeholders', return_value=False), patch('dot_herdr.runtime.load_config', return_value=selected), \
                     patch('dot_herdr.connections.exposure_for', return_value=None), patch('dot_herdr.auth.verifier_from_config', return_value=verifier) as factory, \
                     patch('dot_herdr.endpoint.build', wraps=endpoint.build) as build, patch('dot_herdr.runtime.supervise', new_callable=AsyncMock):
                    await runtime.run(config, cfg=selected)
                    self.assertIs(factory.call_args.args[0], selected)
                    self.assertIs(build.call_args.args[3], verifier)
                    if builtin:
                        self.assertEqual({r.path for r in build.call_args.kwargs['signin_routes']},
                                         {'/.well-known/oauth-authorization-server', '/.well-known/jwks.json', '/authorize', '/login', '/token', '/register', '/revoke'})
                    else:
                        self.assertNotIn('signin_routes', build.call_args.kwargs)
