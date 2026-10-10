"""Offline standards regressions for the owner sign-in service."""
import asyncio
import base64
import hashlib
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx2

from dot_herdr import signin

ISSUER = 'https://herdr.example'
RESOURCE = ISSUER + '/mcp'
CLIENT = 'https://chatgpt.com/oauth/client.json'
REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect'
OWNER_CREDENTIAL = 'test-only-owner-password'
VERIFIER = 'a' * 43
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip('=')


class SigninConformanceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().set_debug(False)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'signin'
        signin.set_password(self.root, OWNER_CREDENTIAL)

        async def fetch(url):
            self.assertEqual(url, CLIENT)
            return {'client_id': CLIENT, 'redirect_uris': [REDIRECT]}

        self.application = signin.app(self.root, issuer=ISSUER, resource=RESOURCE, fetch=fetch)
        self.client = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=self.application), base_url=ISSUER)
        self.addAsyncCleanup(self.client.aclose)

    def query(self, **changes):
        return {k: v for k, v in (dict(client_id=CLIENT, redirect_uri=REDIRECT,
            response_type='code', resource=RESOURCE, code_challenge=CHALLENGE,
            code_challenge_method='S256', state='review-state') | changes).items() if v is not None}

    async def code(self):
        response = await self.client.get('/authorize', params=self.query())
        self.assertEqual(response.status_code, 200)
        fields = dict(re.findall(r'name="(txn|csrf)" value="([^"]+)"', response.text))
        response = await self.client.post('/login', data=fields | {'password': OWNER_CREDENTIAL})
        self.assertEqual(response.status_code, 302)
        return parse_qs(urlsplit(response.headers['location']).query)['code'][0]

    async def exchange(self, code, **changes):
        return await self.client.post('/token', data=dict(grant_type='authorization_code',
            code=code, client_id=CLIENT, resource=RESOURCE, code_verifier=VERIFIER) | changes)

    async def test_FR2_1_token_redirect_optional_and_bindings_preserved(self):
        code = await self.code()
        for changes, error in [({'client_id': 'other-client'}, 'invalid_grant'),
                               ({'code_verifier': 'b' * 43}, 'invalid_grant'),
                               ({'resource': RESOURCE + '/'}, 'invalid_target'),
                               ({'redirect_uri': REDIRECT + '/'}, 'invalid_grant'),
                               ({'redirect_uri': ''}, 'invalid_grant')]:
            with self.subTest(changes=changes):
                response = await self.exchange(code, **changes)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json(), {'error': error})
        response = await self.exchange(code)
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.json())
        replay = await self.exchange(code)
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(replay.json(), {'error': 'invalid_grant'})
        legacy = await self.exchange(await self.code(), redirect_uri=REDIRECT)
        self.assertEqual(legacy.status_code, 200)
        invalid_redirect = await self.client.get('/authorize', params=self.query(redirect_uri=REDIRECT + '/'))
        self.assertEqual(invalid_redirect.status_code, 400)
        self.assertNotIn('location', invalid_redirect.headers)

    async def test_FR2_2_revocation_metadata_advertises_none(self):
        response = await self.client.get('/.well-known/oauth-authorization-server')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get('revocation_endpoint_auth_methods_supported'), ['none'])
        revoked = await self.client.post('/revoke', data={'token': 'unknown', 'client_id': CLIENT})
        self.assertEqual(revoked.status_code, 200)

    async def test_FR2_4_registration_returns_and_stores_accepted_metadata(self):
        for requested, grants in [({}, ['authorization_code']),
                ({'grant_types': ['authorization_code', 'refresh_token'], 'response_types': ['code']},
                 ['authorization_code', 'refresh_token'])]:
            with self.subTest(requested=requested):
                response = await self.client.post('/register', json={
                    'redirect_uris': [REDIRECT], 'token_endpoint_auth_method': 'none'} | requested)
                self.assertEqual(response.status_code, 201)
                doc = response.json()
                self.assertEqual(doc.get('grant_types'), grants)
                self.assertEqual(doc.get('response_types'), ['code'])
                with signin._db(self.root) as db:
                    stored = signin._get(db, 'client', doc['client_id'])
                self.assertEqual(stored['grant_types'], grants)
                self.assertEqual(stored['response_types'], ['code'])

    async def test_FR2_5_registration_invalid_redirect_error(self):
        for redirects in (['https://evil.example/callback'], [], 'not-a-list', [None]):
            with self.subTest(redirects=redirects):
                response = await self.client.post('/register', json={
                    'redirect_uris': redirects, 'token_endpoint_auth_method': 'none'})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json(), {'error': 'invalid_redirect_uri'})
        response = await self.client.post('/register', json={
            'redirect_uris': [REDIRECT], 'token_endpoint_auth_method': 'client_secret_basic'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'invalid_client_metadata'})

    async def test_FR2_6_unsupported_response_type_preserves_redirect_issuer_state(self):
        for response_type, error in [('token', 'unsupported_response_type'),
                                     (None, 'invalid_request'), ('', 'invalid_request')]:
            with self.subTest(response_type=response_type):
                response = await self.client.get('/authorize', params=self.query(response_type=response_type))
                self.assertEqual(response.status_code, 302)
                location = urlsplit(response.headers['location'])
                self.assertEqual(location._replace(query='').geturl(), REDIRECT)
                query = parse_qs(location.query)
                self.assertEqual(query['error'], [error])
                self.assertEqual(query['iss'], [ISSUER])
                self.assertEqual(query['state'], ['review-state'])

    async def test_FR2_7_header_authentication_requires_401_and_matching_challenge(self):
        for endpoint, form in [('/token', {'resource': RESOURCE, 'grant_type': 'authorization_code'}),
                               ('/revoke', {'token': 'unknown', 'client_id': CLIENT})]:
            for scheme, credential in [('Basic', 'eDp5'), ('Bearer', 'test-token')]:
                with self.subTest(endpoint=endpoint, scheme=scheme):
                    response = await self.client.post(endpoint, data=form,
                        headers={'Authorization': scheme + ' ' + credential})
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.json(), {'error': 'invalid_client'})
                    self.assertEqual(response.headers.get('www-authenticate'), scheme)
                    self.assertEqual(response.headers.get('cache-control'), 'no-store')
            with self.subTest(endpoint=endpoint, authentication='body-secret'):
                response = await self.client.post(endpoint, data=form | {'client_secret': 'test-secret'})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json(), {'error': 'invalid_client'})
                self.assertNotIn('www-authenticate', response.headers)
