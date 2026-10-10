"""Opt-in real Codex client, synthetic HTTPS issuer; no user account or fixed ports.

DOT_HERDR_CODEX_INTEGRATION=1 python -m unittest discover -s tests/integration -v
"""
import asyncio
import base64
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs,urlencode
import httpx2
import jwt
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
from starlette.applications import Starlette
from starlette.responses import JSONResponse,RedirectResponse
from starlette.routing import Route,Mount
from dot_herdr.endpoint import JWTVerifier,PairingSession,build_pairing,principal_key

NAME='dot-herdr'

async def reap(child):
    if child and child.returncode is None:
        child.terminate()
        try:await asyncio.wait_for(child.wait(),3)
        except TimeoutError:child.kill();await child.wait()


def certificate(root):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Herdr integration fixture')])
    now=datetime.datetime.now(datetime.timezone.utc)
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
        .not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
        .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),False)
        .sign(ca_key,hashes.SHA256()))
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'127.0.0.1')])).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
        .not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),False)
        .sign(ca_key,hashes.SHA256()))
    for filename,value in [('ca.pem',ca.public_bytes(serialization.Encoding.PEM)),('cert.pem',cert.public_bytes(serialization.Encoding.PEM)),
                           ('key.pem',key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))]:
        path=root/filename;path.write_bytes(value);path.chmod(0o600)
    return key


@unittest.skipUnless(os.environ.get('DOT_HERDR_CODEX_INTEGRATION')=='1' and shutil.which('codex'),'opt-in real Codex fixture')
class CodexOAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_dcr_cimd_and_configured_login_then_actual_authenticated_discovery(self):
        for strategy in ('dcr','cimd','configured'):
            with self.subTest(strategy=strategy):await self.flow(strategy)

    async def flow(self,strategy):
        asyncio.get_running_loop().set_debug(False)
        logger=logging.getLogger('httpx2');old_level=logger.level;logger.setLevel(logging.WARNING)
        self.addCleanup(logger.setLevel,old_level)
        with tempfile.TemporaryDirectory(prefix='dot-herdr-oauth-test-') as folder:
            root=Path(folder);root.chmod(0o700);signing=certificate(root)
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(128)
            issuer='https://127.0.0.1:'+str(listener.getsockname()[1]);resource=issuer+'/mcp'
            state={}
            async def metadata(request):
                result={'issuer':issuer,'authorization_endpoint':issuer+'/authorize','token_endpoint':issuer+'/token',
                        'jwks_uri':issuer+'/jwks','response_types_supported':['code'],'grant_types_supported':['authorization_code'],
                        'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['none'],
                        'scopes_supported':['herdr:observe','herdr:control'],'authorization_response_iss_parameter_supported':True}
                if strategy=='cimd':result['client_id_metadata_document_supported']=True
                elif strategy=='dcr':result['registration_endpoint']=issuer+'/register'
                return JSONResponse(result)
            async def register(request):
                value=await request.json();state['registered']=True
                return JSONResponse({**value,'client_id':'fixture-client','client_id_issued_at':int(time.time()),'token_endpoint_auth_method':'none'},status_code=201)
            async def authorize(request):
                query=dict(request.query_params)
                self.assertEqual(query['resource'],resource);self.assertEqual(query['code_challenge_method'],'S256')
                self.assertEqual(query['scope'],'herdr:observe')
                if strategy=='dcr':self.assertEqual(query['client_id'],'fixture-client')
                elif strategy=='configured':self.assertEqual(query['client_id'],'fixture-preregistered')
                else:self.assertTrue(query['client_id'].startswith('https://chatgpt.com/oauth/codex/'))
                state['authorize']=query
                return RedirectResponse(query['redirect_uri']+'?'+urlencode({'code':'fixture-code','state':query['state'],'iss':issuer}),status_code=302)
            async def token(request):
                query={k:v[0] for k,v in parse_qs((await request.body()).decode()).items()};auth=state['authorize']
                challenge=base64.urlsafe_b64encode(hashlib.sha256(query['code_verifier'].encode()).digest()).decode().rstrip('=')
                self.assertEqual(challenge,auth['code_challenge']);self.assertEqual(query['code'],'fixture-code')
                self.assertEqual(query['resource'],resource);self.assertEqual(query['redirect_uri'],auth['redirect_uri'])
                state['token_issued']=True
                token=jwt.encode({'iss':issuer,'aud':resource,'sub':'fixture-user','client_id':query['client_id'],
                                  'iat':int(time.time()),'exp':int(time.time())+300,'scope':'herdr:observe'},signing,algorithm='RS256')
                return JSONResponse({'access_token':token,'token_type':'Bearer','expires_in':300,'scope':'herdr:observe'})
            public=signing.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            pairing=PairingSession(issuer)
            mcp=build_pairing(JWTVerifier(issuer,resource,public),issuer,resource,pairing).streamable_http_app(json_response=True,stateless_http=True)
            app=Starlette(routes=[Route('/.well-known/oauth-authorization-server',metadata),Route('/.well-known/openid-configuration',metadata),
                                 Route('/register',register,methods=['POST']),Route('/authorize',authorize),Route('/token',token,methods=['POST']),Mount('/',mcp)])
            server=uvicorn.Server(uvicorn.Config(app,ssl_certfile=str(root/'cert.pem'),ssl_keyfile=str(root/'key.pem'),log_level='critical',access_log=False))
            home=root/'codex';home.mkdir(mode=0o700)
            config=home/'config.toml';config.write_text('mcp_oauth_credentials_store = "file"\n');config.chmod(0o600)
            from dot_herdr.connections import register_mcp
            register_mcp(home,resource,resource=resource,client_id='fixture-preregistered' if strategy=='configured' else None)
            env={k:v for k,v in os.environ.items() if k in ('PATH','LANG','SYSTEMROOT')}
            env.update(CODEX_HOME=str(home),CODEX_CA_CERTIFICATE=str(root/'ca.pem'),SSL_CERT_FILE=str(root/'ca.pem'),NO_PROXY='127.0.0.1,localhost')
            child=None;appserver=None;serve=None
            async with mcp.router.lifespan_context(mcp):
                try:
                    serve=asyncio.create_task(server.serve(sockets=[listener]))
                    async with asyncio.timeout(10):
                        while not server.started:await asyncio.sleep(.02)
                    child=await asyncio.create_subprocess_exec(shutil.which('codex'),'mcp','login',NAME,'--scopes','herdr:observe','--no-browser',env=env,
                                                              stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.STDOUT)
                    output=b'';handed=False
                    async with asyncio.timeout(40):
                        while True:
                            chunk=await child.stdout.read(4096)
                            if not chunk:break
                            output=(output+chunk)[-32768:]
                            match=re.search(rb'https://127\.0\.0\.1:[0-9]+/authorize\?[^\s]+',output)
                            if match and not handed:
                                handed=True
                                async with httpx2.AsyncClient(verify=ssl.create_default_context(cafile=str(root/'ca.pem')),trust_env=False,follow_redirects=False) as browser:
                                    response=await browser.get(match.group().decode());self.assertEqual(response.status_code,302)
                                child.stdin.write((response.headers['location']+'\n').encode());await child.stdin.drain()
                        await child.wait()
                    self.assertEqual(child.returncode,0,'Codex fixture sign-in failed; credential-bearing output deliberately withheld')
                    self.assertTrue(state.get('token_issued'));self.assertEqual(bool(state.get('registered')),strategy=='dcr')
                    # Ask the supported app-server API to discover this one server.
                    # Codex itself sends its stored synthetic OAuth token. No credential
                    # file is read by the harness and no model turn/account is invoked.
                    from dot_herdr.login import request_authenticated_discovery
                    with patch.dict(os.environ,env,clear=True):
                        result=await request_authenticated_discovery(codex_home=home)
                    self.assertEqual(result['status'],'discovery_completed')
                    self.assertEqual([c['principal'] for c in pairing.candidates()],[principal_key(issuer,'fixture-user')])
                    self.assertFalse(pairing.closed,'A real authenticated discovery must not auto-confirm the account')
                finally:
                    await reap(appserver);await reap(child)
                    server.should_exit=True
                    if serve:
                        try:await asyncio.wait_for(serve,5)
                        except TimeoutError:serve.cancel();await asyncio.gather(serve,return_exceptions=True)
                    listener.close();pairing.close()
