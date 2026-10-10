"""Pinned OAuth discovery and bounded RS256 verification; no credential storage."""
import asyncio
import json
import time
import math
from datetime import datetime,timezone
from urllib.parse import urlsplit
import httpx2
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from mcp.server.auth.provider import AccessToken
from .core import Rejected

MAX_DOCUMENT=65536
CACHE_SECONDS=300
REFRESH_SECONDS=30
CONTROL_SCOPE_REMEDY='This sign-in allows observation only. To allow control, in ChatGPT in a web browser (chatgpt.com) open Settings → Plugins, remove the Herdr plugin, add it again with the same URL, and tick "Also allow Herdr control" on the password page. Observation works now.'


def record_verified_scopes(config,token):
    """Retain bounded permission names from a verified token, never token bytes."""
    import re
    from .connections import connection_record,save_connection
    scopes=sorted({s for s in token.scopes if isinstance(s,str) and re.fullmatch(r'[A-Za-z0-9:_-]{1,128}',s)})[:32]
    try:
        record=connection_record(config)
        from .endpoint import principal_key
        if record.get('identity')!=principal_key(token.claims['iss'],token.subject):return
        client=token.client_id;expires=getattr(token,'expires_at',None);now=time.time()
        if not isinstance(client,str) or not 1<=len(client)<=256 or not isinstance(expires,(int,float)) or not math.isfinite(expires) or expires<=now:return
        entries=record.get('verified_client_scopes',{}).copy()
        entries={key:value for key,value in entries.items() if value['expires_at']>now or key==record.get('approved_client_id')}
        if client not in entries and len(entries)>=8:
            discard=min((key for key in entries if key!=record.get('approved_client_id')),key=lambda key:entries[key]['verified_at'],default=None)
            if discard is None:return
            del entries[discard]
        entries[client]={'scopes':scopes,'verified_at':now,'expires_at':expires}
        record['verified_client_scopes']=entries;record.pop('last_verified_scopes',None);save_connection(config,record)
    except (Rejected,OSError,ValueError,KeyError):pass  # A record race never rejects an otherwise valid request.


def approved_scope_evidence(record,now=None):
    now=time.time() if now is None else now
    entries=record.get('verified_client_scopes',{})
    current=[{'client_id':client,**entry} for client,entry in entries.items() if isinstance(entry,dict) and isinstance(entry.get('verified_at'),(int,float)) and isinstance(entry.get('expires_at'),(int,float)) and entry['verified_at']<=now<entry['expires_at']]
    current.sort(key=lambda entry:(entry['verified_at'],entry['client_id']),reverse=True)
    if not current:return None
    return {**current[0],'clients':current}


def https_url(value):
    if not isinstance(value,str) or len(value)>2048 or any(ord(c)<33 or ord(c)==127 for c in value):raise Rejected('invalid_auth_url')
    try:
        p=urlsplit(value)
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.fragment or p.query:raise ValueError()
        p.port
    except ValueError:raise Rejected('invalid_auth_url') from None
    return p


def same_origin(issuer,url):
    a,b=https_url(issuer),https_url(url)
    if (a.hostname,a.port or 443)!=(b.hostname,b.port or 443):raise Rejected('auth_origin_not_allowed')
    return url


async def fetch_json(url):
    """No redirects, ambient proxies, cookies or credentials; hard wall and byte limits."""
    https_url(url)
    try:
        async with asyncio.timeout(8):
            async with httpx2.AsyncClient(trust_env=False,follow_redirects=False,timeout=5) as client:
                async with client.stream('GET',url,headers={'Accept':'application/json','Accept-Encoding':'identity'}) as response:
                    if response.status_code!=200:raise Rejected('auth_discovery_unavailable')
                    if response.headers.get('content-encoding','identity').lower()!='identity':raise Rejected('auth_encoded_document_not_allowed')
                    data=bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data)>MAX_DOCUMENT:raise Rejected('auth_document_too_large')
        try:result=json.loads(data)
        except (ValueError,UnicodeDecodeError):raise Rejected('invalid_auth_document') from None
        if not isinstance(result,dict):raise Rejected('invalid_auth_document')
        return result
    except (httpx2.HTTPError,TimeoutError):raise Rejected('auth_discovery_unavailable') from None


async def discover_resource(endpoint,*,fetch=fetch_json,client_id=None):
    """Resolve an existing MCP URL through its protected-resource metadata."""
    from mcp.server.auth.routes import build_resource_metadata_url
    https_url(endpoint)
    metadata_url=str(build_resource_metadata_url(endpoint))
    same_origin(endpoint,metadata_url)
    try:document=await fetch(metadata_url)
    except Rejected as error:
        if str(error)!='auth_discovery_unavailable':raise
        p=https_url(endpoint);issuer=p.scheme+'://'+p.netloc
        await discover_provider(issuer,endpoint,client_id,fetch=fetch,allow_oidc=False)
        return {'resource':endpoint,'issuers':[issuer],'metadata_url':metadata_url,'source':'same_origin_authorization_server'}
    if document.get('resource')!=endpoint:raise Rejected('protected_resource_mismatch')
    issuers=document.get('authorization_servers')
    if not isinstance(issuers,list) or not 1<=len(issuers)<=8 or len(issuers)!=len(set(str(v) for v in issuers)):
        raise Rejected('protected_resource_authorization_servers_required')
    for issuer in issuers:https_url(issuer)
    return {'resource':endpoint,'issuers':issuers,'metadata_url':metadata_url,'source':'protected_resource'}


async def discover_provider(issuer,resource,client_id=None,*,fetch=fetch_json,allow_oidc=True):
    """Check the supported public-client recipe. Actual token/callback behavior needs login."""
    p=https_url(issuer);https_url(resource)
    origin=p.scheme+'://'+p.netloc
    urls=[origin+'/.well-known/oauth-authorization-server'+p.path.rstrip('/')]
    if allow_oidc:urls.append(issuer.rstrip('/')+'/.well-known/openid-configuration')
    metadata=None;errors=[]
    for url in dict.fromkeys(urls):
        try:metadata=await fetch(url);break
        except Rejected as error:errors.append(str(error));continue
    if metadata is None and errors and all(error=='auth_discovery_unavailable' for error in errors):raise Rejected('provider_discovery_unavailable')
    if not isinstance(metadata,dict) or metadata.get('issuer')!=issuer:raise Rejected('provider_issuer_mismatch')
    if not metadata.get('jwks_uri') and 'scopes_supported' not in metadata:raise Rejected('provider_jwks_uri_and_scopes_supported_missing')
    for field in ('authorization_endpoint','token_endpoint','jwks_uri'):
        if not metadata.get(field):raise Rejected('provider_'+field+'_missing')
        same_origin(issuer,metadata[field])
    def strings(field,default=()):
        value=metadata.get(field,list(default))
        if not isinstance(value,list) or len(value)>128 or any(not isinstance(v,str) or len(v)>2048 for v in value):raise Rejected('invalid_provider_metadata')
        return value
    if 'S256' not in strings('code_challenge_methods_supported'):raise Rejected('provider_pkce_s256_required')
    if 'authorization_code' not in strings('grant_types_supported',['authorization_code']):raise Rejected('provider_authorization_code_required')
    if 'code' not in strings('response_types_supported'):raise Rejected('provider_code_response_required')
    if 'none' not in strings('token_endpoint_auth_methods_supported'):raise Rejected('provider_public_client_required')
    if 'scopes_supported' not in metadata:raise Rejected('provider_scopes_supported_missing')
    scopes=strings('scopes_supported')
    if not isinstance(scopes,list) or not {'herdr:observe','herdr:control'}<=set(scopes):raise Rejected('provider_herdr_scopes_required')
    if client_id:
        if not isinstance(client_id,str) or not 1<=len(client_id)<=2048:raise Rejected('invalid_client_id')
        registration='configured_client'
    elif metadata.get('client_id_metadata_document_supported') is True:registration='cimd'
    elif metadata.get('registration_endpoint'):
        same_origin(issuer,metadata['registration_endpoint']);registration='dcr'
    else:raise Rejected('provider_client_registration_required')
    return {'issuer':issuer,'resource':resource,'jwks_url':metadata['jwks_uri'],'registration':registration,
            'metadata_compatible':True,'token_contract':'RS256; iss/sub/client_id/exp/iat; resource audience; Herdr scopes',
            'unverified':['access_token_format_and_claims','callback_registration','account_consent'],
            'key_cache_seconds':CACHE_SECONDS,'unknown_key_refresh_seconds':REFRESH_SECONDS,
            'revocation':'Cached keys last at most 300 seconds. Account revocation is not detected by JWKS; access tokens remain valid until expiry.'}


class JWTVerifier:
    def __init__(self,issuer,resource,public_key=None,*,jwks_url=None,fetch=fetch_json,clock=time.monotonic,on_verified=None):
        https_url(issuer);https_url(resource)
        if (public_key is None)==(jwks_url is None):raise Rejected('exactly_one_auth_key_source_required')
        self.issuer,self.resource,self.public_key=issuer,resource,public_key
        self.jwks_url=same_origin(issuer,jwks_url) if jwks_url is not None else None
        if public_key is not None:
            try:key=load_pem_public_key(public_key.encode())
            except (ValueError,TypeError,AttributeError):raise Rejected('invalid_rsa_public_key') from None
            if not isinstance(key,RSAPublicKey) or not 2048<=key.key_size<=8192:raise Rejected('invalid_rsa_public_key')
        self.last_verified_at=None
        self.fetch,self.clock,self.on_verified=fetch,clock,on_verified
        self._keys={};self._expires=0.;self._attempt=float('-inf');self._lock=asyncio.Lock()

    async def _key(self,kid):
        now=self.clock()
        if now<self._expires and kid in self._keys:return self._keys[kid]
        async with self._lock:
            now=self.clock()
            if now<self._expires and kid in self._keys:return self._keys[kid]
            if now-self._attempt<REFRESH_SECONDS:return None
            self._attempt=now
            document=await self.fetch(self.jwks_url)
            rows=document.get('keys') if isinstance(document,dict) else None
            if not isinstance(rows,list) or not 1<=len(rows)<=32:raise Rejected('invalid_jwks')
            keys={};seen=set()
            for row in rows:
                if not isinstance(row,dict):raise Rejected('invalid_jwks')
                name=row.get('kid')
                if not isinstance(name,str) or not 1<=len(name)<=256 or name in seen:raise Rejected('invalid_jwks_kid')
                seen.add(name)
                if row.get('kty')!='RSA' or row.get('alg','RS256')!='RS256' or row.get('use','sig')!='sig':continue
                if 'key_ops' in row and row['key_ops']!=['verify']:continue
                if any(field in row for field in ('d','p','q','dp','dq','qi','oth')):raise Rejected('private_jwks_key')
                try:key=jwt.algorithms.RSAAlgorithm.from_jwk(row)
                except (ValueError,TypeError,KeyError,jwt.PyJWTError):raise Rejected('invalid_jwks_key') from None
                if not isinstance(key,RSAPublicKey) or not 2048<=key.key_size<=8192:raise Rejected('invalid_jwks_key_size')
                keys[name]=key
            if not keys:raise Rejected('no_supported_jwks_key')
            self._keys=keys;self._expires=self.clock()+CACHE_SECONDS
            return keys.get(kid)

    async def verify_token(self,token):
        try:
            if not isinstance(token,str) or len(token)>16384:return None
            header=jwt.get_unverified_header(token)
            if header.get('alg')!='RS256' or any(k in header for k in ('jku','x5u','jwk','crit')):return None
            key=self.public_key
            if self.jwks_url:
                kid=header.get('kid')
                if not isinstance(kid,str) or not 1<=len(kid)<=256:return None
                key=await self._key(kid)
                if key is None:return None
            c=jwt.decode(token,key,algorithms=['RS256'],issuer=self.issuer,audience=self.resource,
                         options={'require':['exp','iat','sub','iss','aud','client_id']})
            if any(not isinstance(c[field],str) or not 1<=len(c[field])<=(256 if field=='sub' else 2048) for field in ('sub','client_id')):return None
            if any(not isinstance(c[field],(int,float)) or isinstance(c[field],bool) or not math.isfinite(c[field]) for field in ('exp','iat')):return None
            if not isinstance(c.get('scope',''),str):return None
            result=AccessToken(token=token,client_id=c['client_id'],subject=c['sub'],scopes=c.get('scope','').split(),expires_at=c['exp'],resource=self.resource,claims=c)
            self.last_verified_at=datetime.now(timezone.utc).isoformat()
            if self.on_verified:await asyncio.to_thread(self.on_verified,result)
            return result
        except (jwt.PyJWTError,ValueError,TypeError,KeyError,OverflowError,Rejected):return None


def verifier_from_config(cfg,**kwargs):
    from .setup import public_key
    return JWTVerifier(cfg['issuer'],cfg['resource'],public_key(cfg['public_key']) if 'public_key' in cfg else None,
                       jwks_url=cfg.get('jwks_url'),**kwargs)
