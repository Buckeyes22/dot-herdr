"""Public HTTPS callbacks with DNS validation pinned to actual TLS connection."""
import asyncio
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import time
from urllib.parse import urlsplit
from .core import Rejected, encode

MAX_BODY=262144

def decode_secret(secret):
    try:
        if not isinstance(secret,str) or not secret.startswith('whsec_'):raise ValueError
        key=base64.b64decode(secret[6:],validate=True)
        if not 24<=len(key)<=64:raise ValueError
        return key
    except (ValueError,TypeError):raise Rejected('invalid_signing_secret') from None

def headers(secret,event_id,body,sub,now=None,previous_secret=None):
    timestamp=str(int(time.time() if now is None else now))
    value=event_id.encode()+b'.'+timestamp.encode()+b'.'+body
    sig=base64.b64encode(hmac.new(decode_secret(secret),value,hashlib.sha256).digest()).decode()
    if previous_secret:
        sig += ' v1,'+base64.b64encode(hmac.new(decode_secret(previous_secret),value,hashlib.sha256).digest()).decode()
    return {'Content-Type':'application/json','webhook-id':event_id,'webhook-timestamp':timestamp,
            'webhook-signature':'v1,'+sig,'X-MCP-Subscription-Id':sub}

def destination(url,resolve=socket.getaddrinfo):
    if not isinstance(url,str) or len(url)>2048:raise Rejected('invalid_callback')
    try:
        p=urlsplit(url)
        if p.scheme!='https' or not p.hostname or p.username or p.password or p.fragment or p.port not in (None,443):raise ValueError
        if any(ord(c)<33 for c in url):raise ValueError
        addresses=resolve(p.hostname,443,type=socket.SOCK_STREAM)
        if not addresses:raise ValueError
        ips=[]
        for record in addresses:
            ip=ipaddress.ip_address(record[4][0])
            if not ip.is_global:raise ValueError
            if str(ip) not in ips:ips.append(str(ip))
        return p,ips
    except ValueError:raise Rejected('callback_policy_rejected') from None
    except OSError:raise CallbackError('connection_refused') from None

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,ip):
        super().__init__(host,443,timeout=10,context=ssl.create_default_context())
        self.validated_ip=ip
    def connect(self):
        # No second hostname lookup, ambient proxy, tunnel or redirect.
        self.sock=socket.create_connection((self.validated_ip,443),self.timeout)
        self.sock=self._context.wrap_socket(self.sock,server_hostname=self.host)

class PublicTransport:
    async def post(self,url,body,request_headers):
        if len(body)>MAX_BODY:raise Rejected('payload_too_large')
        return await asyncio.to_thread(self._post,url,body,request_headers)
    def _post(self,url,body,request_headers):
        p,ips=destination(url)
        client=PinnedHTTPS(p.hostname,ips[0])
        try:
            client.request('POST',(p.path or '/')+('?' +p.query if p.query else ''),body=body,headers=request_headers)
            response=client.getresponse(); payload=response.read(4097)
            if len(payload)>4096:raise Rejected('callback_response_too_large')
            return response.status,payload
        finally:client.close()

class CallbackError(Rejected):
    def __init__(self,reason):
        super().__init__('callback_verification_failed');self.reason=reason

async def verify(transport,url,secret,sub,clock=time.time):
    decode_secret(secret)
    challenge=secrets.token_urlsafe(32);mid='verification_'+secrets.token_hex(16)
    body=encode({'type':'verification','challenge':challenge}).encode()
    try:
        status,result=await asyncio.wait_for(transport.post(url,body,headers(secret,mid,body,sub,clock())),10)
    except TimeoutError:raise CallbackError('timeout') from None
    except ssl.SSLError:raise CallbackError('tls_error') from None
    except CallbackError:raise
    except Rejected:raise
    except OSError:raise CallbackError('connection_refused') from None
    except Exception:raise CallbackError('connection_refused') from None
    if not 200<=status<300:raise CallbackError('http_5xx' if status>=500 else ('http_4xx' if status>=400 else 'challenge_failed'))
    try:
        echo=json.loads(result).get('challenge','')
        if not isinstance(echo,str) or not hmac.compare_digest(echo,challenge):raise ValueError
    except (ValueError,TypeError,AttributeError):raise CallbackError('challenge_failed') from None

async def deliver_one(store,transport):
    item=store.claim()
    if not item:return False
    if not store.active(item):store.delivered(item,410);return True
    body=item['body'].encode()
    try:
        previous=item['previous_secret'] if item['rotation_until'] and item['rotation_until']>store.clock() else None
        status,_=await asyncio.wait_for(transport.post(item['url'],body,headers(item['secret'],item['event'],body,item['sub'],store.clock(),previous)),10)
    except Rejected:
        status=413  # terminal policy/schema failure, never an endless retry
    except Exception:status=503  # safe categorized failure, no URLs/error bodies logged
    store.delivered(item,status)
    return True
