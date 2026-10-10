"""Bounded Herdr protocol22 requests and invalidation stream; no write retries."""
import asyncio
import json
import re
from .core import Rejected,encode
from .actions import READ_METHODS,WRITE_METHODS
MAX_FRAME=262144
MAX_EVENT_SAMPLE=131072

def error_code(response):
    error=response.get('error')
    code=error.get('code') if isinstance(error,dict) else None
    return code if isinstance(code,str) and re.fullmatch('[a-z_]{1,64}',code) else 'source_error'

class HerdrClient:
    def __init__(self,socket_path,timeout=10):
        self.socket_path,self.timeout=socket_path,timeout
    async def _open(self):
        async with asyncio.timeout(self.timeout):
            return await asyncio.open_unix_connection(self.socket_path,limit=MAX_FRAME+1)
    async def _line(self,reader,timeout=None):
        try:
            async with asyncio.timeout(timeout or self.timeout):
                line=await reader.readline()
            if not line or len(line)>MAX_FRAME:raise ValueError
            value=json.loads(line)
            if not isinstance(value,dict):raise ValueError
            return value
        except (ValueError,TimeoutError):raise Rejected('malformed_source') from None
    async def request(self,method,params):
        if method not in READ_METHODS+WRITE_METHODS:raise Rejected('unsupported_method')
        if len(encode(params).encode())>32768:raise Rejected('source_params_too_large')
        reader,writer=await self._open()
        try:
            writer.write((encode({'id':'read','method':method,'params':params})+'\n').encode())
            async with asyncio.timeout(self.timeout):await writer.drain()
            response=await self._line(reader,40)
            if response.get('id')=='read' and 'error' in response:
                raise Rejected(error_code(response))
            if response.get('id')!='read' or 'result' not in response:raise Rejected('source_error')
            if not isinstance(response['result'],dict):raise Rejected('malformed_source')
            return response['result']
        finally:writer.close();await writer.wait_closed()

    async def collect_events(self,subscriptions,timeout_ms,limit):
        """Own a short-lived subscription socket; never silently restart a gap."""
        if type(timeout_ms)!=int or not 1<=timeout_ms<=30000 or type(limit)!=int or not 1<=limit<=100 or not isinstance(subscriptions,list) or not 1<=len(subscriptions)<=32:raise Rejected('invalid_event_collection')
        params={'subscriptions':subscriptions}
        if len(encode(params).encode())>32768:raise Rejected('source_params_too_large')
        reader,writer=await self._open()
        events=[];size=0;reason=None;ended='deadline'
        deadline=asyncio.get_running_loop().time()+timeout_ms/1000
        try:
            writer.write((encode({'id':'native-watch','method':'events.subscribe','params':params})+'\n').encode())
            async with asyncio.timeout(timeout_ms/1000):
                await writer.drain()
                response=await self._line(reader)
                if response.get('id')!='native-watch':raise Rejected('malformed_source')
                if 'error' in response:raise Rejected(error_code(response))
                result=response.get('result')
                if not isinstance(result,dict) or result.get('type')!='subscription_started':raise Rejected('source_error')
            while len(events)<limit:
                remaining=deadline-asyncio.get_running_loop().time()
                if remaining<=0:break
                try:
                    async with asyncio.timeout(remaining):line=await reader.readline()
                except TimeoutError:break
                if not line:
                    ended='disconnected';break
                if len(line)>MAX_FRAME:raise Rejected('malformed_source')
                value=json.loads(line)
                if not isinstance(value,dict):raise Rejected('malformed_source')
                if 'error' in value:
                    ended='source_error';reason=error_code(value);break
                if not isinstance(value.get('event'),str) or not isinstance(value.get('data'),dict):raise Rejected('malformed_source')
                event_size=len(encode(value).encode())
                if size+event_size>MAX_EVENT_SAMPLE:
                    ended='byte_limit';break
                events.append(value);size+=event_size
            else:ended='event_limit'
        except TimeoutError:ended='deadline'
        except (ValueError,Rejected) as error:
            ended='source_error';reason=str(error) if isinstance(error,Rejected) else 'malformed_source'
        except OSError:
            ended='disconnected';reason='source_unavailable'
        finally:
            writer.close()
            try:await writer.wait_closed()
            except OSError:pass
        return {'events':events,'end_reason':ended,**({'reason':reason} if reason else {}),
                'history':'best_effort','durable':False,'resume_supported':False}
    async def agent(self,pane):
        return (await self.request('agent.get',{'target':pane}))['agent']
    async def visible(self,pane,lines):
        if not 1<=lines<=80:raise Rejected('invalid_lines')
        result=await self.request('agent.read',{'target':pane,'source':'visible','lines':lines,'format':'text','strip_ansi':True})
        # Source handler uses result.read; do not proxy unknown response dictionaries.
        read=result['read'];text=read.get('text','')
        if not isinstance(text,str):raise Rejected('malformed_source')
        text=re.sub(r'\x1b\][^\x07]*(?:\x07|\x1b\\)','',text)
        text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',text)
        text=''.join(c for c in text if c in '\n\t' or ord(c)>=32)
        if re.search(r'(?i)(password|api[_ -]?key|secret|bearer\s|private key)',text):raise Rejected('content_withheld')
        original_bytes=len(text.encode());raw=text.encode()[:16384];text=raw.decode(errors='ignore')
        return {'text':text,'revision':read['revision'],'source':'visible','truncated':bool(read.get('truncated') or len(raw)<original_bytes)}
    async def invalidations(self,panes):
        reader,writer=await self._open()
        try:
            subscriptions=[{'type':'pane.agent_status_changed','pane_id':p} for p in panes]
            subscriptions += [{'type':k} for k in ('pane.moved','pane.closed','pane.exited','pane.agent_detected')]
            writer.write((encode({'id':'watch','method':'events.subscribe','params':{'subscriptions':subscriptions}})+'\n').encode());await writer.drain()
            response=await self._line(reader)
            if response.get('id')!='watch' or response.get('result',{}).get('type')!='subscription_started':raise Rejected('source_error')
            # Timeout reconnects/reconciles rather than treating a quiet stream as healthy forever.
            while True:
                line=await reader.readline()
                if not line or len(line)>MAX_FRAME:raise Rejected('malformed_source')
                event=json.loads(line)
                if 'error' in event:raise Rejected('source_error')
                yield event
        finally:writer.close();await writer.wait_closed()

async def refresh(store,source,key,origin='reconciliation'):
    row=store.db.execute('SELECT pane FROM subjects WHERE key=?',(key,)).fetchone()
    try:store.observe(key,await source.agent(row['pane']),origin)
    except Exception as exc:store.gap(key,str(exc) if isinstance(exc,Rejected) else 'source_error')

def prepare_observation_session(store):
    # A process restart has no upstream replay watermark. Fence persisted observations
    # before the first source read rather than synthesizing missed attention/turn episodes.
    for row in store.db.execute('SELECT key FROM subjects WHERE enabled=1 AND observed IS NOT NULL').fetchall():
        store.gap(row['key'],'disconnected')

async def watch(store,source):
    prepare_observation_session(store)
    while True:
        subjects=store.db.execute('SELECT key,pane FROM subjects WHERE enabled=1').fetchall()
        if not subjects:
            await asyncio.sleep(30)
            continue
        dirty=asyncio.Event()
        async def drain():
            async for event in source.invalidations([r['pane'] for r in subjects]):
                # Invalidation only. Continuously drain while separate reads happen.
                dirty.set()
        producer=asyncio.create_task(drain())
        try:
            dirty.set()
            while True:
                waiter=asyncio.create_task(dirty.wait())
                done,_=await asyncio.wait({producer,waiter},timeout=30,return_when=asyncio.FIRST_COMPLETED)
                if producer in done:
                    waiter.cancel()
                    await producer
                    raise Rejected('disconnected')
                waiter.cancel()
                dirty.clear()
                for row in subjects:await refresh(store,source,row['key'],'reconciliation')
        except Exception:
            for row in subjects:store.gap(row['key'],'disconnected')
            await asyncio.sleep(2)
        finally:
            producer.cancel()
            try:await producer
            except (asyncio.CancelledError,Exception):pass
