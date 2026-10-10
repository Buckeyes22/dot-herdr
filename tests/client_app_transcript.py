"""Synthetic resumed registered-plugin setup for the chosen ChatGPT client."""
import asyncio
import socket
import sys
import time
import tempfile
from pathlib import Path
from unittest.mock import patch
import dot_herdr.cli
from dot_herdr.connections import connection_record,save_connection
from dot_herdr.onboarding import draft_path,guided_setup,save_config
from dot_herdr.status import status,render

async def main():
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);root.chmod(0o700)
        config=root/'config.json';source_socket=root/'source.sock'
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(source_socket))
        issuer='https://mcp.example.test';resource=issuer+'/mcp'
        principal='81e0359a4569f267fff045b6597afe76b1661721677599de2ffa470639099e01'
        control=not (len(sys.argv)>2 and sys.argv[2]=='observe-only')
        cfg={'store':str(root/'store.sqlite'),'socket':str(source_socket),'issuer':issuer,
             'resource':resource,'jwks_url':issuer+'/.well-known/jwks.json',
             'subjects':[] if control else [{'key':'agent','user_subject':'replace-with-approved-issuer-subject','owner':'local','pane':'pane','terminal':'terminal','native':None,'content':False,'control':False}],
             'session_users':['replace-with-approved-issuer-subject'] if control else []}
        save_config(draft_path(config),cfg)
        record=connection_record(config);record.update(route='https',wiring='registered-plugin',stage='identity',endpoint=resource,
            client_app=sys.argv[1] if len(sys.argv)>1 else 'chatgpt-web')
        save_connection(config,record)
        class Source:
            async def request(self,method,params):return {'version':'0.9.3','protocol':22}
            async def agent(self,pane):return {'pane_id':pane,'terminal_id':'terminal','agent_session':None}
        class Pairing:
            def __init__(self,actual_issuer,ttl):self.deadline=10**20;self.clock=lambda:0
            def candidates(self):return [{'subject':'user','principal':principal,'client_id':'approved','expires_at':time.time()+120,'scopes':['herdr:observe']}]
            def observe(self,token):raise AssertionError('No real token in synthetic run')
            def confirm(self,selected):
                assert selected==principal
                return {'issuer':issuer,'subject':'user','principal':principal,'client_id':'approved','scopes':['herdr:observe'],'expires_at':time.time()+120}
            def close(self):pass
        class HTTP:
            def __init__(self,config):self.started=False;self.should_exit=False
            async def serve(self):
                self.started=True
                while not self.should_exit:await asyncio.sleep(.01)
        class Verifier:
            async def verify_token(self,token):return None
        def ask(prompt):
            answer='y' if prompt.startswith(('Approve account ','Keep the connector','Start at user login')) else None
            if answer is None:raise AssertionError('Unexpected prompt: '+prompt)
            print(prompt+answer);return answer
        def runtime(*_):return {'state':'running','pid':42,'runtime_prefix':str(Path(sys.prefix).resolve()),'workers':{'observer':'running','delivery':'running'}}
        try:
            with patch('dot_herdr.auth.discover_provider',return_value={'jwks_url':cfg['jwks_url']}),\
                 patch('dot_herdr.status.port_in_use',return_value=False),\
                 patch('dot_herdr.auth.verifier_from_config',return_value=Verifier()),\
                 patch('dot_herdr.endpoint.PairingSession',Pairing),\
                 patch('dot_herdr.endpoint.build_pairing'),\
                 patch('uvicorn.Server',HTTP),\
                 patch('dot_herdr.service.install'),patch('dot_herdr.service.manage'),\
                 patch('dot_herdr.service.service_status',return_value={'state':'active','pid':42}),\
                 patch('dot_herdr.status.runtime_observation',side_effect=runtime),\
                 patch('dot_herdr.connection_check.status',return_value={'mode':'live_read_only','observations':{}}),\
                 patch('pathlib.Path.home',return_value=root):
                result=await guided_setup(config,ask=ask,say=print,client_factory=lambda _:Source())
                print('STATUS EXCERPT')
                report=await status(config)
                print('\n'.join(line for line in render(report).splitlines() if 'account access:' in line or 'Chosen app:' in line))
            assert result['phase']==('control_scope' if control else 'test_target') and result['status']=='pending'
            assert not (root/'.codex').exists() and not (root/'.agents').exists()
        finally:listener.close()

if __name__=='__main__':asyncio.run(main())
