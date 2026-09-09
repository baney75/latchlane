import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import httpx
import pytest
from latchlane.vault import Vault, atomic_write
from latchlane.cli import broker_url

@pytest.mark.parametrize('url',['https://example.com','http://100.64.0.1:9473','https://user@node.ts.net','https://node.ts.net/path','http://127.0.0.1:9473/#token'])
def test_reject_arbitrary_broker(url):
    with pytest.raises(ValueError):broker_url(url)

def test_cli_and_mcp(tmp_path):
    host=tmp_path/'host';agent=tmp_path/'agent';agent.mkdir(mode=0o700)
    v=Vault(host);v.initialize('fixture-cli-passphrase');v.data['mode']='yolo'
    v.data['keys']['fixture']={'value':'only-a-fixture-value','origin':'https://api.example.com','header':'Authorization','prefix':'Bearer ','safe_paths':[]}
    token='only-a-test-agent-token';v.data['clients'][hashlib.sha256(token.encode()).hexdigest()]={'name':'Test agent'};v.save()
    atomic_write(host/'unattended.key',b'fixture-cli-passphrase')
    atomic_write(agent/'agent.local.json',json.dumps({'url':'http://127.0.0.1:19474','token':token}).encode())
    env=os.environ.copy();env['LATCHLANE_HOME']=str(host)
    prefix=[sys.executable,'-c','from latchlane.cli import main;main()']
    proc=subprocess.Popen(prefix+['start','--port','19474','--no-open'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                if httpx.get('http://127.0.0.1:19474/api/status',trust_env=False).status_code==200:break
            except httpx.HTTPError:pass
            time.sleep(.1)
        env['LATCHLANE_HOME']=str(agent)
        r=subprocess.run(prefix+['keys'],env=env,capture_output=True,text=True,timeout=15)
        assert r.returncode==0 and 'fixture' in r.stdout and 'only-a-fixture-value' not in r.stdout
        r=subprocess.run(prefix+['doctor','--url','http://127.0.0.1:19474'],env=env,capture_output=True,text=True,timeout=15)
        readiness=json.loads(r.stdout)
        assert r.returncode==0 and readiness['broker_state']=='ready' and readiness['agent_pairing_valid'] is True
        assert 'only-a-fixture-value' not in r.stdout and token not in r.stdout
        r=subprocess.run(prefix+['run','--purpose','Verify fixture injection','fixture','TEST_KEY','--',sys.executable,'-c','import os; assert os.environ["TEST_KEY"] == "only-a-fixture-value"; print("child passed")'],env=env,capture_output=True,text=True,timeout=15)
        assert r.returncode==0 and r.stdout.strip()=='child passed',r.stderr
        msgs=[{'jsonrpc':'2.0','id':1,'method':'initialize'},{'jsonrpc':'2.0','id':2,'method':'tools/list'},{'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'latchlane_keys','arguments':{}}}]
        r=subprocess.run(prefix+['mcp'],input=''.join(json.dumps(m)+'\n' for m in msgs),env=env,capture_output=True,text=True,timeout=15)
        replies=[json.loads(s) for s in r.stdout.splitlines()]
        assert len(replies)==3 and len(replies[1]['result']['tools'])==3
        assert 'only-a-fixture-value' not in r.stdout and token not in r.stdout
        # Even a lease created outside MCP cannot be printed through its consume tool.
        with httpx.Client(headers={'Authorization':'Bearer '+token,'X-Latchlane':'1'},trust_env=False) as c:
            rid=c.post('http://127.0.0.1:19474/api/requests',json={'key':'fixture','kind':'lease','purpose':'Test raw boundary'}).json()['id']
        msg={'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'latchlane_consume','arguments':{'id':rid}}}
        r=subprocess.run(prefix+['mcp'],input=json.dumps(msg)+'\n',env=env,capture_output=True,text=True,timeout=15)
        assert 'error' in json.loads(r.stdout) and 'only-a-fixture-value' not in r.stdout
    finally:
        proc.terminate();proc.wait(timeout=10)

@pytest.mark.parametrize('status',[200,423,503])
def test_pair_preserves_existing_credential(tmp_path, monkeypatch, status):
    from argparse import Namespace
    from latchlane import cli
    monkeypatch.setenv('LATCHLANE_HOME',str(tmp_path))
    path=tmp_path/'agent.local.json'
    original=json.dumps({'url':'http://127.0.0.1:19474','token':'fixture-old-token'}).encode()
    atomic_write(path,original)
    class Probe:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def get(self,*args,**kwargs):return httpx.Response(status)
    monkeypatch.setattr(cli.httpx,'Client',Probe)
    monkeypatch.setattr(cli.getpass,'getpass',lambda *args:pytest.fail('Must preserve existing pairing without prompting'))
    with pytest.raises(ValueError):cli.pair(Namespace(url='http://127.0.0.1:19474',name='Fixture'))
    assert path.read_bytes()==original

@pytest.mark.parametrize('replacement_status',[200,403])
def test_pair_replaces_revoked_only_after_success(tmp_path, monkeypatch, replacement_status):
    from argparse import Namespace
    from latchlane import cli
    monkeypatch.setenv('LATCHLANE_HOME',str(tmp_path))
    path=tmp_path/'agent.local.json'
    original=json.dumps({'url':'http://127.0.0.1:19474','token':'fixture-old-token'}).encode()
    atomic_write(path,original)
    class Probe:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def get(self,*args,**kwargs):return httpx.Response(401)
        def post(self,*args,**kwargs):return httpx.Response(replacement_status,json={'token':'fixture-new-token'})
    monkeypatch.setattr(cli.httpx,'Client',Probe)
    monkeypatch.setattr(cli.getpass,'getpass',lambda *args:'fixture-pair-code')
    if replacement_status==200:
        cli.pair(Namespace(url='http://127.0.0.1:19474',name='Fixture'))
        assert json.loads(path.read_bytes())['token']=='fixture-new-token'
    else:
        with pytest.raises(ValueError):cli.pair(Namespace(url='http://127.0.0.1:19474',name='Fixture'))
        assert path.read_bytes()==original


def test_doctor_defaults_to_local_host_and_reports_unavailable_pairing(tmp_path, monkeypatch, capsys):
    from argparse import Namespace
    from latchlane import cli
    agent=tmp_path/'agent';agent.mkdir()
    atomic_write(agent/'agent.local.json',json.dumps({'url':'http://127.0.0.1:19474','token':'fixture-token'}).encode())
    monkeypatch.setenv('LATCHLANE_HOME',str(agent))
    monkeypatch.setattr(cli,'tailscale_bin',lambda:None)
    monkeypatch.setattr(cli,'tail_status',lambda:{})
    seen=[]
    class Probe:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def get(self,url,**kwargs):
            seen.append(url)
            if url.endswith('/api/status'):
                return httpx.Response(200,json={'initialized':True,'locked':False,'version':'fixture'})
            return httpx.Response(423)
    monkeypatch.setattr(cli.httpx,'Client',Probe)
    cli.doctor(Namespace(url=None))
    readiness=json.loads(capsys.readouterr().out)
    assert seen==['http://127.0.0.1:19474/api/status','http://127.0.0.1:19474/api/keys']
    assert readiness['agent_pairing_valid'] is None
    assert readiness['agent_pairing_state']=='unavailable_vault_locked'

    empty=tmp_path/'empty';empty.mkdir()
    monkeypatch.setenv('LATCHLANE_HOME',str(empty))
    seen.clear()
    cli.doctor(Namespace(url=None))
    assert seen==['http://127.0.0.1:9473/api/status']


def test_post_timeout_warns_that_broker_outcome_is_uncertain(monkeypatch):
    from latchlane import cli
    class TimeoutClient:
        def __init__(self,**kwargs):pass
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def request(self,*args,**kwargs):
            raise httpx.ReadTimeout('fixture timeout',request=httpx.Request('POST','http://127.0.0.1'))
    client=object.__new__(cli.Client);client.url='http://127.0.0.1:19474';client.token='fixture-token'
    monkeypatch.setattr(cli.httpx,'Client',TimeoutClient)
    with pytest.raises(ValueError,match='may have reached.*provider state before retrying'):
        client.call('POST','/api/requests/fixture/consume')


def test_owner_accepts_explicit_custom_port(monkeypatch):
    from latchlane import cli
    opened=[]
    monkeypatch.setattr(cli.webbrowser,'open',opened.append)
    monkeypatch.setattr(sys,'argv',['latchlane','owner','--url','http://127.0.0.1:19474'])
    cli.main()
    assert opened==['http://127.0.0.1:19474/']


def test_capture_forwards_optional_auth_metadata_without_secret(monkeypatch, capsys):
    from latchlane import cli, desktop
    captured=[]
    monkeypatch.setattr(desktop, 'app', lambda args, capture: captured.append(capture))
    monkeypatch.setattr(sys, 'argv', ['latchlane', 'capture', 'fixture', '--origin', 'https://api.example.com', '--header', 'X-API-Key', '--prefix', 'none'])
    cli.main()
    assert captured == [('fixture', 'https://api.example.com', 'X-API-Key', '')]
    assert 'fixture' not in capsys.readouterr().out
