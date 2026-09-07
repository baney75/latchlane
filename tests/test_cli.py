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
