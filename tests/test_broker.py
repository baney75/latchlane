import json
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from latchlane.server import create_app
from latchlane.vault import Vault, VaultError

PASSWORD='test-only-passphrase-keep-out-of-production'
SECRET='fixture-not-a-real-credential'
HEAD={'X-Latchlane':'1'}

@pytest.fixture
def setup(tmp_path):
    app=create_app(tmp_path,port=9473,bootstrap='test-setup-token')
    c=TestClient(app,base_url='http://127.0.0.1:9473')
    r=c.post('/api/init',json={'password':PASSWORD},headers=HEAD|{'X-Setup-Token':'test-setup-token'})
    assert r.status_code==200
    assert c.post('/api/keys',json={'name':'sample','value':SECRET,'origin':'https://api.example.com','safe_paths':['/v1/models']},headers=HEAD).status_code==200
    code=c.post('/api/invite',headers=HEAD).json()['code']
    pair=c.post('/api/pair',json={'code':code,'name':'Fixture agent'},headers=HEAD)
    a=TestClient(app,base_url='http://127.0.0.1:9473',headers=HEAD|{'Authorization':'Bearer '+pair.json()['token']})
    return app,c,a,tmp_path

def req(a,**kwargs):
    return a.post('/api/requests',json={'key':'sample','path':'/v1/models','purpose':'Fixture test'}|kwargs)

def test_encryption_and_default_ask(setup):
    app,c,a,path=setup
    assert c.get('/api/owner').json()['mode']=='ask'
    raw=(path/'store.vault').read_bytes()
    assert SECRET.encode() not in raw and PASSWORD.encode() not in raw
    v=Vault(path);v.unlock(PASSWORD)
    assert v.data['keys']['sample']['value']==SECRET
    with pytest.raises(VaultError): Vault(path).unlock('wrong')
    envelope=json.loads(raw);envelope['sealed']=envelope['sealed'][:-5]+'AAAAA'
    (path/'store.vault').write_text(json.dumps(envelope))
    with pytest.raises(VaultError): Vault(path).unlock(PASSWORD)

def test_agents_cannot_admin(setup):
    app,c,a,_=setup
    for path,body in [('/api/mode',{'mode':'yolo'}),('/api/keys',{'name':'bad','value':SECRET,'origin':'https://api.example.com'}),('/api/invite',None),('/api/lock',None)]:
        assert a.post(path,json=body).status_code==401
    assert a.get('/api/owner').status_code==401
    assert a.post('/api/local-session',headers={'X-Setup-Token':'guess'}).status_code==403

def test_approval_single_use_and_identity(setup):
    app,c,a,_=setup
    rid=req(a,kind='lease',path='/').json()['id']
    assert a.post('/api/requests/'+rid+'/consume').status_code==202
    assert a.post('/api/requests/'+rid+'/decision',json={'approve':True}).status_code==401
    assert c.post('/api/requests/'+rid+'/decision',json={'approve':True},headers=HEAD).status_code==200
    assert a.post('/api/requests/'+rid+'/consume').json()['value']==SECRET
    assert a.post('/api/requests/'+rid+'/consume').status_code==403

def test_auto_conservative(setup):
    app,c,a,_=setup
    c.post('/api/mode',json={'mode':'auto'},headers=HEAD)
    assert req(a).json()['status']=='approved'
    for kwargs in [{'method':'POST'},{'path':'/v1/models?delete=1'},{'path':'/other'},{'body':'{}'},{'kind':'lease','path':'/'}]:
        assert req(a,**kwargs).json()['status']=='pending'
    assert req(a,path='//other.example/x').status_code==422
    assert req(a,path='/x\r\nInjected:yes').status_code==422

def test_yolo_and_revocation(setup):
    app,c,a,_=setup
    c.post('/api/mode',json={'mode':'yolo'},headers=HEAD)
    rid=req(a,kind='lease',path='/').json()['id']
    assert a.post('/api/requests/'+rid+'/consume').json()['value']==SECRET
    ident=c.get('/api/owner').json()['clients'][0]['id']
    c.delete('/api/clients/'+ident,headers=HEAD)
    assert a.get('/api/keys').status_code==401

def test_expiry_denial_policy_change_lock(setup):
    app,c,a,_=setup
    rid=req(a).json()['id'];app.state.pending[rid]['expires']=time.time()-1
    assert a.post('/api/requests/'+rid+'/consume').status_code==410
    assert c.post('/api/requests/'+rid+'/decision',json={'approve':True},headers=HEAD).status_code==409
    rid=req(a).json()['id'];c.post('/api/requests/'+rid+'/decision',json={'approve':False},headers=HEAD)
    assert a.post('/api/requests/'+rid+'/consume').status_code==403
    rid=req(a).json()['id'];c.post('/api/mode',json={'mode':'yolo'},headers=HEAD)
    assert a.post('/api/requests/'+rid+'/consume').status_code==404
    c.post('/api/lock',headers=HEAD)
    assert a.get('/api/keys').status_code==423
    assert c.get('/api/owner').status_code==401

def test_no_echo_csrf_host_and_limits(setup):
    app,c,a,_=setup
    r=c.post('/api/keys',json={'name':SECRET,'value':SECRET,'origin':42},headers=HEAD)
    assert r.status_code==422 and SECRET not in r.text
    assert c.post('/api/mode',json={'mode':'yolo'}).status_code==403
    assert c.post('/api/mode',json={'mode':'yolo'},headers=HEAD|{'Origin':'https://evil.example'}).status_code==403
    assert c.get('/api/status',headers={'Host':'evil.example'}).status_code==403
    assert c.post('/api/login',content=b'x'*100001,headers=HEAD).status_code==413
    assert 'no-store' in c.get('/').headers['cache-control']
    for _ in range(5): c.post('/api/login',json={'password':'wrong'},headers=HEAD)
    assert c.post('/api/login',json={'password':PASSWORD},headers=HEAD).status_code==429

def test_pair_code_one_use_and_request_ownership(setup):
    app,c,a,_=setup
    code=c.post('/api/invite',headers=HEAD).json()['code']
    pair=c.post('/api/pair',json={'code':code,'name':'Another'},headers=HEAD)
    assert pair.status_code==200
    assert c.post('/api/pair',json={'code':code,'name':'Again'},headers=HEAD).status_code==403
    b=TestClient(app,base_url='http://127.0.0.1:9473',headers=HEAD|{'Authorization':'Bearer '+pair.json()['token']})
    rid=req(a).json()['id']
    assert b.post('/api/requests/'+rid+'/consume').status_code==404

def test_add_rejects_header_injection_and_duplicate(setup):
    app,c,a,_=setup
    for updates in [{'name':'sample'},{'value':'key\r\nInjected:yes'},{'origin':'http://api.example.com'},{'header':'Host'},{'safe_paths':['/x?a=b']}]:
        r=c.post('/api/keys',json={'name':'new','value':SECRET,'origin':'https://api.example.com'}|updates,headers=HEAD)
        assert r.status_code in (409,422)

def test_restart_retains_mode_and_client(setup):
    app,c,a,path=setup
    c.post('/api/mode',json={'mode':'auto'},headers=HEAD)
    fresh=create_app(path)
    b=TestClient(fresh,base_url='http://127.0.0.1:9473')
    assert b.post('/api/login',json={'password':PASSWORD},headers=HEAD).status_code==200
    assert b.get('/api/owner').json()['mode']=='auto'
    assert b.get('/api/owner').json()['clients'][0]['name']=='Fixture agent'

def test_explicit_initial_mode(tmp_path):
    app=create_app(tmp_path,bootstrap='fixture',initial_mode='yolo')
    c=TestClient(app,base_url='http://127.0.0.1:9473')
    assert c.get('/api/status').json()['initial_mode']=='yolo'
    assert c.post('/api/init',json={'password':PASSWORD},headers=HEAD|{'X-Setup-Token':'fixture'}).status_code==200
    assert c.get('/api/owner').json()['mode']=='yolo'
