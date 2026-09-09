import json
import threading
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from latchlane import __version__
from latchlane.network import NetworkError
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

def key_update(**updates):
    return {'origin':'https://api.example.com','header':'Authorization','prefix':'Bearer ','safe_paths':['/v1/models']}|updates

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
    assert a.patch('/api/keys/sample',json=key_update()).status_code==401
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

def test_paths_reject_normalization_bypasses_without_provider_call(setup,monkeypatch):
    import latchlane.server as broker
    app,c,a,_=setup
    calls=[]
    monkeypatch.setattr(broker,'perform',lambda *args: calls.append(args))
    for path in ['/read/../write','/read/%2e%2e/write','/read/%252e%252e/write','/read/%25252e%25252e/write','/read%2f..%2fwrite','/read%5c..%5cwrite']:
        assert req(a,path=path).status_code==422
    assert calls==[]
    assert req(a,path='/v1/a%20b?format=api.v1').json()['status']=='pending'
    for index,path in enumerate(['/read/../write','/read/%2e%2e/write','/read/%252e%252e/write']):
        response=c.post('/api/keys',json={'name':'rule-'+str(index),'value':SECRET,'origin':'https://api.example.com','safe_paths':[path]},headers=HEAD)
        assert response.status_code==422

def test_network_failure_consumes_request_once(setup,monkeypatch):
    import latchlane.server as broker
    app,c,a,_=setup
    c.post('/api/mode',json={'mode':'auto'},headers=HEAD)
    calls=[]
    def unavailable(*args):
        calls.append(args)
        raise NetworkError('Provider connection failed; automatic retry disabled.')
    monkeypatch.setattr(broker,'perform',unavailable)
    rid=req(a).json()['id']
    assert a.post('/api/requests/'+rid+'/consume').status_code==502
    assert a.post('/api/requests/'+rid+'/consume').status_code==403
    assert len(calls)==1

def test_status_uses_package_version(setup):
    _,c,_,_=setup
    assert c.get('/api/status').json()['version']==__version__

def test_pwa_assets_are_allowlisted_and_private(setup):
    _,c,_,_=setup
    for path,media_type in [
        ('/manifest.webmanifest','application/manifest+json'),
        ('/sw.js','application/javascript'),
        ('/offline.html','text/html'),
        ('/assets/icons/mark-192.png','image/png'),
        ('/assets/icons/mark-512.png','image/png'),
    ]:
        response=c.get(path)
        assert response.status_code==200
        assert response.headers['content-type'].startswith(media_type)
        assert response.headers['cache-control']=='no-store'
    assert c.get('/sw.js').headers['service-worker-allowed']=='/'
    for path in ['/assets/icons/other.png','/assets/icons/mark-192.svg','/static/manifest.webmanifest']:
        assert c.get(path).status_code==404
    assert c.get('/api/status').headers['cache-control']=='no-store'

def test_owner_session_duration_expiry_and_fresh_tokens(setup):
    import latchlane.server as broker
    app,c,_,_=setup
    before=time.time()
    original=c.cookies.get('latchlane_owner')
    day=c.post('/api/login',json={'password':PASSWORD,'session_mode':'day'},headers=HEAD)
    day_token=c.cookies.get('latchlane_owner')
    assert day.status_code==200 and day_token!=original and 'Max-Age=86400' in day.headers['set-cookie']
    details=c.get('/api/owner').json()
    assert details['session_mode']=='day' and before+86390 < details['session_expires'] <= time.time()+86400
    remembered=TestClient(app,base_url='http://127.0.0.1:9473',headers=HEAD)
    remember=remembered.post('/api/login',json={'password':PASSWORD,'session_mode':'remember'})
    assert remember.status_code==200 and 'Max-Age=2592000' in remember.headers['set-cookie']
    assert remembered.get('/api/owner').json()['session_mode']=='remember'
    app.state.sessions[broker.digest(day_token)]['expires']=time.time()-1
    assert c.get('/api/owner').status_code==401

def test_remembered_session_survives_reopen_but_not_lock_or_restart(setup):
    app,c,_,path=setup
    remembered=TestClient(app,base_url='http://127.0.0.1:9473',headers=HEAD)
    remembered.post('/api/login',json={'password':PASSWORD,'session_mode':'remember'})
    token=remembered.cookies.get('latchlane_owner')
    reopened=TestClient(app,base_url='http://127.0.0.1:9473',headers=HEAD)
    reopened.cookies.set('latchlane_owner',token)
    assert reopened.get('/api/owner').status_code==200
    fresh=create_app(path)
    after_restart=TestClient(fresh,base_url='http://127.0.0.1:9473',headers=HEAD)
    after_restart.cookies.set('latchlane_owner',token)
    assert after_restart.get('/api/owner').status_code==401
    assert after_restart.post('/api/login',json={'password':PASSWORD,'session_mode':'remember'}).status_code==200
    assert reopened.post('/api/lock').status_code==200
    assert remembered.get('/api/owner').status_code==401

def test_logout_only_revokes_current_owner_session(setup):
    import latchlane.server as broker
    app,c,_,_=setup
    other=TestClient(app,base_url='http://127.0.0.1:9473',headers=HEAD)
    other.post('/api/login',json={'password':PASSWORD,'session_mode':'remember'})
    response=c.post('/api/logout',headers=HEAD)
    assert response.status_code==200 and 'Max-Age=0' in response.headers['set-cookie']
    assert c.get('/api/owner').status_code==401
    assert other.get('/api/owner').status_code==200 and app.state.vault.data is not None
    token=other.cookies.get('latchlane_owner')
    app.state.sessions[broker.digest(token)]['expires']=time.time()-1
    assert other.post('/api/logout').status_code==200

@pytest.mark.parametrize(('endpoint','unlocked'),[('/api/logout',True),('/api/lock',False)])
def test_pruning_cannot_resurrect_sessions_after_revocation(setup,endpoint,unlocked):
    app,c,_,_=setup
    class BlockingSessions(dict):
        calls=0
        def items(self):
            self.calls+=1
            snapshot=list(super().items())
            if self.calls==1:
                pruner_started.set()
                assert release_pruner.wait(2)
            return snapshot
    token=c.cookies.get('latchlane_owner')
    pruner_started=threading.Event()
    release_pruner=threading.Event()
    revoked=threading.Event()
    app.state.sessions=BlockingSessions(app.state.sessions)
    trigger=TestClient(app,base_url='http://127.0.0.1:9473',headers=HEAD)
    owner=TestClient(app,base_url='http://127.0.0.1:9473',headers=HEAD)
    owner.cookies.set('latchlane_owner',token)
    prune_thread=threading.Thread(target=lambda:trigger.get('/api/status'))
    response={}
    def revoke():
        response['result']=owner.post(endpoint)
        revoked.set()
    revoke_thread=threading.Thread(target=revoke)
    prune_thread.start()
    assert pruner_started.wait(1)
    revoke_thread.start()
    # Before this fix, revocation completed here, then the blocked prune assigned
    # its stale snapshot and restored the token. The locked implementation waits.
    revoked.wait(1)
    assert not revoked.is_set()
    release_pruner.set()
    prune_thread.join(2)
    revoke_thread.join(2)
    assert not prune_thread.is_alive() and not revoke_thread.is_alive()
    assert response['result'].status_code==200
    assert app.state.sessions=={}
    assert (app.state.vault.data is not None)==unlocked

def test_owner_updates_key_without_returning_or_replacing_blank_value(setup):
    app,c,a,_=setup
    rid=req(a).json()['id']
    response=c.patch('/api/keys/sample',json=key_update(header='X-API-Key',prefix='',safe_paths=['/v2/models'],value=''),headers=HEAD)
    assert response.json()=={'ok':True,'name':'sample'} and SECRET not in response.text
    assert app.state.vault.data['keys']['sample']=={'value':SECRET,'origin':'https://api.example.com','header':'X-API-Key','prefix':'','safe_paths':['/v2/models']}
    assert a.post('/api/requests/'+rid+'/consume').status_code==404
    assert 'value' not in c.get('/api/owner').json()['keys'][0]
    bad=c.patch('/api/keys/sample',json=key_update(safe_paths=['/read/../write']),headers=HEAD)
    assert bad.status_code==422 and app.state.vault.data['keys']['sample']['safe_paths']==['/v2/models']

def test_failed_key_update_save_rolls_back_key_and_pending(setup,monkeypatch):
    import latchlane.vault as storage
    app,c,a,_=setup
    rid=req(a).json()['id']
    before=dict(app.state.vault.data['keys']['sample'])
    monkeypatch.setattr(storage,'atomic_write',lambda *args,**kwargs:(_ for _ in ()).throw(OSError('fixture disk full')))
    with pytest.raises(OSError):
        c.patch('/api/keys/sample',json=key_update(origin='https://updated.example.com'),headers=HEAD)
    assert app.state.vault.data['keys']['sample']==before
    assert rid in app.state.pending

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

def test_failed_mode_save_does_not_grant_access(setup,monkeypatch):
    import latchlane.vault as storage
    app,c,a,path=setup
    actual=storage.atomic_write
    monkeypatch.setattr(storage,'atomic_write',lambda *a,**k:(_ for _ in ()).throw(OSError('fixture disk full')))
    with pytest.raises(OSError):c.post('/api/mode',json={'mode':'yolo'},headers=HEAD)
    assert app.state.vault.data['mode']=='ask'
    disk=Vault(path);disk.unlock(PASSWORD);assert disk.data['mode']=='ask'
    monkeypatch.setattr(storage,'atomic_write',actual)
    assert req(a,kind='lease',path='/').json()['status']=='pending'

def test_failed_approval_save_does_not_authorize(setup,monkeypatch):
    import latchlane.vault as storage
    app,c,a,path=setup
    rid=req(a,kind='lease',path='/').json()['id']
    actual=storage.atomic_write
    monkeypatch.setattr(storage,'atomic_write',lambda *a,**k:(_ for _ in ()).throw(OSError('fixture disk full')))
    with pytest.raises(OSError):c.post('/api/requests/'+rid+'/decision',json={'approve':True},headers=HEAD)
    monkeypatch.setattr(storage,'atomic_write',actual)
    assert a.post('/api/requests/'+rid+'/consume').status_code==202

def test_failed_key_save_is_not_visible(setup,monkeypatch):
    import latchlane.vault as storage
    app,c,a,path=setup
    monkeypatch.setattr(storage,'atomic_write',lambda *a,**k:(_ for _ in ()).throw(OSError('fixture disk full')))
    with pytest.raises(OSError):c.post('/api/keys',json={'name':'unsaved','value':SECRET,'origin':'https://api.example.com'},headers=HEAD)
    assert 'unsaved' not in app.state.vault.data['keys']
