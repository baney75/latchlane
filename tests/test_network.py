import socket
import pytest
from latchlane import network
from latchlane.network import validate_origin, NetworkError

@pytest.mark.parametrize('value',['http://example.com','https://user:pass@example.com','https://example.com/path','https://example.com:444','https://example.com?x=1','https://example.com/#x'])
def test_invalid_origins(value):
    with pytest.raises(ValueError): validate_origin(value)

@pytest.mark.parametrize('ip',['127.0.0.1','10.0.0.1','169.254.169.254','::1','100.64.0.1'])
def test_ssrf_denied(monkeypatch,ip):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',(ip,443))])
    with pytest.raises(NetworkError): network.perform({'origin':'https://example.com'},{})

def test_dns_failure_is_sanitized_without_connection_attempt(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:(_ for _ in ()).throw(socket.gaierror('fixture DNS failure')))
    monkeypatch.setattr(network,'PinnedHTTPS',lambda *a,**k:pytest.fail('connection should not be initialized after DNS failure'))
    with pytest.raises(NetworkError,match='Provider connection failed; automatic retry disabled.'):
        network.perform({'origin':'https://example.com'}, {})

def test_dns_pinned_redirect_blocked_and_echo_redacted(monkeypatch):
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',('93.184.216.34',443))])
    seen={}
    class Response:
        status=200
        def read(self,n):return b'echo fixture-key'
    class Connection:
        def __init__(self,host,address):seen.update(host=host,address=address)
        def request(self,*a,**k):seen.update(request=k)
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(network,'PinnedHTTPS',Connection)
    k={'origin':'https://example.com','header':'Authorization','prefix':'Bearer ','value':'fixture-key'}
    result=network.perform(k,{'method':'GET','path':'/'})
    assert seen['address']=='93.184.216.34' and seen['host']=='example.com'
    assert result['body']=='echo [credential redacted]'
    Response.status=302
    with pytest.raises(NetworkError):network.perform(k,{'method':'GET','path':'/'})
