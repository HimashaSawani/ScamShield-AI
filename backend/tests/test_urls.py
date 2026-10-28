import pytest
from backend.app.url_analysis import inspect_url, PSL
from backend.app.detection import analyze

@pytest.mark.parametrize('url,host,domain,subdomain',[
    ('https://secure.example.co.uk/login','secure.example.co.uk','example.co.uk','secure'),
    ('https://bank.invalid@account-check.invalid/login','account-check.invalid',None,None),
    ('https://bank.com.account-check.com/path','bank.com.account-check.com','account-check.com','bank.com'),
    ('https://alice.github.io/path','alice.github.io','alice.github.io',None),
    ('https://EXAMPLE.COM.:443/path','example.com','example.com',None),
    ('http://127.0.0.1/path','127.0.0.1',None,None),
    ('https://[::1]/','::1',None,None),
    ('https://bücher.de/','xn--bcher-kva.de','xn--bcher-kva.de',None),
])
def test_psl_and_destination_boundaries(url,host,domain,subdomain):
    result=inspect_url(url)
    assert (result['hostname'],result['registrable_domain'],result['subdomain'])==(host,domain,subdomain)
    assert result['checks']['failed']==[]
    assert result['checks']['unavailable']

def test_user_information_is_not_proof_of_fraud_or_destination():
    result=inspect_url('https://bank.invalid:secret@account-check.invalid/login')
    assert result['hostname']=='account-check.invalid'
    assert result['user_information']=='bank.invalid: [password redacted]'
    assert 'does not establish fraud' in result['user_information_note']
    assert result['registrable_domain'] is None
    assert result['psl']['snapshot_sha256']==PSL['snapshot_sha256']

@pytest.mark.parametrize('url',['https://','file:///a','https://bad host.com','https://good.com\\@bad.com','https://example.com:bad/','https://%65xample.com/'])
def test_failed_parsing_never_means_safe(url):
    details=inspect_url(url)
    assert details['hostname'] is None
    assert details['checks']['failed']==['URL parsing']
    assert details['checks']['unavailable']

def test_offline_snapshot_without_network(monkeypatch):
    import requests
    def forbidden(*args,**kwargs):raise AssertionError('No network is permitted')
    monkeypatch.setattr(requests.sessions.Session,'send',forbidden)
    assert inspect_url('https://test.example.com/path')['registrable_domain']=='example.com'

def test_static_https_no_flags_is_inconclusive_and_coverage_explicit():
    result=analyze('https://example.com/path','url')
    assert result['assessment']=='Inconclusive'
    assert result['url_details'][0]['hostname']=='example.com'
    assert result['coverage']['failed']==[]
    assert 'Live URL reputation and destination checks' in result['coverage']['unavailable']
