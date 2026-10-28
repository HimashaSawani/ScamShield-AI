"""Offline URL syntax/PSL inspection. Never resolves DNS or fetches input URLs."""
import hashlib
import ipaddress
from importlib import resources
import re
from urllib.parse import urlsplit, unquote
import idna
import tldextract

EXTRACT=tldextract.TLDExtract(suffix_list_urls=(),cache_dir=None,include_psl_private_domains=True)
PSL={'library':'tldextract','version':tldextract.__version__,'mode':'Bundled PSL snapshot; offline; private suffixes included','snapshot_sha256':hashlib.sha256(resources.files('tldextract').joinpath('.tld_set_snapshot').read_bytes()).hexdigest()}

def inspect_url(url):
    details={'url':url,'hostname':None,'unicode_hostname':None,'registrable_domain':None,'public_suffix':None,'subdomain':None,'user_information':None,'user_information_present':False,'psl':PSL,'observations':[],
             'checks':{'completed':[],'failed':[],'unavailable':['Live destination/reputation checks','DNS resolution and sender identity']}}
    def observe(code,description,weight):
        details['observations'].append({'code':code,'description':description,'weight':weight})
    try:
        if '\\' in url or any(c.isspace() or ord(c)<32 for c in url):
            raise ValueError('Ambiguous or invalid URL characters')
        parsed=urlsplit(url)
        host=(parsed.hostname or '').rstrip('.').lower()
        if parsed.scheme not in ['http','https'] or not host:
            raise ValueError('HTTP/HTTPS URL required')
        parsed.port
        try:
            ip=ipaddress.ip_address(host)
        except ValueError:
            ip=None
            host=idna.encode(host,uts46=True,std3_rules=True).decode('ascii').lower()
        if ip is not None:
            host=str(ip)
            observe('ip_host','URL uses an IP address instead of a named host',20)
            details['registrable_domain_note']='IP hosts do not have a registrable domain.'
        else:
            extracted=EXTRACT(host)
            if extracted.suffix:
                details.update(registrable_domain=extracted.top_domain_under_public_suffix or None,public_suffix=extracted.suffix,subdomain=extracted.subdomain or None,is_private_suffix=extracted.is_private)
                details['checks']['completed'].append('PSL domain boundary')
                if not details['registrable_domain']:
                    details['registrable_domain_note']='The hostname is a public suffix, not a registrable domain.'
            else:
                details['registrable_domain_note']='No recognized public suffix in the bundled PSL; no registrable-domain guess is made (including .invalid/.test and local names).'
            details['unicode_hostname']=idna.decode(host)
        details['hostname']=host
        details['checks']['completed']+=['URL parsing','Static URL structure']
        if not details['registrable_domain']:
            details['checks']['unavailable'].append('Registrable domain: '+details.get('registrable_domain_note','unavailable'))
        if parsed.username is not None or parsed.password is not None:
            details['user_information_present']=True
            details['user_information']=unquote(parsed.username or '')+(': [password redacted]' if parsed.password is not None else '')
            details['user_information_note']=f'Text before @ is user information. The destination hostname is {host}. This syntax alone does not establish fraud.'
            observe('url_credentials','URL has user information before @; it is not the destination hostname. This syntax alone does not establish fraud.',30)
        if host.count('.')>=4:
            observe('subdomains','Hostname has many subdomain levels; inspect the actual domain boundary',15)
        if 'xn--' in host or any(ord(c)>127 for c in parsed.hostname):
            observe('unicode_host','Internationalized hostname needs independent visual verification',15)
        if '%' in url:
            observe('encoded_url','URL contains encoded characters',10)
        if parsed.scheme=='http':
            observe('unencrypted','URL uses unencrypted HTTP',10)
        if any(word in host for word in ['bank','paypal','microsoft','apple']) and any(word in host for word in ['verify','secure','login','reward']):
            observe('brand_host','Brand and account-action words in hostname require independent verification',20)
    except (ValueError,UnicodeError,idna.IDNAError):
        details['hostname']=None
        details['checks']['failed'].append('URL parsing')
        observe('invalid_url','URL could not be parsed unambiguously; no safety conclusion is available',0)
    return details
