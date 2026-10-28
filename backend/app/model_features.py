"""Versioned offline features shared by training and worker inference."""
import math
import re
from urllib.parse import urlsplit
from .url_analysis import inspect_url

URL_SCHEMA='url-static-1'
URL_FEATURES=['length','host_length','path_length','query_length','digits','dots','hyphens','slashes','percent','at','equals','ampersands','https','ip','userinfo','unicode','subdomains','entropy','sensitive_words','valid']

def url_features(url):
    detail=inspect_url(url)
    try: parsed=urlsplit(url)
    except ValueError: parsed=urlsplit('')
    host=detail['hostname'] or ''
    counts={c:url.count(c) for c in set(url)}
    entropy=-sum(n/len(url)*math.log2(n/len(url)) for n in counts.values()) if url else 0
    signals={o['code'] for o in detail['observations']}
    return [len(url),len(host),len(parsed.path),len(parsed.query),sum(c.isdigit() for c in url),url.count('.'),url.count('-'),url.count('/'),url.count('%'),url.count('@'),url.count('='),url.count('&'),int(parsed.scheme=='https'),int('ip_host' in signals),int(detail['user_information_present']),int('unicode_host' in signals),len((detail['subdomain'] or '').split('.')) if detail['subdomain'] else 0,entropy,len(re.findall(r'login|verify|secure|account|password|bank|update',url.lower())),int(bool(host))]
