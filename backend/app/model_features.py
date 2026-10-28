"""Versioned offline features shared by training and worker inference."""
import math
import re
from urllib.parse import urlsplit
from .url_analysis import inspect_url

URL_SCHEMA_V1 = 'url-static-1'
URL_FEATURES_V1 = [
    'length', 'host_length', 'path_length', 'query_length', 'digits', 'dots', 'hyphens',
    'slashes', 'percent', 'at', 'equals', 'ampersands', 'https', 'ip', 'userinfo',
    'unicode', 'subdomains', 'entropy', 'sensitive_words', 'valid'
]

URL_SCHEMA_V2 = 'url-static-2'
URL_FEATURES_V2 = [
    'length', 'host_length', 'path_length', 'query_length', 'path_depth', 'path_to_host_ratio',
    'digit_ratio', 'host_digits', 'host_hyphens', 'host_dots', 'subdomain_levels',
    'slashes', 'hyphens', 'percent', 'at', 'equals', 'ampersands', 'https',
    'ip', 'userinfo', 'unicode', 'brand_host',
    'entropy_url', 'entropy_host', 'host_sensitive', 'path_sensitive',
    'has_phish_ext', 'valid'
]

# Keep default URL_SCHEMA pointing to v1 for existing single-version tests
URL_SCHEMA = URL_SCHEMA_V1
URL_FEATURES = URL_FEATURES_V1
URL_SCHEMAS = {
    URL_SCHEMA_V1: URL_FEATURES_V1,
    URL_SCHEMA_V2: URL_FEATURES_V2
}

def url_features_v1(url):
    detail = inspect_url(url)
    try: parsed = urlsplit(url)
    except ValueError: parsed = urlsplit('')
    host = detail['hostname'] or ''
    counts = {c: url.count(c) for c in set(url)}
    entropy = -sum(n / len(url) * math.log2(n / len(url)) for n in counts.values()) if url else 0
    signals = {o['code'] for o in detail['observations']}
    return [
        len(url), len(host), len(parsed.path), len(parsed.query),
        sum(c.isdigit() for c in url), url.count('.'), url.count('-'), url.count('/'),
        url.count('%'), url.count('@'), url.count('='), url.count('&'),
        int(parsed.scheme == 'https'), int('ip_host' in signals),
        int(detail['user_information_present']), int('unicode_host' in signals),
        len((detail['subdomain'] or '').split('.')) if detail['subdomain'] else 0,
        entropy,
        len(re.findall(r'login|verify|secure|account|password|bank|update', url.lower())),
        int(bool(host))
    ]

def url_features_v2(url):
    detail = inspect_url(url)
    try: parsed = urlsplit(url)
    except Exception: parsed = urlsplit('')
    host = detail['hostname'] or ''
    subdomain = detail['subdomain'] or ''
    path = parsed.path or ''
    query = parsed.query or ''
    
    url_len = len(url)
    host_len = len(host)
    path_len = len(path)
    query_len = len(query)
    
    path_segments = [s for s in path.split('/') if s]
    path_depth = len(path_segments)
    
    host_digits = sum(c.isdigit() for c in host)
    host_hyphens = host.count('-')
    host_dots = host.count('.')
    subdomain_levels = len(subdomain.split('.')) if subdomain else 0
    
    path_to_host_ratio = min(path_len / max(1, host_len), 20.0)
    digit_ratio = sum(c.isdigit() for c in url) / max(1, url_len)
    
    counts_url = {c: url.count(c) for c in set(url)}
    entropy_url = -sum(n / url_len * math.log2(n / url_len) for n in counts_url.values()) if url_len else 0
    
    counts_host = {c: host.count(c) for c in set(host)}
    entropy_host = -sum(n / host_len * math.log2(n / host_len) for n in counts_host.values()) if host_len else 0

    kw_regex = r'login|verify|secure|account|password|bank|update|signin|wallet|confirm'
    host_sensitive = len(re.findall(kw_regex, host.lower()))
    path_sensitive = len(re.findall(kw_regex, path.lower()))
    
    signals = {o['code'] for o in detail['observations']}
    is_ip = int('ip_host' in signals)
    is_userinfo = int(detail['user_information_present'])
    is_unicode = int('unicode_host' in signals)
    is_brand_host = int('brand_host' in signals)
    has_phish_ext = int(any(path.lower().endswith(ext) for ext in ['.php', '.cgi', '.apk', '.exe', '.bin', '.scr', '.hta']))
    
    return [
        url_len, host_len, path_len, query_len, path_depth, path_to_host_ratio,
        digit_ratio, host_digits, host_hyphens, host_dots, subdomain_levels,
        url.count('/'), url.count('-'), url.count('%'), url.count('@'),
        url.count('='), url.count('&'), int(parsed.scheme == 'https'),
        is_ip, is_userinfo, is_unicode, is_brand_host,
        entropy_url, entropy_host, host_sensitive, path_sensitive,
        has_phish_ext, int(bool(host))
    ]

def url_features(url, schema='url-static-1'):
    if schema == 'url-static-2':
        return url_features_v2(url)
    return url_features_v1(url)
