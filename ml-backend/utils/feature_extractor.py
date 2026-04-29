import re
import math
from urllib.parse import urlparse

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account',
    'update', 'confirm', 'banking', 'paypal', 'password',
    'credential', 'wallet', 'suspended', 'unusual', 'alert'
]

GAMBLING_KEYWORDS = [
    'slot', 'togel', 'poker', 'casino', 'bet', 'judi',
    'gacor', 'jackpot', 'sbobet', 'maxwin', 'scatter',
    'pragmatic', 'pgsoft', 'rtp', 'spin', 'bonus'
]

TRUSTED_BRANDS = [
    'paypal', 'google', 'facebook', 'apple', 'amazon',
    'microsoft', 'netflix', 'instagram', 'whatsapp', 'bank'
]

def get_entropy(text):
    if not text:
        return 0
    
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    entropy = 0
    for count in freq.values():
        prob = count / len(text)
        entropy -= prob * math.log2(prob)
    
    return round(entropy, 4)


def get_domain_info(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.lower()
        hostname = hostname.replace('www.', '')
        parts = hostname.split('.')
        tld = parts[-1] if len(parts) > 0 else ''
        domain = parts[-2] if len(parts) > 1 else ''
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
        
        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'query': parsed.query,
            'hostname': hostname,
            'subdomain': subdomain,
            'domain': domain,
            'tld': tld,
            'full_url': url
        }
    except Exception:
        return {k: '' for k in ['scheme','netloc','path','query',
                                 'hostname','subdomain','domain',
                                 'tld','full_url']}

def extract_features(url):
    info = get_domain_info(url)
    url_lower = url.lower()
    url_length = len(url)
    has_https = 1 if info['scheme'] == 'https' else 0
    dot_count = url.count('.')
    hyphen_count = info['domain'].count('-') + info['subdomain'].count('-')
    at_count = url.count('@')
    double_slash = url.count('//')
    digit_count = sum(1 for c in info['domain'] if c.isdigit())
    domain_length = len(info['domain'])
    path_depth = info['path'].count('/')
    has_query = 1 if info['query'] else 0
    suspicious_tld = [
        'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw',
        'top', 'click', 'link', 'online', 'site', 'club'
    ]
    has_suspicious_tld = 1 if info['tld'] in suspicious_tld else 0
    has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    has_phishing_keyword = 1 if any(kw in url_lower for kw in PHISHING_KEYWORDS) else 0
    has_gambling_keyword = 1 if any(kw in url_lower for kw in GAMBLING_KEYWORDS) else 0
    brand_in_url = any(brand in url_lower for brand in TRUSTED_BRANDS)
    brand_in_legit_domain = any(
        brand in info['domain'] and info['tld'] in ['com', 'id', 'org', 'net']
        for brand in TRUSTED_BRANDS
    )
    has_brand_spoofing = 1 if (brand_in_url and not brand_in_legit_domain) else 0
    subdomain_length = len(info['subdomain'])
    subdomain_count = info['subdomain'].count('.') + 1 if info['subdomain'] else 0
    domain_entropy = get_entropy(info['domain'])
    special_chars = len(re.findall(r'[%=&?+]', url))
    path_length = len(info['path'])

    return {
        'url_length'           : url_length,
        'has_https'            : has_https,
        'dot_count'            : dot_count,
        'hyphen_count'         : hyphen_count,
        'at_count'             : at_count,
        'double_slash'         : double_slash,
        'digit_count'          : digit_count,
        'domain_length'        : domain_length,
        'path_depth'           : path_depth,
        'has_query'            : has_query,
        'has_suspicious_tld'   : has_suspicious_tld,
        'has_ip'               : has_ip,
        'has_phishing_keyword' : has_phishing_keyword,
        'has_gambling_keyword' : has_gambling_keyword,
        'has_brand_spoofing'   : has_brand_spoofing,
        'subdomain_length'     : subdomain_length,
        'subdomain_count'      : subdomain_count,
        'domain_entropy'       : domain_entropy,
        'special_chars'        : special_chars,
        'path_length'          : path_length
    }


def extract_features_batch(urls):
    return [extract_features(url) for url in urls]