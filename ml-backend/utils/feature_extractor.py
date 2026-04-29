import re
import math
from urllib.parse import urlparse, parse_qs

# Keyword Lists
# Kata kunci yang sering muncul di URL phishing
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account',
    'update', 'confirm', 'banking', 'paypal', 'password',
    'credential', 'wallet', 'suspended', 'unusual', 'alert',
    'validate', 'authenticate', 'recover', 'reset', 'unlock',
    'webscr', 'cmd=', 'dispatch=', 'checkout',
]

# Kata kunci yang sering muncul di URL judol
GAMBLING_KEYWORDS = [
    'slot', 'togel', 'poker', 'casino', 'bet', 'judi',
    'gacor', 'jackpot', 'sbobet', 'maxwin', 'scatter',
    'pragmatic', 'pgsoft', 'rtp', 'spin', 'bonus',
    'zeus', 'olympus', 'bonanza', 'mahjong', 'starlight',
    'domino', 'bandarq', 'ceme', 'capsa', 'parlay',
]

# Brand besar yang sering dipalsukan oleh phisher
TRUSTED_BRANDS = [
    'paypal', 'google', 'facebook', 'apple', 'amazon',
    'microsoft', 'netflix', 'instagram', 'whatsapp', 'bank',
    'bca', 'mandiri', 'bni', 'bri', 'tokopedia', 'shopee',
    'gojek', 'grab', 'ovo', 'dana',
]

# TLD yang jarang dipakai situs resmi, sering dipakai phisher
SUSPICIOUS_TLDS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw',
    'top', 'click', 'link', 'online', 'site', 'club',
    'bid', 'loan', 'win', 'download', 'racing',
    'stream', 'gdn', 'men', 'accountant',
}

# TLD yang umum dipakai situs resmi
LEGITIMATE_TLDS = {
    'com', 'id', 'org', 'net', 'edu', 'gov',
    'co.id', 'go.id', 'ac.id', 'sch.id',
}


# Fungsi Utilitas

def get_entropy(text):
    if not text:
        return 0.0

    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    for count in freq.values():
        prob     = count / len(text)
        entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def get_consonant_ratio(text):
    if not text:
        return 0.0

    text_lower = text.lower()
    huruf      = [c for c in text_lower if c.isalpha()]

    if not huruf:
        return 0.0

    vokal     = set('aeiou')
    konsonan  = [c for c in huruf if c not in vokal]

    return round(len(konsonan) / len(huruf), 4)


def get_domain_info(url):
    try:
        parsed   = urlparse(url)
        hostname = parsed.netloc.lower()

        if ':' in hostname:
            hostname = hostname.split(':')[0]

        hostname = hostname.replace('www.', '')
        parts    = hostname.split('.')

        tld       = parts[-1] if len(parts) > 0 else ''
        domain    = parts[-2] if len(parts) > 1 else ''
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

        return {
            'scheme'   : parsed.scheme,
            'netloc'   : parsed.netloc,
            'path'     : parsed.path,
            'query'    : parsed.query,
            'fragment' : parsed.fragment,
            'port'     : parsed.port,
            'hostname' : hostname,
            'subdomain': subdomain,
            'domain'   : domain,
            'tld'      : tld,
            'full_url' : url,
        }
    except Exception:
        return {k: '' for k in [
            'scheme', 'netloc', 'path', 'query', 'fragment',
            'port', 'hostname', 'subdomain', 'domain', 'tld', 'full_url'
        ]}


# Fungsi Utama

def extract_features(url):
    info      = get_domain_info(url)
    url_lower = url.lower()

    # Fitur Dasar URL
    url_length = len(url)
    has_https = 1 if info['scheme'] == 'https' else 0
    dot_count = url.count('.')
    hyphen_count = info['domain'].count('-') + info['subdomain'].count('-')
    at_count = url.count('@')
    url_tanpa_scheme = re.sub(r'^https?://', '', url)
    double_slash     = url_tanpa_scheme.count('//')
    digit_count = sum(1 for c in info['domain'] if c.isdigit())
    domain_length = len(info['domain'])
    path_depth = info['path'].count('/')
    has_query = 1 if info['query'] else 0
    has_suspicious_tld = 1 if info['tld'] in SUSPICIOUS_TLDS else 0
    has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0

    # Fitur Keyword
    has_phishing_keyword = 1 if any(kw in url_lower for kw in PHISHING_KEYWORDS) else 0
    has_gambling_keyword = 1 if any(kw in url_lower for kw in GAMBLING_KEYWORDS) else 0
    brand_di_url           = any(brand in url_lower for brand in TRUSTED_BRANDS)
    brand_di_domain_legit  = any(
        brand in info['domain'] and info['tld'] in LEGITIMATE_TLDS
        for brand in TRUSTED_BRANDS
    )
    has_brand_spoofing = 1 if (brand_di_url and not brand_di_domain_legit) else 0

    # Fitur Subdomain

    subdomain_length = len(info['subdomain'])
    if info['subdomain']:
        subdomain_count = info['subdomain'].count('.') + 1
    else:
        subdomain_count = 0

    # Fitur Statistik
    domain_entropy = get_entropy(info['domain'])
    special_chars = len(re.findall(r'[%=&?+]', url))
    path_length = len(info['path'])
    total_digit   = sum(1 for c in url if c.isdigit())
    digit_ratio_url = round(total_digit / url_length, 4) if url_length > 0 else 0.0
    has_port = 1 if info['port'] and info['port'] not in (80, 443) else 0
    redirect_patterns = ['redirect', 'redir', 'url=http', 'next=http',
                         'goto=', 'return=', 'returnto=', 'continue=']
    has_redirect = 1 if any(p in url_lower for p in redirect_patterns) else 0
    consonant_ratio = get_consonant_ratio(info['domain'])
    query_length = len(info['query'])
    try:
        query_params = len(parse_qs(info['query']))
    except Exception:
        query_params = 0
    has_fragment = 1 if info['fragment'] else 0

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
        'path_length'          : path_length,
        'digit_ratio_url'      : digit_ratio_url,
        'has_port'             : has_port,
        'has_redirect'         : has_redirect,
        'consonant_ratio'      : consonant_ratio,
        'query_length'         : query_length,
        'query_params'         : query_params,
        'has_fragment'         : has_fragment,
    }


def extract_features_batch(urls):
    return [extract_features(url) for url in urls]