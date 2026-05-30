"""
extract_features.py — Pure URL-based feature extractor.
17 features aligned with LegitPhish (2025) schema.
Zero network calls — works fully offline.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
import tldextract
import pandas as pd

# Use bundled PSL snapshot — no network required
_tld = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

URL_FEATURES = [
    'url_length',
    'has_ip_address',
    'dot_count',
    'https_flag',
    'url_entropy',
    'token_count',
    'subdomain_count',
    'query_param_count',
    'special_char_count',
    'digit_ratio',
    'hyphen_count',
    'at_symbol',
    'double_slash',
    'path_length',
    'domain_length',
    'tld_length',
    'shortening_service',
]

_SHORTENER_DOMAINS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 't.co', 'short.io', 'rb.gy', 'cutt.ly', 'tiny.cc',
    'shorte.st', 'bl.ink', 'shorturl.at', 'trib.al', 'dlvr.it',
}

def _is_shortener(url: str) -> bool:
    ext = _tld(url)
    domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    return domain in _SHORTENER_DOMAINS

_IP_RE = re.compile(
    r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def extract_features(url: str) -> pd.DataFrame:
    """Extract feature vector from a URL. Returns a single-row DataFrame."""
    if not re.match(r'^https?://', url, re.I):
        url = 'http://' + url

    parsed = urlparse(url)
    ext    = _tld(url)
    path   = parsed.path or ''
    query  = parsed.query or ''

    # Tokens: split on non-alphanumeric
    tokens = [t for t in re.split(r'[^a-zA-Z0-9]', url) if t]

    # Subdomains (exclude 'www')
    subdomains = [s for s in (ext.subdomain or '').split('.') if s and s != 'www']

    # Query params
    query_params = parse_qs(query)

    # Special characters (beyond standard URL chars)
    special = re.findall(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', url)

    # Digit ratio (excluding scheme)
    url_no_scheme = re.sub(r'^https?://', '', url)
    digit_ratio   = (
        sum(1 for c in url_no_scheme if c.isdigit()) / len(url_no_scheme)
        if url_no_scheme else 0.0
    )

    domain    = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    path_after_proto = re.sub(r'^https?://', '', url.lower())

    features = {
        'url_length':         len(url),
        'has_ip_address':     1 if _IP_RE.search(url) else 0,
        'dot_count':          url.count('.'),
        'https_flag':         1 if parsed.scheme.lower() == 'https' else 0,
        'url_entropy':        round(_entropy(url), 4),
        'token_count':        len(tokens),
        'subdomain_count':    len(subdomains),
        'query_param_count':  len(query_params),
        'special_char_count': len(special),
        'digit_ratio':        round(digit_ratio, 4),
        'hyphen_count':       url.count('-'),
        'at_symbol':          1 if '@' in url else 0,
        'double_slash':       1 if '//' in path_after_proto else 0,
        'path_length':        len(path),
        'domain_length':      len(domain),
        'tld_length':         len(ext.suffix) if ext.suffix else 0,
        'shortening_service': 1 if _is_shortener(url) else 0,
    }

    return pd.DataFrame([features], columns=URL_FEATURES)
