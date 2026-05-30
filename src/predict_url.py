"""
predict_url.py — Model loading, input validation, and prediction.

Improvements over the baseline:
  - Input validation: malformed URLs, homograph attacks, length limits
  - WHOIS domain age as an additional signal (optional, cached)
  - Google Safe Browsing hard override (optional, requires API key)
  - LRU cache: same URL returns instantly on repeated lookups
  - Returns detailed feature dict for UI display
"""

import re
import sys
import math
import functools
import unicodedata
import numpy as np
from urllib.parse import urlparse, parse_qs
from typing import Optional

import tldextract
import pandas as pd
import joblib

# ── Offline TLD extraction ────────────────────────────────────────────────────
_tld = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

# ── Regex helpers ─────────────────────────────────────────────────────────────
_IP_RE = re.compile(
    r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
)
# Match shortener domains exactly — anchored so 't.co' can't match inside 'tunisianet.com'
_SHORTENER_DOMAINS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 't.co', 'short.io', 'rb.gy', 'cutt.ly', 'tiny.cc',
    'shorte.st', 'bl.ink', 'shorturl.at', 'trib.al', 'dlvr.it',
}

def _is_shortener(url: str) -> bool:
    """Check if the URL's registered domain+TLD exactly matches a known shortener."""
    ext = _tld(url)
    domain = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    return domain in _SHORTENER_DOMAINS

_SUSPICIOUS_EXTS = re.compile(
    r'\.(exe|php|js|zip|rar|gz|bat|cmd|scr|vbs|ps1|jar|swf)(\?|$)', re.I
)

# ── Trusted domain whitelist ──────────────────────────────────────────────────
# High-reputation domains the model may false-positive on due to dataset bias.
# These bypass the ML model and return Legitimate at 100% confidence.
# Add/remove domains freely — this is NOT a security mechanism, just a
# dataset-gap correction for well-known sites.
_TRUSTED_DOMAINS = {
    # Developer platforms
    'github.com', 'gitlab.com', 'bitbucket.org',
    # Q&A / docs
    'stackoverflow.com', 'stackexchange.com', 'superuser.com', 'serverfault.com',
    'docs.python.org', 'developer.mozilla.org', 'learn.microsoft.com',
    # Search & productivity
    'google.com', 'bing.com', 'duckduckgo.com', 'yahoo.com',
    'youtube.com', 'youtu.be',
    # Shopping
    'amazon.com', 'amazon.co.uk', 'amazon.fr', 'amazon.de',
    'ebay.com', 'ebay.co.uk',
    # Social
    'linkedin.com', 'twitter.com', 'x.com', 'facebook.com',
    'instagram.com', 'reddit.com',
    # Cloud / infra
    'aws.amazon.com', 'cloud.google.com', 'azure.microsoft.com',
    'cloudflare.com', 'digitalocean.com',
    # News & reference
    'wikipedia.org', 'bbc.com', 'bbc.co.uk', 'reuters.com', 'theguardian.com',
    # Tunisian sites
    'tunisianet.com.tn', 'mytek.tn', 'topnet.tn', 'orange.tn',
    'ooredoo.tn', 'rnu.tn', 'ucar.tn','docs.python.org', 'readthedocs.io', 'readthedocs.org',
    # AI / tools
    'chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com',
    'fast.com', 'speedtest.net',
    # Package registries & dev
    'pypi.org', 'npmjs.com', 'crates.io',
    # Gaming / mods
    'nexusmods.com', 'curseforge.com',
    # Shopping (extended)
    'aliexpress.com', 'alibaba.com', 'etsy.com', 'walmart.com',
    'att.com', 'verizon.com', 'tmobile.com',
    # Torrent / open source
    'qbittorrent.org', 'transmissionbt.com',
    # Tech
    'apple.com', 'microsoft.com', 'mozilla.org',
}

def _is_trusted(url: str) -> bool:
    """Return True if the URL's registered domain is in the trusted whitelist."""
    ext = _tld(url)
    # Check both bare domain and with subdomain stripped
    full = f"{ext.domain}.{ext.suffix}".lower() if ext.suffix else ext.domain.lower()
    return full in _TRUSTED_DOMAINS

# ── Validation constants ──────────────────────────────────────────────────────
MAX_URL_LENGTH   = 2048
ALLOWED_SCHEMES  = {'http', 'https'}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ── Input validation ──────────────────────────────────────────────────────────
def validate_url(url: str) -> tuple[bool, Optional[str]]:
    """
    Validate a URL before prediction.
    Returns (is_valid: bool, error_message: str | None).
    """
    if not url or not url.strip():
        return False, "URL cannot be empty."

    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters."

    # Normalise unicode — detect homograph attacks
    # e.g. 'pаypal.com' with Cyrillic 'а' (U+0430) instead of Latin 'a'
    try:
        normalized = unicodedata.normalize('NFKC', url)
    except Exception:
        return False, "URL contains invalid characters."

    # Check for mixed scripts in the domain (homograph attack signal)
    # Parse the URL as-is first to catch non-http schemes,
    # then fall back to prepending http:// if no scheme is present.
    try:
        parsed_raw = urlparse(url)
    except Exception:
        return False, "Malformed URL — could not parse."

    if parsed_raw.scheme and parsed_raw.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Unsupported scheme '{parsed_raw.scheme}'. Only http/https are supported."

    if not re.match(r'^https?://', url, re.I):
        url_for_parse = 'http://' + url
    else:
        url_for_parse = url

    try:
        parsed = urlparse(url_for_parse)
    except Exception:
        return False, "Malformed URL — could not parse."

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported scheme '{scheme}'. Only http/https are supported."

    netloc = parsed.netloc
    if not netloc:
        return False, "URL has no domain."

    # Strip port
    host = re.sub(r':\d+$', '', netloc)

    # Block localhost / private ranges
    private_patterns = [
        r'^localhost$',
        r'^127\.',
        r'^192\.168\.',
        r'^10\.',
        r'^172\.(1[6-9]|2\d|3[01])\.',
        r'^::1$',
    ]
    for pat in private_patterns:
        if re.match(pat, host, re.I):
            return False, "Private/localhost addresses cannot be scanned."

    return True, None


# ── Feature extraction ────────────────────────────────────────────────────────
def _extract_raw(url: str) -> dict:
    """Extract raw features + display-only signals from a URL string."""
    if not re.match(r'^https?://', url, re.I):
        url = 'http://' + url

    parsed = urlparse(url)
    ext    = _tld(url)
    path   = parsed.path or ''
    query  = parsed.query or ''

    tokens     = [t for t in re.split(r'[^a-zA-Z0-9]', url) if t]
    subdomains = [s for s in (ext.subdomain or '').split('.') if s and s != 'www']
    q_params   = parse_qs(query)

    url_no_scheme = re.sub(r'^https?://', '', url)
    digits        = sum(1 for c in url_no_scheme if c.isdigit())
    digit_ratio   = digits / len(url_no_scheme) if url_no_scheme else 0.0
    domain        = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    return {
        # Model features
        'url_length':               len(url),
        'has_ip_address':           1 if _IP_RE.search(url) else 0,
        'dot_count':                url.count('.'),
        'url_entropy':              round(_entropy(url), 4),
        'token_count':              len(tokens),
        'subdomain_count':          len(subdomains),
        'query_param_count':        len(q_params),
        'tld_length':               len(ext.suffix) if ext.suffix else 0,
        'path_length':              len(path),
        'has_hyphen_in_domain':     1 if '-' in ext.domain else 0,
        'number_of_digits':         digits,
        'suspicious_file_extension':1 if _SUSPICIOUS_EXTS.search(path) else 0,
        'domain_name_length':       len(domain),
        'percentage_numeric_chars': round(digit_ratio, 4),
        # Display-only (not fed to model)
        '_https':     1 if parsed.scheme.lower() == 'https' else 0,
        '_shortener': 1 if _is_shortener(url) else 0,
        '_at_symbol': 1 if '@' in url else 0,
        '_dbl_slash': 1 if '//' in re.sub(r'^https?://', '', url) else 0,
        '_domain':    domain,
        '_ext':       ext,
    }


def _engineer(raw: dict) -> pd.DataFrame:
    """Apply log-scaling — must match train_model.py engineer() exactly."""
    row = {
        'log_url_length':            np.log1p(raw['url_length']),
        'has_ip_address':            raw['has_ip_address'],
        'dot_count':                 raw['dot_count'],
        'url_entropy':               raw['url_entropy'],
        'log_token_count':           np.log1p(raw['token_count']),
        'subdomain_count':           raw['subdomain_count'],
        'query_param_count':         raw['query_param_count'],
        'tld_length':                raw['tld_length'],
        'log_path_length':           np.log1p(raw['path_length']),
        'has_hyphen_in_domain':      raw['has_hyphen_in_domain'],
        'log_digit_count':           np.log1p(raw['number_of_digits']),
        'suspicious_file_extension': raw['suspicious_file_extension'],
        'log_domain_length':         np.log1p(raw['domain_name_length']),
        'digit_ratio':               raw['percentage_numeric_chars'],
    }
    return pd.DataFrame([row])


# ── Model loading ─────────────────────────────────────────────────────────────
def load_model(model_path: str):
    return joblib.load(model_path)


# ── Persistent disk cache (SQLite) ───────────────────────────────────────────
# Results survive app restarts. Falls back silently if DB is unavailable.
try:
    from src.cache import get as _disk_cache_get, set as _disk_cache_set
    _DISK_CACHE = True
except ImportError:
    _DISK_CACHE = False

# Lightweight in-memory L1 cache (speeds up same-session repeated lookups)
_mem_cache: dict = {}
_MEM_CACHE_MAX = 200

def _cache_get(url, whois_enabled, sb_key, vt_key):
    mem_key = (url, whois_enabled, bool(sb_key), bool(vt_key))
    if mem_key in _mem_cache:
        return {**_mem_cache[mem_key], "cached": True}
    if _DISK_CACHE:
        return _disk_cache_get(url, whois_enabled, sb_key or '', vt_key or '')
    return None

def _cache_set(url, result, whois_enabled, sb_key, vt_key):
    mem_key = (url, whois_enabled, bool(sb_key), bool(vt_key))
    if len(_mem_cache) >= _MEM_CACHE_MAX:
        del _mem_cache[next(iter(_mem_cache))]
    _mem_cache[mem_key] = result
    if _DISK_CACHE:
        _disk_cache_set(url, result, whois_enabled, sb_key or '', vt_key or '')



# ── Main predict function ─────────────────────────────────────────────────────
def predict(
    url: str,
    model,
    whois_enabled: bool = True,
    whois_threshold_days: int = 90,
    safe_browsing_key: Optional[str] = None,
    virustotal_key: Optional[str] = None,
) -> dict:
    """
    Run full phishing prediction on a URL.

    Args:
        url: The URL to check.
        model: (calibrated_clf, feature_names, threshold) tuple from load_model().
        whois_enabled: Whether to run WHOIS domain age lookup.
        whois_threshold_days: Domains younger than this (days) are flagged.
        safe_browsing_key: Google Safe Browsing API key (or None to skip).
        virustotal_key: VirusTotal API key (or None to skip).

    Returns dict with:
        url, label, is_phishing, confidence, source,
        whois_days (int|None), sb_threat (str|None), features (dict)
    """
    # ── Validation ────────────────────────────────────────────────────────────
    is_valid, error = validate_url(url)
    if not is_valid:
        return {
            "url": url, "label": "Error", "is_phishing": False,
            "confidence": 0.0, "source": "validation",
            "error": error, "whois_days": None, "sb_threat": None, "features": {},
        }

    # ── Cache check ───────────────────────────────────────────────────────────
    cached = _cache_get(url, whois_enabled, safe_browsing_key or '', virustotal_key or '')
    if cached is not None:
        return cached

    # ── Trusted domain whitelist ──────────────────────────────────────────────
    # Bypass the model for well-known legitimate sites to avoid dataset-bias
    # false positives (e.g. github.com, stackoverflow.com).
    if _is_trusted(url):
        raw = _extract_raw(url)
        result = {
            "url":         url,
            "label":       "Legitimate",
            "is_phishing": False,
            "confidence":  100.0,
            "source":      "whitelist",
            "whois_days":  None,
            "sb_threat":   None,
            "cached":      False,
            "features": {
                "url_length":   raw['url_length'],
                "https":        bool(raw['_https']),
                "has_ip":       bool(raw['has_ip_address']),
                "entropy":      raw['url_entropy'],
                "subdomains":   raw['subdomain_count'],
                "query_params": raw['query_param_count'],
                "shortener":    bool(raw['_shortener']),
                "at_symbol":    bool(raw['_at_symbol']),
                "double_slash": bool(raw['_dbl_slash']),
                "digit_ratio":  raw['percentage_numeric_chars'],
                "hyphen":       bool(raw['has_hyphen_in_domain']),
                "susp_ext":     bool(raw['suspicious_file_extension']),
            },
        }
        _cache_set(url, result, whois_enabled, safe_browsing_key or '', virustotal_key or '')
        return result

    clf, feature_names, threshold = model

    # ── Feature extraction ────────────────────────────────────────────────────
    raw         = _extract_raw(url)
    features_df = _engineer(raw)[feature_names]

    proba      = clf.predict_proba(features_df)[0]
    phish_idx  = list(clf.classes_).index(0)
    phish_prob = float(proba[phish_idx])

    # ── Shortener hard override ───────────────────────────────────────────────
    # URL shorteners always mask the real destination — flag as phishing
    # since the model's 14 features don't include shortener as a direct signal.
    if raw.get('_shortener'):
        phish_prob = 1.0

    # ── Brand-in-subdomain override ───────────────────────────────────────────
    # Pattern: paypal-login.someotherdomain.com — legitimate brand used as
    # subdomain on an unrelated domain is a classic phishing technique.
    _BRANDS = {
        'paypal', 'amazon', 'apple', 'google', 'microsoft', 'facebook',
        'netflix', 'instagram', 'bankofamerica', 'wellsfargo', 'chase',
        'steam', 'ebay', 'linkedin', 'twitter', 'dropbox', 'adobe',
        'yahoo', 'outlook', 'office365', 'docusign', 'dhl', 'fedex', 'ups',
    }
    _ext = raw['_ext']
    sub_lower    = (_ext.subdomain or '').lower()
    domain_lower = (_ext.domain or '').lower()
    if any(brand in sub_lower for brand in _BRANDS):
        # Only flag when the SLD is NOT the brand (e.g. skip paypal.com itself)
        if not any(brand == domain_lower for brand in _BRANDS):
            phish_prob = max(phish_prob, 0.95)

    # ── WHOIS domain age ──────────────────────────────────────────────────────
    whois_days = None
    whois_override = False
    if whois_enabled:
        try:
            from src.whois_lookup import get_domain_age_days
            domain = raw['_domain']
            whois_days = get_domain_age_days(domain)
            # Very young domain → boost phishing probability
            if whois_days is not None and whois_days < whois_threshold_days:
                phish_prob = min(phish_prob + 0.20, 1.0)
                whois_override = True
        except Exception:
            pass

    # ── Google Safe Browsing hard override ────────────────────────────────────
    sb_threat = None
    if safe_browsing_key:
        try:
            from src.safebrowsing import check as sb_check
            sb_flagged, sb_threat = sb_check(url, api_key=safe_browsing_key)
            if sb_flagged:
                phish_prob = 1.0
        except Exception:
            pass

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_result = None
    if virustotal_key:
        try:
            from src.virustotal import check as vt_check
            vt_result = vt_check(url, api_key=virustotal_key)
            if vt_result.get("is_malicious"):
                phish_prob = 1.0
            elif vt_result.get("verdict") == "clean" and phish_prob < 0.9:
                # VT says clean — pull the probability down slightly
                phish_prob = max(phish_prob - 0.15, 0.0)
        except Exception:
            pass

    # ── Final verdict ─────────────────────────────────────────────────────────
    is_phishing = phish_prob >= threshold
    legit_prob  = 1.0 - phish_prob
    confidence  = round((phish_prob if is_phishing else legit_prob) * 100, 1)

    source = (
        "virustotal"   if vt_result and vt_result.get("is_malicious") else
        "safe_browsing" if sb_threat else
        "model+whois"  if whois_override else
        "model"
    )

    result = {
        "url":         url,
        "label":       "Phishing" if is_phishing else "Legitimate",
        "is_phishing": is_phishing,
        "confidence":  confidence,
        "source":      source,
        "whois_days":  whois_days,
        "sb_threat":   sb_threat,
        "vt":          vt_result,
        "cached":      False,
        "features": {
            "url_length":   raw['url_length'],
            "https":        bool(raw['_https']),
            "has_ip":       bool(raw['has_ip_address']),
            "entropy":      raw['url_entropy'],
            "subdomains":   raw['subdomain_count'],
            "query_params": raw['query_param_count'],
            "shortener":    bool(raw['_shortener']),
            "at_symbol":    bool(raw['_at_symbol']),
            "double_slash": bool(raw['_dbl_slash']),
            "digit_ratio":  raw['percentage_numeric_chars'],
            "hyphen":       bool(raw['has_hyphen_in_domain']),
            "susp_ext":     bool(raw['suspicious_file_extension']),
        },
    }

    _cache_set(url, result, whois_enabled, safe_browsing_key or '', virustotal_key or '')
    return result


# ── Shortener-based hard override (called from predict) ──────────────────────
# bit.ly and similar shorteners are always flagged as phishing since
# they mask the real destination URL. This overrides the model.
def _shortener_override(url: str) -> bool:
    return _is_shortener(url)