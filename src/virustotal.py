"""
virustotal.py — VirusTotal API v3 integration.

Free tier: 500 requests/day, 4 requests/minute.
Aggregates results from 70+ antivirus engines.

Setup:
  1. Register at https://www.virustotal.com/gui/join-us
  2. Get your API key from https://www.virustotal.com/gui/my-apikey
  3. Add it to config.py:  VIRUSTOTAL_API_KEY = "your_key_here"

Result:
  - is_malicious: bool  — True if 3+ engines flagged it
  - malicious_count: int — how many engines flagged it
  - suspicious_count: int — how many engines marked suspicious
  - total_engines: int — total engines that scanned
  - verdict: str — "malicious" | "suspicious" | "clean" | "unrated" | "error"
  - engines: list[str] — names of engines that flagged it (up to 5)
"""

import hashlib
import base64
import functools
import time
from typing import Optional

import requests

# ── Constants ─────────────────────────────────────────────────────────────────
_BASE = "https://www.virustotal.com/api/v3"
_MALICIOUS_THRESHOLD  = 3   # flag if this many engines say malicious
_SUSPICIOUS_THRESHOLD = 5   # flag if this many engines say suspicious

# Simple in-memory rate limiter: VT free tier = 4 req/min
_last_request_time = 0.0
_MIN_INTERVAL = 15.1  # seconds between requests (4/min = 1 per 15s)

# Result cache — keyed by URL
_cache: dict = {}
_CACHE_MAX = 500


def _url_id(url: str) -> str:
    """VirusTotal URL identifier: base64url-encoded URL (no padding)."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _rate_limit():
    """Block until we're allowed to make the next request."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_request_time = time.time()


def _cache_set(key: str, value: dict):
    global _cache
    if len(_cache) >= _CACHE_MAX:
        oldest = next(iter(_cache))
        del _cache[oldest]
    _cache[key] = value


def check(url: str, api_key: Optional[str] = None) -> dict:
    """
    Check a URL against VirusTotal.

    Returns a dict with:
        is_malicious, malicious_count, suspicious_count,
        total_engines, verdict, engines, cached, error (if any)
    """
    _empty = {
        "is_malicious":    False,
        "malicious_count": 0,
        "suspicious_count": 0,
        "total_engines":   0,
        "verdict":         "unavailable",
        "engines":         [],
        "cached":          False,
    }

    if not api_key:
        return {**_empty, "verdict": "disabled"}

    # ── Cache ─────────────────────────────────────────────────────────────────
    if url in _cache:
        return {**_cache[url], "cached": True}

    headers = {
        "x-apikey":     api_key,
        "Accept":       "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        # Step 1: Try to GET existing analysis
        _rate_limit()
        url_id   = _url_id(url)
        resp     = requests.get(f"{_BASE}/urls/{url_id}", headers=headers, timeout=8)

        if resp.status_code == 404:
            # Not cached by VT yet — submit for scanning
            _rate_limit()
            submit = requests.post(
                f"{_BASE}/urls",
                headers=headers,
                data=f"url={requests.utils.quote(url)}",
                timeout=8,
            )
            if submit.status_code not in (200, 201):
                return {**_empty, "verdict": "error", "error": f"Submit failed: {submit.status_code}"}

            analysis_id = submit.json()["data"]["id"]

            # Poll for result (max 3 attempts, 5s apart)
            for _ in range(3):
                time.sleep(5)
                _rate_limit()
                poll = requests.get(f"{_BASE}/analyses/{analysis_id}", headers=headers, timeout=8)
                if poll.status_code == 200:
                    status = poll.json().get("data", {}).get("attributes", {}).get("status", "")
                    if status == "completed":
                        resp = poll
                        break
            else:
                return {**_empty, "verdict": "pending"}

        elif resp.status_code != 200:
            return {**_empty, "verdict": "error", "error": f"HTTP {resp.status_code}"}

        # ── Parse result ──────────────────────────────────────────────────────
        data  = resp.json().get("data", {})
        attrs = data.get("attributes", {})

        # Handle both /urls/{id} and /analyses/{id} response shapes
        stats = attrs.get("last_analysis_stats") or attrs.get("stats", {})
        results = attrs.get("last_analysis_results") or attrs.get("results", {})

        malicious_count  = stats.get("malicious",  0)
        suspicious_count = stats.get("suspicious", 0)
        harmless_count   = stats.get("harmless",   0)
        undetected_count = stats.get("undetected", 0)
        total_engines    = malicious_count + suspicious_count + harmless_count + undetected_count

        # Collect flagging engine names (up to 5)
        flagging_engines = [
            name for name, res in results.items()
            if res.get("category") in ("malicious", "phishing", "suspicious")
        ][:5]

        # Verdict logic
        is_malicious = (
            malicious_count  >= _MALICIOUS_THRESHOLD or
            suspicious_count >= _SUSPICIOUS_THRESHOLD
        )

        if malicious_count >= _MALICIOUS_THRESHOLD:
            verdict = "malicious"
        elif suspicious_count >= _SUSPICIOUS_THRESHOLD:
            verdict = "suspicious"
        elif total_engines == 0:
            verdict = "unrated"
        else:
            verdict = "clean"

        result = {
            "is_malicious":    is_malicious,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "total_engines":   total_engines,
            "verdict":         verdict,
            "engines":         flagging_engines,
            "cached":          False,
        }

        _cache_set(url, result)
        return result

    except requests.Timeout:
        return {**_empty, "verdict": "timeout"}
    except Exception as e:
        return {**_empty, "verdict": "error", "error": str(e)}
