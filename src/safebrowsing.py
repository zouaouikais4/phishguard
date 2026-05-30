"""
safebrowsing.py — Google Safe Browsing v4 API integration.

Checks a URL against Google's live database of phishing, malware,
and unwanted software URLs. Acts as a hard override: if Google flags it,
the URL is Phishing regardless of what the ML model says.

Requires a free API key in config.py:
  SAFE_BROWSING_API_KEY = "AIzaSy..."
  Get one at: https://developers.google.com/safe-browsing/v4/get-started

If no key is set, check() silently returns (False, None).
"""

import functools
import requests
from typing import Optional, Tuple

_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",     # phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

_PLATFORM_TYPES   = ["ANY_PLATFORM"]
_THREAT_ENTRY_TYPES = ["URL"]


@functools.lru_cache(maxsize=512)
def check(url: str, api_key: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Check a URL against Google Safe Browsing.

    Returns:
        (is_flagged: bool, threat_type: str | None)
        is_flagged = True means Google considers this URL dangerous.
        threat_type is the matched category (e.g. "SOCIAL_ENGINEERING") or None.

    Results are cached (LRU, 512 entries) so re-checking the same URL is free.
    """
    if not api_key:
        return False, None

    payload = {
        "client": {
            "clientId":      "phishguard",
            "clientVersion": "3.0",
        },
        "threatInfo": {
            "threatTypes":      _THREAT_TYPES,
            "platformTypes":    _PLATFORM_TYPES,
            "threatEntryTypes": _THREAT_ENTRY_TYPES,
            "threatEntries":    [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            _API_URL,
            params={"key": api_key},
            json=payload,
            timeout=4,
        )
        resp.raise_for_status()
        data = resp.json()

        matches = data.get("matches", [])
        if matches:
            threat_type = matches[0].get("threatType", "UNKNOWN")
            return True, threat_type

        return False, None

    except Exception:
        # Network error, quota exceeded, bad key — fail open (don't block the user)
        return False, None
