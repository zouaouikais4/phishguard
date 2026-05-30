"""
whois_lookup.py — Domain age lookup via WHOIS with LRU cache.

Windows-compatible: uses a thread-based timeout to prevent hangs,
and gracefully falls back to None on any error.
"""

import functools
import datetime
import threading
from typing import Optional


def _whois_with_timeout(domain: str, timeout: int = 5) -> Optional[object]:
    """Run whois.whois() in a thread with a hard timeout."""
    result = [None]
    error  = [None]

    def _run():
        try:
            import whois as _whois
            result[0] = _whois.whois(domain)
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout)

    if t.is_alive():
        # Timed out — leave thread to die, return None
        return None
    if error[0]:
        return None
    return result[0]


@functools.lru_cache(maxsize=512)
def get_domain_age_days(domain: str) -> Optional[int]:
    """
    Return the number of days since the domain was registered.
    Returns None if lookup fails or date is unavailable.
    Cached (LRU, 512 entries).
    """
    try:
        import whois as _whois  # noqa: F401
    except ImportError:
        return None

    try:
        w = _whois_with_timeout(domain, timeout=5)
        if w is None:
            return None

        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None

        # Some registrars return a date, not datetime
        if isinstance(creation, datetime.date) and not isinstance(creation, datetime.datetime):
            creation = datetime.datetime(creation.year, creation.month, creation.day)

        age = (datetime.datetime.utcnow() - creation).days
        return max(age, 0)

    except Exception:
        return None


def domain_age_feature(domain: str, young_threshold_days: int = 90) -> int:
    """
    Returns:
      -1 → domain is very young (suspicious)
       0 → lookup failed / unknown
       1 → domain is established
    """
    age = get_domain_age_days(domain)
    if age is None:
        return 0
    return -1 if age < young_threshold_days else 1
