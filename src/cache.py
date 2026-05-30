"""
cache.py — Persistent disk-based cache using SQLite.

Replaces the in-memory dict cache in predict_url.py.
Results survive app restarts — repeated scans of the same URL
are instant even after restarting the Flask server.

Storage: models/cache.db (SQLite, auto-created)
Max entries: configurable (default 5,000 — oldest evicted first)
TTL: configurable (default 7 days — stale entries auto-purged)
"""

import os
import json
import sqlite3
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Optional

BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH   = os.path.join(BASE_DIR, 'models', 'cache.db')

DEFAULT_MAX_ENTRIES = 5000
DEFAULT_TTL_DAYS    = 7

# Thread-local connections — one per thread (Flask uses multiple threads)
_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Get or create a thread-local SQLite connection."""
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _init_db(_local.conn)
    return _local.conn


def _init_db(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS url_cache (
            key       TEXT PRIMARY KEY,
            url       TEXT NOT NULL,
            result    TEXT NOT NULL,
            created   TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_created ON url_cache(created)")
    conn.commit()


def _make_key(url: str, whois_enabled: bool, safe_browsing_key: str, virustotal_key: str) -> str:
    """Stable cache key from URL + config combo."""
    raw = f"{url}|{whois_enabled}|{bool(safe_browsing_key)}|{bool(virustotal_key)}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get(
    url: str,
    whois_enabled: bool = True,
    safe_browsing_key: str = '',
    virustotal_key: str = '',
    ttl_days: int = DEFAULT_TTL_DAYS,
) -> Optional[dict]:
    """
    Retrieve a cached result. Returns None if not found or expired.
    """
    try:
        conn    = _get_conn()
        key     = _make_key(url, whois_enabled, safe_browsing_key, virustotal_key)
        cutoff  = (datetime.utcnow() - timedelta(days=ttl_days)).isoformat()

        row = conn.execute(
            "SELECT result, created FROM url_cache WHERE key = ? AND created > ?",
            (key, cutoff)
        ).fetchone()

        if row:
            result = json.loads(row['result'])
            result['cached'] = True
            return result
        return None

    except Exception:
        return None


def set(
    url: str,
    result: dict,
    whois_enabled: bool = True,
    safe_browsing_key: str = '',
    virustotal_key: str = '',
    max_entries: int = DEFAULT_MAX_ENTRIES,
):
    """
    Store a result. Evicts oldest entries if over max_entries.
    """
    try:
        conn    = _get_conn()
        key     = _make_key(url, whois_enabled, safe_browsing_key, virustotal_key)
        payload = {k: v for k, v in result.items() if k != 'cached'}

        conn.execute(
            "INSERT OR REPLACE INTO url_cache (key, url, result, created) VALUES (?, ?, ?, ?)",
            (key, url, json.dumps(payload), datetime.utcnow().isoformat())
        )

        # Evict oldest if over limit
        count = conn.execute("SELECT COUNT(*) FROM url_cache").fetchone()[0]
        if count > max_entries:
            overshoot = count - max_entries
            conn.execute("""
                DELETE FROM url_cache
                WHERE key IN (
                    SELECT key FROM url_cache
                    ORDER BY created ASC
                    LIMIT ?
                )
            """, (overshoot,))

        conn.commit()

    except Exception:
        pass   # Cache failures are non-fatal


def purge_expired(ttl_days: int = DEFAULT_TTL_DAYS):
    """Remove entries older than ttl_days. Call on startup to keep DB clean."""
    try:
        conn   = _get_conn()
        cutoff = (datetime.utcnow() - timedelta(days=ttl_days)).isoformat()
        conn.execute("DELETE FROM url_cache WHERE created <= ?", (cutoff,))
        conn.commit()
    except Exception:
        pass


def stats() -> dict:
    """Return cache statistics."""
    try:
        conn  = _get_conn()
        total = conn.execute("SELECT COUNT(*) FROM url_cache").fetchone()[0]
        oldest = conn.execute("SELECT MIN(created) FROM url_cache").fetchone()[0]
        newest = conn.execute("SELECT MAX(created) FROM url_cache").fetchone()[0]
        return {"total_entries": total, "oldest": oldest, "newest": newest, "db_path": DB_PATH}
    except Exception:
        return {"total_entries": 0, "db_path": DB_PATH}
