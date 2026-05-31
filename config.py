"""
config.py — Central configuration for PhishGuard.

API keys are read from environment variables — never hardcode secrets here.

Local development: create a .env file (gitignored) or set vars in your terminal:
    $env:SAFE_BROWSING_API_KEY = "AIzaSy..."   (PowerShell)
    set SAFE_BROWSING_API_KEY=AIzaSy...        (CMD)

Production (Render): set vars in Dashboard → Environment tab.
"""

import os

# ── Model ─────────────────────────────────────────────────────────────────────
PHISHING_THRESHOLD = float(os.environ.get('PHISHING_THRESHOLD', '0.72'))

# ── Google Safe Browsing ──────────────────────────────────────────────────────
# Free key: https://developers.google.com/safe-browsing/v4/get-started
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY', None)

# ── VirusTotal ────────────────────────────────────────────────────────────────
# Free key: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', None)

# ── WHOIS ─────────────────────────────────────────────────────────────────────
WHOIS_ENABLED = os.environ.get('WHOIS_ENABLED', 'false').lower() == 'true'
WHOIS_YOUNG_DOMAIN_DAYS = int(os.environ.get('WHOIS_YOUNG_DOMAIN_DAYS', '90'))

# ── Cache ─────────────────────────────────────────────────────────────────────
CACHE_MAX_SIZE = int(os.environ.get('CACHE_MAX_SIZE', '1000'))
