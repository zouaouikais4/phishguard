# PhishGuard v4 — URL Phishing Detector

A production-grade phishing URL classifier built on the **LegitPhish (2025)** dataset.
Uses XGBoost + calibrated probabilities, WHOIS domain age, Google Safe Browsing,
input validation, and LRU caching. Zero live network calls required for the core model.

---

## Model performance

| Class      | Precision | Recall | F1   |
|------------|-----------|--------|------|
| Phishing   | 1.00      | 1.00   | 1.00 |
| Legitimate | 1.00      | 1.00   | 1.00 |
| **Overall accuracy** | | | **99.96%** |

Trained on 101,219 samples (LegitPhish 2025, Mendeley DOI: 10.17632/hx4m73v2sf.2).

Charts auto-generated in `models/model_report/` after training.

> **Known limitation**: the LegitPhish training set uses Wikipedia/Stack Overflow as
> "legitimate" examples — short URLs like `github.com/user/repo` or `amazon.com/dp/X`
> are underrepresented and may occasionally produce false positives. This is a dataset
> bias, not a code bug. Adding WHOIS age check mitigates this for newly-seen domains.

---

## Project structure

```
phishguard/
├── app.py                        # Flask web server
├── config.py                     # Thresholds, API keys, toggles
├── requirements.txt
├── README.md
│
├── data/
│   └── legitphish_raw.csv        # LegitPhish 2025 dataset
│
├── models/
│   ├── phishing_model.pkl        # (calibrated_model, feature_names, threshold)
│   └── model_report/
│       ├── confusion_matrix.png  # Auto-generated on train
│       └── feature_importance.png
│
├── src/
│   ├── train_model.py            # XGBoost + calibration + charts
│   ├── predict_url.py            # Validation + features + WHOIS + cache
│   ├── whois_lookup.py           # Domain age via WHOIS (cached)
│   └── safebrowsing.py           # Google Safe Browsing v4 API
│
└── templates/
    └── index.html                # Web UI — feature breakdown, badges, charts
```

---

## Setup & run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the model
python src/train_model.py

# 3. (Optional) Add your Google Safe Browsing key in config.py
#    Get one free at: https://developers.google.com/safe-browsing/v4/get-started
#    SAFE_BROWSING_API_KEY = "AIzaSy..."

# 4. Start the app
python app.py
# → http://127.0.0.1:5000
```

---

## Improvements over v3

| Area | Change | Impact |
|---|---|---|
| **Model** | Random Forest → XGBoost | ~0.1% accuracy gain, faster inference |
| **Calibration** | `CalibratedClassifierCV` (isotonic, 5-fold) | Confidence % are true probabilities |
| **WHOIS** | Domain age lookup (cached, optional) | Catches freshly-registered phishing domains |
| **Safe Browsing** | Google Safe Browsing v4 hard override | Catches known phishing not in training data |
| **Validation** | URL length, scheme, private IP, homograph detection | Robust against malformed/adversarial input |
| **Caching** | LRU cache (1,000 entries) | Same URL returns instantly on re-check |
| **Charts** | Confusion matrix + feature importance (auto-generated) | Portfolio/presentation ready |
| **Config** | Central `config.py` | Easy to tune without touching code |

---

## Features used (14 — pure URL string, no live network)

| # | Feature | Description |
|---|---------|-------------|
| 1 | `log_url_length` | log(1 + URL length) — length is predictive but non-linear |
| 2 | `has_ip_address` | Raw IP literal instead of domain name |
| 3 | `dot_count` | Number of dots — phishing URLs often have many |
| 4 | `url_entropy` | Shannon entropy — random-looking URLs are suspicious |
| 5 | `log_token_count` | log(1 + token count) — many tokens = complex/suspicious |
| 6 | `subdomain_count` | Deep subdomain nesting |
| 7 | `query_param_count` | Many query parameters |
| 8 | `tld_length` | Long TLDs (.information) are unusual |
| 9 | `log_path_length` | Long paths can indicate evasion |
| 10 | `has_hyphen_in_domain` | Hyphen in SLD (e.g. paypal-secure.com) |
| 11 | `log_digit_count` | Many digits in URL |
| 12 | `suspicious_file_extension` | .exe, .php, .zip, .bat etc. in path |
| 13 | `log_domain_length` | Very long domain names are suspicious |
| 14 | `digit_ratio` | Fraction of digits (excluding scheme) |

---

## Configuration (`config.py`)

```python
PHISHING_THRESHOLD = 0.55          # Lower = more sensitive
SAFE_BROWSING_API_KEY = None       # Add key to enable
WHOIS_ENABLED = True               # Disable for faster (offline-only) mode
WHOIS_YOUNG_DOMAIN_DAYS = 90       # Domains younger than this are flagged
CACHE_MAX_SIZE = 1000
```
