# 🛡 PhishGuard

> AI-powered phishing URL detector — LegitPhish 2025 dataset · v5.0

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-orange?logo=scikit-learn)
![Dataset](https://img.shields.io/badge/Dataset-LegitPhish%202025-green)
![Accuracy](https://img.shields.io/badge/Accuracy-96%25-brightgreen)
![Deploy](https://img.shields.io/badge/Deploy-Railway-blueviolet?logo=railway)

---

## Overview

PhishGuard is a machine learning web application that detects phishing URLs in real time. It combines a **Random Forest classifier** trained on the LegitPhish 2025 dataset with **VirusTotal** and **Google Safe Browsing** API integrations for layered threat detection.

🔗 **Live demo:** https://web-production-7bd64.up.railway.app

---

## Features

- 🤖 **ML Model** — Random Forest, 300 trees, trained on 101,219 URLs
- 🔍 **VirusTotal Integration** — checks against 90+ antivirus engines
- 🛡 **Google Safe Browsing** — Google's live phishing/malware blacklist
- 📦 **Batch Scan** — scan up to 20 URLs at once
- 📄 **PDF Export** — download a styled scan report
- 🌙 **Dark / Light mode** — toggle in the header
- ⚡ **Rate limiting** — 30 requests/minute per IP
- 💾 **Disk cache** — repeated scans return instantly
- 📊 **Model charts** — feature importance + confusion matrix

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask 3.0 |
| ML | scikit-learn, XGBoost, pandas, numpy |
| APIs | VirusTotal v3, Google Safe Browsing v4 |
| Frontend | Vanilla JS, CSS variables, Google Fonts |
| Deploy | Railway.app, Gunicorn |
| Model storage | Google Drive (downloaded at startup) |
| Dataset | LegitPhish 2025 (Mendeley Data) |

---

## Dataset

**LegitPhish (2025)** — Potpelwar et al., Mendeley Data
- 101,219 manually verified URLs
- 63,678 phishing · 37,540 legitimate
- Sources: URLHaus, PhishTank, Wikipedia, Stack Overflow
- DOI: [10.17632/hx4m73v2sf.2](https://data.mendeley.com/datasets/hx4m73v2sf/2)

---

## Model Performance

| Metric | Value |
|---|---|
| Accuracy | 96% |
| Phishing detection | 96% (24/25) |
| False positives | 4% (1/25) |
| Threshold | 0.72 |

Features used (16 — pure URL analysis, no network calls):

`log_url_length` · `has_ip_address` · `dot_count` · `url_entropy` · `log_token_count` · `subdomain_count` · `query_param_count` · `tld_length` · `log_path_length` · `has_hyphen_in_domain` · `log_digit_count` · `suspicious_file_extension` · `log_domain_length` · `digit_ratio`

---

## Local Setup

```bash
# 1. Clone
git clone https://github.com/zouaouikais4/phishguard.git
cd phishguard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Download dataset & train model
#    Get dataset from https://data.mendeley.com/datasets/hx4m73v2sf/2
#    Save as data/legitphish_raw.csv
python src/train_model.py

# 4. Set API keys (PowerShell)
$env:SAFE_BROWSING_API_KEY = "your_key"
$env:VIRUSTOTAL_API_KEY    = "your_key"
$env:GDRIVE_FILE_ID        = "your_drive_id"
$env:WHOIS_ENABLED         = "false"

# 5. Run
python app.py
```

Open: http://127.0.0.1:5000

---

## Cloud Deployment (Railway.app)

1. Fork this repo
2. Upload `models/phishing_model.pkl` to Google Drive (share as "Anyone with the link")
3. Connect repo to [railway.app](https://railway.app) → New Project → Deploy from GitHub
4. Set environment variables in Railway dashboard → Variables tab:

| Variable | Value |
|---|---|
| `GDRIVE_FILE_ID` | Your Google Drive file ID |
| `VIRUSTOTAL_API_KEY` | From virustotal.com (free) |
| `SAFE_BROWSING_API_KEY` | From Google Cloud Console (free) |
| `WHOIS_ENABLED` | `false` |
| `PHISHING_THRESHOLD` | `0.72` |

Railway auto-detects `railway.json` and handles the rest.

---

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Web UI |
| `/predict` | POST | Scan a single URL |
| `/predict/batch` | POST | Scan up to 20 URLs |
| `/export/pdf` | POST | Export scan result as PDF |
| `/charts/<file>` | GET | Model performance charts |

**Single scan:**
```json
POST /predict
{ "url": "https://example.com" }
```

**Batch scan:**
```json
POST /predict/batch
{ "urls": ["https://example.com", "http://suspicious-site.xyz"] }
```

---

## Project Structure

```
phishguard/
├── app.py                    # Flask server + API routes
├── startup.py                # Downloads model from Google Drive at boot
├── config.py                 # Reads API keys from environment variables
├── requirements.txt
├── railway.json              # Railway.app deploy config
├── Procfile
├── .env.example              # Environment variable reference (no real keys)
├── src/
│   ├── predict_url.py        # Prediction logic + trusted domain whitelist
│   ├── extract_features.py   # URL feature extraction (16 features)
│   ├── train_model.py        # Model training script
│   ├── virustotal.py         # VirusTotal API integration
│   ├── safebrowsing.py       # Google Safe Browsing integration
│   ├── whois_lookup.py       # WHOIS domain age lookup
│   ├── cache.py              # SQLite disk cache
│   └── pdf_report.py         # ReportLab PDF generation
├── templates/
│   └── index.html            # Web UI
├── models/
│   └── model_report/         # feature_importance.png, confusion_matrix.png
└── data/                     # Dataset CSVs (gitignored)
```

---

## Security

All API keys are stored as environment variables — never in code or Git history.
See `.env.example` for the list of required variables.

---

## Academic Context

Developed as part of the **GLSI2 program** at the Faculté des Sciences de Bizerte, Université de Carthage.

---

## License

MIT
