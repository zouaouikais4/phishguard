# 🛡 PhishGuard

> AI-powered phishing URL detector — LegitPhish 2025 dataset · v5.0

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-orange?logo=scikit-learn)
![Dataset](https://img.shields.io/badge/Dataset-LegitPhish%202025-green)
![Accuracy](https://img.shields.io/badge/Accuracy-96%25-brightgreen)

---

## Overview

PhishGuard is a machine learning web application that detects phishing URLs in real time. It combines a **Random Forest classifier** trained on the LegitPhish 2025 dataset with **VirusTotal** and **Google Safe Browsing** API integrations for layered threat detection.

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
| Deploy | Render.com, Gunicorn |
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

# 4. Configure API keys (optional)
#    Edit config.py and add your keys

# 5. Run
python app.py
```

Open: http://127.0.0.1:5000

---

## Cloud Deployment (Render.com)

1. Fork this repo
2. Upload `models/phishing_model.pkl` to Google Drive (share as public)
3. Connect repo to [render.com](https://render.com) → New Web Service
4. Set environment variables in Render dashboard:

| Variable | Value |
|---|---|
| `GDRIVE_FILE_ID` | Your Google Drive file ID |
| `VIRUSTOTAL_API_KEY` | From virustotal.com (free) |
| `SAFE_BROWSING_API_KEY` | From Google Cloud Console (free) |

Render auto-detects `render.yaml` and handles the rest.

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
├── config.py                 # API keys + thresholds
├── requirements.txt
├── render.yaml               # Render.com deploy config
├── Procfile
├── src/
│   ├── predict_url.py        # Prediction logic + whitelist
│   ├── extract_features.py   # URL feature extraction
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



---

## License

MIT