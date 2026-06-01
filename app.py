"""
app.py — Flask web server for PhishGuard v5.
"""

import os, sys, re, traceback
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from flask import Flask, request, jsonify, render_template, send_from_directory, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from src.predict_url import load_model, predict as predict_url
from config import (
    PHISHING_THRESHOLD, SAFE_BROWSING_API_KEY,
    WHOIS_ENABLED, WHOIS_YOUNG_DOMAIN_DAYS, VIRUSTOTAL_API_KEY
)

app = Flask(__name__)

# ── Rate limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour", "30 per minute"],
    storage_uri="memory://",
)

# ── Load model ─────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'phishing_model.pkl')
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}\nRun: python src/train_model.py")

_model = load_model(MODEL_PATH)
print(f"✅  Model loaded from {MODEL_PATH}")

# ── Cache startup ──────────────────────────────────────────────────────────────
try:
    from src.cache import purge_expired, stats as cache_stats
    import sqlite3 as _sqlite3

    model_mtime = os.path.getmtime(MODEL_PATH)
    cs = cache_stats()
    if cs['newest']:
        from datetime import datetime as _dt
        cache_newest = _dt.fromisoformat(cs['newest']).timestamp()
        if model_mtime > cache_newest:
            conn = _sqlite3.connect(cs['db_path'])
            conn.execute('DELETE FROM url_cache')
            conn.commit()
            conn.close()
            print("🗑️  Cache cleared (model was retrained)")
        else:
            purge_expired()
    else:
        purge_expired()
    cs = cache_stats()
    print(f"💾  Cache: {cs['total_entries']} entries in {os.path.basename(cs['db_path'])}")
except Exception as e:
    print(f"Cache init warning: {e}")


# ── URL validation ─────────────────────────────────────────────────────────────
# Accepts http:// and https:// URLs with a valid domain or IP and optional path/query.
_URL_RE = re.compile(
    r'^https?://'                          # scheme
    r'(([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'  # domain
    r'|((\d{1,3}\.){3}\d{1,3}))'          # or IPv4
    r'(:\d{1,5})?'                         # optional port
    r'([/?#][^\s]*)?$'                     # optional path/query/fragment
)

def _validate_url(url: str):
    """Return (cleaned_url, error_message). error_message is None if valid."""
    if not url:
        return None, "No URL provided."
    if len(url) > 2048:
        return None, "URL too long (max 2048 chars)."
    # Auto-prefix bare domains — e.g. "google.com" → "https://google.com"
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if not _URL_RE.match(url):
        return None, "Invalid URL. Please enter a valid URL (e.g. https://example.com)."
    return url, None


# ── Helpers ────────────────────────────────────────────────────────────────────
def _run_predict(url):
    return predict_url(
        url,
        model=_model,
        whois_enabled=WHOIS_ENABLED,
        whois_threshold_days=WHOIS_YOUNG_DOMAIN_DAYS,
        safe_browsing_key=SAFE_BROWSING_API_KEY,
        virustotal_key=VIRUSTOTAL_API_KEY,
    )


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/health')
def health():
    """Health check endpoint for Railway and uptime monitors."""
    return jsonify({"status": "ok", "model": "loaded"}), 200


@app.route('/charts/<path:filename>')
def charts(filename):
    chart_dir = os.path.join(BASE_DIR, 'models', 'model_report')
    if not os.path.exists(os.path.join(chart_dir, filename)):
        return jsonify({"error": "Chart not found. Run train_model.py first."}), 404
    return send_from_directory(chart_dir, filename)


@app.route('/predict', methods=['POST'])
@limiter.limit("30 per minute")
def predict():
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON."}), 400

    url, err = _validate_url(data.get('url', '').strip())
    if err:
        return jsonify({"error": err}), 400

    try:
        return jsonify(_run_predict(url))
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


@app.route('/predict/batch', methods=['POST'])
@limiter.limit("10 per minute")
def predict_batch():
    """Scan multiple URLs at once. Body: {"urls": ["url1", "url2", ...]}"""
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON."}), 400

    raw_urls = data.get('urls', [])
    if not isinstance(raw_urls, list) or not raw_urls:
        return jsonify({"error": "Provide a non-empty 'urls' list."}), 400
    if len(raw_urls) > 20:
        return jsonify({"error": "Max 20 URLs per batch request."}), 400

    results = []
    for raw in raw_urls:
        url, err = _validate_url(str(raw).strip())
        if err:
            results.append({"url": raw, "error": err})
            continue
        try:
            results.append(_run_predict(url))
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    phishing_count = sum(1 for r in results if r.get('is_phishing'))
    return jsonify({
        "total":    len(results),
        "phishing": phishing_count,
        "safe":     len(results) - phishing_count,
        "results":  results,
    })


@app.route('/export/pdf', methods=['POST'])
@limiter.limit("10 per minute")
def export_pdf():
    """Generate a PDF report for a scan result. Body: the result JSON from /predict."""
    try:
        data = request.get_json(force=True, silent=True) or {}
    except Exception:
        return jsonify({"error": "Invalid JSON."}), 400

    if 'url' not in data:
        return jsonify({"error": "Pass the full scan result JSON in the request body."}), 400

    try:
        from src.pdf_report import generate_pdf
        import io
        buf = generate_pdf(data)
        buf.seek(0)
        filename = f"phishguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(buf, mimetype='application/pdf',
                         as_attachment=True, download_name=filename)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"PDF generation failed: {e}"}), 500


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found."}), 404

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429

@app.errorhandler(500)
def internal_error(e):
    traceback.print_exc()
    return jsonify({"error": "Internal server error."}), 500


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    sep = '─' * 50
    print(f"\n{sep}")
    print(f"  PhishGuard v5.0")
    print(f"  Threshold    : {PHISHING_THRESHOLD}")
    print(f"  WHOIS        : {'enabled' if WHOIS_ENABLED else 'disabled (fast mode)'}")
    print(f"  Safe Browsing: {'enabled' if SAFE_BROWSING_API_KEY else 'disabled'}")
    print(f"  VirusTotal   : {'enabled' if VIRUSTOTAL_API_KEY else 'disabled'}")
    print(f"  Batch API    : /predict/batch (max 20 URLs)")
    print(f"  PDF Export   : /export/pdf")
    print(f"  Health check : /health")
    print(f"  URL          : http://127.0.0.1:5000")
    print(f"{sep}\n")
    app.run(debug=True, use_reloader=False)
