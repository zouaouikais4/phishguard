"""
patch.py — Apply all improvements to PhishGuard v5.

Run from your project root:
    cd C:\\Users\\KAIS\\Downloads\\phishguard-v4\\phishguard
    python patch.py

What this adds:
  1.  Error message clears when you start typing
  2.  Confidence gauge bar (visual progress bar under the %)
  3.  Dark / light mode toggle (sun/moon button in header)
  4.  /predict/batch endpoint (scan multiple URLs at once)
  5.  Rate limiting via flask-limiter (30 req/min per IP)
  6.  /export/pdf endpoint (ReportLab PDF report of last scan)
  7.  Procfile + render.yaml for free Render.com deployment
  8.  requirements.txt updated with new deps
  9.  Version badge updated to v5.0
"""

import os, re

BASE = os.path.dirname(os.path.abspath(__file__))

def write(rel, content):
    path = os.path.join(BASE, rel.replace('/', os.sep))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'  ✅ {rel}')

def patch_file(rel, old, new):
    path = os.path.join(BASE, rel.replace('/', os.sep))
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    if old not in content:
        print(f'  ⚠  Could not find patch target in {rel} — skipping')
        return
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content.replace(old, new, 1))
    print(f'  ✅ patched {rel}')

print(f'\nApplying patches to: {BASE}\n')

# ─────────────────────────────────────────────────────────────────────────────
# 1. requirements.txt — add flask-limiter and reportlab
# ─────────────────────────────────────────────────────────────────────────────
write('requirements.txt', '''\
flask>=3.0
flask-limiter>=3.5
joblib>=1.3
scikit-learn>=1.4
pandas>=2.1
numpy>=1.26
tldextract>=5.1
xgboost>=2.0
python-whois>=0.9
requests>=2.31
matplotlib>=3.8
vt-py>=0.18
reportlab>=4.1
gunicorn>=21.2
''')

# ─────────────────────────────────────────────────────────────────────────────
# 2. app.py — add rate limiting, batch endpoint, PDF export
# ─────────────────────────────────────────────────────────────────────────────
write('app.py', '''\
"""
app.py — Flask web server for PhishGuard v5.
"""

import os, sys, traceback, json
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

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour", "30 per minute"],
    storage_uri="memory://",
)

# ── Load model ────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'phishing_model.pkl')
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model not found: {MODEL_PATH}\\nRun: python src/train_model.py")

_model = load_model(MODEL_PATH)
print(f"✅  Model loaded from {MODEL_PATH}")

# ── Cache startup ─────────────────────────────────────────────────────────────
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


# ── Helpers ───────────────────────────────────────────────────────────────────
def _run_predict(url):
    return predict_url(
        url,
        model=_model,
        whois_enabled=WHOIS_ENABLED,
        whois_threshold_days=WHOIS_YOUNG_DOMAIN_DAYS,
        safe_browsing_key=SAFE_BROWSING_API_KEY,
        virustotal_key=VIRUSTOTAL_API_KEY,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


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

    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "No URL provided."}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL too long (max 2048 chars)."}), 400

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

    urls = data.get('urls', [])
    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "Provide a non-empty \\'urls\\' list."}), 400
    if len(urls) > 20:
        return jsonify({"error": "Max 20 URLs per batch request."}), 400

    results = []
    for url in urls:
        url = str(url).strip()
        if not url:
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


# ── Error handlers ────────────────────────────────────────────────────────────

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


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print(f"\\n{\\'─\\'*50}")
    print(f"  PhishGuard v5.0")
    print(f"  Threshold    : {PHISHING_THRESHOLD}")
    print(f"  WHOIS        : {\\'enabled\\' if WHOIS_ENABLED else \\'disabled\\'}")
    print(f"  Safe Browsing: {\\'enabled\\' if SAFE_BROWSING_API_KEY else \\'disabled\\'}")
    print(f"  VirusTotal   : {\\'enabled\\' if VIRUSTOTAL_API_KEY else \\'disabled\\'}")
    print(f"  Batch API    : /predict/batch (max 20 URLs)")
    print(f"  PDF Export   : /export/pdf")
    print(f"  URL          : http://127.0.0.1:5000")
    print(f"{\\'─\\'*50}\\n")
    app.run(debug=True, use_reloader=False)
''')

# ─────────────────────────────────────────────────────────────────────────────
# 3. src/pdf_report.py — ReportLab PDF generation
# ─────────────────────────────────────────────────────────────────────────────
write('src/pdf_report.py', '''\
"""
pdf_report.py — Generate a styled PDF scan report using ReportLab.
Called by the /export/pdf endpoint in app.py.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# ── Colour palette (matches the UI) ──────────────────────────────────────────
C_BG       = colors.HexColor('#0d1117')
C_CARD     = colors.HexColor('#111820')
C_BORDER   = colors.HexColor('#1e2d3d')
C_ACCENT   = colors.HexColor('#00e5ff')
C_DANGER   = colors.HexColor('#ff3b5c')
C_SAFE     = colors.HexColor('#00e676')
C_WARN     = colors.HexColor('#ffb300')
C_TEXT     = colors.HexColor('#c9d8e8')
C_DIM      = colors.HexColor('#607080')
C_WHITE    = colors.white


def generate_pdf(result: dict) -> io.BytesIO:
    """
    Generate a PDF report from a predict_url() result dict.
    Returns a BytesIO buffer containing the PDF.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Header ────────────────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        'title', fontSize=22, textColor=C_WHITE,
        fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=4,
    )
    sub_style = ParagraphStyle(
        'sub', fontSize=9, textColor=C_DIM,
        fontName='Helvetica', alignment=TA_CENTER, spaceAfter=16,
    )

    story.append(Paragraph('🛡 PhishGuard', title_style))
    story.append(Paragraph('URL Threat Detection Report · LegitPhish 2025 · v5.0', sub_style))
    story.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceAfter=16))

    # ── Verdict banner ────────────────────────────────────────────────────────
    is_phishing = result.get('is_phishing', False)
    verdict_color = C_DANGER if is_phishing else C_SAFE
    verdict_text  = 'PHISHING DETECTED' if is_phishing else 'URL IS SAFE'
    confidence    = result.get('confidence', 0)

    verdict_style = ParagraphStyle(
        'verdict', fontSize=18, textColor=verdict_color,
        fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=4,
    )
    story.append(Paragraph(verdict_text, verdict_style))

    conf_style = ParagraphStyle(
        'conf', fontSize=13, textColor=verdict_color,
        fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=8,
    )
    story.append(Paragraph(f'{confidence}% confidence', conf_style))

    url_style = ParagraphStyle(
        'url', fontSize=8, textColor=C_DIM,
        fontName='Courier', alignment=TA_CENTER, spaceAfter=20,
    )
    story.append(Paragraph(result.get('url', ''), url_style))
    story.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceAfter=16))

    # ── Scan metadata ─────────────────────────────────────────────────────────
    label_style = ParagraphStyle('lbl', fontSize=7, textColor=C_DIM,
                                 fontName='Helvetica', spaceAfter=12)
    story.append(Paragraph('// SCAN METADATA', label_style))

    meta_data = [
        ['Scanned at', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Detection source', result.get('source', 'model')],
        ['Cached result', 'Yes' if result.get('cached') else 'No'],
    ]
    if result.get('whois_days') is not None:
        meta_data.append(['Domain age (days)', str(result['whois_days'])])
    if result.get('sb_threat'):
        meta_data.append(['Safe Browsing threat', result['sb_threat']])
    vt = result.get('vt', {})
    if vt and vt.get('verdict') not in (None, 'disabled', 'unavailable'):
        meta_data.append(['VirusTotal verdict', vt.get('verdict', '-')])
        meta_data.append(['VT engines flagged', f"{vt.get('malicious_count',0)}/{vt.get('total_engines',0)}"])

    meta_table = Table(meta_data, colWidths=[5*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME',  (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE',  (0,0), (-1,-1), 9),
        ('TEXTCOLOR', (0,0), (0,-1),  C_DIM),
        ('TEXTCOLOR', (1,0), (1,-1),  C_TEXT),
        ('BACKGROUND',(0,0), (-1,-1), C_CARD),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [C_CARD, colors.HexColor('#0f161e')]),
        ('GRID',      (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING',(0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0),(-1,-1),6),
        ('LEFTPADDING',(0,0),(-1,-1),10),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # ── Feature breakdown ─────────────────────────────────────────────────────
    story.append(Paragraph('// FEATURE BREAKDOWN', label_style))

    f = result.get('features', {})
    feat_rows = [
        ['Feature', 'Value', 'Assessment'],
        ['URL Length',    str(f.get('url_length','-')),      'Suspicious' if (f.get('url_length',0) or 0) > 75 else 'OK'],
        ['HTTPS',         'YES' if f.get('https') else 'NO', 'OK' if f.get('https') else 'Warning'],
        ['IP in URL',     'YES' if f.get('has_ip') else 'NO','Suspicious' if f.get('has_ip') else 'OK'],
        ['Entropy',       f'{f.get("entropy",0):.3f}',       'Warning' if (f.get('entropy',0) or 0) > 4.5 else 'OK'],
        ['Subdomains',    str(f.get('subdomains',0)),        'Suspicious' if (f.get('subdomains',0) or 0) > 2 else 'OK'],
        ['Query Params',  str(f.get('query_params',0)),      'Warning' if (f.get('query_params',0) or 0) > 5 else 'OK'],
        ['URL Shortener', 'YES' if f.get('shortener') else 'NO', 'Suspicious' if f.get('shortener') else 'OK'],
        ['@ Symbol',      'YES' if f.get('at_symbol') else 'NO', 'Suspicious' if f.get('at_symbol') else 'OK'],
        ['Double Slash',  'YES' if f.get('double_slash') else 'NO', 'Suspicious' if f.get('double_slash') else 'OK'],
        ['Digit Ratio',   f'{(f.get("digit_ratio",0) or 0)*100:.1f}%', 'Warning' if (f.get('digit_ratio',0) or 0) > 0.3 else 'OK'],
        ['Hyphen in Domain','YES' if f.get('hyphen') else 'NO','Warning' if f.get('hyphen') else 'OK'],
        ['Suspicious Ext.','YES' if f.get('susp_ext') else 'NO','Suspicious' if f.get('susp_ext') else 'OK'],
    ]

    def assess_color(val):
        if val == 'Suspicious': return C_DANGER
        if val == 'Warning':    return C_WARN
        return C_SAFE

    feat_table = Table(feat_rows, colWidths=[5*cm, 4*cm, 8*cm])
    ts = TableStyle([
        ('FONTNAME',     (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTNAME',     (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE',     (0,0), (-1,-1), 9),
        ('TEXTCOLOR',    (0,0), (-1,0),  C_ACCENT),
        ('TEXTCOLOR',    (0,1), (1,-1),  C_TEXT),
        ('BACKGROUND',   (0,0), (-1,0),  colors.HexColor('#0a1520')),
        ('ROWBACKGROUNDS',(0,1),(-1,-1), [C_CARD, colors.HexColor('#0f161e')]),
        ('GRID',         (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING',   (0,0), (-1,-1), 6),
        ('BOTTOMPADDING',(0,0), (-1,-1), 6),
        ('LEFTPADDING',  (0,0), (-1,-1), 10),
        ('ALIGN',        (0,0), (-1,-1), 'LEFT'),
    ])
    # Colour the Assessment column
    for i, row in enumerate(feat_rows[1:], 1):
        c = assess_color(row[2])
        ts.add('TEXTCOLOR', (2,i), (2,i), c)
        ts.add('FONTNAME',  (2,i), (2,i), 'Helvetica-Bold')
    feat_table.setStyle(ts)
    story.append(feat_table)
    story.append(Spacer(1, 20))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceBefore=8))
    footer_style = ParagraphStyle('footer', fontSize=7, textColor=C_DIM,
                                  fontName='Helvetica', alignment=TA_CENTER)
    story.append(Paragraph(
        'Generated by PhishGuard v5.0 · LegitPhish 2025 dataset · '
        'For security assessment purposes only.',
        footer_style
    ))

    # ── Build ─────────────────────────────────────────────────────────────────
    # Dark background on every page
    def dark_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.restoreState()

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)
    return buf
''')

# ─────────────────────────────────────────────────────────────────────────────
# 4. Patch index.html — error clears on input, gauge bar, dark/light toggle,
#    PDF export button, batch scan UI, v5.0 badge
# ─────────────────────────────────────────────────────────────────────────────

# 4a. Add CSS for gauge bar, light mode, dark/light toggle, batch UI
patch_file('templates/index.html',
    '    @media (max-width:540px) { .input-row { flex-direction:column; } .verdict-banner { flex-wrap:wrap; } .conf-pill { margin-left:0; } }',
    '''    /* ── Gauge bar ── */
    .gauge-wrap { margin-top:8px; }
    .gauge-track { height:6px; background:var(--border); border-radius:3px; overflow:hidden; }
    .gauge-fill  { height:100%; border-radius:3px; transition:width .6s ease; }
    .gauge-fill.phishing { background:var(--danger); }
    .gauge-fill.safe     { background:var(--safe); }

    /* ── Dark/light toggle ── */
    .theme-btn {
      background:none; border:1px solid var(--border); color:var(--muted);
      font-size:.85rem; width:34px; height:34px; border-radius:8px;
      cursor:pointer; display:grid; place-items:center; transition:border-color .2s, color .2s; flex-shrink:0;
    }
    .theme-btn:hover { border-color:var(--accent); color:var(--accent); }

    /* Light mode overrides */
    body.light {
      --bg:      #f0f4f8; --surface: #ffffff; --card: #ffffff;
      --border:  #d0dce8; --text:    #1a2535; --dim:  #6b7a8d; --muted: #8898aa;
    }
    body.light body::before { display:none; }
    body.light .orb { opacity:.06; }

    /* ── Batch scan ── */
    .batch-toggle {
      font-family:var(--mono); font-size:.62rem; color:var(--muted); background:none;
      border:1px solid var(--border); border-radius:6px; padding:4px 10px;
      cursor:pointer; margin-top:10px; transition:color .2s, border-color .2s;
    }
    .batch-toggle:hover { color:var(--accent); border-color:rgba(0,229,255,.4); }
    .batch-area { display:none; margin-top:12px; }
    .batch-area.open { display:block; }
    .batch-input {
      width:100%; background:var(--surface); border:1px solid var(--border); border-radius:10px;
      padding:12px 16px; color:var(--text); font-family:var(--mono); font-size:.78rem;
      outline:none; resize:vertical; min-height:90px; transition:border-color .2s;
    }
    .batch-input:focus { border-color:var(--accent); }
    .batch-btn {
      margin-top:8px; background:transparent; color:var(--accent);
      border:1px solid rgba(0,229,255,.4); border-radius:8px; padding:8px 20px;
      font-family:var(--sans); font-weight:700; font-size:.8rem; cursor:pointer;
      transition:background .2s;
    }
    .batch-btn:hover { background:rgba(0,229,255,.08); }
    .batch-results { margin-top:12px; display:flex; flex-direction:column; gap:6px; }
    .batch-item {
      background:var(--surface); border:1px solid var(--border); border-radius:8px;
      padding:10px 14px; display:flex; align-items:center; gap:10px; font-family:var(--mono); font-size:.75rem;
    }
    .batch-item .b-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
    .batch-item .b-dot.phishing { background:var(--danger); }
    .batch-item .b-dot.safe     { background:var(--safe); }
    .batch-item .b-url { flex:1; color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .batch-item .b-conf { color:var(--muted); flex-shrink:0; }
    .batch-summary { font-family:var(--mono); font-size:.72rem; color:var(--muted); margin-top:6px; }

    /* ── PDF export button ── */
    .export-btn {
      display:inline-flex; align-items:center; gap:6px;
      background:none; border:1px solid var(--border); color:var(--muted);
      font-family:var(--mono); font-size:.65rem; letter-spacing:1px;
      border-radius:8px; padding:6px 14px; cursor:pointer; margin-top:12px;
      transition:color .2s, border-color .2s;
    }
    .export-btn:hover { color:var(--accent); border-color:rgba(0,229,255,.4); }

    @media (max-width:540px) { .input-row { flex-direction:column; } .verdict-banner { flex-wrap:wrap; } .conf-pill { margin-left:0; } }'''
)

# 4b. Add theme toggle button and batch toggle to header area
patch_file('templates/index.html',
    '<a class="charts-link" href="#" onclick="openCharts(); return false;">📊 Model Charts</a>',
    '''<a class="charts-link" href="#" onclick="openCharts(); return false;">📊 Model Charts</a>
      <button class="theme-btn" id="themeBtn" onclick="toggleTheme()" title="Toggle dark/light mode">🌙</button>'''
)

# 4c. Update version badge
patch_file('templates/index.html',
    'LegitPhish 2025 · v4.0',
    'LegitPhish 2025 · v5.0'
)

# 4d. Add batch scan UI below the error message div
patch_file('templates/index.html',
    '      <div class="error-msg" id="errorMsg"></div>\n    </div>',
    '''      <div class="error-msg" id="errorMsg"></div>
      <button class="batch-toggle" onclick="toggleBatch()">⊞ Batch scan multiple URLs</button>
      <div class="batch-area" id="batchArea">
        <textarea class="batch-input" id="batchInput" placeholder="Enter one URL per line (max 20)..."></textarea>
        <button class="batch-btn" onclick="runBatch()">▶ Scan All</button>
        <div class="batch-results" id="batchResults"></div>
        <div class="batch-summary" id="batchSummary"></div>
      </div>
    </div>'''
)

# 4e. Add gauge bar and PDF export button inside the result card
patch_file('templates/index.html',
    '          <div class="conf-pill">\n            <div class="conf-val" id="confVal"></div>\n            <div class="conf-lbl">confidence</div>\n          </div>',
    '''          <div class="conf-pill">
            <div class="conf-val" id="confVal"></div>
            <div class="conf-lbl">confidence</div>
            <div class="gauge-wrap">
              <div class="gauge-track"><div class="gauge-fill" id="gaugeFill" style="width:0%"></div></div>
            </div>
          </div>'''
)

# 4f. Add PDF export button after the features section
patch_file('templates/index.html',
    '        </div>\n      </div>\n    </div>\n\n    <div class="history-section">',
    '''        </div>
        <div style="padding:0 32px 20px">
          <button class="export-btn" id="exportBtn" onclick="exportPDF()">⬇ Export PDF Report</button>
        </div>
      </div>
    </div>

    <div class="history-section">'''
)

# 4g. Patch JavaScript — add all new functions before closing </script>
patch_file('templates/index.html',
    "    document.getElementById('urlInput').addEventListener('keydown', e => {\n      if (e.key === 'Enter') scan();\n    });",
    """    document.getElementById('urlInput').addEventListener('keydown', e => {
      if (e.key === 'Enter') scan();
    });

    // Clear error on typing
    document.getElementById('urlInput').addEventListener('input', () => {
      const el = document.getElementById('errorMsg');
      el.style.display = 'none'; el.textContent = '';
    });

    // ── Gauge bar ─────────────────────────────────────────────────────────────
    function updateGauge(confidence, isPhishing) {
      const fill = document.getElementById('gaugeFill');
      fill.style.width = confidence + '%';
      fill.className = 'gauge-fill ' + (isPhishing ? 'phishing' : 'safe');
    }

    // Hook into renderResult to update gauge
    const _origRender = renderResult;
    function renderResult(data) {
      _origRender(data);
      updateGauge(data.confidence, data.is_phishing);
      window._lastScanResult = data;
    }

    // ── Dark / light mode ─────────────────────────────────────────────────────
    (function() {
      const saved = localStorage.getItem('phishguard_theme');
      if (saved === 'light') { document.body.classList.add('light'); document.getElementById('themeBtn').textContent = '☀'; }
    })();

    function toggleTheme() {
      const isLight = document.body.classList.toggle('light');
      const btn = document.getElementById('themeBtn');
      btn.textContent = isLight ? '☀' : '🌙';
      localStorage.setItem('phishguard_theme', isLight ? 'light' : 'dark');
    }

    // ── Batch scan ────────────────────────────────────────────────────────────
    function toggleBatch() {
      document.getElementById('batchArea').classList.toggle('open');
    }

    async function runBatch() {
      const raw   = document.getElementById('batchInput').value;
      const urls  = raw.split('\\n').map(u => u.trim()).filter(Boolean).slice(0, 20);
      const resDiv= document.getElementById('batchResults');
      const sumDiv= document.getElementById('batchSummary');

      if (!urls.length) return;
      resDiv.innerHTML = '<div class="history-empty">Scanning...</div>';
      sumDiv.textContent = '';

      try {
        const res  = await fetch('/predict/batch', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ urls })
        });
        const data = await res.json();
        if (data.error) { resDiv.innerHTML = `<div class="history-empty">${data.error}</div>`; return; }

        resDiv.innerHTML = data.results.map(r =>
          `<div class="batch-item">
            <div class="b-dot ${r.is_phishing ? 'phishing' : 'safe'}"></div>
            <span class="b-url">${escHtml(r.url)}</span>
            <span class="b-conf">${r.confidence}% · ${r.label}</span>
          </div>`
        ).join('');
        sumDiv.textContent = `// ${data.total} scanned · ${data.phishing} phishing · ${data.safe} safe`;

      } catch(e) {
        resDiv.innerHTML = '<div class="history-empty">Server error during batch scan.</div>';
      }
    }

    // ── PDF export ────────────────────────────────────────────────────────────
    async function exportPDF() {
      const result = window._lastScanResult;
      if (!result) return;
      const btn = document.getElementById('exportBtn');
      btn.textContent = '⏳ Generating...';
      btn.disabled = true;

      try {
        const res = await fetch('/export/pdf', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(result)
        });
        if (!res.ok) { const d = await res.json(); alert(d.error); return; }
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href = url; a.download = 'phishguard_report.pdf'; a.click();
        URL.revokeObjectURL(url);
      } catch(e) {
        alert('PDF export failed. Is Flask running?');
      } finally {
        btn.textContent = '⬇ Export PDF Report';
        btn.disabled = false;
      }
    }"""
)

# ─────────────────────────────────────────────────────────────────────────────
# 5. Procfile — for Render / Railway deployment
# ─────────────────────────────────────────────────────────────────────────────
write('Procfile', 'web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120\n')

# ─────────────────────────────────────────────────────────────────────────────
# 6. render.yaml — one-click Render.com deploy config
# ─────────────────────────────────────────────────────────────────────────────
write('render.yaml', '''\
services:
  - type: web
    name: phishguard
    env: python
    buildCommand: "pip install -r requirements.txt"
    startCommand: "gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120"
    envVars:
      - key: PYTHON_VERSION
        value: "3.11"
      - key: SAFE_BROWSING_API_KEY
        sync: false
      - key: VIRUSTOTAL_API_KEY
        sync: false
''')

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────
print('\n✅ All patches applied!\n')
print('Next steps:')
print('  1. pip install flask-limiter reportlab gunicorn')
print('  2. python app.py')
print('  3. Test batch scan: paste multiple URLs in the input card')
print('  4. Test PDF: scan a URL then click "Export PDF Report"')
print('  5. Deploy: push to GitHub then connect to render.com and point to render.yaml')
