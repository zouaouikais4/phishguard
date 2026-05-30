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
