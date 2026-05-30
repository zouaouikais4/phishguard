"""
train_model.py — Train PhishGuard on LegitPhish (2025) using XGBoost.

Improvements over the Random Forest baseline:
  - XGBoost: better accuracy on tabular data, faster inference
  - CalibratedClassifierCV: true probability scores (not just raw RF votes)
  - Threshold tuned to PHISHING_THRESHOLD from config.py
  - Auto-generates confusion matrix + feature importance charts
  - Saves (calibrated_model, feature_names, threshold) tuple

Run from project root:
    python src/train_model.py
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import (
    classification_report, accuracy_score,
    confusion_matrix, ConfusionMatrixDisplay
)
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR   = os.path.join(BASE_DIR, 'data')
MODEL_DIR  = os.path.join(BASE_DIR, 'models')
REPORT_DIR = os.path.join(MODEL_DIR, 'model_report')
RAW_CSV    = os.path.join(DATA_DIR, 'legitphish_raw.csv')
MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_model.pkl')

os.makedirs(MODEL_DIR,  exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

sys.path.insert(0, BASE_DIR)
from config import PHISHING_THRESHOLD

RAW_FEATURE_COLS = [
    'url_length', 'has_ip_address', 'dot_count', 'url_entropy',
    'token_count', 'subdomain_count', 'query_param_count', 'tld_length',
    'path_length', 'has_hyphen_in_domain', 'number_of_digits',
    'suspicious_file_extension', 'domain_name_length', 'percentage_numeric_chars',
]

FEATURE_NAMES = [
    'log_url_length', 'has_ip_address', 'dot_count', 'url_entropy',
    'log_token_count', 'subdomain_count', 'query_param_count', 'tld_length',
    'log_path_length', 'has_hyphen_in_domain', 'log_digit_count',
    'suspicious_file_extension', 'log_domain_length', 'digit_ratio',
]

FEATURE_DISPLAY_NAMES = [
    'URL Length (log)', 'IP in URL', 'Dot Count', 'URL Entropy',
    'Token Count (log)', 'Subdomain Count', 'Query Params', 'TLD Length',
    'Path Length (log)', 'Hyphen in Domain', 'Digit Count (log)',
    'Suspicious Extension', 'Domain Length (log)', 'Digit Ratio',
]


def engineer(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame()
    out['log_url_length']            = np.log1p(df['url_length'])
    out['has_ip_address']            = df['has_ip_address']
    out['dot_count']                 = df['dot_count']
    out['url_entropy']               = df['url_entropy']
    out['log_token_count']           = np.log1p(df['token_count'])
    out['subdomain_count']           = df['subdomain_count']
    out['query_param_count']         = df['query_param_count']
    out['tld_length']                = df['tld_length']
    out['log_path_length']           = np.log1p(df['path_length'])
    out['has_hyphen_in_domain']      = df['has_hyphen_in_domain']
    out['log_digit_count']           = np.log1p(df['number_of_digits'])
    out['suspicious_file_extension'] = df['suspicious_file_extension']
    out['log_domain_length']         = np.log1p(df['domain_name_length'])
    out['digit_ratio']               = df['percentage_numeric_chars']
    return out


def load_data():
    if not os.path.exists(RAW_CSV):
        raise FileNotFoundError(
            f"Dataset not found: {RAW_CSV}\n"
            "Download from https://data.mendeley.com/datasets/hx4m73v2sf/2\n"
            f"and save as {RAW_CSV}"
        )
    print(f"📂  Loading {RAW_CSV} …")
    raw = pd.read_csv(RAW_CSV)
    print(f"    Shape: {raw.shape}")

    label_col = next(
        (c for c in raw.columns if c.strip().lower() in ('classlabel', 'label')), None
    )
    if label_col is None:
        raise ValueError(f"No label column found. Columns: {list(raw.columns)}")

    df = raw[RAW_FEATURE_COLS + [label_col]].dropna()
    df[label_col] = df[label_col].astype(int)

    print(f"\n📊  Class distribution (0=phishing, 1=legitimate):")
    print(df[label_col].value_counts().to_string())

    X = engineer(df[RAW_FEATURE_COLS])
    y = df[label_col].values
    return X, y


def plot_confusion_matrix(y_test, y_pred, path):
    fig, ax = plt.subplots(figsize=(6, 5))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#0d1117')

    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(cm, display_labels=['Phishing', 'Legitimate'])
    disp.plot(ax=ax, colorbar=False, cmap='Blues')

    ax.set_title('Confusion Matrix', color='white', fontsize=13, pad=12)
    ax.set_xlabel('Predicted', color='#94a3b8')
    ax.set_ylabel('Actual',    color='#94a3b8')
    ax.tick_params(colors='#94a3b8')
    for spine in ax.spines.values():
        spine.set_edgecolor('#1e2d3d')

    # Recolor text in cells
    for text in disp.text_.ravel():
        text.set_color('white')
        text.set_fontsize(14)
        text.set_fontweight('bold')

    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
    plt.close()
    print(f"    Saved → {path}")


def plot_feature_importance(model, path):
    # Get importances from the base XGB estimator inside the calibrated wrapper
    # For CalibratedClassifierCV, get first fold's base estimator
    if hasattr(model, "calibrated_classifiers_"):
        base = model.calibrated_classifiers_[0].estimator
    elif hasattr(model, "estimator"):
        base = model.estimator
    else:
        base = model
    importances = base.feature_importances_
    indices = np.argsort(importances)

    fig, ax = plt.subplots(figsize=(8, 6))
    fig.patch.set_facecolor('#0d1117')
    ax.set_facecolor('#0d1117')

    colors = ['#00e5ff' if importances[i] >= np.percentile(importances, 70) else '#1e2d3d'
              for i in indices]
    bars = ax.barh(range(len(indices)), importances[indices], color=colors, height=0.65)

    ax.set_yticks(range(len(indices)))
    ax.set_yticklabels([FEATURE_DISPLAY_NAMES[i] for i in indices], color='#c9d8e8', fontsize=9)
    ax.set_xlabel('Feature Importance', color='#94a3b8', fontsize=10)
    ax.set_title('Feature Importance (XGBoost)', color='white', fontsize=13, pad=12)
    ax.tick_params(axis='x', colors='#94a3b8')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    for spine in ['bottom', 'left']:
        ax.spines[spine].set_edgecolor('#1e2d3d')

    # Value labels
    for bar, idx in zip(bars, indices):
        ax.text(bar.get_width() + 0.001, bar.get_y() + bar.get_height() / 2,
                f'{importances[idx]:.3f}', va='center', color='#64748b', fontsize=8)

    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
    plt.close()
    print(f"    Saved → {path}")


def train():
    X, y = load_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n🔀  Train: {len(X_train):,}  |  Test: {len(X_test):,}\n")

    # ── XGBoost ──────────────────────────────────────────────────────────────
    print("⚡  Training XGBoost …")
    scale = (y_train == 0).sum() / (y_train == 1).sum()   # handle class imbalance
    xgb = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )

    # ── Calibration ──────────────────────────────────────────────────────────
    print("🎯  Calibrating probabilities (isotonic, 5-fold) …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    calibrated = CalibratedClassifierCV(xgb, method='isotonic', cv=cv)
    calibrated.fit(X_train, y_train)

    # ── Evaluate ─────────────────────────────────────────────────────────────
    y_proba     = calibrated.predict_proba(X_test)
    phish_idx   = list(calibrated.classes_).index(0)
    y_pred      = np.where(y_proba[:, phish_idx] >= PHISHING_THRESHOLD, 0, 1)

    acc = accuracy_score(y_test, y_pred)
    print(f"\n✅  Accuracy @{PHISHING_THRESHOLD} threshold: {acc*100:.2f}%\n")
    print(f"── Classification Report ─────────────────────────────────────────")
    print(classification_report(y_test, y_pred, target_names=['Phishing', 'Legitimate']))

    # ── Charts ───────────────────────────────────────────────────────────────
    print("📊  Generating charts …")
    plot_confusion_matrix(
        y_test, y_pred,
        os.path.join(REPORT_DIR, 'confusion_matrix.png')
    )
    plot_feature_importance(
        calibrated,
        os.path.join(REPORT_DIR, 'feature_importance.png')
    )

    # ── Save ─────────────────────────────────────────────────────────────────
    joblib.dump((calibrated, FEATURE_NAMES, PHISHING_THRESHOLD), MODEL_PATH)
    print(f"\n✅  Model saved → {MODEL_PATH}")
    print(f"    Threshold: {PHISHING_THRESHOLD}")
    print(f"    Features:  {len(FEATURE_NAMES)}")


if __name__ == '__main__':
    train()
