"""
startup.py — Download phishing_model.pkl from Google Drive at startup.
Called automatically by app.py before loading the model.
"""

import os
import sys
import requests

MODEL_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_model.pkl')

# Set GDRIVE_FILE_ID as an environment variable on Render
GDRIVE_FILE_ID = os.environ.get('GDRIVE_FILE_ID', '')


def download_model():
    """Download model from Google Drive if not already present."""
    if os.path.exists(MODEL_PATH):
        print(f"✅ Model already present at {MODEL_PATH}")
        return

    if not GDRIVE_FILE_ID:
        raise RuntimeError(
            "GDRIVE_FILE_ID environment variable not set.\n"
            "Set it on Render: Dashboard → Your Service → Environment → Add Variable"
        )

    os.makedirs(MODEL_DIR, exist_ok=True)
    print(f"⬇️  Downloading model from Google Drive (ID: {GDRIVE_FILE_ID}) ...")

    # Google Drive direct download URL
    url = f"https://drive.google.com/uc?export=download&id={GDRIVE_FILE_ID}"

    session = requests.Session()
    response = session.get(url, stream=True, timeout=120)

    # Handle Google's virus-scan confirmation page for large files
    token = None
    for key, value in response.cookies.items():
        if key.startswith('download_warning'):
            token = value
            break

    if token:
        url = f"https://drive.google.com/uc?export=download&id={GDRIVE_FILE_ID}&confirm={token}"
        response = session.get(url, stream=True, timeout=120)

    # Check we got a binary file not an HTML error page
    content_type = response.headers.get('Content-Type', '')
    if 'text/html' in content_type:
        raise RuntimeError(
            "Google Drive returned an HTML page instead of the model file.\n"
            "Make sure the file is shared as 'Anyone with the link' → Viewer."
        )

    total = int(response.headers.get('Content-Length', 0))
    downloaded = 0

    with open(MODEL_PATH, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)

    size_mb = downloaded / 1024 / 1024
    print(f"✅ Model downloaded ({size_mb:.1f} MB) → {MODEL_PATH}")


if __name__ == '__main__':
    download_model()
