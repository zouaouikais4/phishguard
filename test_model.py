"""
test_model.py — Run test dataset against PhishGuard.

Usage:
    1. python app.py   (keep running)
    2. python test_model.py  (in another terminal)
"""

import csv, json, time, urllib.request, urllib.error
from pathlib import Path

FLASK_URL = "http://127.0.0.1:5000/predict"
TEST_FILE = Path(__file__).parent / "test_urls.csv"
DELAY     = 2.5   # seconds between requests — stays under 30/min rate limit

GREEN = "\033[92m"; RED = "\033[91m"; YELLOW = "\033[93m"
DIM   = "\033[2m";  BOLD = "\033[1m"; RESET  = "\033[0m"

def predict(url):
    payload = json.dumps({"url": url}).encode()
    req = urllib.request.Request(
        FLASK_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())

def main():
    with open(TEST_FILE, newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))

    total = len(rows)
    correct = 0
    false_positives = []
    false_negatives = []
    errors = []

    print(f"\n{BOLD}{'─'*80}{RESET}")
    print(f"{BOLD}  PhishGuard Test Report — {total} URLs{RESET}")
    print(f"  (sending 1 request every {DELAY}s to respect rate limit)")
    print(f"{BOLD}{'─'*80}{RESET}\n")

    col_w = 52
    print(f"  {'URL':<{col_w}} {'EXPECTED':<12} {'PREDICTED':<12} {'CONF':>6}  RESULT")
    print(f"  {'─'*col_w} {'─'*11} {'─'*11} {'─'*6}  {'─'*6}")

    for i, row in enumerate(rows):
        url      = row['url'].strip()
        expected = row['expected'].strip()

        try:
            result     = predict(url)
            predicted  = result.get('label', 'Error')
            confidence = result.get('confidence', 0)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print(f"\n  {YELLOW}Rate limited — waiting 60s...{RESET}")
                time.sleep(60)
                try:
                    result     = predict(url)
                    predicted  = result.get('label', 'Error')
                    confidence = result.get('confidence', 0)
                except Exception as e2:
                    errors.append((url, str(e2)))
                    predicted = 'Error'; confidence = 0
            else:
                errors.append((url, str(e)))
                predicted = 'Error'; confidence = 0
        except Exception as e:
            errors.append((url, str(e)))
            predicted = 'Error'; confidence = 0

        is_correct = predicted == expected
        if predicted == 'Error':
            symbol = f"{YELLOW}ERR {RESET}"
        elif is_correct:
            symbol = f"{GREEN}✓ OK{RESET}"; correct += 1
        else:
            symbol = f"{RED}✗ NO{RESET}"
            if expected == 'Legitimate' and predicted == 'Phishing':
                false_positives.append((url, confidence))
            elif expected == 'Phishing' and predicted == 'Legitimate':
                false_negatives.append((url, confidence))

        pred_str = (f"{RED}{predicted:<12}{RESET}" if predicted == 'Phishing'
                    else f"{GREEN}{predicted:<12}{RESET}" if predicted == 'Legitimate'
                    else f"{YELLOW}{predicted:<12}{RESET}")

        url_display = (url[:col_w-3] + '...') if len(url) > col_w else url
        print(f"  {url_display:<{col_w}} {expected:<12} {pred_str} {confidence:>5.1f}%  {symbol}")

        if i < total - 1:
            time.sleep(DELAY)

    # Summary
    print(f"\n{BOLD}{'─'*80}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}\n")
    accuracy  = (correct / total * 100) if total else 0
    acc_color = GREEN if accuracy >= 90 else (YELLOW if accuracy >= 75 else RED)
    print(f"  Total URLs  : {total}")
    print(f"  Correct     : {correct}")
    print(f"  Accuracy    : {acc_color}{BOLD}{accuracy:.1f}%{RESET}")
    print(f"  Phishing    : {len([r for r in rows if r['expected']=='Phishing'])}")
    print(f"  Legitimate  : {len([r for r in rows if r['expected']=='Legitimate'])}")

    if false_positives:
        print(f"\n  {YELLOW}False Positives (legit → flagged phishing):{RESET}")
        for url, conf in false_positives:
            print(f"    {DIM}{url}{RESET}  ({conf:.1f}%)")
    if false_negatives:
        print(f"\n  {RED}False Negatives (phishing → missed):{RESET}")
        for url, conf in false_negatives:
            print(f"    {DIM}{url}{RESET}  ({conf:.1f}%)")
    if errors:
        print(f"\n  {YELLOW}Errors:{RESET}")
        for url, err in errors:
            print(f"    {DIM}{url}{RESET} — {err}")

    print(f"\n{BOLD}{'─'*80}{RESET}\n")
    if accuracy >= 90: print(f"  {GREEN}Great accuracy!{RESET}\n")
    elif accuracy >= 75: print(f"  {YELLOW}Decent. Tune threshold in config.py.{RESET}\n")
    else: print(f"  {RED}Low accuracy. See false positives above.{RESET}\n")

if __name__ == '__main__':
    main()