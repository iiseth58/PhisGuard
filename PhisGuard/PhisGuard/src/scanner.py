import os
import json
import requests
import time
from utils import (
    is_valid_url_format,
    domain_main_label_letters_only,
    normalize_url_input,
    is_probably_url
)

risk_message = {
    'low': '✅ SAFE',
    'medium': '⚠️ SUSPICIOUS',
    'high': '🚨 DANGEROUS'
}

CACHE_FILE = "phishtank.json"
CACHE_TTL = 24 * 60 * 60  # 1 day in seconds

def fetch_phishtank_data():
    # If cache exists and is fresh, load it
    if os.path.exists(CACHE_FILE):
        mtime = os.path.getmtime(CACHE_FILE)
        if time.time() - mtime < CACHE_TTL:
            try:
                with open(CACHE_FILE, "r") as f:
                    return json.load(f)
            except:
                pass  # fall through to re-download if cache is corrupt

    # Otherwise, download fresh data
    url = "http://data.phishtank.com/data/online-valid.json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            with open(CACHE_FILE, "w") as f:
                json.dump(data, f)
            return data
        else:
            print("⚠️ Failed to fetch PhishTank data")
            return []
    except Exception as e:
        print(f"⚠️ Error fetching PhishTank data: {e}")
        return []

def check_with_phishtank(url: str, phishing_data):
    # Normalize both input and feed URLs for better matching
    normalized = url.strip().lower().rstrip('/')
    for entry in phishing_data:
        entry_url = entry.get("url", "").strip().lower().rstrip('/')
        if entry_url == normalized:
            print("✅ Match found in PhishTank!")
            return True
    return False

class SimpleScanner:
    def __init__(self):
        self.scan_count = 0
        self.data_file = "scans.json"
        self.load_data()
        # Load phishing data once (cached)
        self.phishing_data = fetch_phishtank_data()

        if not self.phishing_data:
            print("⚠️ Warning: PhishTank feed is empty or failed to load. Skipping phishing checks.")
        else:
            print(f"✅ Loaded {len(self.phishing_data)} PhishTank entries")

    def load_data(self):
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r") as f:
                    self.scan_history = json.load(f)
            except:
                self.scan_history = {}
        else:
            self.scan_history = {}

    def save_data(self):
        try:
            with open(self.data_file, "w") as f:
                json.dump(self.scan_history, f)
        except:
            pass

    def scan_url(self, url: str):
        problems = []
        good_things = []
        risk_score = 0

        # Debug: show how many entries are being checked
        print(f"Checking against {len(self.phishing_data)} PhishTank entries...")

        # Check against PhishTank
        flagged = check_with_phishtank(url, self.phishing_data)
        if flagged:
            problems.append("Flagged by PhishTank (phishing)")
            risk_score += 70

        has_https = url.startswith('https://')
        if has_https:
            good_things.append("Uses secure HTTPS")
            risk_score -= 10
        else:
            problems.append("Not using HTTPS")
            risk_score += 20

        # Clamp score between 0–100
        risk_score = max(0, min(100, risk_score))

        if risk_score >= 70:
            risk_level = 'high'
        elif risk_score >= 40:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'problems': problems,
            'good_things': good_things
        }

    def check_url(self, url: str):
        raw = url.strip()
        if not raw:
            print("❌ Please enter a URL!")
            return

        normalized = normalize_url_input(raw)
        if not normalized:
            print("❌ Please enter a valid URL (no spaces).")
            return

        if not (is_valid_url_format(normalized) or is_probably_url(raw)):
            print("❌ That doesn't look like a valid URL format. Aborting scan.")
            return

        if not domain_main_label_letters_only(normalized):
            print("❌ Domain name looks suspicious (contains digits or invalid characters). Aborting scan.")
            return

        url = normalized
        print(f"🔍 Scanning: {url}")
        if url in self.scan_history:
            print("Found previous scan.")
            self.show_old_result(url)
            return
        result = self.scan_url(url)
        self.scan_history[url] = result
        self.scan_count += 1
        self.save_data()
        self.show_result(result)

    def show_result(self, result):
        print("\n📊 RESULT:")
        print("=" * 40)
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Verdict: {risk_message[result['risk_level']]}")
        if result['problems']:
            print("\n🚨 Problems Found:")
            for p in result['problems']:
                print(f"   • {p}")
        if result['good_things']:
            print("\n✅ Good Signs:")
            for g in result['good_things']:
                print(f"   • {g}")
        print("\n💡 Advice:")
        if result['risk_level'] == 'high':
            print("   Don't visit this website!")
        elif result['risk_level'] == 'medium':
            print("   Be careful - don't enter passwords!")
        else:
            print("   Looks safe, but always be careful!")

    def show_old_result(self, url: str):
        result = self.scan_history.get(url)
        if result:
            print("\n📋 Previous scan result:")
            self.show_result(result)

    def show_stats(self):
        print(f"\n📈 Statistics:")
        print("=" * 30)
        print(f"Scans today: {self.scan_count}")
        print(f"Total in history: {len(self.scan_history)}")

class BetterScanner(SimpleScanner):
    def scan_url(self, url):
        result = super().scan_url(url)
        if '@' in url:
            result['problems'].append("Contains @ symbol (suspicious)")
            result['risk_score'] += 15
        result['risk_score'] = max(0, min(100, result['risk_score']))
        if result['risk_score'] >= 70:
            result['risk_level'] = 'high'
        elif result['risk_score'] >= 40:
            result['risk_level'] = 'medium'
        else:
            result['risk_level'] = 'low'
        return result
