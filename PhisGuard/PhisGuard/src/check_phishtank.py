import json

try:
    with open("phishtank.json", "r") as f:
        data = json.load(f)
    print(f"✅ Loaded {len(data)} phishing entries from phishtank.json")
except Exception as e:
    print(f"⚠️ Error loading phishtank.json: {e}")
