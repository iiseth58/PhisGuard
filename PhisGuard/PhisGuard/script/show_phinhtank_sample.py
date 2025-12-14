import json

with open("phishtank.json", "r") as f:
    data = json.load(f)

print("Showing 5 sample phishing URLs from PhishTank:")
for entry in data[:5]:
    print(entry.get("url"))
