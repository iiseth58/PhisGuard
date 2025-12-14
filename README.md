# 🛡️ PhisGuard
This is a Python-based tool that scans URLs for potential phishing and security risks.It integrates with the ** PhishTank** database to detect known phishing sites, applies heuristic checks (HTTPS usage, suspicious domain patterns, "@" symbols), and provides a clear risk score with advice. 

# ✨ Features
_ **PhishTank integration**: Matches URLs against thousands of known phishing entries.
_ **Risk scoring system**: Assigns a score (0–100) with verdicts: ✅ SAFE, ⚠️ SUSPICIOUS, 🚨 DANGEROUS.
_ **Heuristic checks**:
   - HTTPS vs HTTP
   - Suspicious domain labels
   - `@` symbols in URLs
_ **Caching**: PhishTank feed stored locally (`phishtank.json`) for faster repeated scans.
_ **Scan history**: Results saved in `scans.json` for reuse and statistics.
_ **CLI menu**: ASCII art banner, interactive options, batch testing, and stats.

# ⚙️ Setup
1. Clone the repository:
   ```bash
   . git clone https://github.com/yourusername/PhisGuard.git
   . cd PhisGuard
2. Create a virtual environment:
   ```bash
   python -m venv .venv
3. Activate the environment:
  _ Windows:
      ```bash
      .venv\Scripts\activate
  _ MacOS/Linux:
      ```bash
      source .venv/bin/activate
4. Install dependencies:
   . pip install requests

# 🚀 Usage 
_Run the CLI:
   ``bash
   python main.py

_You'll see: 

🛡️ SIMPLE URL SAFETY CHECKER
========================================
Choose an option:
1. Check a URL
2. Test examples
3. See statistics
4. Quit

Choose an option:

1. to scan the URL
2. to test the example to understand the result
3. to view statistics
4. to quit

**🧪 Example Output**

🔍 Scanning: https://consultasonliine.org/boloes/
Checking against 46833 PhishTank entries...
✅ Match found in PhishTank!

📊 RESULT:
====================================
Risk Score: 60/100
Verdict: ⚠️ SUSPICIOUS

🚨 Problems Found:
• Flagged by PhishTank (phishing)

✅ Good Signs:
• Uses secure HTTPS

💡 Advice:
Be careful - don't enter passwords!

# How It Works
_ Check URL against PhishTank feed
_ Apply heuristic checks:
   . Missing HTTPS -> +20 risk
   . Suspicious domain/@ symbol -> +15 risk
_ Combine results into risk score (0-100)
_ Display verdict: ✅ SAFE, ⚠️ SUSPICIOUS, 🚨 DANGEROUS

# 📂 Project Structure

PhisGuard/
|
|___-scanner.py       # core scanning login + PhisTank integration
|___-utils.py         # Helper functions for URL validation/normalization
|___-test.py          # Example test URLs
|___-main.py          # CLI menu interface
|___-phishtank.json   # Cached phishing feed (suto-downloaded)
|___-Scans.json       # Saved scan history

# ⚠️ Disclaimer
This project is for educational and research purposes only . It should not relied upon as a sole security solution .Always use professional security tools and best practices when browsing online.Feel free to modify and extend it.
For questions or improvement, feel free to reach out!
