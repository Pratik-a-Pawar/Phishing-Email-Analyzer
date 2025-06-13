# 🛡️ Phishing Email Analyzer - SOC-Style Threat Detection Tool

This project simulates how a SOC Analyst handles suspicious emails. It parses `.eml` files, extracts IOCs (URLs, IPs), checks threat reputations using VirusTotal and AbuseIPDB APIs, and generates a structured SOC report.

---

## 🚀 Features

- 📩 Parses `.eml` phishing emails  
- 🔍 Extracts indicators (URLs, IPs)  
- 🧪 Checks real-time reputation with:
  - VirusTotal (URLs)
  - AbuseIPDB (IP addresses)
- 🧾 Generates `report.txt` with detailed threat summary  
- 💡 Designed to simulate real-world alert triage in a SOC

---

## 📁 Project Structure

Phishing_Analyzer/
├── main.py # Main script
├── .env # Contains API keys (excluded from GitHub)
├── report.txt # Generated incident-style report
├── Email_Samples/ # Folder with sample .eml files
├── utils/
│ └── parse_email.py # Email parsing and IOC extraction
├── apis/
│ ├── vt_api.py # VirusTotal integration
│ └── abuseipdb_api.py # AbuseIPDB integration


---

## 🧰 Requirements

- Python 3.10+
- Libraries:
  - `requests`
  - `beautifulsoup4`
  - `python-dotenv`

Install all at once:
```bash
pip install requests beautifulsoup4 python-dotenv


🔐 Environment Variables
Create a .env file in the root folder with:

VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

✅ How to Use
Place your .eml file inside /Email_Samples

Open main.py, update the email path if needed

Run the analyzer:

python main.py

Open report.txt to view the full threat report

📊 Sample Output

===== EMAIL SUMMARY =====
From    : FakePayPal <spoof@paypal.com>
To      : user@example.com
Subject : Suspicious Login Attempt

===== EXTRACTED URLs =====
 - http://malicious-site.com/login

===== VIRUSTOTAL RESULTS =====
URL: http://malicious-site.com/login
 - Malicious : 4
 - Suspicious: 1
 - Harmless  : 2

🧠 Use Case
SOC Analyst Portfolio Project

Blue Team / Threat Hunting Training

Demonstrates log triage, threat intel API usage, and automated reporting

🏆 Resume Highlight Example

Built a Python-based Phishing Email Analyzer that extracts IOCs from .eml files, uses VirusTotal & AbuseIPDB APIs to validate threat reputation, and generates SOC-style incident reports.

⚠️ Disclaimer
This tool is for educational use only

Do not use it on private or sensitive emails without permission

Always test in a secure, controlled environment

Connect
If you liked this project, feel free to ⭐ star the repo or connect with me on LinkedIn

linkedin.com/in/pratik-pawar-135b6727b

