from utils.parse_email import parse_email
from apis.vt_api import check_url_virustotal
from apis.abuseipdb_api import check_ip_abuseipdb

import re

# Step 1: Load email
email_path = "Email_Samples/phishing_sample.eml"
email_data = parse_email(email_path)

print("\n========================")
print("📨 Email Summary")
print("========================")
print(f"From    : {email_data['From']}")
print(f"To      : {email_data['To']}")
print(f"Subject : {email_data['Subject']}")

# Step 2: Show URLs
print("\n========================")
print("🔗 Extracted URLs")
print("========================")
for url in email_data["URLs"]:
    print(" -", url)

# Step 3: Extract IPs from body text (simple pattern)
ips = re.findall(r'[0-9]+(?:\.[0-9]+){3}', email_data["Body"])

print("\n========================")
print("🌐 Extracted IPs")
print("========================")
if ips:
    for ip in ips:
        print(" -", ip)
else:
    print("No IPs found in email body.")

# Step 4: VirusTotal URL Check
print("\n========================")
print("🧪 VirusTotal URL Reputation")
print("========================")
for url in email_data["URLs"]:
    vt_result = check_url_virustotal(url)
    if "error" not in vt_result:
        print(f"\nURL: {vt_result['url']}")
        print(f" - Malicious : {vt_result['malicious']}")
        print(f" - Suspicious: {vt_result['suspicious']}")
        print(f" - Harmless  : {vt_result['harmless']}")
    else:
        print(f"\nURL: {url} — Error: {vt_result['error']}")

# Step 5: AbuseIPDB IP Check
print("\n========================")
print("🚨 AbuseIPDB IP Reputation")
print("========================")
if ips:
    for ip in ips:
        ip_result = check_ip_abuseipdb(ip)
        if "error" not in ip_result:
            print(f"\nIP Address : {ip_result['ip']}")
            print(f" - Confidence Score: {ip_result['abuseConfidenceScore']}")
            print(f" - Country        : {ip_result['countryCode']}")
            print(f" - Domain         : {ip_result['domain']}")
        else:
            print(f"\nIP: {ip} — Error: {ip_result['error']}")
            
# 📝 SAVE TO report.txt FILE
with open("report.txt", "w", encoding="utf-8") as report:
    report.write("===== EMAIL SUMMARY =====\n")
    report.write(f"From    : {email_data['From']}\n")
    report.write(f"To      : {email_data['To']}\n")
    report.write(f"Subject : {email_data['Subject']}\n\n")

    report.write("===== EXTRACTED URLs =====\n")
    for url in email_data["URLs"]:
        report.write(f"- {url}\n")
    report.write("\n")

    report.write("===== VIRUSTOTAL RESULTS =====\n")
    for url in email_data["URLs"]:
        if url.startswith("http"):
            vt_result = check_url_virustotal(url)
            if "error" not in vt_result:
                report.write(f"\nURL: {vt_result['url']}\n")
                report.write(f" - Malicious : {vt_result['malicious']}\n")
                report.write(f" - Suspicious: {vt_result['suspicious']}\n")
                report.write(f" - Harmless  : {vt_result['harmless']}\n")
            else:
                report.write(f"\nURL: {url} — Error: {vt_result['error']}\n")

    report.write("\n===== ABUSEIPDB RESULTS =====\n")
    if not ips:
        report.write("No IPs found in email body.\n")
    else:
        for ip in ips:
            ip_result = check_ip_abuseipdb(ip)
            if "error" not in ip_result:
                report.write(f"\nIP: {ip_result['ip']}\n")
                report.write(f" - Confidence Score: {ip_result['abuseConfidenceScore']}\n")
                report.write(f" - Country        : {ip_result['countryCode']}\n")
                report.write(f" - Domain         : {ip_result['domain']}\n")
            else:
                report.write(f"\nIP: {ip} — Error: {ip_result['error']}\n")

