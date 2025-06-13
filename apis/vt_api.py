import requests
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def check_url_virustotal(url):
    headers = {
        "x-apikey": VT_API_KEY
    }

    # Step 1: Submit URL to VirusTotal for scanning
    submit_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    # Check if submission is successful
    if submit_response.status_code != 200:
        return {"url": url, "error": "URL submission failed"}

    # Extract the ID returned by VT
    url_id = submit_response.json()["data"]["id"]

    # Step 2: Use the ID to fetch the analysis report
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
    analysis_response = requests.get(analysis_url, headers=headers)

    if analysis_response.status_code == 200:
        data = analysis_response.json()["data"]["attributes"]["stats"]
        return {
            "url": url,
            "malicious": data.get("malicious", 0),
            "suspicious": data.get("suspicious", 0),
            "harmless": data.get("harmless", 0)
        }
    else:
        return {"url": url, "error": "Failed to fetch analysis"}
