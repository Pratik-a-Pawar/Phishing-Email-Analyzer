import requests
import os
from dotenv import load_dotenv

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    response = requests.get(url, headers=headers, params=querystring)
    
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "ip": ip,
            "abuseConfidenceScore": data["abuseConfidenceScore"],
            "countryCode": data["countryCode"],
            "domain": data["domain"]
        }
    else:
        return {"ip": ip, "error": "Failed to get data"}
