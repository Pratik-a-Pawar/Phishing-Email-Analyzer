import requests
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": VT_API_KEY
}

response = requests.get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers)
print(response.status_code)
print(response.text)
