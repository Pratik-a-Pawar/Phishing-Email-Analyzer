import os
import email
from bs4 import BeautifulSoup

def parse_email(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_email = f.read()

    msg = email.message_from_string(raw_email)

    email_data = {
        "Subject": msg.get("Subject"),
        "From": msg.get("From"),
        "To": msg.get("To"),
        "Body": "",
        "URLs": []
    }

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/html" or content_type == "text/plain":
                try:
                    part_body = part.get_payload(decode=True).decode(errors='ignore')
                    body += part_body
                except:
                    continue
    else:
        body = msg.get_payload(decode=True).decode(errors='ignore')

    # Use BeautifulSoup to extract URLs from HTML content
    soup = BeautifulSoup(body, 'html.parser')
    urls = [a['href'] for a in soup.find_all('a', href=True)]

    email_data["Body"] = body.strip()[:500]  # First 500 characters
    email_data["URLs"] = urls

    return email_data
