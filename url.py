import requests
import re
from urllib.parse import urlparse

def is_valid_url(url):
    """
    Validate the URL format using regex.
    """
    regex = re.compile(
        r'^(?:http|https)://'  # http:// or https://
        r'(?:\S+(?::\S*)?@)?'  # optional username:password@
        r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}'  # domain
        r'(?::\d{2,5})?'  # optional port
        r'(?:/[^?#]*)?'  # optional path
        r'(?:\?[^#]*)?'  # optional query
        r'(?:#.*)?$', re.IGNORECASE)  # optional fragment
    return re.match(regex, url)

# Known suspicious keywords
SUSPICIOUS_KEYWORDS = ["phishing", "malware", "suspicious", "login", "account-verification"]

def check_url(url):
    if not is_valid_url(url):
        return "Invalid URL format."

    try:
        response = requests.head(url, allow_redirects=True)
        final_url = response.url
        print(f"The URL redirects to: {final_url}")

        # Check for suspicious keywords
        if any(keyword in final_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
            return "⚠️ Potential phishing site detected!"

        return "✅ URL seems safe."
    except requests.exceptions.RequestException as e:
        return f"❌ Error: {e}"

        
# Blacklisted domains
BLACKLISTED_DOMAINS = ["example-phishing.com", "malicious-site.net"]

def check_blacklist(url):
    """
    Check if the domain is blacklisted.
    """
    domain = urlparse(url).netloc
    if domain in BLACKLISTED_DOMAINS:
        return True
    return False

def check_url(url):
    if not is_valid_url(url):
        return "Invalid URL format."

    try:
        response = requests.head(url, allow_redirects=True)
        final_url = response.url
        print(f"The URL redirects to: {final_url}")

        # Check for suspicious keywords
        if any(keyword in final_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
            return "⚠️ Potential phishing site detected!"

        # Check against blacklist
        if check_blacklist(final_url):
            return "🚨 URL is on the blacklist!"

        return "✅ URL seems safe."
    except requests.exceptions.RequestException as e:
        return f"❌ Error: {e}"


def check_url(url):
    if not is_valid_url(url):
        return "Invalid URL format."

    try:
        response = requests.head(url, allow_redirects=True)
        final_url = response.url
        print(f"The URL redirects to: {final_url}")
        return "URL seems safe."
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

url = input("Enter a URL to check: ")
print(check_url(url))
