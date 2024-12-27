import requests
import re
from urllib.parse import urlparse
import logging

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


# Set up logging
logging.basicConfig(filename='phishing_detector.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def check_url(url):
    if not is_valid_url(url):
        return "Invalid URL format."

    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        print(f"The URL redirects to: {final_url}")

        # Check for suspicious keywords
        if any(keyword in final_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
            logging.info(f"Suspicious URL detected: {final_url}")
            return "⚠️ Potential phishing site detected!"

        # Check against blacklist
        if check_blacklist(final_url):
            logging.info(f"Blacklisted URL detected: {final_url}")
            return "🚨 URL is on the blacklist!"

        return "✅ URL seems safe."
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking URL {url}: {e}")
        return f"❌ Error: {e}"


def check_url(url):
    if not is_valid_url(url):
        return "Invalid URL format."

    try:
        # Add a timeout to the request
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        print(f"The URL redirects to: {final_url}")

        if any(keyword in final_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
            logging.info(f"Suspicious URL detected: {final_url}")
            return "⚠️ Potential phishing site detected!"

        if check_blacklist(final_url):
            logging.info(f"Blacklisted URL detected: {final_url}")
            return "🚨 URL is on the blacklist!"

        return "✅ URL seems safe."
    except requests.exceptions.Timeout:
        logging.error(f"Timeout while checking URL: {url}")
        return "❌ Error: The request timed out."
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking URL {url}: {e}")
        return f"❌ Error: {e}"

#The main function starts
def main():
    print("🔍 URL Shortener Detector - Prevent Phishing Attempts")
    print("Enter 'exit' to quit.\n")
    
    while True:
        url = input("Enter a URL to check: ").strip()
        if url.lower() == "exit":
            print("Exiting the program. Stay safe!")
            break
        
        result = check_url(url)
        print(result, "\n")

if __name__ == "__main__":
    main()
