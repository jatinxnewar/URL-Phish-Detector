import requests
import re
from urllib.parse import urlparse
import logging

# Constants
SUSPICIOUS_KEYWORDS = ["phishing", "malware", "suspicious", "login", "account-verification"]
BLACKLISTED_DOMAINS = ["example-phishing.com", "malicious-site.net"]

# Logging setup
logging.basicConfig(
    filename="phishing_detector.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

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
    )
    return re.match(regex, url)

def check_blacklist(domain):
    """
    Check if the domain is blacklisted.
    """
    return domain in BLACKLISTED_DOMAINS

def analyze_url(url):
    """
    Analyze the given URL for potential threats.
    """
    if not is_valid_url(url):
        return "Invalid URL format."

    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        domain = urlparse(final_url).netloc.lower()

        print(f"🔗 Final URL: {final_url}")

        # Check for suspicious keywords
        if any(keyword in final_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
            logging.info(f"Suspicious URL detected: {final_url}")
            return "⚠️ Potential phishing site detected!"

        # Check against blacklist
        if check_blacklist(domain):
            logging.info(f"Blacklisted URL detected: {final_url}")
            return "🚨 URL is on the blacklist!"

        return "✅ URL seems safe."
    except requests.exceptions.Timeout:
        logging.error(f"Timeout while checking URL: {url}")
        return "❌ Error: The request timed out."
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking URL {url}: {e}")
        return f"❌ Error: {e}"

def main():
    """
    Main program for user interaction.
    """
    print("🔍 Basic URL Threat Analyzer")
    print("Type 'exit' to quit.\n")

    while True:
        url = input("Enter a URL to check: ").strip()
        if url.lower() == "exit":
            print("Exiting the program. Stay safe!")
            break

        result = analyze_url(url)
        print(result, "\n")

if __name__ == "__main__":
    main()
