import requests
import re
from urllib.parse import urlparse
import logging

# Constants
SUSPICIOUS_KEYWORDS = ["phishing", "malware", "suspicious", "login", "account-verification"]
BLACKLISTED_DOMAINS = ["example-phishing.com", "malicious-site.net"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd"]  # Add known shorteners

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
        headers = {"User-Agent": "Mozilla/5.0 (compatible; URLChecker/1.0)"}
        response = requests.head(url, allow_redirects=True, headers=headers, timeout=5)
        final_url = response.url
        domain = urlparse(final_url).netloc.lower()

        print(f"🔗 Final URL: {final_url}")

        # Check for shortened URLs
        if is_shortened_url(domain):
            logging.warning(f"Shortened URL detected: {final_url}")
            return "⚠️ Shortened URL detected. Proceed with caution!"

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

def is_shortened_url(domain):
    """
    Check if the domain is a known URL shortener.
    """
    return domain in URL_SHORTENERS

def check_safe_browsing_api(url):
    """
    Placeholder for integration with Google's Safe Browsing API.
    """
    # Simulate Safe Browsing detection (replace with actual API call)
    return False

def analyze_url(url):
    """
    Analyze the given URL for potential threats.
    """
    if not is_valid_url(url):
        return "Invalid URL format."

    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; URLChecker/1.0)"}
        response = requests.head(url, allow_redirects=True, headers=headers, timeout=5)
        final_url = response.url
        domain = urlparse(final_url).netloc.lower()

        print(f"🔗 Final URL: {final_url}")

        # Check for shortened URLs
        if is_shortened_url(domain):
            logging.warning(f"Shortened URL detected: {final_url}")
            return "⚠️ Shortened URL detected. Proceed with caution!"

        # Check for suspicious keywords
        if any(keyword in final_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
            logging.info(f"Suspicious URL detected: {final_url}")
            return "⚠️ Potential phishing site detected!"

        # Check against blacklist
        if check_blacklist(domain):
            logging.info(f"Blacklisted URL detected: {final_url}")
            return "🚨 URL is on the blacklist!"

        # Check Safe Browsing API
        if check_safe_browsing_api(final_url):
            logging.info(f"Unsafe URL detected by Safe Browsing API: {final_url}")
            return "🚨 URL flagged by Safe Browsing API!"

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
