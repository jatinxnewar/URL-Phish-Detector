import requests
import re
import logging
import os
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Constants
SUSPICIOUS_KEYWORDS = {"phishing", "malware", "suspicious", "login", "account-verification"}
BLACKLISTED_DOMAINS = {"example-phishing.com", "malicious-site.net"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd"}

# Logging setup
logging.basicConfig(
    filename="phishing_detector.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def check_safe_browsing_api(url: str) -> bool:
    """Check the URL against Google's Safe Browsing API."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        logging.warning("Safe Browsing API key is missing.")
        return False

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "url-analyzer", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(api_url, json=payload, timeout=5)
        response.raise_for_status()
        response_data = response.json()

        if "matches" in response_data:
            logging.info(f"🚨 Unsafe URL detected: {url}")
            return True

        return False

    except requests.RequestException as e:
        logging.error(f"Safe Browsing API error: {e}")
        return False

def is_valid_url(url: str) -> bool:
    """Validate the URL format using regex."""
    regex = re.compile(
        r'^(https?:\/\/)?'  # http:// or https://
        r'([\w.-]+(?:\.[a-zA-Z]{2,6}))'  # Domain
        r'(:\d{2,5})?'  # Optional port
        r'(\/.*)?$', re.IGNORECASE  # Optional path
    )
    return re.match(regex, url) is not None

def is_shortened_url(domain: str) -> bool:
    """Check if the domain is a known URL shortener."""
    return domain in URL_SHORTENERS

def check_blacklist(domain: str) -> bool:
    """Check if the domain is blacklisted."""
    return domain in BLACKLISTED_DOMAINS

def analyze_url(url: str) -> str:
    """Analyze the given URL for potential threats."""
    if not is_valid_url(url):
        return "❌ Invalid URL format."

    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; URLChecker/1.0)"}
        response = requests.head(url, allow_redirects=True, headers=headers, timeout=5)
        final_url = response.url
        domain = urlparse(final_url).netloc.lower()

        print(f"🔗 Final URL: {final_url}")

        if is_shortened_url(domain):
            logging.warning(f"⚠️ Shortened URL detected: {final_url}")
            return "⚠️ Warning: Shortened URL detected. Proceed with caution!"

        if any(keyword in final_url.lower() for keyword in SUSPICIOUS_KEYWORDS):
            logging.info(f"⚠️ Suspicious URL detected: {final_url}")
            return "⚠️ Potential phishing site detected!"

        if check_blacklist(domain):
            logging.info(f"🚨 Blacklisted URL detected: {final_url}")
            return "🚨 URL is on the blacklist!"

        if check_safe_browsing_api(final_url):
            logging.info(f"🚨 Unsafe URL flagged by Safe Browsing API: {final_url}")
            return "🚨 Warning: URL flagged by Safe Browsing API!"

        return "✅ URL seems safe."
    
    except requests.Timeout:
        logging.error(f"❌ Timeout while checking URL: {url}")
        return "❌ Error: The request timed out."
    
    except requests.RequestException as e:
        logging.error(f"❌ Error checking URL {url}: {e}")
        return f"❌ Error: {e}"

def main():
    """Main program for user interaction."""
    print("🔍 URL Threat Analyzer")
    print("Type 'exit' to quit.\n")

    while True:
        try:
            url = input("Enter a URL to check: ").strip()
            if url.lower() == "exit":
                print("Exiting the program. Stay safe! 🛡️")
                break

            result = analyze_url(url)
            print(result, "\n")

        except KeyboardInterrupt:
            print("\nExiting program. Stay safe! 🛡️")
            break

if __name__ == "__main__":
    main()
