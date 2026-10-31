
from urllib.parse import urlsplit
import ipaddress


def extract_features(url: str) -> dict:
    """Extract basic structural features from a URL."""

    # 1. Normalize input
    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty")

    if "://" not in url:
        url = "https://" + url

   
    # 2. Parse URL
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()
    except ValueError as error:
        raise ValueError("Invalid URL format") from error

    # 3. Validate parsed URL
    if scheme not in ("http", "https"):
        raise ValueError("URL must use HTTP or HTTPS")

    if not hostname:
        raise ValueError("URL must contain a hostname")


    # 4. Calculate lengths
    url_length = len(url)
    hostname_length = len(hostname)

    # 5. Detect IP addresses
    try:
        ipaddress.ip_address(hostname)
        has_ip_host = True
    except ValueError:
        has_ip_host = False

    # 6. Count subdomains
    if has_ip_host or not hostname:
        subdomain_count = 0
    else:
        labels = hostname.split(".")
        subdomain_count = max(0, len(labels) - 2)

    # 7. Detect @ symbol
    has_at_symbol = "@" in url

    # 8. Return extracted features
    return {
        "scheme": scheme,
        "hostname": hostname,
        "url_length": url_length,
        "hostname_length": hostname_length,
        "subdomain_count": subdomain_count,
        "uses_https": scheme == "https",
        "has_ip_host": has_ip_host,
        "has_at_symbol": has_at_symbol,
    }
