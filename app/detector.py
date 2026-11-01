
from app.analyzer import extract_features


def analyze_url(url: str) -> dict:
    """Analyze URL features and return explainable findings."""

    features = extract_features(url)
    findings = []
    score = 0

    # Rule 1: IP address used as hostname
    if features["has_ip_host"]:
        findings.append({
            "rule": "IP_ADDRESS_HOST",
            "severity": "medium",
            "reason": "The hostname is an IP address."
        })
        score += 25

    # Rule 2: URL does not use HTTPS
    if not features["uses_https"]:
        findings.append({
            "rule": "NO_HTTPS",
            "severity": "low",
            "reason": "The URL does not use HTTPS."
        })
        score += 10

    # Rule 3: Unusually long URL
    if features["url_length"] > 100:
        findings.append({
            "rule": "LONG_URL",
            "severity": "low",
            "reason": "The URL is unusually long."
        })
        score += 10

    # Rule 4: Many subdomains
    if features["subdomain_count"] >= 3:
        findings.append({
            "rule": "MANY_SUBDOMAINS",
            "severity": "low",
            "reason": "The hostname contains three or more subdomains."
        })
        score += 10
    
    # Rule: URL shortener domain
    shortener_domains = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
    }

    hostname = features["hostname"].lower()

    if hostname in shortener_domains:
        findings.append({
            "rule": "URL_SHORTENER",
            "severity": "low",
            "reason": (
                "The URL uses a shortening service that may hide "
                "the final destination."
            )
        })
        score += 10

    # Rule 5: @ symbol in URL
    if features["has_at_symbol"]:
        findings.append({
            "rule": "AT_SYMBOL",
            "severity": "medium",
            "reason": "The URL contains an @ symbol, which can obscure the hostname."
        })
        score += 20
    
    # Rule 8: Punycode hostname
    hostname = features["hostname"].lower()

    if "xn--" in hostname:
        findings.append({
            "rule": "PUNYCODE_HOST",
            "severity": "low",
            "reason": (
                "The hostname contains a punycode label. "
                "Internationalized domains can be legitimate, "
                "so this indicator alone does not imply phishing."
            )
        })
        score += 5

    score = min(score, 100)
    
    # Rule 7: Suspicious keywords in the URL
    suspicious_keywords = {
        "verify-account",
        "password-reset",
        "secure-login",
        "account-verification",
    }

    normalized_url = url.lower()
    matched_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in normalized_url
    ]

    if matched_keywords:
        findings.append({
            "rule": "SUSPICIOUS_KEYWORD",
            "severity": "low",
            "reason": (
                "The URL contains potentially suspicious keyword(s): "
                + ", ".join(matched_keywords)
                + ". These words can also appear in legitimate URLs."
            )
        })
        score += 5


    return {
        "url": url,
        "risk_score": score,
        "findings": findings,
        "features": features,
        "note": (
            "Heuristic assessment only; this score is not a "
            "probability of phishing and cannot establish safety."
        )
    }
