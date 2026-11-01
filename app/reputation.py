
"""Google Safe Browsing reputation checks for PhishGuard."""

import os

import requests
from dotenv import load_dotenv

load_dotenv()

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


def check_url_reputation(url: str) -> dict:
    """Check a URL against Google's known-threat lists."""

    api_key = os.getenv("SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "status": "error",
            "message": "Safe Browsing API key is not configured.",
            "threat_types": [],
        }

    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": api_key},
            json=payload,
            timeout=10,
        )

        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])

        if matches:
            threat_types = sorted(
                {
                    match["threat"]["threatType"]
                    for match in matches
                    if match.get("threat", {}).get("threatType")
                }
            )

            return {
                "status": "unsafe",
                "message": "Google Safe Browsing identified a known threat.",
                "threat_types": threat_types,
            }

        return {
            "status": "safe",
            "message": "No known threats were reported by Google Safe Browsing.",
            "threat_types": [],
        }

    except requests.exceptions.Timeout:
        return {
            "status": "error",
            "message": "Safe Browsing request timed out. Try again later.",
            "threat_types": [],
        }

    except requests.exceptions.HTTPError as error:
        status_code = (
            error.response.status_code
            if error.response is not None
            else "unknown"
        )

        return {
            "status": "error",
            "message": (
                f"Google Safe Browsing returned HTTP {status_code}. "
                "Check API access, key restrictions, and quota."
            ),
            "threat_types": [],
        }

    except requests.exceptions.JSONDecodeError:
        return {
            "status": "error",
            "message": "Google Safe Browsing returned an invalid JSON response.",
            "threat_types": [],
        }

    except requests.exceptions.RequestException as error:
        return {
            "status": "error",
            "message": (
                f"Network request failed: {type(error).__name__}. "
                "Check your internet connection."
            ),
            "threat_types": [],
        }

    except (ValueError, TypeError, AttributeError):
        return {
            "status": "error",
            "message": "Google Safe Browsing returned an unexpected response.",
            "threat_types": [],
        }
