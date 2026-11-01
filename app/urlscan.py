
import os

import requests
from dotenv import load_dotenv

load_dotenv()

URLSCAN_API_URL = "https://urlscan.io/api/v1/scan/"


def submit_url_for_scanning(url: str) -> dict:
    """Submit a URL to URLScan.io for analysis."""

    api_key = os.getenv("URLSCAN_API_KEY")

    if not api_key:
        return {
            "status": "error",
            "message": "URLScan.io API key is not configured.",
        }

    try:
        response = requests.post(
            URLSCAN_API_URL,
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
            },
            json={
                "url": url,
                "visibility": "unlisted",
            },
            timeout=15,
        )

        if response.status_code == 429:
            return {
                "status": "error",
                "message": "URLScan.io rate limit reached. Try again later.",
            }

        response.raise_for_status()
        data = response.json()

        scan_id = data.get("uuid")

        if not scan_id:
            return {
                "status": "error",
                "message": "URLScan.io did not return a scan ID.",
            }

        return {
            "status": "submitted",
            "scan_id": scan_id,
            "result_url": data.get(
                "result",
                f"https://urlscan.io/result/{scan_id}/",
            ),
            "message": "URL submitted successfully. Results may take time.",
        }

    except requests.Timeout:
        return {
            "status": "error",
            "message": "URLScan.io request timed out.",
        }
    except requests.RequestException:
        return {
            "status": "error",
            "message": "Could not connect to URLScan.io.",
        }
    except ValueError:
        return {
            "status": "error",
            "message": "URLScan.io returned an invalid response.",
        }

def get_urlscan_result(scan_id: str) -> dict:
    """Retrieve a completed URLScan.io report."""

    api_key = os.getenv("URLSCAN_API_KEY")

    if not api_key:
        return {
            "status": "error",
            "message": "URLScan.io API key is not configured.",
        }

    if not scan_id or "/" in scan_id:
        return {
            "status": "error",
            "message": "A valid scan ID is required.",
        }

    result_api_url = (
        f"https://urlscan.io/api/v1/result/{scan_id}/"
    )

    try:
        response = requests.get(
            result_api_url,
            headers={"api-key": api_key},
            timeout=15,
        )

        if response.status_code == 404:
            return {
                "status": "pending",
                "message": (
                    "The scan is still processing. "
                    "Please check again later."
                ),
            }

        if response.status_code == 410:
            return {
                "status": "error",
                "message": "This scan result is no longer available.",
            }

        response.raise_for_status()
        data = response.json()

        page = data.get("page", {})
        verdicts = data.get("verdicts", {})
        urlscan_verdict = verdicts.get("urlscan", {})
        overall_verdict = verdicts.get("overall", {})

        verdict = (
            overall_verdict
            if overall_verdict.get("hasVerdicts")
            else urlscan_verdict
        )

        return {
            "status": "complete",
            "message": "URLScan.io scan results retrieved.",
            "result_url": (
                f"https://urlscan.io/result/{scan_id}/"
            ),
            "page_title": page.get("title", "Unknown"),
            "domain": page.get("domain", "Unknown"),
            "ip": page.get("ip", "Unknown"),
            "country": page.get("country", "Unknown"),
            "malicious": verdict.get("malicious"),
            "score": verdict.get("score"),
            "categories": verdict.get("categories", []),
        }

    except requests.Timeout:
        return {
            "status": "error",
            "message": "URLScan.io result request timed out.",
        }
    except requests.RequestException:
        return {
            "status": "error",
            "message": "Could not retrieve URLScan.io results.",
        }
    except ValueError:
        return {
            "status": "error",
            "message": "URLScan.io returned an invalid response.",
        }
