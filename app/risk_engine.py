
"""Unified risk assessment engine for PhishGuard."""

def classify_risk(score: int) -> str:
    """Convert a numerical score into a risk category."""

    if score >= 70:
        return "Critical"
    elif score >= 40:
        return "High"
    elif score >= 20:
        return "Medium"
    return "Low"


def build_risk_assessment(
    heuristic_report: dict,
    reputation_result: dict,
    urlscan_result: dict,
) -> dict:
    """
    Combine heuristic, Google Safe Browsing, and URLScan.io results.

    Confirmed threat intelligence can raise the score to 100.
    Unavailable or inconclusive services never reduce the score.
    """

    heuristic_score = heuristic_report.get("risk_score", 0)
    heuristic_score = max(0, min(int(heuristic_score), 100))

    reputation_status = reputation_result.get("status", "error")
    urlscan_status = urlscan_result.get("status", "error")

    findings = list(heuristic_report.get("findings", []))
    evidence = []

    # Start with the heuristic score.
    final_score = heuristic_score

    evidence.append({
        "source": "Heuristic Detector",
        "status": "complete",
        "message": (
            f"Heuristic analysis returned a score of "
            f"{heuristic_score}/100."
        )
    })

    # Google Safe Browsing assessment.
    if reputation_status == "unsafe":
        final_score = 100

        evidence.append({
            "source": "Google Safe Browsing",
            "status": "unsafe",
            "message": reputation_result.get(
                "message",
                "A known threat was identified."
            ),
            "threat_types": reputation_result.get(
                "threat_types", []
            )
        })

        findings.append({
            "rule": "GOOGLE_KNOWN_THREAT",
            "severity": "critical",
            "reason": "Google Safe Browsing identified a known threat."
        })

    elif reputation_status == "safe":
        evidence.append({
            "source": "Google Safe Browsing",
            "status": "no_match",
            "message": reputation_result.get("message", "")
        })

    else:
        evidence.append({
            "source": "Google Safe Browsing",
            "status": "unavailable",
            "message": reputation_result.get(
                "message",
                "Threat intelligence could not be retrieved."
            )
        })

    # URLScan.io assessment.
    if urlscan_status == "complete":
        malicious = urlscan_result.get("malicious")

        if malicious is True:
            final_score = 100

            findings.append({
                "rule": "URLSCAN_MALICIOUS",
                "severity": "critical",
                "reason": "URLScan.io reported the website as malicious."
            })

            scan_status = "malicious"

        elif malicious is False:
            scan_status = "no_malicious_verdict"

        else:
            scan_status = "inconclusive"

        evidence.append({
            "source": "URLScan.io",
            "status": scan_status,
            "message": urlscan_result.get(
                "message",
                "URLScan.io results were retrieved."
            ),
            "categories": urlscan_result.get("categories", []),
            "urlscan_score": urlscan_result.get("score"),
            "result_url": urlscan_result.get("result_url")
        })

    else:
        evidence.append({
            "source": "URLScan.io",
            "status": (
                "pending"
                if urlscan_status == "pending"
                else "unavailable"
            ),
            "message": urlscan_result.get(
                "message",
                "URLScan.io results are not available."
            )
        })

    final_score = min(final_score, 100)
    risk_level = classify_risk(final_score)

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "verdict": (
            "Potentially malicious"
            if final_score >= 70
            else "Suspicious"
            if final_score >= 40
            else "Needs attention"
            if final_score >= 20
            else "No strong indicators detected"
        ),
        "url": heuristic_report.get("url", ""),
        "findings": findings,
        "evidence": evidence,
        "heuristic_score": heuristic_score,
        "note": (
            "This assessment combines heuristic indicators and "
            "available threat-intelligence results. A low score "
            "or absence of reported threats does not guarantee "
            "that a URL is safe."
        )
    }
