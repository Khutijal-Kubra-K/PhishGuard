
import pytest

from app.risk_engine import (
    classify_risk,
    build_risk_assessment,
)


@pytest.mark.parametrize(
    "score, expected",
    [
        (0, "Low"),
        (19, "Low"),
        (20, "Medium"),
        (39, "Medium"),
        (40, "High"),
        (69, "High"),
        (70, "Critical"),
        (100, "Critical"),
    ],
)
def test_classify_risk(score, expected):
    assert classify_risk(score) == expected


def make_heuristic_report(score=10):
    return {
        "url": "https://example.com",
        "risk_score": score,
        "findings": [],
    }


def make_safe_reputation():
    return {
        "status": "safe",
        "message": "No known threats reported.",
        "threat_types": [],
    }


def make_no_urlscan_result():
    return {
        "status": "error",
        "message": "URLScan result unavailable.",
    }


def test_heuristic_score_is_preserved():
    report = build_risk_assessment(
        make_heuristic_report(30),
        make_safe_reputation(),
        make_no_urlscan_result(),
    )

    assert report["risk_score"] == 30
    assert report["risk_level"] == "Medium"
    assert report["heuristic_score"] == 30


def test_google_known_threat_sets_critical_score():
    reputation = {
        "status": "unsafe",
        "message": "Known threat identified.",
        "threat_types": ["SOCIAL_ENGINEERING"],
    }

    report = build_risk_assessment(
        make_heuristic_report(10),
        reputation,
        make_no_urlscan_result(),
    )

    assert report["risk_score"] == 100
    assert report["risk_level"] == "Critical"

    rules = [item["rule"] for item in report["findings"]]
    assert "GOOGLE_KNOWN_THREAT" in rules


def test_urlscan_malicious_sets_critical_score():
    urlscan = {
        "status": "complete",
        "malicious": True,
        "score": 100,
        "categories": ["phishing"],
        "message": "Malicious website detected.",
        "result_url": "https://urlscan.io/result/test/",
    }

    report = build_risk_assessment(
        make_heuristic_report(5),
        make_safe_reputation(),
        urlscan,
    )

    assert report["risk_score"] == 100
    assert report["risk_level"] == "Critical"

    rules = [item["rule"] for item in report["findings"]]
    assert "URLSCAN_MALICIOUS" in rules


def test_pending_urlscan_does_not_mean_safe():
    urlscan = {
        "status": "pending",
        "message": "Scan is still processing.",
    }

    report = build_risk_assessment(
        make_heuristic_report(25),
        make_safe_reputation(),
        urlscan,
    )

    assert report["risk_score"] == 25
    assert report["risk_level"] == "Medium"

    statuses = {
        item["source"]: item["status"]
        for item in report["evidence"]
    }

    assert statuses["URLScan.io"] == "pending"


def test_api_errors_do_not_reduce_heuristic_score():
    reputation = {
        "status": "error",
        "message": "Google API unavailable.",
    }

    report = build_risk_assessment(
        make_heuristic_report(50),
        reputation,
        make_no_urlscan_result(),
    )

    assert report["risk_score"] == 50
    assert report["risk_level"] == "High"


def test_non_malicious_urlscan_result_does_not_guarantee_safety():
    urlscan = {
        "status": "complete",
        "malicious": False,
        "score": 0,
        "categories": [],
        "message": "No malicious verdict reported.",
    }

    report = build_risk_assessment(
        make_heuristic_report(30),
        make_safe_reputation(),
        urlscan,
    )

    assert report["risk_score"] == 30
    assert report["risk_level"] == "Medium"


def test_assessment_contains_evidence_and_verdict():
    report = build_risk_assessment(
        make_heuristic_report(10),
        make_safe_reputation(),
        make_no_urlscan_result(),
    )

    assert "verdict" in report
    assert "evidence" in report
    assert "findings" in report
    assert "note" in report
    assert len(report["evidence"]) == 3
