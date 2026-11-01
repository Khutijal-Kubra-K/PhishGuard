
import requests


from app.urlscan import (
    get_urlscan_result,
    submit_url_for_scanning,
)

def test_submit_url_success(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    class MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "uuid": "test-scan-123",
                "result": (
                    "https://urlscan.io/result/test-scan-123/"
                ),
            }

    def mock_post(*args, **kwargs):
        assert args[0] == (
            "https://urlscan.io/api/v1/scan/"
        )
        assert kwargs["headers"]["api-key"] == "test-api-key"
        assert kwargs["json"]["url"] == "https://example.com"
        assert kwargs["json"]["visibility"] == "unlisted"
        return MockResponse()

    monkeypatch.setattr(requests, "post", mock_post)

    result = submit_url_for_scanning("https://example.com")

    assert result["status"] == "submitted"
    assert result["scan_id"] == "test-scan-123"
    assert result["result_url"] == (
        "https://urlscan.io/result/test-scan-123/"
    )


def test_submit_url_missing_api_key(monkeypatch):
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)

    result = submit_url_for_scanning("https://example.com")

    assert result["status"] == "error"
    assert "API key" in result["message"]


def test_submit_url_rate_limit(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    class MockResponse:
        status_code = 429

        def raise_for_status(self):
            pass

    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: MockResponse(),
    )

    result = submit_url_for_scanning("https://example.com")

    assert result["status"] == "error"
    assert "rate limit" in result["message"].lower()


def test_submit_url_timeout(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    def mock_post(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(requests, "post", mock_post)

    result = submit_url_for_scanning("https://example.com")

    assert result["status"] == "error"
    assert "timed out" in result["message"].lower()


def test_submit_url_invalid_json(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    class MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            raise ValueError("Invalid JSON")

    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: MockResponse(),
    )

    result = submit_url_for_scanning("https://example.com")

    assert result["status"] == "error"
    assert "invalid response" in result["message"].lower()


def test_submit_url_missing_scan_id(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    class MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"message": "Submission successful"}

    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: MockResponse(),
    )

    result = submit_url_for_scanning("https://example.com")

    assert result["status"] == "error"
    assert "scan ID" in result["message"]
def test_get_completed_scan_result(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    class MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "page": {
                    "title": "Example Domain",
                    "domain": "example.com",
                    "ip": "203.0.113.10",
                    "country": "US",
                },
                "verdicts": {
                    "overall": {
                        "hasVerdicts": True,
                        "malicious": False,
                        "score": -100,
                        "categories": [],
                    }
                },
            }

    monkeypatch.setattr(
        "app.urlscan.requests.get",
        lambda *args, **kwargs: MockResponse(),
    )

    result = get_urlscan_result("test-scan-id")

    assert result["status"] == "complete"
    assert result["page_title"] == "Example Domain"
    assert result["domain"] == "example.com"
    assert result["malicious"] is False
    assert result["score"] == -100


def test_get_scan_result_pending(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    class MockResponse:
        status_code = 404

    monkeypatch.setattr(
        "app.urlscan.requests.get",
        lambda *args, **kwargs: MockResponse(),
    )

    result = get_urlscan_result("test-scan-id")

    assert result["status"] == "pending"


def test_get_scan_result_gone(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    class MockResponse:
        status_code = 410

    monkeypatch.setattr(
        "app.urlscan.requests.get",
        lambda *args, **kwargs: MockResponse(),
    )

    result = get_urlscan_result("test-scan-id")

    assert result["status"] == "error"


def test_get_scan_result_missing_api_key(monkeypatch):
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)

    result = get_urlscan_result("test-scan-id")

    assert result["status"] == "error"
    assert "API key" in result["message"]


def test_get_scan_result_timeout(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    def mock_get(*args, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(
        "app.urlscan.requests.get",
        mock_get,
    )

    result = get_urlscan_result("test-scan-id")

    assert result["status"] == "error"
    assert "timed out" in result["message"]


def test_get_scan_result_invalid_json(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "test-api-key")

    class MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            raise ValueError("Invalid JSON")

    monkeypatch.setattr(
        "app.urlscan.requests.get",
        lambda *args, **kwargs: MockResponse(),
    )

    result = get_urlscan_result("test-scan-id")

    assert result["status"] == "error"
    assert "invalid response" in result["message"]