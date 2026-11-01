
from unittest.mock import Mock, patch

from app.reputation import check_url_reputation


@patch("app.reputation.requests.post")
@patch("app.reputation.os.getenv", return_value="test-api-key")
def test_known_threat_returns_unsafe(mock_env, mock_post):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "matches": [
            {
                "threat": {
                    "threatType": "SOCIAL_ENGINEERING"
                }
            }
        ]
    }
    mock_post.return_value = response

    result = check_url_reputation("https://example.test")

    assert result["status"] == "unsafe"
    assert "SOCIAL_ENGINEERING" in result["threat_types"]

    mock_post.assert_called_once()


@patch("app.reputation.requests.post")
@patch("app.reputation.os.getenv", return_value="test-api-key")
def test_no_known_threat_returns_safe(mock_env, mock_post):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {}
    mock_post.return_value = response

    result = check_url_reputation("https://example.test")

    assert result["status"] == "safe"
    assert result["threat_types"] == []

    mock_post.assert_called_once()


@patch("app.reputation.os.getenv", return_value=None)
def test_missing_api_key_returns_error(mock_env):
    result = check_url_reputation("https://example.test")

    assert result["status"] == "error"
    assert "not configured" in result["message"]
