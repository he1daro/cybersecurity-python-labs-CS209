from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client


def test_build_headers_without_api_key() -> None:
    headers = api_client.build_headers()
    assert headers == {"Accept": "application/json"}


def test_build_headers_ignores_whitespace_only_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NVD_API_KEY", "   \t  ")
    headers = api_client.build_headers()
    assert headers == {"Accept": "application/json"}


def test_build_headers_strips_valid_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NVD_API_KEY", "  test-secret-key-123  ")
    headers = api_client.build_headers()
    assert headers == {
        "Accept": "application/json",
        "apiKey": "test-secret-key-123",
    }


def test_fetch_response_success(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    result = api_client.fetch_response("CVE-2099-10001")

    assert result == payload
    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_response_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    response = Mock(spec=requests.Response)
    response.status_code = 404
    response.raise_for_status.side_effect = requests.HTTPError(
        "404 Client Error",
        response=response,
    )

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_unexpected_redirect_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = Mock(spec=requests.Response)
    response.status_code = 302

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.HTTPError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON",
        "{",
        1,
    )

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")


def test_fetch_response_network_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_get = Mock(side_effect=requests.Timeout("Connection timed out"))
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(requests.Timeout):
        api_client.fetch_response("CVE-2099-10001")
