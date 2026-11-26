import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main


def test_cli_local_input_generates_json_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-10001",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Offline sample."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": (
                                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
                                    ),
                                    "availabilityImpact": "LOW",
                                    "baseScore": 6.0,
                                },
                            }
                        ]
                    },
                }
            }
        ]
    }
    input_file = tmp_path / "sample.json"
    input_file.write_text(json.dumps(payload), encoding="utf-8")

    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(input_file)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["cve_id"] == "CVE-2099-10001"
    assert report["variant"] == 14
    assert report["observed"] == "LOW"
    assert report["decision"] == "review"


def test_cli_missing_file_returns_exit_code_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_file = tmp_path / "does_not_exist.json"

    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(missing_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "File error" in captured.err


def test_cli_invalid_json_file_returns_exit_code_1(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    broken_file = tmp_path / "broken.json"
    broken_file.write_text("{not valid json", encoding="utf-8")

    exit_code = main.main(["--cve", "CVE-2099-10001", "--input", str(broken_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "Data error" in captured.err


def test_cli_http_error_hides_secrets_and_body(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("NVD_API_KEY", "SECRET_TOKEN_DO_NOT_LEAK")
    fake_response = Mock(spec=requests.Response)
    fake_response.status_code = 403
    fake_response.text = "INTERNAL_SERVER_BODY_DUMP"

    def raise_http_error(cve_id: str) -> None:
        raise requests.HTTPError("403 Forbidden", response=fake_response)

    monkeypatch.setattr(api_client, "fetch_response", raise_http_error)

    exit_code = main.main(["--cve", "CVE-2021-44228"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "403" in captured.err
    assert "SECRET_TOKEN_DO_NOT_LEAK" not in captured.err
    assert "INTERNAL_SERVER_BODY_DUMP" not in captured.err


def test_cli_invalid_cve_format_exits_with_code_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main.main(["--cve", "cve-2021-44228"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert captured.out == ""
    assert "--cve" in captured.err


def test_cli_invalid_variant_number_returns_exit_code_2(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(main, "VARIANT_NUMBER", True)

    exit_code = main.main(["--cve", "CVE-2099-10001"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "VARIANT_NUMBER" in captured.err
