import copy
import json
from pathlib import Path
from typing import Any

import pytest

from labs.lab04 import analysis

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


def test_sample_payload_variant_14_returns_other(
    sample_payload: dict[str, Any],
) -> None:
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report == {
        "cve_id": "CVE-2099-10001",
        "variant": 14,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {
            "threshold": 6.0,
            "field": "availabilityImpact",
            "expected": "LOW",
        },
        "observed": "HIGH",
        "decision": "other",
    }


@pytest.mark.parametrize(
    ("score", "expected_decision"),
    [(5.9, "other"), (6.0, "review"), (6.1, "review")],
)
def test_variant_14_threshold_boundaries(
    sample_payload: dict[str, Any],
    score: float,
    expected_decision: str,
) -> None:
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["availabilityImpact"] = "LOW"
    cvss_data["baseScore"] = score

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report["observed"] == "LOW"
    assert report["score"] == score
    assert report["decision"] == expected_decision


def test_variant_14_high_score_with_none_impact_returns_other(
    sample_payload: dict[str, Any],
) -> None:
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["availabilityImpact"] = "NONE"
    cvss_data["baseScore"] = 9.1

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report["observed"] == "NONE"
    assert report["decision"] == "other"


def test_not_found_record_sets_null_data_fields() -> None:
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    record = analysis.extract_record(payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert record is None
    assert report == {
        "cve_id": "CVE-2099-10001",
        "variant": 14,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {
            "threshold": 6.0,
            "field": "availabilityImpact",
            "expected": "LOW",
        },
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_record_skips_cvss_scoring(sample_payload: dict[str, Any]) -> None:
    cve_obj = sample_payload["vulnerabilities"][0]["cve"]
    cve_obj["vulnStatus"] = "Rejected"
    cve_obj["metrics"]["cvssMetricV31"][0]["cvssData"]["availabilityImpact"] = "LOW"

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["cvss_version"] is None
    assert report["observed"] is None
    assert report["decision"] == "rejected"


def test_missing_vuln_status_returns_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    del sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"]

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report["vuln_status"] is None
    assert report["score"] is None
    assert report["observed"] is None
    assert report["decision"] == "insufficient_data"


def test_missing_cvss_v31_returns_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    del sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report["score"] is None
    assert report["observed"] is None
    assert report["decision"] == "insufficient_data"


def test_missing_variant_field_returns_insufficient_data(
    sample_payload: dict[str, Any],
) -> None:
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    del cvss_data["availabilityImpact"]

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report["score"] == 9.8
    assert report["observed"] is None
    assert report["decision"] == "insufficient_data"


@pytest.mark.parametrize("bad_value", [None, 123, "MEDIUM", ""])
def test_invalid_variant_field_value_raises_value_error(
    sample_payload: dict[str, Any],
    bad_value: Any,
) -> None:
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["availabilityImpact"] = bad_value

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    with pytest.raises(ValueError):
        analysis.build_report(record, "CVE-2099-10001", 14)


@pytest.mark.parametrize("bad_score", [True, False, "9.8", -0.1, 10.1, float("nan")])
def test_invalid_base_score_raises_value_error(
    sample_payload: dict[str, Any],
    bad_score: Any,
) -> None:
    cvss_data = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][
        0
    ]["cvssData"]
    cvss_data["baseScore"] = bad_score

    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, "CVE-2099-10001")


def test_primary_metric_has_priority_over_earlier_secondary(
    sample_payload: dict[str, Any],
) -> None:
    secondary_metric = {
        "source": "cna@example.org",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "availabilityImpact": "HIGH",
            "baseScore": 9.8,
        },
    }
    primary_metric = {
        "source": "nvd@nist.gov",
        "type": "Primary",
        "cvssData": {
            "version": "3.1",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
            "availabilityImpact": "LOW",
            "baseScore": 6.5,
        },
    }
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        secondary_metric,
        primary_metric,
    ]

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report["score"] == 6.5
    assert report["score_source"] == "nvd@nist.gov"
    assert report["observed"] == "LOW"
    assert report["decision"] == "review"


def test_fallback_to_first_metric_when_no_primary(
    sample_payload: dict[str, Any],
) -> None:
    first_secondary = {
        "source": "first@example.org",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "availabilityImpact": "LOW",
            "baseScore": 6.2,
        },
    }
    second_secondary = {
        "source": "second@example.org",
        "type": "Secondary",
        "cvssData": {
            "version": "3.1",
            "availabilityImpact": "HIGH",
            "baseScore": 9.0,
        },
    }
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [
        first_secondary,
        second_secondary,
    ]

    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    report = analysis.build_report(record, "CVE-2099-10001", 14)

    assert report["score"] == 6.2
    assert report["score_source"] == "first@example.org"
    assert report["decision"] == "review"


def test_extract_and_build_do_not_mutate_payload(
    sample_payload: dict[str, Any],
) -> None:
    snapshot = copy.deepcopy(sample_payload)
    record = analysis.extract_record(sample_payload, "CVE-2099-10001")
    analysis.build_report(record, "CVE-2099-10001", 14)

    assert sample_payload == snapshot
