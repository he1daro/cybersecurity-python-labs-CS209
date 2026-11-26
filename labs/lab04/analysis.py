import math
import re
from typing import Any

CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

VARIANT_RULE: dict[int, dict[str, Any]] = {
    14: {"threshold": 6.0, "field": "availabilityImpact", "expected": "LOW"},
}

ALLOWED_METRIC_VALUE: dict[str, set[str]] = {
    "availabilityImpact": {"NONE", "LOW", "HIGH"},
}


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Validate NVD payload and return an internal CVE record or None if not found.

    Internal record keys:
        cve_id (str): Requested CVE identifier.
        vuln_status (str | None): NVD vulnerability status or None if absent.
        description (str | None): First non-empty English description or None.
        cvss_version (str | None): CVSS version ('3.1') or None.
        score (float | None): Selected CVSS v3.1 baseScore or None.
        score_source (str | None): Source of the selected metric or None.
        vector (str | None): CVSS vectorString or None.
        cvss_data (dict[str, Any] | None): Shallow copy of selected cvssData or None.
    """
    if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError(f"Invalid CVE identifier: {cve_id!r}")
    is_dict_payload = isinstance(payload, dict)
    if not is_dict_payload:
        raise ValueError("NVD response payload must be a JSON object")

    vulnerabilities = payload.get("vulnerabilities")
    is_list_vulns = isinstance(vulnerabilities, list)
    if not is_list_vulns:
        raise ValueError("Field 'vulnerabilities' must be a list")
    if len(vulnerabilities) > 1:
        raise ValueError(
            "Expected at most one vulnerability record for exact CVE lookup"
        )
    if not vulnerabilities:
        return None

    item = vulnerabilities[0]
    has_cve_dict = isinstance(item, dict) and isinstance(item.get("cve"), dict)
    if not has_cve_dict:
        raise ValueError("Vulnerability entry must contain a 'cve' object")

    cve_obj = item["cve"]
    record_id = cve_obj.get("id")
    if not isinstance(record_id, str) or record_id != cve_id:
        raise ValueError("Returned CVE identifier does not match requested cve_id")

    vuln_status: str | None = None
    if "vulnStatus" in cve_obj:
        raw_status = cve_obj["vulnStatus"]
        if not isinstance(raw_status, str) or not raw_status.strip():
            raise ValueError("Field 'vulnStatus' must be a non-empty string")
        vuln_status = raw_status

    description: str | None = None
    if "descriptions" in cve_obj:
        descriptions = cve_obj["descriptions"]
        if not isinstance(descriptions, list):
            raise ValueError("Field 'descriptions' must be a list")
        for entry in descriptions:
            is_dict_entry = isinstance(entry, dict)
            if not is_dict_entry:
                raise ValueError("Each description entry must be an object")
            lang = entry.get("lang")
            value = entry.get("value")
            has_str_fields = isinstance(lang, str) and isinstance(value, str)
            if not has_str_fields:
                raise ValueError("Description 'lang' and 'value' must be strings")
            if description is None and lang == "en" and value.strip():
                description = value

    if vuln_status is None or vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "vuln_status": vuln_status,
            "description": description,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    metric_list: list[Any] = []
    if "metrics" in cve_obj:
        metrics = cve_obj["metrics"]
        if not isinstance(metrics, dict):
            raise ValueError("Field 'metrics' must be an object")
        if "cvssMetricV31" in metrics:
            raw_metrics = metrics["cvssMetricV31"]
            if not isinstance(raw_metrics, list):
                raise ValueError("Field 'cvssMetricV31' must be a list")
            metric_list = raw_metrics

    if not metric_list:
        return {
            "cve_id": cve_id,
            "vuln_status": vuln_status,
            "description": description,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "cvss_data": None,
        }

    if not all(isinstance(metric, dict) for metric in metric_list):
        raise ValueError("Every element in 'cvssMetricV31' must be an object")

    selected_metric = metric_list[0]
    for metric in metric_list:
        if metric.get("type") == "Primary":
            selected_metric = metric
            break

    cvss_data = selected_metric.get("cvssData")
    has_cvss_data = isinstance(cvss_data, dict)
    if not has_cvss_data:
        raise ValueError("Selected CVSS metric must contain a 'cvssData' object")

    if "baseScore" not in cvss_data:
        raise ValueError("Selected 'cvssData' is missing required 'baseScore'")
    raw_score = cvss_data["baseScore"]
    is_valid_number = not isinstance(raw_score, bool) and isinstance(
        raw_score, (int, float)
    )
    if not is_valid_number:
        raise ValueError("Field 'baseScore' must be a finite number, not bool")
    score = float(raw_score)
    if not math.isfinite(score) or not (0.0 <= score <= 10.0):
        raise ValueError("Field 'baseScore' must be within [0, 10]")

    cvss_version: str | None = None
    if "version" in cvss_data:
        raw_version = cvss_data["version"]
        if not isinstance(raw_version, str) or not raw_version.strip():
            raise ValueError("Field 'version' must be a non-empty string")
        if raw_version != "3.1":
            raise ValueError(f"Unsupported CVSS version: {raw_version}")
        cvss_version = raw_version

    vector: str | None = None
    if "vectorString" in cvss_data:
        raw_vector = cvss_data["vectorString"]
        if not isinstance(raw_vector, str) or not raw_vector.strip():
            raise ValueError("Field 'vectorString' must be a non-empty string")
        vector = raw_vector

    score_source: str | None = None
    if "source" in selected_metric:
        raw_source = selected_metric["source"]
        if not isinstance(raw_source, str) or not raw_source.strip():
            raise ValueError("Field 'source' must be a non-empty string")
        score_source = raw_source

    return {
        "cve_id": cve_id,
        "vuln_status": vuln_status,
        "description": description,
        "cvss_version": cvss_version,
        "score": score,
        "score_source": score_source,
        "vector": vector,
        "cvss_data": dict(cvss_data),
    }


def build_report(
    record: dict[str, Any] | None,
    cve_id: str,
    variant: int,
) -> dict[str, Any]:
    """Apply the variant rule to an extracted CVE record and build the final report."""
    if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError(f"Invalid CVE identifier: {cve_id!r}")
    is_int_variant = not isinstance(variant, bool) and isinstance(variant, int)
    if not is_int_variant:
        raise ValueError("Variant number must be an integer")
    if variant not in VARIANT_RULE:
        raise ValueError(f"Unsupported variant number: {variant}")

    rule = dict(VARIANT_RULE[variant])
    if record is None:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": None,
            "vuln_status": None,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "not_found",
        }

    is_dict_record = isinstance(record, dict)
    if not is_dict_record:
        raise ValueError("Record must be a dictionary or None")

    vuln_status = record.get("vuln_status")
    description = record.get("description")

    if vuln_status == "Rejected":
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "rejected",
        }

    score = record.get("score")
    cvss_data = record.get("cvss_data")
    if vuln_status is None or score is None or not isinstance(cvss_data, dict):
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": None,
            "score": None,
            "score_source": None,
            "vector": None,
            "rule": rule,
            "observed": None,
            "decision": "insufficient_data",
        }

    field = rule["field"]
    if field not in cvss_data:
        return {
            "cve_id": cve_id,
            "variant": variant,
            "description": description,
            "vuln_status": vuln_status,
            "cvss_version": record.get("cvss_version"),
            "score": score,
            "score_source": record.get("score_source"),
            "vector": record.get("vector"),
            "rule": rule,
            "observed": None,
            "decision": "insufficient_data",
        }

    observed = cvss_data[field]
    if not isinstance(observed, str) or observed not in ALLOWED_METRIC_VALUE[field]:
        raise ValueError(f"Invalid value {observed!r} for metric field '{field}'")

    decision = (
        "review"
        if score >= rule["threshold"] and observed == rule["expected"]
        else "other"
    )

    return {
        "cve_id": cve_id,
        "variant": variant,
        "description": description,
        "vuln_status": vuln_status,
        "cvss_version": record.get("cvss_version"),
        "score": score,
        "score_source": record.get("score_source"),
        "vector": record.get("vector"),
        "rule": rule,
        "observed": observed,
        "decision": decision,
    }
