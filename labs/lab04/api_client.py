import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT: tuple[float, float] = (3.05, 10)


def build_headers() -> dict[str, str]:
    """Build HTTP headers for NVD API requests, including apiKey if configured."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key is not None:
        cleaned_key = api_key.strip()
        if cleaned_key:
            headers["apiKey"] = cleaned_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Fetch raw JSON payload for a single CVE identifier from NVD API 2.0."""
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise requests.HTTPError(
            f"Unexpected HTTP status code: {response.status_code}",
            response=response,
        )
    return response.json()
