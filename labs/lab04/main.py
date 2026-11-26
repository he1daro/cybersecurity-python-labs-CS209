import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_ID_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def load_response(path: str | Path) -> Any:
    """Read and parse a UTF-8 encoded JSON response from a local file."""
    raw_text = Path(path).read_text(encoding="utf-8")
    return json.loads(raw_text)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI utility to fetch or load a CVE record and print its JSON report."""
    if (
        not isinstance(VARIANT_NUMBER, int)
        or not (1 <= VARIANT_NUMBER <= 15)
    ):
        print(
            "Configuration error: VARIANT_NUMBER must be an integer between 1 and 15.",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser(
        description="Analyze a CVE record from NVD API 2.0 or a local JSON file."
    )
    parser.add_argument(
        "--cve",
        required=True,
        help="CVE identifier in format CVE-YYYY-NNNN.",
    )
    parser.add_argument(
        "--input",
        dest="input_path",
        default=None,
        help="Optional path to a local UTF-8 NVD JSON file.",
    )
    args = parser.parse_args(argv)

    if not CVE_ID_PATTERN.fullmatch(args.cve):
        parser.error("argument --cve: must match pattern CVE-[0-9]{4}-[0-9]{4,}")

    try:
        if args.input_path is not None:
            payload = load_response(args.input_path)
        else:
            payload = api_client.fetch_response(args.cve)

        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except UnicodeDecodeError:
        print("File error: input file is not valid UTF-8.", file=sys.stderr)
        return 1
    except json.JSONDecodeError:
        print("Data error: response is not valid JSON.", file=sys.stderr)
        return 1
    except requests.HTTPError as exc:
        status_code = (
            exc.response.status_code if exc.response is not None else "unknown"
        )
        print(f"HTTP error: NVD API returned status {status_code}.", file=sys.stderr)
        return 1
    except requests.Timeout:
        print("Network error: request to NVD API timed out.", file=sys.stderr)
        return 1
    except requests.ConnectionError:
        print("Network error: failed to connect to NVD API.", file=sys.stderr)
        return 1
    except requests.RequestException:
        print("Network error: NVD API request failed.", file=sys.stderr)
        return 1
    except OSError:
        print("File error: unable to read the specified input file.", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
