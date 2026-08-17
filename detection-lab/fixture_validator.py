#!/usr/bin/env python3
"""Validate public or hidden detection fixtures without hard-coded case IDs."""

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ALLOWED_EXPECTED = {"alert", "no_alert"}

REQUIRED_FIXTURE_FIELDS = {
    "case_id",
    "events",
    "expected",
}

REQUIRED_EVENT_FIELDS = {
    "channel",
    "event_code",
    "event_id",
    "image",
    "parent_image",
}

MAX_ERROR_SAMPLES = 50


def sha256_file(path: Path) -> str:
    """Return the SHA-256 fingerprint of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def record_error(
    errors: list[dict[str, Any]],
    locator: str,
    category: str,
    detail: str,
) -> None:
    """Save a bounded error with an exact JSON-style locator."""
    if len(errors) < MAX_ERROR_SAMPLES:
        errors.append(
            {
                "locator": locator,
                "category": category,
                "detail": detail,
            }
        )


def validate_event(
    event: Any,
    locator: str,
    errors: list[dict[str, Any]],
    categories: Counter[str],
) -> bool:
    """Validate one event and return True when it is structurally valid."""
    valid = True

    if not isinstance(event, dict):
        categories["event_not_object"] += 1
        record_error(
            errors,
            locator,
            "event_not_object",
            "Event must be a JSON object.",
        )
        return False

    missing = sorted(REQUIRED_EVENT_FIELDS - event.keys())

    if missing:
        valid = False
        categories["missing_event_fields"] += 1
        record_error(
            errors,
            locator,
            "missing_event_fields",
            ",".join(missing),
        )

    if "event_code" in event and not isinstance(event["event_code"], int):
        valid = False
        categories["invalid_event_code"] += 1
        record_error(
            errors,
            f"{locator}/event_code",
            "invalid_event_code",
            "event_code must be an integer.",
        )

    if "event_id" in event and not isinstance(event["event_id"], int):
        valid = False
        categories["invalid_event_id"] += 1
        record_error(
            errors,
            f"{locator}/event_id",
            "invalid_event_id",
            "event_id must be an integer.",
        )

    if "delta_seconds" in event:
        delta = event["delta_seconds"]

        if (
            isinstance(delta, bool)
            or not isinstance(delta, (int, float))
            or delta < 0
        ):
            valid = False
            categories["invalid_delta_seconds"] += 1
            record_error(
                errors,
                f"{locator}/delta_seconds",
                "invalid_delta_seconds",
                "delta_seconds must be a non-negative number.",
            )

    for field in ("channel", "image", "parent_image"):
        if field in event and (
            not isinstance(event[field], str) or not event[field].strip()
        ):
            valid = False
            categories[f"invalid_{field}"] += 1
            record_error(
                errors,
                f"{locator}/{field}",
                f"invalid_{field}",
                f"{field} must be a non-empty string.",
            )

    return valid


def validate_document(document: Any, input_path: Path) -> dict[str, Any]:
    """Validate a fixture document and return a deterministic result."""
    errors: list[dict[str, Any]] = []
    categories: Counter[str] = Counter()
    expected_counts: Counter[str] = Counter()

    total_fixtures = 0
    total_events = 0
    valid_fixtures = 0
    invalid_fixtures = 0
    seen_case_ids: set[str] = set()

    if not isinstance(document, dict):
        categories["root_not_object"] += 1
        record_error(
            errors,
            "/",
            "root_not_object",
            "Document root must be a JSON object.",
        )
        fixture_list: list[Any] = []
    elif "fixtures" not in document:
        categories["missing_fixtures"] += 1
        record_error(
            errors,
            "/fixtures",
            "missing_fixtures",
            "Document must contain a fixtures field.",
        )
        fixture_list = []
    elif not isinstance(document["fixtures"], list):
        categories["fixtures_not_list"] += 1
        record_error(
            errors,
            "/fixtures",
            "fixtures_not_list",
            "fixtures must be a list.",
        )
        fixture_list = []
    else:
        fixture_list = document["fixtures"]

    for fixture_index, fixture in enumerate(fixture_list):
        total_fixtures += 1
        locator = f"/fixtures/{fixture_index}"
        fixture_valid = True

        if not isinstance(fixture, dict):
            categories["fixture_not_object"] += 1
            record_error(
                errors,
                locator,
                "fixture_not_object",
                "Fixture must be a JSON object.",
            )
            invalid_fixtures += 1
            continue

        missing = sorted(REQUIRED_FIXTURE_FIELDS - fixture.keys())

        if missing:
            fixture_valid = False
            categories["missing_fixture_fields"] += 1
            record_error(
                errors,
                locator,
                "missing_fixture_fields",
                ",".join(missing),
            )

        case_id = fixture.get("case_id")

        if not isinstance(case_id, str) or not case_id.strip():
            fixture_valid = False
            categories["invalid_case_id"] += 1
            record_error(
                errors,
                f"{locator}/case_id",
                "invalid_case_id",
                "case_id must be a non-empty string.",
            )
        elif case_id in seen_case_ids:
            fixture_valid = False
            categories["duplicate_case_id"] += 1
            record_error(
                errors,
                f"{locator}/case_id",
                "duplicate_case_id",
                "case_id must be unique within the input.",
            )
        else:
            seen_case_ids.add(case_id)

        expected = fixture.get("expected")

        if expected not in ALLOWED_EXPECTED:
            fixture_valid = False
            categories["invalid_expected"] += 1
            record_error(
                errors,
                f"{locator}/expected",
                "invalid_expected",
                "expected must be alert or no_alert.",
            )
        else:
            expected_counts[expected] += 1

        events = fixture.get("events")

        if not isinstance(events, list) or not events:
            fixture_valid = False
            categories["invalid_events"] += 1
            record_error(
                errors,
                f"{locator}/events",
                "invalid_events",
                "events must be a non-empty list.",
            )
        else:
            total_events += len(events)

            for event_index, event in enumerate(events):
                event_locator = f"{locator}/events/{event_index}"

                if not validate_event(
                    event,
                    event_locator,
                    errors,
                    categories,
                ):
                    fixture_valid = False

        if fixture_valid:
            valid_fixtures += 1
        else:
            invalid_fixtures += 1

    verdict = (
        "valid"
        if not categories and isinstance(document, dict)
        else "malformed_input"
    )

    return {
        "schema_version": "1.0",
        "input": {
            "file_name": input_path.name,
            "sha256": sha256_file(input_path),
        },
        "counts": {
            "total_fixtures": total_fixtures,
            "valid_fixtures": valid_fixtures,
            "invalid_fixtures": invalid_fixtures,
            "total_events": total_events,
        },
        "expected_counts": dict(sorted(expected_counts.items())),
        "error_categories": dict(sorted(categories.items())),
        "error_samples": errors,
        "verdict": verdict,
    }


def malformed_document_result(
    input_path: Path,
    category: str,
    detail: str,
) -> dict[str, Any]:
    """Create a deterministic result when the whole document cannot load."""
    return {
        "schema_version": "1.0",
        "input": {
            "file_name": input_path.name,
            "sha256": sha256_file(input_path),
        },
        "counts": {
            "total_fixtures": 0,
            "valid_fixtures": 0,
            "invalid_fixtures": 0,
            "total_events": 0,
        },
        "expected_counts": {},
        "error_categories": {category: 1},
        "error_samples": [
            {
                "locator": "/",
                "category": category,
                "detail": detail,
            }
        ],
        "verdict": "malformed_input",
    }


def parse_args() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate detection fixture JSON."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to a fixture JSON file.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path for the validation result.",
    )
    return parser.parse_args()


def main() -> int:
    """Run validation and return a meaningful process exit code."""
    args = parse_args()

    if not args.input.is_file():
        print(f"Input is not a file: {args.input}", file=sys.stderr)
        return 3

    try:
        with args.input.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
    except UnicodeDecodeError as exc:
        result = malformed_document_result(
            args.input,
            "invalid_encoding",
            str(exc),
        )
    except json.JSONDecodeError as exc:
        result = malformed_document_result(
            args.input,
            "invalid_json",
            f"Line {exc.lineno}, column {exc.colno}: {exc.msg}",
        )
    else:
        result = validate_document(document, args.input)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        "validated"
        f" fixtures={result['counts']['total_fixtures']}"
        f" valid={result['counts']['valid_fixtures']}"
        f" invalid={result['counts']['invalid_fixtures']}"
        f" verdict={result['verdict']}"
    )

    return 0 if result["verdict"] == "valid" else 2


if __name__ == "__main__":
    raise SystemExit(main())
