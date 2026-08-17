#!/usr/bin/env python3
"""Stream and validate a Windows JSONL replay without changing the source."""

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


REQUIRED_FIELDS = {
    "schema_version",
    "event_id",
    "timestamp",
    "channel",
    "event_code",
    "computer",
    "user",
    "image",
    "parent_image",
    "command_family",
    "command_line",
}

MAX_ERROR_SAMPLES = 20


def sha256_file(path: Path) -> str:
    """Calculate a file hash without loading the whole file into memory."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def valid_timestamp(value: object) -> bool:
    """Return True when value is a valid ISO-8601 UTC timestamp."""
    if not isinstance(value, str):
        return False

    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False

    return value.endswith("Z")


def add_error(
    errors: list[dict[str, object]],
    line_number: int,
    category: str,
    detail: str,
) -> None:
    """Save a bounded number of exact error locators."""
    if len(errors) < MAX_ERROR_SAMPLES:
        errors.append(
            {
                "line_number": line_number,
                "category": category,
                "detail": detail,
            }
        )


def validate_replay(input_path: Path) -> dict[str, object]:
    """Validate a JSONL replay and return a deterministic summary."""
    total_lines = 0
    valid_lines = 0
    invalid_lines = 0

    schema_versions: Counter[str] = Counter()
    channels: Counter[str] = Counter()
    event_codes: Counter[str] = Counter()
    error_categories: Counter[str] = Counter()
    errors: list[dict[str, object]] = []

    with input_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            total_lines += 1
            line = raw_line.strip()

            if not line:
                invalid_lines += 1
                error_categories["empty_line"] += 1
                add_error(errors, line_number, "empty_line", "Line is empty.")
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                invalid_lines += 1
                error_categories["invalid_json"] += 1
                add_error(
                    errors,
                    line_number,
                    "invalid_json",
                    f"Column {exc.colno}: {exc.msg}",
                )
                continue

            if not isinstance(event, dict):
                invalid_lines += 1
                error_categories["not_object"] += 1
                add_error(
                    errors,
                    line_number,
                    "not_object",
                    "JSON value is not an object.",
                )
                continue

            missing = sorted(REQUIRED_FIELDS - event.keys())

            if missing:
                invalid_lines += 1
                error_categories["missing_fields"] += 1
                add_error(
                    errors,
                    line_number,
                    "missing_fields",
                    ",".join(missing),
                )
                continue

            if not isinstance(event["event_code"], int):
                invalid_lines += 1
                error_categories["invalid_event_code"] += 1
                add_error(
                    errors,
                    line_number,
                    "invalid_event_code",
                    "event_code must be an integer.",
                )
                continue

            if not valid_timestamp(event["timestamp"]):
                invalid_lines += 1
                error_categories["invalid_timestamp"] += 1
                add_error(
                    errors,
                    line_number,
                    "invalid_timestamp",
                    "timestamp must be ISO-8601 UTC ending in Z.",
                )
                continue

            valid_lines += 1
            schema_versions[str(event["schema_version"])] += 1
            channels[str(event["channel"])] += 1
            event_codes[str(event["event_code"])] += 1

    return {
        "schema_version": "1.0",
        "input": {
            "file_name": input_path.name,
            "sha256": sha256_file(input_path),
        },
        "counts": {
            "total_lines": total_lines,
            "valid_lines": valid_lines,
            "invalid_lines": invalid_lines,
        },
        "observed": {
            "schema_versions": dict(sorted(schema_versions.items())),
            "channels": dict(sorted(channels.items())),
            "event_codes": dict(sorted(event_codes.items())),
        },
        "error_categories": dict(sorted(error_categories.items())),
        "error_samples": errors,
        "verdict": "valid" if invalid_lines == 0 else "malformed_input",
    }


def parse_args() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Validate a Windows JSONL replay."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to the source JSONL replay.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path for the machine-readable JSON result.",
    )
    return parser.parse_args()


def main() -> int:
    """Program entry point."""
    args = parse_args()

    if not args.input.is_file():
        print(f"Input is not a file: {args.input}", file=sys.stderr)
        return 3

    result = validate_replay(args.input)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        "validated"
        f" total={result['counts']['total_lines']}"
        f" valid={result['counts']['valid_lines']}"
        f" invalid={result['counts']['invalid_lines']}"
        f" verdict={result['verdict']}"
    )

    return 0 if result["verdict"] == "valid" else 2


if __name__ == "__main__":
    raise SystemExit(main())
