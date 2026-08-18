#!/usr/bin/env python3
"""Run semantic detection fixtures without matching case IDs or commands."""

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


CORE_EVENT_FIELDS = {
    "channel",
    "event_code",
    "event_id",
    "image",
    "parent_image",
}


def sha256_file(path: Path) -> str:
    """Return the SHA-256 fingerprint of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def normalized_binary(value: Any) -> str:
    """Return a lowercase executable basename for comparison."""
    if not isinstance(value, str):
        return ""

    normalized = value.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1].lower()


def normalized_channel(value: Any) -> str:
    """Map short and full Windows channel names to one meaning."""
    if not isinstance(value, str):
        return ""

    channel = value.strip().lower()

    if "sysmon" in channel:
        return "sysmon"

    if channel == "security" or channel.endswith("/security"):
        return "security"

    return channel


def validate_policy(policy: Any) -> list[str]:
    """Return policy problems; an empty list means valid."""
    errors: list[str] = []

    required = {
        "correlation_window_seconds",
        "sysmon_process_channel",
        "sysmon_process_event_code",
        "security_process_channel",
        "security_process_event_code",
        "detection_techniques",
    }

    if not isinstance(policy, dict):
        return ["Policy root must be an object."]

    missing = sorted(required - policy.keys())

    if missing:
        errors.append("Missing policy fields: " + ",".join(missing))
        return errors

    window = policy["correlation_window_seconds"]

    if (
        isinstance(window, bool)
        or not isinstance(window, (int, float))
        or window < 0
    ):
        errors.append(
            "correlation_window_seconds must be a non-negative number."
        )

    techniques = policy["detection_techniques"]

    if (
        not isinstance(techniques, list)
        or not techniques
        or not all(
            isinstance(item, str) and item.strip()
            for item in techniques
        )
    ):
        errors.append(
            "detection_techniques must be a non-empty string list."
        )

    return errors


def decode_events(
    events: Any,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate event fields and return decoded events and errors."""
    errors: list[str] = []

    if not isinstance(events, list):
        return [], ["events must be a list."]

    if not events:
        return [], []

    decoded: list[dict[str, Any]] = []

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            errors.append(
                f"/events/{index}: event must be an object."
            )
            continue

        missing = sorted(CORE_EVENT_FIELDS - event.keys())

        if missing:
            errors.append(
                f"/events/{index}: missing fields {','.join(missing)}"
            )
            continue

        if not isinstance(event["event_code"], int):
            errors.append(
                f"/events/{index}/event_code: must be an integer."
            )
            continue

        for field in ("channel", "image", "parent_image"):
            if (
                not isinstance(event[field], str)
                or not event[field].strip()
            ):
                errors.append(
                    f"/events/{index}/{field}: "
                    "must be a non-empty string."
                )

        decoded.append(event)

    return decoded, errors


def semantic_match(
    events: list[dict[str, Any]],
    policy: dict[str, Any],
) -> tuple[bool, list[str], str]:
    """Return detection decision, evidence locators and explanation."""
    techniques = set(policy["detection_techniques"])
    window = float(policy["correlation_window_seconds"])

    configured_sysmon_channel = normalized_channel(
        policy["sysmon_process_channel"]
    )
    configured_security_channel = normalized_channel(
        policy["security_process_channel"]
    )

    sysmon_candidates: list[tuple[int, dict[str, Any]]] = []
    security_candidates: list[tuple[int, dict[str, Any]]] = []

    for index, event in enumerate(events):
        channel = normalized_channel(event["channel"])
        event_code = event["event_code"]

        if (
            channel == configured_sysmon_channel
            and event_code == policy["sysmon_process_event_code"]
        ):
            technique_id = event.get("technique_id")

            if (
                isinstance(technique_id, str)
                and technique_id in techniques
            ):
                sysmon_candidates.append((index, event))

        if (
            channel == configured_security_channel
            and event_code == policy["security_process_event_code"]
        ):
            security_candidates.append((index, event))

    if not sysmon_candidates:
        return (
            False,
            [],
            "No Sysmon process event matched the configured techniques.",
        )

    for sysmon_index, sysmon_event in sysmon_candidates:
        sysmon_image = normalized_binary(sysmon_event["image"])
        sysmon_parent = normalized_binary(
            sysmon_event["parent_image"]
        )

        for security_index, security_event in security_candidates:
            security_image = normalized_binary(
                security_event["image"]
            )
            security_parent = normalized_binary(
                security_event["parent_image"]
            )

            delta = security_event.get("delta_seconds")

            if (
                isinstance(delta, bool)
                or not isinstance(delta, (int, float))
            ):
                continue

            same_process = (
                sysmon_image == security_image
                and sysmon_parent == security_parent
            )

            inside_window = 0 <= float(delta) <= window

            if same_process and inside_window:
                return (
                    True,
                    [
                        f"/events/{sysmon_index}",
                        f"/events/{security_index}",
                    ],
                    "Correlated Sysmon 1 and Security 4688 "
                    "process events.",
                )

    return (
        False,
        [
            f"/events/{index}"
            for index, _ in sysmon_candidates
        ],
        "Technique matched, but no related Security 4688 event "
        "matched the process, parent and time window.",
    )


def classify_fixture(
    fixture: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Classify one fixture and compare detection with expectation."""
    case_id = fixture.get("case_id")
    expected = fixture.get("expected")
    events = fixture.get("events")

    decoded, decode_errors = decode_events(events)

    if isinstance(events, list) and not events:
        status = "no_telemetry"
        detected = False
        locators: list[str] = []
        explanation = "The fixture contained no telemetry events."

    elif decode_errors:
        status = "decoder_failure"
        detected = False
        locators = []
        explanation = "; ".join(decode_errors)

    else:
        detected, locators, explanation = semantic_match(
            decoded,
            policy,
        )

        if detected:
            status = "alerted"
        elif expected == "alert":
            status = "rule_miss"
        else:
            status = "suppressed"

    predicted = "alert" if detected else "no_alert"
    matched_expectation = predicted == expected

    return {
        "case_id": case_id,
        "expected": expected,
        "predicted": predicted,
        "status": status,
        "matched_expectation": matched_expectation,
        "evidence_locators": locators,
        "explanation": explanation,
    }


def run_suite(
    fixture_document: dict[str, Any],
    policy: dict[str, Any],
    fixture_path: Path,
    policy_path: Path,
) -> dict[str, Any]:
    """Run every fixture and return deterministic results."""
    results = [
        classify_fixture(fixture, policy)
        for fixture in fixture_document["fixtures"]
    ]

    status_counts = Counter(
        result["status"] for result in results
    )

    passed = sum(
        result["matched_expectation"] for result in results
    )

    failed = len(results) - passed

    return {
        "schema_version": "1.0",
        "inputs": {
            "fixture": {
                "file_name": fixture_path.name,
                "sha256": sha256_file(fixture_path),
            },
            "policy": {
                "file_name": policy_path.name,
                "sha256": sha256_file(policy_path),
            },
        },
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "status_counts": dict(
                sorted(status_counts.items())
            ),
        },
        "results": results,
        "verdict": "pass" if failed == 0 else "fail",
    }


def parse_args() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run the semantic detection fixture suite."
    )

    parser.add_argument(
        "--fixtures",
        required=True,
        type=Path,
        help="Fixture JSON input.",
    )

    parser.add_argument(
        "--policy",
        required=True,
        type=Path,
        help="Behavior policy JSON input.",
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Machine-readable result JSON.",
    )

    return parser.parse_args()


def load_json(path: Path) -> Any:
    """Load one UTF-8 JSON document."""
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    """Run the suite and return non-zero on a mismatch."""
    args = parse_args()

    for path in (args.fixtures, args.policy):
        if not path.is_file():
            print(
                f"Input is not a file: {path}",
                file=sys.stderr,
            )
            return 3

    try:
        fixture_document = load_json(args.fixtures)
        policy = load_json(args.policy)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(
            f"Cannot decode input: {exc}",
            file=sys.stderr,
        )
        return 2

    policy_errors = validate_policy(policy)

    if policy_errors:
        for error in policy_errors:
            print(
                f"Policy error: {error}",
                file=sys.stderr,
            )

        return 2

    if (
        not isinstance(fixture_document, dict)
        or not isinstance(
            fixture_document.get("fixtures"),
            list,
        )
    ):
        print(
            "Fixture document must contain a fixtures list.",
            file=sys.stderr,
        )
        return 2

    result = run_suite(
        fixture_document,
        policy,
        args.fixtures,
        args.policy,
    )

    args.output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.output.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "suite"
        f" total={result['summary']['total']}"
        f" passed={result['summary']['passed']}"
        f" failed={result['summary']['failed']}"
        f" verdict={result['verdict']}"
    )

    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
