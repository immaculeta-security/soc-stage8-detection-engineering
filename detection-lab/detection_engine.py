#!/usr/bin/env python3
"""Run semantic B2 detection fixtures without answer constants."""

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ENGINE_VERSION = "2.0.0"

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
    """Return a lowercase executable basename."""
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
    """Return policy errors; an empty list means valid."""
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
        return ["Missing policy fields: " + ",".join(missing)]

    errors: list[str] = []
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
    """Normalize fixture events and record parsing problems."""
    if not isinstance(events, list):
        return [], ["events must be a list."]

    if not events:
        return [], []

    decoded: list[dict[str, Any]] = []
    errors: list[str] = []

    for index, event in enumerate(events):
        locator = f"/events/{index}"

        if not isinstance(event, dict):
            errors.append(f"{locator}: event must be an object.")
            continue

        missing = sorted(CORE_EVENT_FIELDS - event.keys())

        if missing:
            errors.append(
                f"{locator}: missing fields {','.join(missing)}"
            )
            continue

        if (
            isinstance(event["event_code"], bool)
            or not isinstance(event["event_code"], int)
        ):
            errors.append(
                f"{locator}/event_code: must be an integer."
            )
            continue

        invalid_text = False

        for field in ("channel", "image", "parent_image"):
            if (
                not isinstance(event[field], str)
                or not event[field].strip()
            ):
                errors.append(
                    f"{locator}/{field}: must be a non-empty string."
                )
                invalid_text = True

        if invalid_text:
            continue

        normalized_event = dict(event)
        normalized_event["normalized_channel"] = normalized_channel(
            event["channel"]
        )
        normalized_event["normalized_image"] = normalized_binary(
            event["image"]
        )
        normalized_event["normalized_parent_image"] = (
            normalized_binary(event["parent_image"])
        )
        normalized_event["source_locator"] = locator

        decoded.append(normalized_event)

    return decoded, errors


def semantic_match(
    events: list[dict[str, Any]],
    policy: dict[str, Any],
) -> tuple[bool, list[str], str]:
    """Evaluate process-event correlation independently of expectation."""
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
        channel = event["normalized_channel"]
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
        for security_index, security_event in security_candidates:
            delta = security_event.get("delta_seconds")

            if (
                isinstance(delta, bool)
                or not isinstance(delta, (int, float))
            ):
                continue

            same_process = (
                sysmon_event["normalized_image"]
                == security_event["normalized_image"]
                and sysmon_event["normalized_parent_image"]
                == security_event["normalized_parent_image"]
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
        "Technique matched, but no Security 4688 event "
        "matched the process, parent, and time window.",
    )


def classify_fixture(
    fixture: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Classify one fixture using the six B2 outcome states."""
    case_id = fixture.get("case_id")
    expected = fixture.get("expected")
    events = fixture.get("events")

    decoded, parse_errors = decode_events(events)

    if isinstance(events, list) and not events:
        status = "no_telemetry"
        detected = False
        locators: list[str] = []
        explanation = "The fixture contained no telemetry events."

    elif parse_errors:
        status = "parse_failure"
        detected = False
        locators = []
        explanation = "; ".join(parse_errors)

    else:
        detected, locators, explanation = semantic_match(
            decoded,
            policy,
        )

        if detected and expected == "no_alert":
            status = "unexpected_alert"
        elif detected:
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
        "normalized_event_count": len(decoded),
        "parse_errors": parse_errors,
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
        "engine_version": ENGINE_VERSION,
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
        description="Run the portable B2 semantic detection suite."
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
