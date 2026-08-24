#!/usr/bin/env python3
"""Evaluate replay decisions against supplied ground truth after detection."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


EVALUATOR_VERSION = "1.0.0"


def parse_arguments() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Evaluate replay provenance and decisions."
    )
    parser.add_argument(
        "--replay",
        required=True,
        help="Immutable signed replay JSONL.",
    )
    parser.add_argument(
        "--normalized",
        required=True,
        help="Normalized candidate JSONL.",
    )
    parser.add_argument(
        "--decisions",
        required=True,
        help="Replay decision JSONL.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Machine-readable evaluation JSON.",
    )
    return parser.parse_args()


def sha256_bytes(value: bytes) -> str:
    """Calculate a byte-string SHA-256."""
    return hashlib.sha256(value).hexdigest()


def load_jsonl_by_source_locator(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Load JSONL records keyed by their source locator."""
    records = {}
    problems = []

    with path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            try:
                record = json.loads(raw_line)
                locator = record.get("source_locator")

                if not locator:
                    problems.append(
                        {
                            "file": path.name,
                            "line_number": line_number,
                            "category": "missing_source_locator",
                        }
                    )
                    continue

                if locator in records:
                    problems.append(
                        {
                            "file": path.name,
                            "line_number": line_number,
                            "category": "duplicate_source_locator",
                            "source_locator": locator,
                        }
                    )
                    continue

                records[locator] = record

            except json.JSONDecodeError as error:
                problems.append(
                    {
                        "file": path.name,
                        "line_number": line_number,
                        "category": "parse_failure",
                        "detail": str(error),
                    }
                )

    return records, problems


def main() -> int:
    """Evaluate all supplied ground-truth replay events."""
    arguments = parse_arguments()

    replay_path = Path(arguments.replay)
    normalized_path = Path(arguments.normalized)
    decisions_path = Path(arguments.decisions)
    output_path = Path(arguments.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    normalized, normalized_problems = (
        load_jsonl_by_source_locator(normalized_path)
    )
    decisions, decision_problems = (
        load_jsonl_by_source_locator(decisions_path)
    )

    results = []
    assigned_locators = set()
    source_parse_failures = []

    with replay_path.open("rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            try:
                source_event = json.loads(raw_line)
            except json.JSONDecodeError as error:
                source_parse_failures.append(
                    {
                        "line_number": line_number,
                        "detail": str(error),
                    }
                )
                continue

            if (
                "marker" not in source_event
                or "mitre_technique" not in source_event
            ):
                continue

            source_locator = (
                f"{replay_path.name}:line:{line_number}"
            )
            assigned_locators.add(source_locator)

            expected_technique = str(
                source_event["mitre_technique"]
            )
            normalized_event = normalized.get(source_locator)
            decision = decisions.get(source_locator)

            if normalized_event is None:
                status = "no_telemetry"
                matched = False
                actual_techniques = []
                explanation = (
                    "Assigned source event has no normalized record."
                )

            elif decision is None:
                status = "rule_miss"
                matched = False
                actual_techniques = []
                explanation = (
                    "Normalized record has no decision record."
                )

            else:
                actual_techniques = sorted(
                    {
                        str(match["technique_id"])
                        for match in decision.get("matches", [])
                    }
                )

                if (
                    decision.get("status") == "alerted"
                    and expected_technique in actual_techniques
                ):
                    status = "alerted"
                    matched = True
                    explanation = (
                        "Semantic decision alerted with the supplied "
                        "ground-truth technique."
                    )
                else:
                    status = "rule_miss"
                    matched = False
                    explanation = (
                        "Decision did not alert with the supplied "
                        "ground-truth technique."
                    )

            results.append(
                {
                    "source_locator": source_locator,
                    "source_line_sha256": sha256_bytes(raw_line),
                    "source_event_id": str(
                        source_event.get("event_id")
                    ),
                    "expected_technique": expected_technique,
                    "normalized_locator": (
                        decision.get("normalized_locator")
                        if decision
                        else None
                    ),
                    "normalized_event_sha256": (
                        decision.get("normalized_event_sha256")
                        if decision
                        else None
                    ),
                    "decision_status": (
                        decision.get("status")
                        if decision
                        else None
                    ),
                    "actual_techniques": actual_techniques,
                    "evaluation_status": status,
                    "matched_expectation": matched,
                    "explanation": explanation,
                }
            )

    unexpected_alerts = sorted(
        locator
        for locator, decision in decisions.items()
        if (
            decision.get("status") == "alerted"
            and locator not in assigned_locators
        )
    )

    status_counts = {}

    for result in results:
        status = result["evaluation_status"]
        status_counts[status] = status_counts.get(status, 0) + 1

    failures = sum(
        not result["matched_expectation"]
        for result in results
    )
    failures += len(unexpected_alerts)
    failures += len(normalized_problems)
    failures += len(decision_problems)
    failures += len(source_parse_failures)

    report = {
        "schema_version": "1.0",
        "evaluator_version": EVALUATOR_VERSION,
        "inputs": {
            "replay_file": replay_path.name,
            "normalized_file": normalized_path.name,
            "decisions_file": decisions_path.name,
        },
        "counts": {
            "assigned_source_events": len(results),
            "matched": sum(
                result["matched_expectation"]
                for result in results
            ),
            "failed": failures,
            "unexpected_alerts": len(unexpected_alerts),
        },
        "status_counts": dict(sorted(status_counts.items())),
        "unexpected_alert_locators": unexpected_alerts,
        "normalized_input_problems": normalized_problems,
        "decision_input_problems": decision_problems,
        "source_parse_failures": source_parse_failures,
        "results": results,
        "ground_truth_usage": (
            "marker presence and mitre_technique are used only "
            "after detection to evaluate supplied expectations; "
            "they are not inputs to event_adapter.py, "
            "replay-policy.json or replay_detector.py decisions."
        ),
        "verdict": "pass" if failures == 0 else "fail",
    }

    output_path.write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"replay-evaluation "
        f"assigned={len(results)} "
        f"matched={report['counts']['matched']} "
        f"failed={failures} "
        f"unexpected_alerts={len(unexpected_alerts)} "
        f"verdict={report['verdict']}"
    )

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
