#!/usr/bin/env python3
"""Apply versioned semantic rules to normalized replay candidates."""

import argparse
import collections
import hashlib
import json
from pathlib import Path
from typing import Any


ENGINE_VERSION = "1.0.0"


def parse_arguments() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Detect normalized replay behaviors."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Normalized candidate JSONL.",
    )
    parser.add_argument(
        "--policy",
        required=True,
        help="Versioned replay policy JSON.",
    )
    parser.add_argument(
        "--decisions-output",
        required=True,
        help="JSONL output containing every decision.",
    )
    parser.add_argument(
        "--alerts-output",
        required=True,
        help="JSONL output containing alerts only.",
    )
    parser.add_argument(
        "--summary-output",
        required=True,
        help="Machine-readable detection summary.",
    )
    return parser.parse_args()


def sha256_bytes(value: bytes) -> str:
    """Calculate a byte-string SHA-256."""
    return hashlib.sha256(value).hexdigest()


def load_policy(path: Path) -> dict[str, Any]:
    """Load and validate the versioned rule policy."""
    document = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(document.get("rules"), list):
        raise ValueError("policy rules must be a list")

    for index, rule in enumerate(document["rules"]):
        required = {
            "rule_id",
            "rule_version",
            "name",
            "technique_id",
            "severity",
            "required_features",
        }
        missing = sorted(required - set(rule))

        if missing:
            raise ValueError(
                f"rule {index} missing fields: {','.join(missing)}"
            )

        if not isinstance(rule["required_features"], list):
            raise ValueError(
                f"rule {index} required_features must be a list"
            )

    return document


def matching_rules(
    event: dict[str, Any],
    rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return rules whose required semantic features are present."""
    observed = set(event.get("behavior_features", []))
    matches = []

    for rule in rules:
        required = set(rule["required_features"])

        if required and required.issubset(observed):
            matches.append(rule)

    return matches


def main() -> int:
    """Apply all rules and preserve normalized-to-decision provenance."""
    arguments = parse_arguments()

    input_path = Path(arguments.input)
    policy_path = Path(arguments.policy)
    decisions_path = Path(arguments.decisions_output)
    alerts_path = Path(arguments.alerts_output)
    summary_path = Path(arguments.summary_output)

    decisions_path.parent.mkdir(parents=True, exist_ok=True)
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    policy = load_policy(policy_path)
    rules = policy["rules"]

    total = 0
    alerted = 0
    suppressed = 0
    parse_failures = 0
    rule_counts = collections.Counter()
    technique_counts = collections.Counter()
    error_samples = []

    with (
        input_path.open("rb") as source,
        decisions_path.open("w", encoding="utf-8", newline="\n")
        as decisions_output,
        alerts_path.open("w", encoding="utf-8", newline="\n")
        as alerts_output,
    ):
        for normalized_line_number, raw_line in enumerate(
            source,
            start=1,
        ):
            total += 1
            normalized_hash = sha256_bytes(raw_line)

            try:
                event = json.loads(raw_line)
                matches = matching_rules(event, rules)

                status = "alerted" if matches else "suppressed"

                decision = {
                    "engine_version": ENGINE_VERSION,
                    "policy_version": policy["policy_version"],
                    "normalized_locator": (
                        f"{input_path.name}:line:"
                        f"{normalized_line_number}"
                    ),
                    "normalized_event_sha256": normalized_hash,
                    "source_locator": event.get("source_locator"),
                    "source_line_sha256": event.get(
                        "source_line_sha256"
                    ),
                    "timestamp": event.get("timestamp"),
                    "computer": event.get("computer"),
                    "user": event.get("user"),
                    "image": event.get("image"),
                    "parent_image": event.get("parent_image"),
                    "behavior_features": event.get(
                        "behavior_features",
                        [],
                    ),
                    "status": status,
                    "reason_code": (
                        "semantic_rule_match"
                        if matches
                        else "no_semantic_rule_match"
                    ),
                    "matches": [
                        {
                            "rule_id": rule["rule_id"],
                            "rule_version": rule["rule_version"],
                            "name": rule["name"],
                            "technique_id": rule["technique_id"],
                            "severity": rule["severity"],
                            "required_features":
                                rule["required_features"],
                        }
                        for rule in matches
                    ],
                }

                serialized = (
                    json.dumps(
                        decision,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                )

                decisions_output.write(serialized)

                if matches:
                    alerted += 1
                    alerts_output.write(serialized)

                    for rule in matches:
                        rule_counts[rule["rule_id"]] += 1
                        technique_counts[rule["technique_id"]] += 1
                else:
                    suppressed += 1

            except (
                json.JSONDecodeError,
                KeyError,
                TypeError,
                ValueError,
            ) as error:
                parse_failures += 1

                if len(error_samples) < 10:
                    error_samples.append(
                        {
                            "normalized_line_number":
                                normalized_line_number,
                            "detail": str(error),
                        }
                    )

    summary = {
        "schema_version": "1.0",
        "engine_version": ENGINE_VERSION,
        "policy_version": policy["policy_version"],
        "input_file": input_path.name,
        "policy_file": policy_path.name,
        "counts": {
            "total_candidates": total,
            "alerted": alerted,
            "suppressed": suppressed,
            "parse_failures": parse_failures,
        },
        "rule_alert_counts": dict(sorted(rule_counts.items())),
        "technique_alert_counts": dict(
            sorted(technique_counts.items())
        ),
        "error_samples": error_samples,
        "verdict": "pass" if parse_failures == 0 else "fail",
    }

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"replay-detection total={total} "
        f"alerted={alerted} "
        f"suppressed={suppressed} "
        f"parse_failures={parse_failures} "
        f"verdict={summary['verdict']}"
    )

    return 0 if parse_failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
