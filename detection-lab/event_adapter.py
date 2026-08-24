#!/usr/bin/env python3
"""Normalize the signed Windows replay and preserve source provenance."""

import argparse
import collections
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ADAPTER_VERSION = "1.0.0"

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

CHANNEL_ALIASES = {
    "sysmon": "Microsoft-Windows-Sysmon/Operational",
    "microsoft-windows-sysmon/operational":
        "Microsoft-Windows-Sysmon/Operational",
    "security": "Security",
}

RARE_FAMILY_FEATURES = {
    "credential_access": "credential_access_behavior",
    "download": "ingress_transfer_behavior",
    "encoded_or_obfuscated": "encoded_or_obfuscated_behavior",
    "registry_run_key": "registry_persistence_behavior",
}


def parse_arguments() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Normalize a Windows JSONL replay."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Immutable source replay JSONL.",
    )
    parser.add_argument(
        "--candidates-output",
        required=True,
        help="Normalized semantic candidate JSONL.",
    )
    parser.add_argument(
        "--accounting-output",
        required=True,
        help="Machine-readable source-accounting JSON.",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    """Calculate a file SHA-256."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def normalize_channel(value: Any) -> str:
    """Normalize known channel aliases."""
    text = str(value).strip()
    return CHANNEL_ALIASES.get(text.lower(), text)


def normalize_binary(value: Any) -> str:
    """Return a lowercase Windows binary basename."""
    text = str(value).strip().replace("\\", "/")
    return text.rsplit("/", 1)[-1].lower()


def semantic_features(event: dict[str, Any]) -> list[str]:
    """Derive behavioral features without private or literal constants."""
    features = []

    family = str(event["command_family"]).strip().lower()
    image = normalize_binary(event["image"])
    parent = normalize_binary(event["parent_image"])

    family_feature = RARE_FAMILY_FEATURES.get(family)

    if family_feature:
        features.append(family_feature)

    if image == "cmd.exe" and parent == "wmiprvse.exe":
        features.append("remote_shell_parent_relationship")

    if image == "rundll32.exe" and parent == "services.exe":
        features.append("service_proxy_execution_relationship")

    return sorted(set(features))


def normalize_event(
    event: dict[str, Any],
    line_number: int,
    source_name: str,
    source_line_sha256: str,
) -> dict[str, Any]:
    """Create one portable normalized event."""
    return {
        "adapter_version": ADAPTER_VERSION,
        "source_locator": f"{source_name}:line:{line_number}",
        "source_line_sha256": source_line_sha256,
        "source_event_id": str(event["event_id"]),
        "source_schema_version": str(event["schema_version"]),
        "timestamp": str(event["timestamp"]),
        "channel": normalize_channel(event["channel"]),
        "event_code": int(event["event_code"]),
        "computer": str(event["computer"]),
        "user": str(event["user"]),
        "image": normalize_binary(event["image"]),
        "parent_image": normalize_binary(event["parent_image"]),
        "command_family": str(
            event["command_family"]
        ).strip().lower(),
        "behavior_features": semantic_features(event),
    }


def main() -> int:
    """Process the complete replay and write deterministic outputs."""
    arguments = parse_arguments()

    input_path = Path(arguments.input)
    candidates_path = Path(arguments.candidates_output)
    accounting_path = Path(arguments.accounting_output)

    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    accounting_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    valid = 0
    invalid = 0
    candidates = 0

    schemas = collections.Counter()
    channels = collections.Counter()
    event_codes = collections.Counter()
    families = collections.Counter()
    feature_counts = collections.Counter()
    error_categories = collections.Counter()
    error_samples = []

    with (
        input_path.open("rb") as source,
        candidates_path.open("w", encoding="utf-8", newline="\n")
        as candidate_output,
    ):
        for line_number, raw_line in enumerate(source, start=1):
            total += 1
            line_hash = hashlib.sha256(raw_line).hexdigest()

            try:
                event = json.loads(raw_line)

                if not isinstance(event, dict):
                    raise TypeError("event must be a JSON object")

                missing = sorted(REQUIRED_FIELDS - set(event))

                if missing:
                    raise KeyError(",".join(missing))

                normalized = normalize_event(
                    event,
                    line_number,
                    input_path.name,
                    line_hash,
                )

                valid += 1
                schemas[normalized["source_schema_version"]] += 1
                channels[normalized["channel"]] += 1
                event_codes[str(normalized["event_code"])] += 1
                families[normalized["command_family"]] += 1

                for feature in normalized["behavior_features"]:
                    feature_counts[feature] += 1

                if normalized["behavior_features"]:
                    candidate_output.write(
                        json.dumps(
                            normalized,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )
                    candidates += 1

            except json.JSONDecodeError as error:
                invalid += 1
                error_categories["parse_failure"] += 1

                if len(error_samples) < 10:
                    error_samples.append(
                        {
                            "line_number": line_number,
                            "category": "parse_failure",
                            "detail": str(error),
                        }
                    )

            except KeyError as error:
                invalid += 1
                error_categories["missing_fields"] += 1

                if len(error_samples) < 10:
                    error_samples.append(
                        {
                            "line_number": line_number,
                            "category": "missing_fields",
                            "detail": str(error),
                        }
                    )

            except (TypeError, ValueError) as error:
                invalid += 1
                error_categories["normalization_failure"] += 1

                if len(error_samples) < 10:
                    error_samples.append(
                        {
                            "line_number": line_number,
                            "category": "normalization_failure",
                            "detail": str(error),
                        }
                    )

    accounting = {
        "schema_version": "1.0",
        "adapter_version": ADAPTER_VERSION,
        "input": {
            "path": input_path.name,
            "bytes": input_path.stat().st_size,
            "sha256": sha256_file(input_path),
        },
        "counts": {
            "total_events": total,
            "valid_events": valid,
            "invalid_events": invalid,
            "semantic_candidates": candidates,
        },
        "source_schema_versions": dict(sorted(schemas.items())),
        "channels": dict(sorted(channels.items())),
        "event_codes": dict(sorted(event_codes.items())),
        "command_families": dict(sorted(families.items())),
        "behavior_features": dict(sorted(feature_counts.items())),
        "error_categories": dict(sorted(error_categories.items())),
        "error_samples": error_samples,
        "prohibited_decision_fields": [
            "case_id",
            "expected",
            "marker",
            "mitre_technique",
            "training_token",
        ],
        "verdict": "pass" if invalid == 0 else "fail",
    }

    accounting_path.write_text(
        json.dumps(
            accounting,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"adapter total={total} "
        f"valid={valid} "
        f"invalid={invalid} "
        f"candidates={candidates} "
        f"verdict={accounting['verdict']}"
    )

    return 0 if invalid == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
