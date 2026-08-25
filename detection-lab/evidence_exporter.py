#!/usr/bin/env python3
"""Export assigned raw events after detection for evidence navigation."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


EXPORTER_VERSION = "1.0.0"


def parse_arguments() -> argparse.Namespace:
    """Read command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Export evaluated raw replay evidence."
    )
    parser.add_argument(
        "--replay",
        required=True,
        help="Immutable signed replay JSONL.",
    )
    parser.add_argument(
        "--evaluation",
        required=True,
        help="Post-detection replay evaluation JSON.",
    )
    parser.add_argument(
        "--raw-output",
        required=True,
        help="Native JSONL excerpts output.",
    )
    parser.add_argument(
        "--manifest-output",
        required=True,
        help="Raw artifact manifest output.",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    """Calculate a file SHA-256."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def main() -> int:
    """Export exact evaluated source lines and their provenance."""
    arguments = parse_arguments()

    replay_path = Path(arguments.replay)
    evaluation_path = Path(arguments.evaluation)
    raw_output_path = Path(arguments.raw_output)
    manifest_path = Path(arguments.manifest_output)

    raw_output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    evaluation = json.loads(
        evaluation_path.read_text(encoding="utf-8")
    )

    expected = {
        result["source_locator"]: result
        for result in evaluation["results"]
    }

    exported = []
    markers = set()

    with (
        replay_path.open("rb") as source,
        raw_output_path.open("wb") as raw_output,
    ):
        for line_number, raw_line in enumerate(source, start=1):
            locator = f"{replay_path.name}:line:{line_number}"

            if locator not in expected:
                continue

            event = json.loads(raw_line)
            actual_hash = hashlib.sha256(raw_line).hexdigest()
            expected_hash = expected[locator]["source_line_sha256"]

            if actual_hash != expected_hash:
                raise ValueError(
                    f"source hash mismatch at {locator}"
                )

            marker = event.get("marker")

            if marker:
                markers.add(str(marker))

            raw_output.write(raw_line)

            exported.append(
                {
                    "source_locator": locator,
                    "source_line_sha256": actual_hash,
                    "source_event_id": str(
                        event.get("event_id")
                    ),
                    "mitre_technique": str(
                        event.get("mitre_technique")
                    ),
                    "timestamp": str(event.get("timestamp")),
                    "raw_excerpt_file": raw_output_path.name,
                    "raw_excerpt_line": len(exported) + 1,
                    "evaluation_status": expected[locator][
                        "evaluation_status"
                    ],
                }
            )

    problems = []

    if len(markers) != 1:
        problems.append(
            f"expected_one_evidence_marker_observed_{len(markers)}"
        )

    manifest = {
        "schema_version": "1.0",
        "exporter_version": EXPORTER_VERSION,
        "source": {
            "file_name": replay_path.name,
            "bytes": replay_path.stat().st_size,
            "sha256": sha256_file(replay_path),
        },
        "evidence_marker": (
            sorted(markers)[0]
            if len(markers) == 1
            else None
        ),
        "raw_excerpt": {
            "file_name": raw_output_path.name,
            "event_count": len(exported),
            "sha256": sha256_file(raw_output_path),
        },
        "events": exported,
        "problems": problems,
        "verdict": "pass" if not problems else "fail",
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        f"evidence-export events={len(exported)} "
        f"markers={len(markers)} "
        f"verdict={manifest['verdict']}"
    )

    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
