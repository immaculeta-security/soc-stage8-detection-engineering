#!/usr/bin/env python3
"""Run the unattended B2 Stage 8 regression suite and emit JUnit XML."""

import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
RUNNER_VERSION = "2.0.0"


def sha256_file(path: Path) -> str:
    """Return the SHA-256 fingerprint of one file."""
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def run_command(
    name: str,
    arguments: list[str],
    expected_exit: int,
) -> dict[str, Any]:
    """Run one command and check its exit code."""
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    passed = completed.returncode == expected_exit

    return {
        "name": name,
        "classname": "component",
        "passed": passed,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
        "detail": (
            "Command returned the expected exit code."
            if passed
            else (
                f"Expected exit {expected_exit}, "
                f"received {completed.returncode}."
            )
        ),
    }


def fixture_testcases(
    result_path: Path,
    classname: str,
) -> list[dict[str, Any]]:
    """Convert detection results into individual JUnit test cases."""
    with result_path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)

    testcases: list[dict[str, Any]] = []

    for result in document["results"]:
        testcases.append(
            {
                "name": str(result["case_id"]),
                "classname": classname,
                "passed": bool(result["matched_expectation"]),
                "stdout": "",
                "stderr": "",
                "detail": (
                    f"expected={result['expected']} "
                    f"predicted={result['predicted']} "
                    f"status={result['status']} "
                    f"locators={result['evidence_locators']} "
                    f"explanation={result['explanation']}"
                ),
            }
        )

    return testcases


def classification_contract_testcase(
    result_path: Path,
) -> dict[str, Any]:
    """Verify that the engine can emit every required B2 status."""
    required = {
        "DIAG-NO-TELEMETRY": "no_telemetry",
        "DIAG-PARSE-FAILURE": "parse_failure",
        "DIAG-RULE-MISS": "rule_miss",
        "DIAG-SUPPRESSED": "suppressed",
        "DIAG-ALERTED": "alerted",
        "DIAG-UNEXPECTED-ALERT": "unexpected_alert",
    }

    try:
        with result_path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)

        observed = {
            str(result["case_id"]): str(result["status"])
            for result in document["results"]
        }

        problems = []

        for case_id, expected_status in required.items():
            actual_status = observed.get(case_id)

            if actual_status != expected_status:
                problems.append(
                    f"{case_id}: expected {expected_status}, "
                    f"observed {actual_status}"
                )

        passed = not problems
        detail = (
            "All six B2 outcome classifications were produced."
            if passed
            else "; ".join(problems)
        )

    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        passed = False
        observed = {}
        detail = f"Could not verify classification contract: {error}"

    return {
        "name": "six-outcome-classification-contract",
        "classname": "classification",
        "passed": passed,
        "stdout": json.dumps(observed, sort_keys=True),
        "stderr": "",
        "detail": detail,
    }


def add_testcase(
    suite: ET.Element,
    testcase: dict[str, Any],
) -> None:
    """Add one testcase to the JUnit document."""
    element = ET.SubElement(
        suite,
        "testcase",
        {
            "classname": testcase["classname"],
            "name": testcase["name"],
        },
    )

    if not testcase["passed"]:
        failure = ET.SubElement(
            element,
            "failure",
            {
                "message": testcase["detail"],
                "type": "verdict_mismatch",
            },
        )
        failure.text = testcase["detail"]

    output_parts = []

    if testcase["stdout"]:
        output_parts.append("stdout:\n" + testcase["stdout"])

    if testcase["stderr"]:
        output_parts.append("stderr:\n" + testcase["stderr"])

    output_parts.append("detail:\n" + testcase["detail"])

    system_out = ET.SubElement(element, "system-out")
    system_out.text = "\n\n".join(output_parts)


def write_junit(
    output_path: Path,
    testcases: list[dict[str, Any]],
    input_hashes: dict[str, str],
) -> tuple[int, int]:
    """Write deterministic JUnit XML."""
    failures = sum(not testcase["passed"] for testcase in testcases)

    suite = ET.Element(
        "testsuite",
        {
            "name": "ubi-stage8-b2-detection-regression",
            "tests": str(len(testcases)),
            "failures": str(failures),
            "errors": "0",
        },
    )

    properties = ET.SubElement(suite, "properties")

    ET.SubElement(
        properties,
        "property",
        {
            "name": "runner_version",
            "value": RUNNER_VERSION,
        },
    )

    for name, value in sorted(input_hashes.items()):
        ET.SubElement(
            properties,
            "property",
            {
                "name": name,
                "value": value,
            },
        )

    for testcase in testcases:
        add_testcase(suite, testcase)

    tree = ET.ElementTree(suite)
    ET.indent(tree, space=" ")
    tree.write(
        output_path,
        encoding="utf-8",
        xml_declaration=True,
    )

    return len(testcases), failures


def main() -> int:
    """Run every B2 acceptance test and emit the report."""
    results = ROOT / "tests" / "results"
    results.mkdir(parents=True, exist_ok=True)

    paths = {
        "public_validation":
            results / "public-fixture-validation.json",
        "malformed_fixture":
            results / "public-fixture-malformed-validation.json",
        "smoke_replay":
            results / "replay-smoke-validation.json",
        "malformed_replay":
            results / "replay-malformed-validation.json",
        "public_detection":
            results / "public-detection-results.json",
        "mutation_detection":
            results / "mutation-results.json",
        "holdout_validation":
            results / "benign-holdout-validation.json",
        "holdout_detection":
            results / "benign-holdout-results.json",
        "classification":
            results / "classification-diagnostics-results.json",
    }

    components = [
        run_command(
            "public-fixture-schema-valid",
            [
                PYTHON,
                "detection-lab/fixture_validator.py",
                "--input",
                "fixtures/public-fixtures.json",
                "--output",
                str(paths["public_validation"]),
            ],
            0,
        ),
        run_command(
            "malformed-fixture-rejected",
            [
                PYTHON,
                "detection-lab/fixture_validator.py",
                "--input",
                "fixtures/public-fixtures-malformed.json",
                "--output",
                str(paths["malformed_fixture"]),
            ],
            2,
        ),
        run_command(
            "replay-smoke-valid",
            [
                PYTHON,
                "detection-lab/replay_validator.py",
                "--input",
                "fixtures/replay-smoke.jsonl",
                "--output",
                str(paths["smoke_replay"]),
            ],
            0,
        ),
        run_command(
            "malformed-replay-rejected",
            [
                PYTHON,
                "detection-lab/replay_validator.py",
                "--input",
                "fixtures/replay-malformed.jsonl",
                "--output",
                str(paths["malformed_replay"]),
            ],
            2,
        ),
        run_command(
            "public-detection-suite",
            [
                PYTHON,
                "detection-lab/detection_engine.py",
                "--fixtures",
                "fixtures/public-fixtures.json",
                "--policy",
                "rules/behavior-policy.json",
                "--output",
                str(paths["public_detection"]),
            ],
            0,
        ),
        run_command(
            "eight-mutation-suite",
            [
                PYTHON,
                "detection-lab/detection_engine.py",
                "--fixtures",
                "fixtures/mutation-tests.json",
                "--policy",
                "rules/behavior-policy.json",
                "--output",
                str(paths["mutation_detection"]),
            ],
            0,
        ),
        run_command(
            "twelve-holdout-schema-valid",
            [
                PYTHON,
                "detection-lab/fixture_validator.py",
                "--input",
                "fixtures/benign-holdouts.json",
                "--output",
                str(paths["holdout_validation"]),
            ],
            0,
        ),
        run_command(
            "twelve-benign-holdout-suite",
            [
                PYTHON,
                "detection-lab/detection_engine.py",
                "--fixtures",
                "fixtures/benign-holdouts.json",
                "--policy",
                "rules/behavior-policy.json",
                "--output",
                str(paths["holdout_detection"]),
            ],
            0,
        ),
        run_command(
            "classification-diagnostic-exit",
            [
                PYTHON,
                "detection-lab/detection_engine.py",
                "--fixtures",
                "fixtures/classification-diagnostics.json",
                "--policy",
                "rules/behavior-policy.json",
                "--output",
                str(paths["classification"]),
            ],
            1,
        ),
    ]

    all_tests = list(components)

    all_tests.extend(
        fixture_testcases(
            paths["public_detection"],
            "public_detection",
        )
    )
    all_tests.extend(
        fixture_testcases(
            paths["mutation_detection"],
            "mutation_detection",
        )
    )
    all_tests.extend(
        fixture_testcases(
            paths["holdout_detection"],
            "benign_holdout",
        )
    )
    all_tests.append(
        classification_contract_testcase(paths["classification"])
    )

    input_hashes = {
        "behavior_policy_sha256": sha256_file(
            ROOT / "rules" / "behavior-policy.json"
        ),
        "public_fixture_sha256": sha256_file(
            ROOT / "fixtures" / "public-fixtures.json"
        ),
        "mutation_fixture_sha256": sha256_file(
            ROOT / "fixtures" / "mutation-tests.json"
        ),
        "benign_holdout_sha256": sha256_file(
            ROOT / "fixtures" / "benign-holdouts.json"
        ),
        "classification_fixture_sha256": sha256_file(
            ROOT / "fixtures" / "classification-diagnostics.json"
        ),
    }

    output_path = ROOT / "regression-results.xml"

    total, failures = write_junit(
        output_path,
        all_tests,
        input_hashes,
    )

    verdict = "pass" if failures == 0 else "fail"

    print(
        f"regression tests={total} "
        f"failures={failures} "
        f"verdict={verdict} "
        f"report={output_path.name}"
    )

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
