#!/usr/bin/env python3
"""Run the unattended Stage 8 regression suite and emit JUnit XML."""

import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def sha256_file(path: Path) -> str:
    """Return the SHA-256 fingerprint of a file."""
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
    """Run one command and describe whether it behaved correctly."""
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
        "expected_exit": expected_exit,
        "actual_exit": completed.returncode,
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
    """Convert detection JSON results into individual test cases."""
    with result_path.open("r", encoding="utf-8") as handle:
        document = json.load(handle)

    testcases: list[dict[str, Any]] = []

    for result in document["results"]:
        testcases.append(
            {
                "name": str(result["case_id"]),
                "classname": classname,
                "passed": bool(result["matched_expectation"]),
                "expected_exit": None,
                "actual_exit": None,
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


def add_testcase(
    suite: ET.Element,
    testcase: dict[str, Any],
) -> None:
    """Add one JUnit testcase element."""
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
    """Write deterministic JUnit XML and return tests and failures."""
    failures = sum(not testcase["passed"] for testcase in testcases)

    suite = ET.Element(
        "testsuite",
        {
            "name": "ubi-stage8-detection-regression",
            "tests": str(len(testcases)),
            "failures": str(failures),
            "errors": "0",
        },
    )

    properties = ET.SubElement(suite, "properties")

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
    ET.indent(tree, space="  ")

    tree.write(
        output_path,
        encoding="utf-8",
        xml_declaration=True,
    )

    return len(testcases), failures


def main() -> int:
    """Run every acceptance test and emit the regression report."""
    results_directory = ROOT / "tests" / "results"
    results_directory.mkdir(parents=True, exist_ok=True)

    public_validation = (
        results_directory / "public-fixture-validation.json"
    )
    malformed_fixture_validation = (
        results_directory
        / "public-fixture-malformed-validation.json"
    )
    smoke_validation = (
        results_directory / "replay-smoke-validation.json"
    )
    malformed_replay_validation = (
        results_directory / "replay-malformed-validation.json"
    )
    public_detection = (
        results_directory / "public-detection-results.json"
    )
    mutation_detection = (
        results_directory / "mutation-results.json"
    )

    component_tests = [
        run_command(
            "public-fixture-schema-valid",
            [
                PYTHON,
                "detection-lab/fixture_validator.py",
                "--input",
                "fixtures/public-fixtures.json",
                "--output",
                str(public_validation),
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
                str(malformed_fixture_validation),
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
                str(smoke_validation),
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
                str(malformed_replay_validation),
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
                str(public_detection),
            ],
            0,
        ),
        run_command(
            "mutation-detection-suite",
            [
                PYTHON,
                "detection-lab/detection_engine.py",
                "--fixtures",
                "fixtures/mutation-tests.json",
                "--policy",
                "rules/behavior-policy.json",
                "--output",
                str(mutation_detection),
            ],
            0,
        ),
    ]

    all_tests = list(component_tests)
    all_tests.extend(
        fixture_testcases(
            public_detection,
            "public_detection",
        )
    )
    all_tests.extend(
        fixture_testcases(
            mutation_detection,
            "mutation_detection",
        )
    )

    input_hashes = {
        "public_fixture_sha256": sha256_file(
            ROOT / "fixtures" / "public-fixtures.json"
        ),
        "mutation_fixture_sha256": sha256_file(
            ROOT / "fixtures" / "mutation-tests.json"
        ),
        "behavior_policy_sha256": sha256_file(
            ROOT / "rules" / "behavior-policy.json"
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
