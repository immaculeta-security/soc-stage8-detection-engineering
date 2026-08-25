# Stage 8 Portfolio Continuity Record

## 1. Previous-stage commit and component reused

The prior submitted project is SOC Analyst Stage 7, stored in the retained
submission folder `UBI-2026-0004-STAGE_7`.

Its submitted `assessment-manifest.json` records commit:

`e3d0cde7d585dd6bbb40f765fb026b2de6cf6843`

The submitted assessment manifest has SHA-256:

`c324258d8b6411649999b16af45fc8ae3de4f7251a15334e6b834bf42192e2b2`

The local Stage 7 `.git` directory no longer contains a commit object, so the
commit is reported from the retained submitted manifest and is not described as
independently verified from local Git history.

The exact Stage 7 component reused is its fixture-driven expected-result and
evidence-provenance interface:

- input fixture: `tests/public-fixtures.json`
- automated runner: `tests/test_public_fixtures.py`
- machine-readable result: `test-results.xml`
- raw evidence boundary: `evidence/raw/`
- derived evidence boundary: `evidence/derived/`

Retained Stage 7 hashes:

- `tests/public-fixtures.json`:
  `2268ad52b39a59b1ea5cd5e69f6411e259fe0cf4d76ecc516c17e68c02ea00d1`
- `tests/test_public_fixtures.py`:
  `df4e919e6c42e5dac4ff59fdcf9b95b1624d134c7ac3da542704b5ddbf079c14`
- `test-results.xml`:
  `bb26553309423468c8a6434a03a0b38582096a4182679366b01d857a5e5af618`

No Stage 7 source code, raw packet evidence, private marker or case answer was
copied into Stage 8 detection logic.

## 2. Interface consumed and backward-compatible extension

Stage 7 represented each network control as a structured JSON fixture with a
case identifier and explicit expected network and logging results. A Python
runner compared observed behavior with those expectations and emitted
machine-readable test results.

Stage 8 retains that interface pattern:

- structured JSON fixtures remain inputs;
- expected outcomes remain data, not rule constants;
- the detection implementation is separate from result assertions;
- every test produces an explicit actual status;
- the unattended suite emits JUnit XML;
- a non-matching verdict causes a non-zero exit.

Stage 8 extends the interface for portable Windows detection engineering:

- network `allow` and `deny` outcomes become `alert` and `no_alert`;
- failure classification adds `no_telemetry`, `parse_failure`, `rule_miss`,
  `suppressed`, `alerted` and `unexpected_alert`;
- event sequences include normalized channel, image, parent-image, timing and
  command-family features;
- semantic attack mutations and benign holdouts are separate fixture groups;
- exact raw, normalized and decision locators and hashes are retained.

The extension is backward-compatible at the architectural level: inputs remain
structured fixtures, implementation remains separate from expectations, and
machine-readable results remain the reproduction interface.

## 3. Preserved raw-to-result provenance

Stage 7 separated immutable or collected evidence under `evidence/raw/` from
generated telemetry under `evidence/derived/` and linked central claims through
hashes and exact locators.

Stage 8 preserves and strengthens that model:

1. The signed `windows-replay.jsonl` remains read-only outside the project
   derivation directories.
2. `raw-events/source-accounting.json` records the complete input filename,
   byte count, SHA-256, schema counts, channel counts and validity totals.
3. `raw-events/normalized-candidates.jsonl` records the exact source line
   locator and source-line SHA-256 for every semantic candidate.
4. `alerts/replay-decisions.jsonl` records the normalized locator, normalized
   event hash, matching rule ID/version, technique and reason code.
5. `tests/results/replay-evaluation.json` verifies each supplied ground-truth
   event only after detection and records the complete
   source-to-normalized-to-decision chain.
6. `regression-results.xml` preserves the machine-readable fixture result
   interface.
7. `evidence-index.csv` ties material claims to exact artifacts and locators.

Three clean full runs produced byte-identical outputs and identical summary
hashes.

## 4. Migration record

Stage 7 analyzed containerized network paths, firewall decisions and Suricata
visibility. Stage 8 analyzes versioned Windows process events from a signed
JSONL replay. The event schemas are therefore intentionally different.

The incompatible network-specific fields—source zone, destination zone,
service, expected network result and expected log code—were not forced into the
Windows schema.

They were migrated to the portable event contract implemented by
`detection-lab/event_adapter.py`, including:

- source schema version;
- source locator and source-line hash;
- normalized channel and event code;
- normalized image and parent image;
- command-family behavior;
- semantic behavior features.

Stage 7 network rules were not presented as Windows detections. Stage 8 uses new
versioned semantic replay rules while retaining the earlier test, provenance and
machine-result interfaces.

The B2 signed replay contains twelve labelled source events covering six unique
ATT&CK techniques twice, while `technique-matrix.csv` lists twelve unique
techniques. This discrepancy is preserved in
`decisions/B2-source-coverage-discrepancy.md`; unsupported source evidence is
not fabricated.

## 5. Stage 9 handoff

Stage 8 hands the following components to the final incident case:

- `detection-lab/event_adapter.py`: versioned Windows replay normalization;
- `detection-lab/replay_detector.py`: semantic decision engine;
- `detection-lab/replay_evaluator.py`: post-detection ground-truth evaluation;
- `detection-lab/run_full_replay.py`: one-command deterministic workflow;
- `rules/replay-policy.json`: versioned semantic rule definitions;
- `raw-events/source-accounting.json`: complete immutable-source accounting;
- `raw-events/normalized-candidates.jsonl`: source-linked normalized evidence;
- `alerts/replay-decisions.jsonl`: rule decisions and reason codes;
- `tests/results/replay-evaluation.json`: raw-to-alert verification;
- `regression-results.xml`: portable machine-readable regression results;
- the documented coverage gaps and false-positive decisions.

Stage 9 can add incident-specific parsers and rules while retaining the same
source locator, normalized event, decision, test and evidence-index interfaces.
