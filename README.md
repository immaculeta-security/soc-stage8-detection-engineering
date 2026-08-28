# SOC Analyst Stage 8 — Detection Engineering Under Adversary Pressure

## Candidate and assignment

- Project: SOC Advanced 4 / SOC-A4
- Candidate binding: UBI-2026-0004
- Assigned variant: D3
- Controlling release: B2 portable route
- Assigned archive: `soc-analysis-stage-8-shared-b2.tar.gz`
- Assigned archive SHA-256: `75c476baac8b1c123522006e53053f766bd36baad4e3238223da67e12a53843c`
- Evidence marker: `UBI-A8-B79056480F9B`

The evidence marker is preserved in setup evidence,
`raw-events/raw-artifact-manifest.json`, `evidence-index.csv`,
`integrity-attestation.md`, and the defense recording. It is not used by
detection rules.

## Purpose

This repository processes the signed 250,000-event Windows replay through a
portable detection-as-code workflow:

1. Verify and account for the immutable replay.
2. Normalize versioned event records.
3. Select semantic behavior candidates.
4. Apply versioned semantic rules.
5. Produce alert decisions.
6. Evaluate decisions against supplied ground truth only after detection.
7. Run canonical, benign, malformed-input, mutation, holdout, and
   failure-classification tests.
8. Emit deterministic JSON, JSONL, and JUnit XML evidence.

No VM, Docker, Wazuh, cloud account, live endpoint, or internet connection is
required for the controlling B2 route.

## Supported environment

Validated environment:

- Operating system: Ubuntu 24.04.4 LTS
- Kernel: Linux 7.0.0-30-generic
- Architecture: x86_64
- Python: 3.12.3
- Git: 2.43.0
- Logical CPUs used: 2
- Memory available to VM: 3.8 GiB
- Free disk during final verification: 4.3 GB

The B2 minimum is Python 3.11 or newer, 4 GB RAM, and 2 GB free disk. The VM
reported 3.8 GiB because operating systems report binary GiB for a configured
4 GB allocation.

Measured complete workflow:

- Wall-clock runtime: 19.46 seconds
- Peak resident memory: 20,392 KB / 19.91 MB
- Exit status: 0

## Required external input

The complete signed replay is an issued input and remains read-only outside the
repository:

`windows-replay.jsonl`

Expected properties:

- Bytes: 81,133,259
- Lines: 250,000
- SHA-256: `ea7f96497f9275ccdc47fdb026480558547db5bfaa7aa8bf3a806a2bc9272838`

Set or substitute the exact local replay path when running the complete test.
The submitted raw excerpt and manifest do not replace the complete signed replay
during reproduction.

## Exact reproduction order

Run all commands from the submission root.

### 1. Clean generated outputs

```bash
python3 detection-lab/project_tasks.py clean
```

### 2. Verify required source files and Python

```bash
python3 detection-lab/project_tasks.py provision
```

### 3. Compile programs and validate JSON inputs

```bash
python3 detection-lab/project_tasks.py build
```

### 4. Run the complete signed-replay workflow

```bash
python3 detection-lab/project_tasks.py test \
  --replay /absolute/path/to/windows-replay.jsonl
```

Replace `/absolute/path/to/windows-replay.jsonl` with the staff-provided B2
replay location. No other command value requires manual answer editing.

For my validated environment, the replay was located at:

```text
/home/immaculeta/ubi-stage8/source/b2/unpacked/evidence/sealed-evidence/evidence/windows-replay.jsonl
```

My validated full command was:

```bash
python3 detection-lab/project_tasks.py test \
  --replay /home/immaculeta/ubi-stage8/source/b2/unpacked/evidence/sealed-evidence/evidence/windows-replay.jsonl
```

### 5. Export the evaluated native raw excerpts

```bash
python3 detection-lab/evidence_exporter.py \
  --replay /absolute/path/to/windows-replay.jsonl \
  --evaluation tests/results/clean-run/replay-evaluation.json \
  --raw-output raw-events/assigned-source-events.jsonl \
  --manifest-output raw-events/raw-artifact-manifest.json
```

My validated export command was:

```bash
python3 detection-lab/evidence_exporter.py \
  --replay /home/immaculeta/ubi-stage8/source/b2/unpacked/evidence/sealed-evidence/evidence/windows-replay.jsonl \
  --evaluation tests/results/clean-run/replay-evaluation.json \
  --raw-output raw-events/assigned-source-events.jsonl \
  --manifest-output raw-events/raw-artifact-manifest.json
```

### Public suite only

```bash
python3 detection-lab/project_tasks.py test
```

The public-only command runs the published fixture, malformed-input, mutation,
holdout, and failure-classification suite without the complete replay.

## Expected successful results

Complete workflow:

- Source events: 250,000
- Valid source events: 250,000
- Invalid source events: 0
- Semantic candidates: 12
- Replay alerts: 12
- Matched supplied replay expectations: 12
- Rule misses: 0
- Unexpected replay alerts: 0
- Public, mutation, and holdout regression tests: 66
- Regression failures: 0

Three clean full-run summaries are byte-identical with SHA-256:

`25b5f9bc5cfa3ffa342f647b11761a99eefc157859932614e55d1c3a22b3d8d1`

## Main components

### `detection-lab/event_adapter.py`

Reads all replay events, normalizes fields, derives semantic features, and
preserves source locators and source-line hashes.

### `detection-lab/replay_detector.py`

Applies versioned semantic rules without using ground-truth labels, expected
verdicts, private identifiers, or exact command strings.

### `detection-lab/replay_evaluator.py`

Compares completed decisions with supplied ground truth only after detection.

### `detection-lab/evidence_exporter.py`

Exports exact evaluated source lines and creates the candidate-bound raw
artifact manifest.

### `detection-lab/detection_engine.py`

Runs the portable public, mutation, benign, and diagnostic fixture interface.

### `detection-lab/run_regression.py`

Runs 66 unattended checks and emits deterministic JUnit XML.

### `detection-lab/run_full_replay.py`

Runs normalization, replay detection, post-detection evaluation, and regression
in one command.

### `detection-lab/project_tasks.py`

Provides the documented clean, provision, build, and test entry commands.

## Provenance chain

Every replay result is traceable through the following chain.

### 1. Raw source

`raw-events/raw-artifact-manifest.json` records:

- the complete replay filename, byte count, and SHA-256;
- the assigned evidence marker;
- the exact source line locator;
- the source-line SHA-256;
- the native raw excerpt line.

`raw-events/assigned-source-events.jsonl` preserves the 12 exact assigned
source-event lines.

### 2. Normalized event

`raw-events/normalized-candidates.jsonl` records:

- adapter version;
- normalized channel and event code;
- normalized image and parent image;
- command family;
- semantic behavior features;
- original source locator;
- original source-line SHA-256.

### 3. Detection decision

`alerts/replay-decisions.jsonl` records:

- normalized locator;
- normalized event SHA-256;
- source locator and source-line SHA-256;
- matching rule ID and version;
- ATT&CK technique;
- decision status;
- reason code.

`alerts/replay-alerts.jsonl` contains the alerted decision records.

### 4. Post-detection evaluation

`tests/results/replay-evaluation.json` records:

- supplied expected technique;
- actual detected technique;
- alert status;
- source locator;
- normalized locator;
- source-line hash;
- normalized-event hash;
- matched or failed verdict.

### 5. Claim evidence

`evidence-index.csv` records:

- material claim;
- report section;
- exact artifact path;
- exact locator;
- collection time;
- artifact hash;
- what the artifact proves;
- what it does not prove;
- confidence;
- alternative considered;
- final disposition.

## Detection boundaries

The decision-producing adapter, replay policy, and replay detector do not use:

- case IDs;
- fixture IDs;
- expected verdicts;
- private marker values;
- supplied ATT&CK ground-truth fields;
- source event IDs as rule constants;
- training tokens;
- exact command strings.

Ground-truth labels are read only by `replay_evaluator.py` after detection to
measure supplied expectations.

The evidence exporter reads the marker only after evaluation to preserve the
candidate-bound raw artifact manifest. It does not produce detection decisions.

## Detection rules

The replay policy is stored at:

`rules/replay-policy.json`

The six evidence-supported semantic replay rules cover:

- T1059.001 — PowerShell / encoded interpreter behavior
- T1105 — Ingress tool transfer
- T1547.001 — Registry Run Keys or Startup Folder
- T1003.001 — LSASS credential-access behavior
- T1059.003 — Windows command shell
- T1218.011 — Rundll32 proxy execution

The signed replay contains two assigned events for each of these six unique
techniques.

## Test groups

The unattended test portfolio contains:

- 12 published expected-alert cases;
- 24 published expected no-alert controls;
- malformed fixture rejection;
- malformed replay rejection;
- 8 semantic mutation cases;
- 12 benign holdouts;
- six required outcome classifications;
- full signed-replay normalization;
- replay semantic decisions;
- post-detection ground-truth evaluation;
- repeated clean-run hash comparison.

The six classified outcomes are:

- `no_telemetry`
- `parse_failure`
- `rule_miss`
- `suppressed`
- `alerted`
- `unexpected_alert`

## Deterministic results

Three complete output directories were produced:

- `tests/results/clean-run/`
- `tests/results/full-run-one/`
- `tests/results/full-run-two/`

The directories were compared recursively and were byte-identical.

The corresponding summary files are:

- `tests/results/clean-run-summary.json`
- `tests/results/full-run-one-summary.json`
- `tests/results/full-run-two-summary.json`

All three summary files have SHA-256:

`25b5f9bc5cfa3ffa342f647b11761a99eefc157859932614e55d1c3a22b3d8d1`

The JUnit regression report is:

`regression-results.xml`

It records:

- Tests: 66
- Failures: 0
- Errors: 0

## Source-coverage discrepancy

The signed replay contains 12 labelled assigned events covering six unique
ATT&CK techniques twice. The supplied `technique-matrix.csv` lists twelve
unique techniques. The published expected-alert fixtures cover five unique
techniques.

The matrix techniques without explicit labelled replay events are:

- T1027
- T1053.005
- T1057
- T1087.001
- T1136.001
- T1555

This discrepancy is documented in:

`decisions/B2-source-coverage-discrepancy.md`

The implementation does not fabricate unsupported raw events. Evidence-supported
replay techniques are detected and evaluated from the signed source.
Unsupported matrix rows remain explicitly documented as source-coverage gaps
unless programme staff provides a corrected pack or written mapping.

## Portfolio continuity

`continuity-record.md` documents reuse of the Stage 7 fixture-driven expected
result, JUnit, and raw-versus-derived provenance interface.

The retained Stage 7 submitted manifest records commit:

`e3d0cde7d585dd6bbb40f765fb026b2de6cf6843`

The Stage 7 local Git object was unavailable, so the commit is attributed to the
retained submitted manifest rather than described as independently verified
from local Git history.

Stage 7 network-specific detection logic was not misrepresented as Windows
detection logic. Stage 8 extends the structured fixture, automated assertion,
machine-readable result, and evidence-provenance interfaces.

## Security and privacy

The submission is candidate-bound and must remain view-only. The private marker
appears only in required evidence and documentation.

Do not publicly share this package during the assessment window.

No real credentials, malware, or live-system data are included. The project
does not execute attacks against personal, employer, production, or
internet-connected systems.

## Known limitations

- The issued replay provides labelled raw evidence for six unique matrix
  techniques, not all twelve unique matrix rows.
- The public expected-alert fixtures cover five unique techniques.
- The Stage 7 submitted commit is recorded in its retained manifest, but its
  local Git object is unavailable.
- The complete signed replay remains an external issued input and must be
  supplied to the full-run command.
- Current replay detections operate on the telemetry fields available in the
  signed replay. Additional endpoint telemetry could improve distinction
  between closely related credential-access and obfuscation behaviors.

## Defense starting points

For a selected replay alert:

1. Open `tests/results/replay-evaluation.json`.
2. Find the selected result and its source locator.
3. Locate the native excerpt through
   `raw-events/raw-artifact-manifest.json`.
4. Open the corresponding normalized record in
   `raw-events/normalized-candidates.jsonl`.
5. Open the decision in `alerts/replay-decisions.jsonl`.
6. Explain the matching rule in `rules/replay-policy.json`.
7. Rerun the complete workflow from a clean state.

For the assigned defense preparation, review matrix row 3. The panel may select
any published row or bounded mutation during the recorded defense.

## Assistance declaration

Documentation and AI-assisted guidance were used for planning, explanation,
code review, command construction, debugging, and documentation support. All
commands were run by the candidate, outputs were checked against local
artifacts, and the candidate remains responsible for every claim and for
reproducing the project during defense.

## Repository

Repository URL: https://github.com/immaculeta-security/soc-stage8-detection-engineering
