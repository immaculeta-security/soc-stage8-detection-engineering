# Stage 8 B2 Detection Rule Test Records

Candidate: `UBI-2026-0004`  
Variant: `D3`  
Private assignment marker: `UBI-A8-B79056480F9B`  
Replay-embedded shared source marker: `UBI-A8-SHARED-B1`  

The shared source marker is preserved because it is part of the immutable
replay distributed in the verified B2 archive. It is not used as the private
candidate binding and is not a detection input.
Execution route: B2 portable signed replay  
Atomic GUID: Not applicable to the controlling B2 portable route  
Replay SHA-256: `ea7f96497f9275ccdc47fdb026480558547db5bfaa7aa8bf3a806a2bc9272838`  
Adapter version: `1.0.0`  
Replay policy version: `1.0.0`  
Replay detector version: `1.0.0`  

The B2 brief makes the signed Windows replay the complete scored source.
“Normalized event” below replaces the earlier Wazuh-event layer. No live
endpoint was changed, so cleanup means confirming that immutable input remained
unchanged and generated outputs can be removed by the documented clean command.

## Shared test evidence

- Full source accounting: `raw-events/source-accounting.json`
- Raw assigned-event excerpt: `raw-events/assigned-source-events.jsonl`
- Raw artifact manifest: `raw-events/raw-artifact-manifest.json`
- Normalized candidates: `raw-events/normalized-candidates.jsonl`
- Replay decisions: `alerts/replay-decisions.jsonl`
- Replay alerts: `alerts/replay-alerts.jsonl`
- Replay evaluation: `tests/results/clean-run/replay-evaluation.json`
- Public suite: `tests/results/public-detection-results.json`
- Mutation suite: `tests/results/mutation-results.json`
- Benign holdouts: `tests/results/benign-holdout-results.json`
- JUnit report: `tests/results/clean-run/regression-results.xml`
- Clean-run summary: `tests/results/clean-run-summary.json`

The public suite passed 36 of 36 cases: 12 expected alerts and 24 expected
no-alert controls. The mutation suite passed eight of eight cases: seven
alerted and the documented outside-window mutation was suppressed. The benign
holdout suite suppressed all 12 cases. These suites exercise the portable
fixture engine. They support general negative and mutation behaviour, but they
are not represented as technique-specific raw replay events when the signed
replay does not supply such an event.

---

## Row 1 — T1059.001 PowerShell

Rule: `UBI-A8-1001`, version `1.0.0`, severity `high`  
Required semantic feature: `encoded_or_obfuscated_behavior`  
Threshold/window: one normalized event with the required feature; no
cross-event replay window.

### Telemetry chain

| Layer | UTC time | Artifact | Exact locator | Relevant fields |
|---|---|---|---|---|
| Source event 1 | 2026-07-08T05:20:30Z | `windows-replay.jsonl` | line 19231 | Sysmon event 1; PowerShell; WinWord parent; encoded/obfuscated family |
| Source event 2 | 2026-07-09T13:23:30Z | `windows-replay.jsonl` | line 134611 | Sysmon event 1; PowerShell; WinWord parent; encoded/obfuscated family |
| Normalized events | same source times | `raw-events/normalized-candidates.jsonl` | lines 1 and 7 | `encoded_or_obfuscated_behavior`; raw and normalized hashes |
| Decisions/alerts | deterministic replay run | `alerts/replay-decisions.jsonl` | lines 1 and 7 | `UBI-A8-1001`; status `alerted`; reason `semantic_rule_match` |
| Evaluation | deterministic replay run | `tests/results/clean-run/replay-evaluation.json` | results for source lines 19231 and 134611 | expected and actual technique `T1059.001`; matched `true` |

### Detection logic and tests

The rule detects an encoded or obfuscated interpreter behaviour supplied by the
versioned adapter. It does not match the private marker, case ID, expected
verdict, training token, or one exact Atomic command string.

Assigned replay result: two alerts, both matched. General mutation evidence:
renamed-binary, different-encoding, removed-command-family, full-path/case,
channel-alias, and window-boundary fixture mutations matched their expectations.
General benign evidence: all 24 published controls and 12 benign holdouts were
suppressed.

Tuning history: channel aliases and executable case/path normalization were
added after the first public run produced 12 verdict mismatches. The preserved
pre-normalization result is
`tests/results/public-detection-results-before-channel-normalization.json`.

Blind spot: if the source loses the behaviour signal and the remaining process
fields resemble ordinary administration, this rule can miss the activity.
Test next with an encoded interpreter represented only through script-block or
content telemetry.

---

## Row 2 — T1053.005 Scheduled Task

Rule: not implemented from assigned replay evidence  
Assigned replay result: `no_telemetry`

The required technique appears in `coverage-matrix.csv`, but no labelled
canonical T1053.005 attack event exists in the issued signed replay. No raw UTC
time, normalized event, alert, or technique-specific benign replay pair is
invented.

General benign and malformed-input suites still ran, but they do not establish
T1053.005 attack coverage.

Blind spot and next improvement: scheduled-task creation requires task
scheduler operational events, registry task-cache evidence, or process
telemetry containing semantically parsed task creation. Test after staff
provides an authorized canonical source event or written mapping.

Cleanup: not applicable; immutable replay only.

---

## Row 3 — T1547.001 Registry Run Keys or Startup Folder

Rule: `UBI-A8-1003`, version `1.0.0`, severity `high`  
Required semantic feature: `registry_persistence_behavior`  
Threshold/window: one normalized event with the required feature; no
cross-event replay window.

### Telemetry chain

| Layer | UTC time | Artifact | Exact locator | Relevant fields |
|---|---|---|---|---|
| Source event 1 | 2026-07-09T02:42:30Z | `windows-replay.jsonl` | line 96151 | Sysmon event 1; `REG.EXE`; `cmd.exe` parent; registry-run-key family |
| Source event 2 | 2026-07-10T10:45:30Z | `windows-replay.jsonl` | line 211531 | Sysmon event 1; `REG.EXE`; `cmd.exe` parent; registry-run-key family |
| Normalized events | same source times | `raw-events/normalized-candidates.jsonl` | lines 5 and 11 | `registry_persistence_behavior`; source locators and hashes |
| Decisions/alerts | deterministic replay run | `alerts/replay-decisions.jsonl` | lines 5 and 11 | `UBI-A8-1003`; status `alerted`; reason `semantic_rule_match` |
| Evaluation | deterministic replay run | `tests/results/clean-run/replay-evaluation.json` | results for source lines 96151 and 211531 | expected and actual technique `T1547.001`; matched `true` |

### Detection logic and tests

The adapter identifies registry persistence behaviour and the rule requires
that semantic feature. The rule does not use the evidence marker, supplied
MITRE label, training token, case ID, expected verdict, or exact command line.

Assigned replay result: two alerts, both matched. General public, mutation, and
benign holdout suites passed. The issued public expected-alert fixtures do not
contain a T1547.001 canonical attack; therefore those fixture results are not
misrepresented as a technique-specific T1547.001 benign pair.

Tuning history: the semantic replay rule was separated from the supplied
ground-truth label so that evaluation occurs only after the decision. Provenance
locators were corrected so the normalized locator points to
`normalized-candidates.jsonl`, not the original replay.

Blind spot: registry persistence performed through another API, a renamed
utility, a startup-folder file operation, or missing command-family telemetry
may evade this feature. Test next with authorized registry-set telemetry and a
startup-folder file-create event.

Cleanup: not applicable; processing the replay makes no endpoint change.

### Row 3 defense explanation

I start at `windows-replay.jsonl` line 96151 or 211531. I verify the raw line
hash through `raw-events/raw-artifact-manifest.json`. I then open normalized
candidate line 5 or 11 and show `registry_persistence_behavior`. Next I open
decision line 5 or 11 and show rule `UBI-A8-1003`, version `1.0.0`, and status
`alerted`. Finally, I show the matching result in
`tests/results/clean-run/replay-evaluation.json`. Ground-truth labels are used
only at this last evaluation stage.

---

## Row 4 — T1003.001 LSASS Memory Credential Dumping

Rule: `UBI-A8-1004`, version `1.0.0`, severity `critical`  
Required semantic feature: `credential_access_behavior`  
Threshold/window: one normalized event with the required feature.

### Telemetry chain

| Layer | UTC time | Artifact | Exact locator | Relevant fields |
|---|---|---|---|---|
| Source event 1 | 2026-07-09T08:03:00Z | `windows-replay.jsonl` | line 115381 | Sysmon event 1; Rundll32; PowerShell parent; credential-access family |
| Source event 2 | 2026-07-10T16:06:00Z | `windows-replay.jsonl` | line 230761 | Sysmon event 1; Rundll32; PowerShell parent; credential-access family |
| Normalized events | same source times | `raw-events/normalized-candidates.jsonl` | lines 6 and 12 | `credential_access_behavior`; provenance hashes |
| Decisions/alerts | deterministic replay run | `alerts/replay-decisions.jsonl` | lines 6 and 12 | `UBI-A8-1004`; `critical`; `alerted` |
| Evaluation | deterministic replay run | `tests/results/clean-run/replay-evaluation.json` | results for source lines 115381 and 230761 | matched `true` |

Assigned replay result: two alerts, both matched. General benign controls and
holdouts were suppressed, but the replay does not supply a technique-specific
benign LSASS-access event.

Tuning history: detection input was separated from post-detection supplied
ground truth. Blind spot: direct memory access by another process or loss of
credential-access classification may evade the rule. Test next with authorized
process-access telemetry and non-Rundll32 credential-access variants.

Cleanup: not applicable; immutable replay only.

---

## Row 5 — T1087.001 Local Account Discovery

Rule: not implemented from assigned replay evidence  
Assigned replay result: `no_telemetry`

No labelled canonical T1087.001 attack event exists in the issued replay.
Therefore no raw event, normalization result, alert, or technique-specific
benign replay pair is claimed.

Blind spot and next improvement: account discovery may appear through command
execution, PowerShell APIs, WMI, or directory queries. Test after an authorized
canonical source event or written mapping is supplied.

Cleanup: not applicable; immutable replay only.

---

## Row 6 — T1057 Process Discovery

Rule: not implemented from assigned replay attack evidence  
Assigned replay result: `no_telemetry`

T1057 appears in published fixtures only among expected no-alert controls. Those
controls were correctly suppressed, but a benign label is not substituted for
a canonical T1057 attack event.

Evidence: `fixtures/public-fixtures.json` and
`tests/results/public-detection-results.json`.

Blind spot and next improvement: process discovery can use Tasklist, WMI,
PowerShell, native APIs, or renamed tools. Test with an authorized canonical
attack and benign administration pair when supplied.

Cleanup: not applicable; immutable replay only.

---

## Row 7 — T1105 Ingress Tool Transfer

Rule: `UBI-A8-1002`, version `1.0.0`, severity `high`  
Required semantic feature: `ingress_transfer_behavior`  
Threshold/window: one normalized event with the required feature.

### Telemetry chain

| Layer | UTC time | Artifact | Exact locator | Relevant fields |
|---|---|---|---|---|
| Source event 1 | 2026-07-08T21:22:00Z | `windows-replay.jsonl` | line 76921 | Sysmon event 1; Certutil; PowerShell parent; download family |
| Source event 2 | 2026-07-10T05:25:00Z | `windows-replay.jsonl` | line 192301 | Sysmon event 1; Certutil; PowerShell parent; download family |
| Normalized events | same source times | `raw-events/normalized-candidates.jsonl` | lines 4 and 10 | `ingress_transfer_behavior`; provenance hashes |
| Decisions/alerts | deterministic replay run | `alerts/replay-decisions.jsonl` | lines 4 and 10 | `UBI-A8-1002`; `alerted` |
| Evaluation | deterministic replay run | `tests/results/clean-run/replay-evaluation.json` | results for source lines 76921 and 192301 | matched `true` |

Assigned replay result: two alerts, both matched. General mutation and benign
suites passed, but they do not prove every alternate transfer protocol.

Tuning history: executable path/case and channel aliases were normalized in the
fixture engine. Blind spot: another transfer utility, browser download, BITS,
SMB, or missing download classification may evade the rule. Test next with
authorized alternate-tool and protocol variants.

Cleanup: not applicable; immutable replay only.

---

## Row 8 — T1218.011 Rundll32 Proxy Execution

Rule: `UBI-A8-1006`, version `1.0.0`, severity `high`  
Required semantic feature: `service_proxy_execution_relationship`  
Threshold/window: one normalized event with the required feature.

### Telemetry chain

| Layer | UTC time | Artifact | Exact locator | Relevant fields |
|---|---|---|---|---|
| Source event 1 | 2026-07-08T16:01:30Z | `windows-replay.jsonl` | line 57691 | Sysmon event 1; Rundll32; Services parent; native family |
| Source event 2 | 2026-07-10T00:04:30Z | `windows-replay.jsonl` | line 173071 | Sysmon event 1; Rundll32; Services parent; native family |
| Normalized events | same source times | `raw-events/normalized-candidates.jsonl` | lines 3 and 9 | `service_proxy_execution_relationship`; provenance hashes |
| Decisions/alerts | deterministic replay run | `alerts/replay-decisions.jsonl` | lines 3 and 9 | `UBI-A8-1006`; `alerted` |
| Evaluation | deterministic replay run | `tests/results/clean-run/replay-evaluation.json` | results for source lines 57691 and 173071 | matched `true` |

Assigned replay result: two alerts, both matched. Changed-parent,
full-path/case, and channel-alias fixture mutations passed in the general
portable suite. Benign mismatched-parent and mismatched-image holdouts were
suppressed by that fixture engine.

Tuning history: matching was based on a semantic service/proxy relationship
instead of an exact Atomic command string. Blind spot: proxy execution with a
different signed binary or non-service parent may evade this rule. Test next
with additional authorized LOLBin and parent-process variants.

Cleanup: not applicable; immutable replay only.

---

## Row 9 — T1059.003 Windows Command Shell

Rule: `UBI-A8-1005`, version `1.0.0`, severity `high`  
Required semantic feature: `remote_shell_parent_relationship`  
Threshold/window: one normalized event with the required feature.

### Telemetry chain

| Layer | UTC time | Artifact | Exact locator | Relevant fields |
|---|---|---|---|---|
| Source event 1 | 2026-07-08T10:41:00Z | `windows-replay.jsonl` | line 38461 | Sysmon event 1; Cmd; WMI Provider parent; native family |
| Source event 2 | 2026-07-09T18:44:00Z | `windows-replay.jsonl` | line 153841 | Sysmon event 1; Cmd; WMI Provider parent; native family |
| Normalized events | same source times | `raw-events/normalized-candidates.jsonl` | lines 2 and 8 | `remote_shell_parent_relationship`; provenance hashes |
| Decisions/alerts | deterministic replay run | `alerts/replay-decisions.jsonl` | lines 2 and 8 | `UBI-A8-1005`; `alerted` |
| Evaluation | deterministic replay run | `tests/results/clean-run/replay-evaluation.json` | results for source lines 38461 and 153841 | matched `true` |

Assigned replay result: two alerts, both matched. General changed-parent,
renamed-binary, path/case, and channel mutation cases passed; benign
mismatched-parent and security-only controls were suppressed by the fixture
engine.

Tuning history: matching uses the normalized parent relationship and not the
training token. Blind spot: another remote execution parent, direct API use, or
renamed shell may evade the feature. Test next with WinRM, service, scheduled
task, and renamed-shell variants.

Cleanup: not applicable; immutable replay only.

---

## Row 10 — T1136.001 Create Local Account

Rule: not implemented from assigned replay evidence  
Assigned replay result: `no_telemetry`

No labelled canonical T1136.001 attack event exists in the issued replay. No
raw, normalized, alert, or technique-specific benign result is invented.

Blind spot and next improvement: local-account creation requires Security
account-management events, SAM changes, or semantically parsed account-creation
commands. Test when authorized canonical telemetry is supplied.

Cleanup: not applicable; immutable replay only.

---

## Row 11 — T1555 Credentials from Password Stores

Rule: not implemented from assigned replay evidence  
Assigned replay result: `no_telemetry`

No labelled canonical T1555 attack event exists in the issued replay. No
technique-specific source event or benign pair is claimed.

Blind spot and next improvement: browser, vault, registry, memory, and
application-specific password-store access require richer file, registry, API,
or process-access telemetry. Test when authorized canonical evidence is
supplied.

Cleanup: not applicable; immutable replay only.

---

## Row 12 — T1027 Obfuscated Files or Information

Rule: not independently implemented as T1027 from assigned replay evidence  
Assigned replay result: `no_telemetry`

The replay contains encoded/obfuscated behaviour, but the supplied ground truth
labels those events T1059.001. They were not relabelled as T1027. No distinct
labelled T1027 canonical event exists in the assigned replay.

General different-encoding mutation evidence passed for the portable fixture
engine, but this does not create an independent raw T1027 canonical event.

Blind spot and next improvement: obfuscation can affect scripts, binaries,
archives, strings, environment variables, or staged content. Test with an
authorized T1027-labelled canonical source and benign packed/software-update
controls.

Cleanup: not applicable; immutable replay only.

---

## Overall disposition

Six replay-backed rules alerted on all 12 assigned labelled source events. The
remaining six required matrix techniques are preserved as explicit
`no_telemetry` or source-coverage gaps. No missing raw evidence was fabricated,
and no supplied event was relabelled to create unsupported coverage.

The weakest part of the submission is the absence of labelled canonical replay
attacks for six matrix techniques. Evidence that would change this conclusion
is a corrected signed replay, an additional authorized fixture, or a written
staff mapping to existing source events.
