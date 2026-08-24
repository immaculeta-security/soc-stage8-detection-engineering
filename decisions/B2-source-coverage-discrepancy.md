# B2 Signed-Source Coverage Discrepancy

## Status

Open — clarification requested from programme staff.

## Controlling requirements

The B2 brief requires completion of all twelve rows in `technique-matrix.csv`.
It also states that the signed Windows replay is the complete scored source and
that the harness must run twelve canonical attacks.

## Reproducible observations

The assigned replay contains 250,000 JSONL events and matches the SHA-256 in
`source-manifest.json`.

Exactly twelve replay events contain the supplied ground-truth fields
`marker` and `mitre_technique`.

Those twelve events represent six unique techniques, each appearing twice:

- T1003.001
- T1059.001
- T1059.003
- T1105
- T1218.011
- T1547.001

The technique matrix requires these additional six techniques:

- T1027
- T1053.005
- T1057
- T1087.001
- T1136.001
- T1555

The public fixtures contain twelve expected-alert cases, but those cases cover
only five attack techniques:

- T1003.001
- T1059.001
- T1059.003
- T1105
- T1218.011

The published no-alert fixtures additionally use T1016, T1033, T1057 and T1082.
A benign technique label does not establish a canonical attack source event.

## What this proves

This proves that the supplied labelled replay events and published attack
fixtures do not individually provide canonical attack examples for all twelve
matrix techniques.

## What this does not prove

This does not prove that the six missing techniques were intentionally omitted.
It does not prove that no undocumented semantic interpretation is expected.
It does not authorize creation or fabrication of missing raw events.

## Current disposition

Continue implementing the documented portable interface and the
evidence-supported replay detections. Do not use `marker`, `mitre_technique`,
case IDs, training tokens or expected verdicts as detection constants.

Record unsupported matrix rows as source-coverage gaps unless programme staff
provides a corrected pack or written mapping.
