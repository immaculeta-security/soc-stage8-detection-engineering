# Portable Event Decoder and Adapter

Stage 8 B2 uses the issued signed Windows JSONL replay as the complete scored
source. The controlling B2 route does not require Wazuh, a live Windows agent,
Sysmon installation, Docker, or XML decoder execution.

The versioned portable decoder is implemented by:

- `detection-lab/event_adapter.py`

The adapter reads each immutable JSONL source record, validates its required
fields, normalizes channel names and process fields, derives documented
semantic behaviour features, and preserves:

- the original source filename;
- the exact source line number;
- the SHA-256 of the original source line;
- the normalized-event SHA-256; and
- the adapter version.

The adapter does not copy the private evidence marker, supplied
`mitre_technique` ground-truth label, case IDs, expected verdicts, or training
tokens into the detector input.

Primary outputs:

- `raw-events/source-accounting.json`
- `raw-events/normalized-candidates.jsonl`

The Wazuh XML files supplied in the B2 compatibility materials are not used as
scored evidence. They remain optional compatibility examples under the issued
brief and do not replace the portable replay workflow.
