# PII Scanner: Project Context

Reusable context for collaborating (human or AI) on this library. Keep it short, keep it current.

## Purpose
A lightweight Python library that scans data for PII before it lands somewhere it shouldn't, as a gate inside an ingestion framework.

## Users
- Users: senior data engineers who want PII scanning in their pipelines. Assume high technical skill; docs should be terse.

## Hard constraints
- Plain Python library, pip-installable, Python 3.10+.
- Core deps: `pandas` only (plus `google-cloud-bigquery` when the BQ phase lands, ideally as an optional extra).
- Trivial to drop into a pipeline: pass a DataFrame and the columns to scan; get back which columns pass, and for failures, which PII tags were found.
- Lightweight and pragmatic. No heavy NLP (spaCy, Presidio) in core. May be an optional extra much later.

## Core behaviour
- Fail if any PII is found. Default failure threshold is zero matches. A configurable per-tag threshold may exist, but the default must stay strict.
- Bias towards catching PII: a missed PII is worse than a false positive.
- Scan the full column by default in pandas. Sampling is opt-in, because "no PII in a sample" is not "no PII".

## Detection (v1)
Three layers, cheapest first:

1. Column-name heuristics (e.g. `email`, `phone`, `dob`, `ni_number`).
2. Regex on values.
3. Checksum/format validators to cut false positives (Luhn for cards, NI number format, IBAN mod-97, sort code format).

Initial tags (UK GDPR focus): `NAME`, `EMAIL`, `PHONE`, `NI_NUMBER`, `POSTCODE`, `DOB`, `CARD_NUMBER`, `IBAN`, `SORT_CODE`, `IP_ADDRESS`. Plus a custom-rule hook so users can register their own tag + regex + optional validator.

Extended set (benchmarked against Google Sensitive Data Protection infoTypes; full list in README): more UK IDs (NHS, CHI, passport, driving licence, UTR), international phone, street address, special-category data (health, ethnicity, religion, sexual orientation), gender, device/location IDs, vehicle IDs, and credentials/secrets.

- Weak formats need a hotword in the pattern (named group `v` = the reported value) or a column-name hint.
- Every tag has a sensitivity (`LOW`/`MODERATE`/`HIGH`). `fail_sensitivity` (default `LOW`, i.e. strict) moves lower tags to `warnings`.
- Quasi-identifier tags (postcode, DOB, gender, ethnicity, coordinates) feed a k-anonymity check across columns. It's reported whenever 2+ columns qualify, and fails only with `min_k`.

## Result object
```python
result = scan_dataframe(df, columns=["email", "notes", "phone"])

result.ok  # bool: True only if nothing failed
result.passed_columns  # ["notes"]
result.failed_columns  # {"email": ColumnFinding(...), "phone": ColumnFinding(...)}
# ColumnFinding: tags, match_count, match_rate, masked_shapes
```

- Optional `raise_on_fail=True` to raise `PIIFoundError` (carrying the result) for pipelines that want a hard stop. Default is to return the result.

## Masking rules (non-negotiable)
The scanner must never put raw PII into results, logs, or exceptions.

- Findings report a shape, not a value. Every character is replaced by its class: `D` = digit, `L` = letter, with spaces and punctuation kept as structure. Example: `+44 7911 123456` becomes `+DD DDDD DDDDDD`.
- Shapes are aggregated with counts (top N per column), never per-row.
- Opt-in `include_rows` reports 0-based row *positions* (ints) only, never index labels (which can be PII).
- Re-identification risk reports group counts only, never the combinations.
- No sample values, prefixes, suffixes or hashes of raw data.
- Tests must assert that no raw matched value appears anywhere in the result's repr or exceptions.

## Phased plan
1. pandas DataFrame scanning (done): detectors, validators, result object, masking, tests; scan options (column selection, time windows, sampling modes, limits), sensitivity, row positions, JSON output, re-identification risk.
2. BigQuery mode (next, not started; only the optional extra is declared): same `ScanResult` returned. Two options: run in memory (pull data into pandas) or run remotely, pushing detection into BQ (`REGEXP_CONTAINS` etc.) so only counts and shapes come back and data never leaves the warehouse.
3. Later, TBD: other backends, optional NLP extra, pipeline integrations.

## Non-goals (for now)
- Redaction or remediation of data (detect and report only).
- ML/NLP-based entity recognition in core.
- Non-UK regimes beyond what falls out naturally.
- A UI, service or scheduler. This is a library called from a pipeline.

## Conventions
- Type hints throughout; `ruff` + `pytest`.
- Pure functions for detectors (easy to test); no global state.
- Small public API: `scan_dataframe`, `ScanResult`, `ColumnFinding`, `register_detector`.

## Open questions
- Which orchestrator runs this (Airflow / Cloud Run / Dataflow / other)? Affects packaging and how failures surface.
- How are internal packages distributed (private PyPI, Artifact Registry, git install)?
- Do we want a per-tag failure threshold at all, or strictly zero everywhere? (Implemented; default stays zero.)
- `NAME` in free text is best-effort (titles, context phrases, a first-name list). Is that enough, or do we need an optional NLP extra?
- Hotword *likelihood* rules, allowlists and overlap resolution (e.g. IMEI also matches `CARD_NUMBER`; `12-03-24` dates match `SORT_CODE`) are not implemented yet.
