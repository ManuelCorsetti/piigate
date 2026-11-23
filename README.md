# piigate

Lightweight PII scanning gate for ingestion pipelines. Detect and report only. See `context.md`.

```python
from piigate import scan_dataframe

result = scan_dataframe(df)  # all columns; or columns=[...], exclude_columns=[...]
result.ok  # False if any column failed (or min_k re-identification check failed)
result.passed_columns  # ["notes"]
result.failed_columns  # {"email": ColumnFinding(tags, match_count, match_rate, masked_shapes, ...)}
result.warnings  # tags below fail_sensitivity, same shape as failed_columns
result.reidentification_risk  # k-anonymity over quasi-identifier columns, or None
result.to_json()  # for logs / alerts

scan_dataframe(df, raise_on_fail=True)  # raises PIIFoundError(result)
```

## Options

| Option | Default | |
|---|---|---|
| `columns` / `exclude_columns` | all / none | which columns to scan |
| `thresholds={"TAG": n}` | 0 | per-tag tolerated match count |
| `fail_sensitivity` | `"LOW"` (everything fails) | `"MODERATE"`/`"HIGH"`: lower tags become `warnings` |
| `timestamp_column`, `since`, `until` | off | incremental scan of a time window (`since` inclusive) |
| `sample` | off | int rows or float fraction; `sample_method="random"\|"head"`, `random_state` |
| `max_findings` | off | stop scanning a column after N findings (`finding.truncated`) |
| `fail_fast` | False | stop at first failing column (`result.skipped_columns`) |
| `include_rows` | False | `finding.row_positions`: 0-based positions, never index labels |
| `min_k` | off | fail if k-anonymity over quasi-identifier columns < `min_k` (risk is always reported) |
| `name_heuristics`, `top_n`, `detectors` | True, 5, built-ins + registered | |

## Tags

Sensitivity in brackets; `*` = quasi-identifier (feeds re-identification risk).

- UK identifiers: `NI_NUMBER` `NHS_NUMBER` `CHI_NUMBER` `PASSPORT_NUMBER` `DRIVING_LICENCE` `UTR` (H)
- Contact / person: `NAME` `EMAIL` `PHONE` (UK + international) `STREET_ADDRESS` `DOB`* (M), `POSTCODE`* `GENDER`* (L)
- Special category (Art. 9): `HEALTH` `ETHNIC_GROUP`* `RELIGION` `SEXUAL_ORIENTATION` (H)
- Financial: `CARD_NUMBER` `IBAN` (H), `SORT_CODE` (M), `SWIFT_CODE` (L)
- Device / location: `IMEI` `LOCATION_COORDINATES`* `VIN` `VEHICLE_REGISTRATION` (M), `IP_ADDRESS` `MAC_ADDRESS` (L)
- Secrets: `AWS_CREDENTIALS` `GCP_API_KEY` `GCP_CREDENTIALS` `JSON_WEB_TOKEN` `PRIVATE_KEY` `AUTH_TOKEN` `PASSWORD` (H)

Weak formats (`UTR`, `PASSPORT_NUMBER`, `CHI_NUMBER`, unspaced NHS, `IMEI`, `SWIFT_CODE`,
`VEHICLE_REGISTRATION`, `DOB` in values) only match after a hotword (`passport no 123456789`) or by
column name. `GENDER`, `RELIGION`, `SEXUAL_ORIENTATION` are column-name only. `NAME` in free text is
best-effort (titles, context phrases, a short first-name list), not NLP.

## Custom rules

`register_detector(tag, regex, validator=None, column_names=(), sensitivity="HIGH",
quasi_identifier=False)`. A named group `v` limits validation and shaping to that group, so a
pattern can require a hotword: `r"(?i:staff\s+id)\s*(?P<v>\d{6})"`.

Findings contain masked shapes only (`+DD DDDD DDDDDD`), never raw values.
Dev: `pip install -e .[dev]`, `ruff`, `pytest`.
