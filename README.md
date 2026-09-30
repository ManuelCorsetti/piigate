# piigate

Lightweight PII scanning gate for ingestion pipelines. Detect and report only. See `context.md`.

```python
from piigate import scan_dataframe

result = scan_dataframe(df, columns=["email", "notes", "phone"])
result.ok  # True only if nothing failed
result.passed_columns  # ["notes"]
result.failed_columns  # {"email": ColumnFinding(tags, match_count, match_rate, masked_shapes), ...}

scan_dataframe(df, cols, raise_on_fail=True)  # raises PIIFoundError(result)
```

Options: `thresholds={"TAG": n}` (default 0), `sample=N` (opt-in), `name_heuristics=False`,
`top_n`, `detectors=[...]`. Custom rules: `register_detector(tag, regex, validator=None, column_names=())`.

Findings contain masked shapes only (`+DD DDDD DDDDDD`), never raw values.
`NAME` and `DOB` are column-name-only tags (regex is too weak). Dev: `pip install -e .[dev]`, `ruff`, `pytest`.
