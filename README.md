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

Speed: each distinct value is scanned once. `pip install piigate[fast]` (google-re2) scans all
rules in a single pass; `engine="python"|"re2"|"auto"`, results identical. `benchmarks/bench_scan.py`.

Options: `thresholds={"TAG": n}` (default 0), `sample=N` (opt-in), `name_heuristics=False`,
`top_n`, `detectors=[...]`. Custom rules: `register_detector(tag, regex, validator=None, column_names=())`.

Detectors are declarative RE2-compatible JSON (`src/piigate/rules/`, spec in `docs/ruleset.md`);
`load_ruleset(path)` loads your own.

Findings contain masked shapes only (`+DD DDDD DDDDDD`), never raw values.
`NAME` and `DOB` are column-name-only tags (regex is too weak). Dev: `pip install -e .[dev]`, `ruff`, `pytest`.
