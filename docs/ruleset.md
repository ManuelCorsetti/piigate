# Ruleset format (v1)

Detectors are data, so other implementations (Rust, Go, BigQuery SQL) can share them. The bundled
set is `src/piigate/rules/uk_gdpr.json`. Load your own with `load_ruleset(path_or_dict)` and combine
with `default_detectors() + load_ruleset(...)`.

```json
{"version": 1, "name": "uk_gdpr", "detectors": [{
  "tag": "EMAIL",
  "patterns": [{"regex": "(?i)(?:^|[^\\w.+-])([\\w.+-]+@[a-z0-9-]+(?:\\.[a-z0-9-]+)+)", "gate": "@"}],
  "validator": null,
  "name_hint": {"fragments": ["email"], "tokens": [], "qualified": null},
  "examples": {"match": ["..."], "no_match": ["..."]},
  "column_names": {"hit": ["..."], "miss": ["..."]}
}]}
```

## Patterns
- **RE2 syntax only**: no lookaround, backreferences, atomic groups or possessive quantifiers.
  Enforced at load time (`check_re2`) and checked against the real RE2 engine in tests.
- **ASCII semantics**: `\d`, `\w`, `\s` are ASCII (Python compiles with `re.ASCII`). Case-insensitivity
  is inline `(?i)` so the string is self-contained.
- **Exactly one capture group**, holding the matched text. Boundaries sit outside it as consuming
  groups, e.g. `(?:^|[^A-Za-z0-9])(...)(?:$|[^A-Za-z0-9])`.
- Several patterns per detector are OR-ed; matches are summed.
- **`gate`** (optional, string or list): cheap necessary conditions. If a gate does not match a
  text, the pattern cannot match it, so the engine may skip it. Gates in a list run in order, each
  only on rows that passed the previous one. A gate must never be stricter than its pattern; a test
  fuzzes this (pattern match implies every gate matches). Gates are RE2 syntax with no capture groups.

## Matching algorithm
Search from `pos`. On a match, take the capture group. If the validator accepts it, count it and set
`pos` to the group end (not the match end, so the trailing boundary char can lead the next match).
If the validator rejects it, set `pos` to group start + 1 so a valid match overlapping the rejected
one is still found. Reference: `Detector.matches`.

## Validators
Named, implemented per language: `luhn`, `ni_number`, `iban`, `sort_code`, `uk_phone`, `ip_address`
(see `validators.py`). `null` means the pattern alone decides.

## Column-name hints
Names are normalised first (`firstName`, `First Name`, `first-name` -> `first_name`).
- `fragments`: match if the name with underscores removed contains the fragment.
- `tokens`: match if any underscore-separated token equals it.
- `qualified`: `{"word": "name", "qualifiers": [...]}` matches the word token only when it is first or
  follows a qualifier (`first_name`, `name` yes; `file_name` no).

## Conformance
`examples` and `column_names` are test vectors every implementation should pass.

## BigQuery note (phase 2)
Patterns run under `REGEXP_CONTAINS` / `REGEXP_EXTRACT` as-is (single capture group). Validators
have no SQL equivalent, so remote mode will either get counts of candidate matches (upper bound) or
need UDFs for the checksums.
