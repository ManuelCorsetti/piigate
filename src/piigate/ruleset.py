"""Declarative rulesets: detectors as JSON data, portable across implementations.

Format (version 1), see ``docs/ruleset.md``::

    {"version": 1, "name": "...", "detectors": [{
        "tag": "EMAIL",
        "patterns": [{"regex": "(?i)(?:^|[^\\w.+-])([\\w.+-]+@...)",   # RE2, one capture group
                      "gate": "@"}],  # optional: string or list, each a cheap necessary condition
        "validator": "luhn" | null,                          # name from validators.VALIDATORS
        "name_hint": {"fragments": [...], "tokens": [...], "qualified": {...}},
        "examples": {"match": [...], "no_match": [...]},      # conformance vectors
        "column_names": {"hit": [...], "miss": [...]}
    }]}
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from importlib import resources
from pathlib import Path
from typing import Any

from .detectors import Detector, NameHint, name_contains
from .validators import VALIDATORS

SUPPORTED_VERSION = 1
_CLASS = re.compile(r"\[(?:\\.|[^\]\\])*\]")
_ESCAPED = re.compile(r"\\.")
_BACKREF = re.compile(r"\\[1-9kgGZ]|\(\?P=")
_UNSUPPORTED = re.compile(r"\(\?(?:=|!|<=|<!|>|\(|#)|[*+?}]\+")


def check_re2(pattern: str) -> None:
    """Raise ``ValueError`` if ``pattern`` uses constructs RE2 (BigQuery, Go, Rust) lacks:
    lookaround, backreferences, atomic groups, possessive quantifiers, conditionals."""
    bare = pattern.replace("\\\\", "")
    if _BACKREF.search(bare):
        raise ValueError(f"backreference not supported by RE2: {pattern!r}")
    bare = _CLASS.sub("[]", _ESCAPED.sub("", bare))
    if _UNSUPPORTED.search(bare):
        raise ValueError(
            f"lookaround/atomic/possessive/conditional not supported by RE2: {pattern!r}"
        )


def compile_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a ruleset pattern: ASCII classes (as in RE2), exactly one capture group."""
    check_re2(pattern)
    compiled = re.compile(pattern, re.ASCII)
    if compiled.groups != 1:
        raise ValueError(
            f"pattern needs exactly one capture group, has {compiled.groups}: {pattern!r}"
        )
    return compiled


def compile_gate(gate: str) -> re.Pattern[str]:
    """Compile a gate: RE2-compatible, ASCII, no capture groups."""
    check_re2(gate)
    compiled = re.compile(gate, re.ASCII)
    if compiled.groups:
        raise ValueError(f"gate must not have capture groups: {gate!r}")
    return compiled


def _gate_chain(gate: str | list[str] | None) -> tuple[re.Pattern[str], ...]:
    if not gate:
        return ()
    return tuple(compile_gate(g) for g in ([gate] if isinstance(gate, str) else gate))


def name_hint_from_spec(spec: Mapping[str, Any]) -> NameHint:
    """Build a column-name hint from ``fragments`` / ``tokens`` / ``qualified`` keys.

    ``qualified``: ``{"word": "name", "qualifiers": [...]}`` matches the word token only when it
    is the first token or follows a qualifier (``first_name`` yes, ``file_name`` no).
    """
    base = name_contains(*spec.get("fragments", ()), tokens=spec.get("tokens", ()))
    q = spec.get("qualified")
    if not q:
        return base
    word, quals = q["word"], frozenset(q["qualifiers"])

    def hint(norm: str) -> bool:
        toks = norm.split("_")
        return base(norm) or any(
            t == word and (i == 0 or toks[i - 1] in quals) for i, t in enumerate(toks)
        )

    return hint


def detectors_from_dict(doc: Mapping[str, Any]) -> tuple[Detector, ...]:
    if doc.get("version") != SUPPORTED_VERSION:
        raise ValueError(f"unsupported ruleset version: {doc.get('version')!r}")
    out = []
    for d in doc["detectors"]:
        vname = d.get("validator")
        if vname is not None and vname not in VALIDATORS:
            raise ValueError(f"{d['tag']}: unknown validator {vname!r}")
        specs = [{"regex": p} if isinstance(p, str) else p for p in d.get("patterns", ())]
        patterns = tuple(compile_pattern(p["regex"]) for p in specs)
        gates = tuple(_gate_chain(p.get("gate")) for p in specs)
        spec = d.get("name_hint")
        out.append(
            Detector(
                tag=d["tag"],
                patterns=patterns,
                validator=VALIDATORS[vname] if vname else None,
                name_hint=name_hint_from_spec(spec) if spec else None,
                group=1,
                gates=gates,
                portable=True,
            )
        )
    return tuple(out)


def load_ruleset(source: str | Path | Mapping[str, Any]) -> tuple[Detector, ...]:
    """Load detectors from a ruleset: a dict, a JSON file path, or a bundled name (``"uk_gdpr"``).

    Combine with the defaults via ``default_detectors() + load_ruleset(...)``.
    """
    if isinstance(source, Mapping):
        return detectors_from_dict(source)
    path = Path(source)
    if path.suffix == ".json":
        text = path.read_text(encoding="utf-8")
    else:
        text = resources.files("piigate").joinpath("rules", f"{source}.json").read_text("utf-8")
    return detectors_from_dict(json.loads(text))
