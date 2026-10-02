"""Detector type, column-name helpers, and the custom-detector hook.

The built-in detectors are declarative: see ``rules/uk_gdpr.json`` and :mod:`piigate.ruleset`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import cache

Validator = Callable[[str], bool]
NameHint = Callable[[str], bool]


@dataclass(frozen=True)
class Detector:
    """``patterns`` find candidates in values (``group`` is the capture group holding the
    matched text); ``validator`` (optional) confirms each; ``name_hint`` flags a column by its
    normalised name alone (see :func:`normalise_name`)."""

    tag: str
    patterns: tuple[re.Pattern[str], ...] = ()
    validator: Validator | None = None
    name_hint: NameHint | None = None
    group: int = 0

    def matches(self, text: str) -> Iterator[str]:
        """Yield validated matched substrings of ``text``.

        Ruleset patterns put their boundaries *outside* the capture group (no lookarounds, for
        RE2 portability), so after a match we resume at the end of the group, not the match. After
        a rejected candidate we resume one character into it, so a valid match overlapping a
        failed one is still found.
        """
        for pat in self.patterns:
            pos = 0
            while pos <= len(text):
                m = pat.search(text, pos)
                if m is None:
                    break
                start, end = m.span(self.group)
                if self.validator is None or self.validator(m.group(self.group)):
                    yield m.group(self.group)
                    pos = end if end > pos else pos + 1
                else:
                    pos = start + 1


def normalise_name(name: object) -> str:
    """``"First Name"`` / ``"firstName"`` / ``"first-name"`` -> ``"first_name"``."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(name))
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def name_contains(*fragments: str, tokens: Iterable[str] = ()) -> NameHint:
    """Hint matching if the underscore-stripped name contains any fragment, or any whole token."""
    frags = tuple(fragments)
    toks = frozenset(tokens)

    def hint(norm: str) -> bool:
        return any(f in norm.replace("_", "") for f in frags) or bool(toks & set(norm.split("_")))

    return hint


_custom: list[Detector] = []


def register_detector(
    tag: str,
    pattern: str | re.Pattern[str],
    validator: Validator | None = None,
    column_names: Iterable[str] = (),
) -> Detector:
    """Register a custom detector for all later scans in this process.

    ``pattern`` is a plain Python regex (not checked for RE2 portability; use a ruleset file for
    that, see :func:`piigate.load_ruleset`). ``column_names``: fragments that flag a column by
    name. Returns the detector, which can also be passed explicitly via
    ``scan_dataframe(detectors=...)`` to avoid the process-wide registry.
    """
    compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
    frags = tuple(normalise_name(c).replace("_", "") for c in column_names)
    det = Detector(tag, (compiled,), validator, name_contains(*frags) if frags else None)
    _custom.append(det)
    return det


@cache
def builtin_detectors() -> tuple[Detector, ...]:
    from .ruleset import load_ruleset

    return load_ruleset("uk_gdpr")


def default_detectors() -> tuple[Detector, ...]:
    return builtin_detectors() + tuple(_custom)
