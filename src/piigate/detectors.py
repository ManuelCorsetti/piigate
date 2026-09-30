"""Detector definitions and the built-in UK GDPR set."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from . import validators

Validator = Callable[[str], bool]
NameHint = Callable[[str], bool]


@dataclass(frozen=True)
class Detector:
    """``pattern`` finds candidates in values; ``validator`` (optional) confirms each match;
    ``name_hint`` flags a column by its normalised name alone (see :func:`normalise_name`)."""

    tag: str
    pattern: re.Pattern[str] | None = None
    validator: Validator | None = None
    name_hint: NameHint | None = None


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


_NAME_QUALIFIERS = frozenset(
    "first last middle full given family maiden customer client patient employee contact "
    "person holder legal preferred".split()
)
_NAME_COMPACT = frozenset("surname forename firstname lastname fullname middlename".split())


def _name_col_hint(norm: str) -> bool:
    toks = norm.split("_")
    if _NAME_COMPACT & set(toks):
        return True
    return any(
        t == "name" and (i == 0 or toks[i - 1] in _NAME_QUALIFIERS) for i, t in enumerate(toks)
    )


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


BUILTIN_DETECTORS: tuple[Detector, ...] = (
    Detector("NAME", name_hint=_name_col_hint),  # regex is weak for names: column-name only
    Detector(
        "EMAIL",
        _rx(r"(?<![\w.+-])[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+"),
        name_hint=name_contains("email"),
    ),
    Detector(
        "PHONE",
        _rx(r"(?<![\w+])(?:\+44|0044|0)[\d\s\-()]{9,16}\d(?!\d)"),
        validators.uk_phone,
        name_contains("phone", "mobile", "msisdn", tokens=("tel", "cell")),
    ),
    Detector(
        "NI_NUMBER",
        _rx(r"(?<![a-z0-9])[a-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[a-d](?![a-z0-9])"),
        validators.ni_number,
        name_contains("nationalinsurance", "ninumber", "nino", "nationalins"),
    ),
    Detector(
        "POSTCODE",
        _rx(r"(?<![a-z0-9])(?:GIR ?0AA|[a-z]{1,2}\d[a-z\d]? ?\d[a-z]{2})(?![a-z0-9])"),
        name_hint=name_contains("postcode", "postalcode", "zipcode", tokens=("zip",)),
    ),
    Detector(
        "DOB",  # a bare date isn't DOB, so column-name only
        name_hint=name_contains("dateofbirth", "birthdate", "birthday", tokens=("dob", "birth")),
    ),
    Detector(
        "CARD_NUMBER",
        _rx(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
        validators.luhn,
        name_contains("cardnumber", "cardno", "creditcard", "debitcard", "ccnum", tokens=("pan",)),
    ),
    Detector(
        "IBAN",
        _rx(
            r"(?<![a-z0-9])[a-z]{2}\d{2}"
            r"(?:(?: [a-z0-9]{4}){2,7}(?: [a-z0-9]{1,3})?|[a-z0-9]{11,30})(?![a-z0-9])"
        ),
        validators.iban,
        name_contains("iban"),
    ),
    Detector(
        "SORT_CODE",
        _rx(r"(?<![\d-])\d{2}([- ])\d{2}\1\d{2}(?![\d-])"),
        validators.sort_code,
        name_contains("sortcode"),
    ),
    Detector(
        "IP_ADDRESS",
        _rx(
            r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
            r"|(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])"
        ),
        validators.ip_address,
        name_contains("ipaddress", "ipaddr", "ipv4", "ipv6", tokens=("ip",)),
    ),
)

_custom: list[Detector] = []


def register_detector(
    tag: str,
    pattern: str | re.Pattern[str],
    validator: Validator | None = None,
    column_names: Iterable[str] = (),
) -> Detector:
    """Register a custom detector for all later scans in this process.

    ``column_names``: fragments that flag a column by name. Returns the detector, which can also
    be passed explicitly via ``scan_dataframe(detectors=...)`` to avoid the process-wide registry.
    """
    compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
    frags = tuple(normalise_name(c).replace("_", "") for c in column_names)
    det = Detector(tag, compiled, validator, name_contains(*frags) if frags else None)
    _custom.append(det)
    return det


def default_detectors() -> tuple[Detector, ...]:
    return BUILTIN_DETECTORS + tuple(_custom)
