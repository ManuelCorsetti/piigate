"""Detector definitions and the built-in set (UK GDPR focus, plus common global types)."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from . import validators
from ._wordlists import ETHNIC_PHRASES, FIRST_NAMES, HEALTH_TERMS, trie_regex

Validator = Callable[[str], bool]
NameHint = Callable[[str], bool]

LOW, MODERATE, HIGH = "LOW", "MODERATE", "HIGH"
SENSITIVITY_LEVELS: tuple[str, ...] = (LOW, MODERATE, HIGH)


@dataclass(frozen=True)
class Detector:
    """``pattern`` finds candidates in values; ``validator`` (optional) confirms each match;
    ``name_hint`` flags a column by its normalised name alone (see :func:`normalise_name`).

    If ``pattern`` has a named group ``v``, only that group is validated and shaped. This lets a
    pattern require context (a hotword such as ``passport no``) without reporting it.
    ``sensitivity`` is ``LOW`` / ``MODERATE`` / ``HIGH``. ``quasi_identifier`` marks tags that
    re-identify people in combination (postcode, DOB, gender...); see re-identification risk.
    """

    tag: str
    pattern: re.Pattern[str] | None = None
    validator: Validator | None = None
    name_hint: NameHint | None = None
    sensitivity: str = HIGH
    quasi_identifier: bool = False

    def __post_init__(self) -> None:
        if self.sensitivity not in SENSITIVITY_LEVELS:
            raise ValueError(f"sensitivity must be one of {SENSITIVITY_LEVELS}")


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


# "ip_address", "email_address", "mac_address" etc. are not postal addresses.
_NON_POSTAL = frozenset(
    "ip ipv4 ipv6 email mac web url wallet server host contract memory hardware bluetooth wifi "
    "network remote local bind proxy".split()
)


def _address_col_hint(norm: str) -> bool:
    toks = norm.split("_")
    for i, t in enumerate(toks):
        if t == "street" or t.startswith(("streetaddress", "addressline", "postaladdress")):
            return True
        stem = re.fullmatch(r"(\w*?)(?:address|addr)\d*", t)
        if stem is None:
            continue
        prefix = stem.group(1) or (toks[i - 1] if i else "")
        if prefix not in _NON_POSTAL:
            return True
    return False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Hotword, then up to a few separators and an optional "no"/"number"/"ref"/"is", then the value.
_GAP = r"[^\w\n]{0,4}(?:(?:no|num|number|ref|reference|id|is|was)\b\.?[^\w\n]{0,4}){0,2}"


def _ctx(hotwords: str, value: str) -> re.Pattern[str]:
    """Value only counts when preceded by a hotword; the value is group ``v``."""
    return _rx(rf"(?<![a-z0-9])(?:{hotwords})(?![a-z]){_GAP}(?P<v>{value})(?![a-z0-9])")


_CAP = r"[A-Z][a-z]+(?:[-'][A-Z]?[a-z]+)?"
_CAP_NAME = rf"{_CAP}(?:\s+{_CAP}){{0,2}}"
_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
_DATE = (
    r"\d{1,2}[/.\-]\d{1,2}[/.\-](?:\d{4}|\d{2})|\d{4}-\d{2}-\d{2}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?\s+{_MONTH},?\s+\d{{4}}"
    rf"|{_MONTH}\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}"
    r"|(?:19|20)\d{2}"
)
_STREET_SUFFIX = (
    r"street|st|road|rd|avenue|ave|lane|ln|drive|close|way|court|crescent|place|gardens|grove"
    r"|terrace|square|hill|mews|row|walk|rise|parade|boulevard|park"
)

BUILTIN_DETECTORS: tuple[Detector, ...] = (
    # --- Names: column name first, then best-effort free-text patterns (no NLP) ---
    Detector("NAME", name_hint=_name_col_hint, sensitivity=MODERATE),
    Detector(  # Title + capitalised name: "Mrs Sarah Thompson"
        "NAME",
        re.compile(
            r"(?<![A-Za-z])(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Sir|Dame|Lady|Lord|Rev|Revd)\.?\s+"
            rf"(?P<v>{_CAP_NAME})"
        ),
        sensitivity=MODERATE,
    ),
    Detector(  # Context phrase + capitalised name: "spoke to Sarah Thompson"
        "NAME",
        re.compile(
            r"(?i:(?<![a-z])(?:my name is|name is|name:|named|called|spoke (?:to|with)"
            r"|speaking (?:to|with)|dear|regards,?|sincerely,?|signed(?: by)?|attn:?|c/o))\s+"
            rf"(?!(?:Sir|Madam|Customer|Team|All|Colleague|Friend)s?\b)(?P<v>{_CAP_NAME})"
        ),
        sensitivity=MODERATE,
    ),
    Detector(  # Known first name + capitalised surname: "Sarah Thompson"
        "NAME",
        re.compile(rf"(?<![A-Za-z])(?=[A-Z])(?P<v>{trie_regex(FIRST_NAMES)}\s+{_CAP})(?![A-Za-z])"),
        sensitivity=MODERATE,
    ),
    Detector(
        "EMAIL",  # also URL-encoded "@" (%40)
        _rx(r"(?<![\w.+-])[\w.+-]+(?:@|%40)[a-z0-9-]+(?:\.[a-z0-9-]+)+"),
        name_hint=name_contains("email"),
        sensitivity=MODERATE,
    ),
    Detector(
        "PHONE",
        _rx(r"(?<![\w+])(?:\+44|0044|0)[\d\s\-()]{9,16}\d(?!\d)"),
        validators.uk_phone,
        name_contains("phone", "mobile", "msisdn", tokens=("tel", "cell")),
        sensitivity=MODERATE,
    ),
    Detector(  # International (non-UK), "+" or "00" prefixed
        "PHONE",
        _rx(r"(?<![\w+])(?:\+[1-9]|00[1-9]\d{0,2}[\s\-.(])[\d\s\-.()]{6,20}\d(?!\d)"),
        validators.intl_phone,
        sensitivity=MODERATE,
    ),
    Detector(
        "NI_NUMBER",
        _rx(r"(?<![a-z0-9])[a-z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[a-d](?![a-z0-9])"),
        validators.ni_number,
        name_contains("nationalinsurance", "ninumber", "nino", "nationalins"),
    ),
    Detector(
        "NHS_NUMBER",  # spaced / dashed 3-3-4 is distinctive enough on its own
        _rx(r"(?<![\d-])\d{3}([ -])\d{3}\1\d{4}(?![\d-])"),
        validators.nhs_number,
        name_contains("nhsnumber", "nhsno", tokens=("nhs",)),
    ),
    Detector("NHS_NUMBER", _ctx(r"nhs", r"\d{10}"), validators.nhs_number),
    Detector(
        "CHI_NUMBER",
        _ctx(r"chi|community health index", r"\d{6}\s?\d{4}"),
        validators.chi_number,
        name_contains("chinumber", "chino", "communityhealthindex", tokens=("chi",)),
    ),
    Detector(
        "PASSPORT_NUMBER",
        _ctx(r"passport", r"\d{9}|[a-z]{2}\d{7}"),
        name_hint=name_contains("passport"),
    ),
    Detector(
        "DRIVING_LICENCE",
        _rx(r"(?<![a-z0-9])[a-z][a-z9]{4}\d{6}[a-z9]{2}\d[a-z0-9]{2}(?![a-z0-9])"),
        validators.uk_driving_licence,
        name_contains(
            "drivinglicence", "drivinglicense", "driverslicense", "driverlicense", "licenceno",
            "licenseno", "licencenumber", "licensenumber",
        ),
    ),
    Detector(
        "UTR",  # 10 digits is too weak alone: requires a hotword
        _ctx(r"utr|unique tax(?:payer)? ref(?:erence)?|tax ref(?:erence)?", r"\d{5}\s?\d{5}k?"),
        name_hint=name_contains("utr", "taxpayerref", "taxref", "uniquetaxpayer"),
    ),
    Detector(
        "POSTCODE",
        _rx(r"(?<![a-z0-9])(?:GIR ?0AA|[a-z]{1,2}\d[a-z\d]? ?\d[a-z]{2})(?![a-z0-9])"),
        name_hint=name_contains("postcode", "postalcode", "zipcode", tokens=("zip",)),
        sensitivity=LOW,
        quasi_identifier=True,
    ),
    Detector(
        "STREET_ADDRESS",
        re.compile(
            rf"(?<![\w])(?P<v>\d{{1,4}}[a-zA-Z]?,?\s+(?:{_CAP}\s+){{1,3}}"
            rf"(?i:{_STREET_SUFFIX}))(?![A-Za-z])"
        ),
        name_hint=_address_col_hint,
        sensitivity=MODERATE,
    ),
    Detector(
        "DOB",  # a bare date isn't DOB: needs a hotword, or the column name
        _ctx(r"born(?:\s+(?:on|in))?|d\.?o\.?b\.?|date\s+of\s+birth|birth\s?date|birthday", _DATE),
        name_hint=name_contains("dateofbirth", "birthdate", "birthday", tokens=("dob", "birth")),
        sensitivity=MODERATE,
        quasi_identifier=True,
    ),
    Detector(
        "GENDER",  # column-name only: values like "F"/"male" are too ambiguous in free text
        name_hint=name_contains("gender", tokens=("sex",)),
        sensitivity=LOW,
        quasi_identifier=True,
    ),
    # --- GDPR Art. 9 special-category data ---
    Detector(
        "HEALTH",
        _rx(rf"(?<![a-z])(?=[a-z])(?:{trie_regex(HEALTH_TERMS)}|(?-i:AIDS))(?![a-z])"),
        name_hint=name_contains(
            "diagnos", "medication", "allerg", "disabilit", "symptom", "prescription",
            "medicalcondition", "healthcondition", "medicalhistory", "medicalrecord",
            "healthrecord", "medicalnote", "clinicalnote",
        ),
    ),
    Detector(
        "ETHNIC_GROUP",
        _rx(rf"(?<![a-z])(?:{'|'.join(ETHNIC_PHRASES)})(?![a-z])"),
        name_hint=name_contains("ethnic", tokens=("race",)),
        quasi_identifier=True,
    ),
    Detector("RELIGION", name_hint=name_contains("religio", tokens=("faith",))),
    Detector("SEXUAL_ORIENTATION", name_hint=name_contains("sexualorientation", "sexuality")),
    # --- Financial ---
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
        "SORT_CODE",  # space-separated only when not part of a longer digit run (phone numbers)
        _rx(
            r"(?<![\d-])(?:\d{2}-\d{2}-\d{2}(?![\d-])"
            r"|(?<!\d )\d{2} \d{2} \d{2}(?![\d-])(?! \d))"
        ),
        validators.sort_code,
        name_contains("sortcode"),
        sensitivity=MODERATE,
    ),
    Detector(
        "SWIFT_CODE",
        _ctx(r"bic|swift", r"[a-z]{6}[a-z0-9]{2}(?:[a-z0-9]{3})?"),
        validators.swift_code,
        name_contains("swift", "bic"),
        sensitivity=LOW,
    ),
    # --- Device / network / location ---
    Detector(
        "IP_ADDRESS",
        _rx(
            r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
            r"|(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])"
        ),
        validators.ip_address,
        name_contains("ipaddress", "ipaddr", "ipv4", "ipv6", tokens=("ip",)),
        sensitivity=LOW,
    ),
    Detector(
        "MAC_ADDRESS",
        _rx(
            r"(?<![\w:-])[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}(?![\w:-])"
            r"|(?<![\w.])[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}(?![\w.])"
        ),
        validators.mac_address,
        name_contains("macaddress", "macaddr", tokens=("mac",)),
        sensitivity=LOW,
    ),
    Detector(
        "IMEI",
        _ctx(r"imei", r"\d{15}|\d{2}-\d{6}-\d{6}-\d"),
        validators.luhn,
        name_contains("imei"),
        sensitivity=MODERATE,
    ),
    Detector(
        "LOCATION_COORDINATES",
        _rx(r"(?<![\d.])[-+]?\d{1,2}\.\d{3,}\s*,\s*[-+]?\d{1,3}\.\d{3,}(?![\d.])"),
        validators.coordinates,
        name_contains(
            "latitude", "longitude", "latlong", "latlng", "geolocation", "coordinates",
            tokens=("lat", "lon", "lng", "geo"),
        ),
        sensitivity=MODERATE,
        quasi_identifier=True,
    ),
    Detector(
        "VIN",
        _rx(r"(?<![a-z0-9])[a-hj-npr-z0-9]{17}(?![a-z0-9])"),
        validators.vin,
        name_contains("vin", "vehicleidentification", "chassisnumber"),
        sensitivity=MODERATE,
    ),
    Detector(
        "VEHICLE_REGISTRATION",
        _ctx(
            r"reg(?:istration)?|vrm|vrn|number\s?plate|licen[cs]e\s?plate",
            r"[a-z]{2}\d{2}\s?[a-z]{3}",
        ),
        name_hint=name_contains("vehiclereg", "numberplate", "licenceplate", "licenseplate", "vrm"),
        sensitivity=MODERATE,
    ),
    # --- Credentials / secrets (not PII, but must never land in a warehouse) ---
    Detector(
        "AWS_CREDENTIALS",
        re.compile(
            r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}(?![A-Z0-9])"
        ),
    ),
    Detector(
        "AWS_CREDENTIALS",
        _rx(r"aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?(?P<v>[a-z0-9/+=]{40})(?![a-z0-9/+=])"),
    ),
    Detector("GCP_API_KEY", re.compile(r"(?<![\w-])AIza[0-9A-Za-z_\-]{35}(?![\w-])")),
    Detector(
        "GCP_CREDENTIALS",
        re.compile(r"\"type\"\s*:\s*\"service_account\"|\"private_key_id\"\s*:\s*\"[0-9a-f]{40}\""),
    ),
    Detector(
        "JSON_WEB_TOKEN",
        re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    ),
    Detector("PRIVATE_KEY", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    Detector(
        "AUTH_TOKEN",
        re.compile(
            r"(?i:bearer)\s+[A-Za-z0-9\-._~+/]{20,}=*"
            r"|(?i:authorization:\s*basic)\s+[A-Za-z0-9+/]{8,}={0,2}"
            r"|(?<![\w])gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"
            r"|(?<![\w])xox[abposr]-[A-Za-z0-9-]{10,}"
            r"|(?<![\w])[sr]k_live_[0-9A-Za-z]{24,}"
        ),
        name_hint=name_contains(
            "apikey", "accesstoken", "authtoken", "secretkey", "clientsecret", "refreshtoken",
            "bearertoken", "sessiontoken",
        ),
    ),
    Detector(
        "PASSWORD",
        _rx(
            r"(?<![a-z])(?:password|passwd|passcode|pwd|pass)[\"']?\s*[:=]\s*[\"']?"
            r"(?P<v>[^\s'\",;]{3,})"
            r"|[a-z][a-z0-9+.-]*://[^\s/:@]+:(?P<v2>[^\s/@]+)@"
        ),
        validators.password_value,
        name_contains("password", "passwd", "passcode", tokens=("pwd",)),
    ),
)

_custom: list[Detector] = []


def register_detector(
    tag: str,
    pattern: str | re.Pattern[str],
    validator: Validator | None = None,
    column_names: Iterable[str] = (),
    *,
    sensitivity: str = HIGH,
    quasi_identifier: bool = False,
) -> Detector:
    """Register a custom detector for all later scans in this process.

    ``column_names``: fragments that flag a column by name. A named group ``v`` in ``pattern``
    limits validation/shaping to that group (use it to require a hotword). Returns the detector,
    which can also be passed via ``scan_dataframe(detectors=...)`` to avoid the global registry.
    """
    compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
    frags = tuple(normalise_name(c).replace("_", "") for c in column_names)
    det = Detector(
        tag, compiled, validator, name_contains(*frags) if frags else None,
        sensitivity=sensitivity, quasi_identifier=quasi_identifier,
    )
    _custom.append(det)
    return det


def default_detectors() -> tuple[Detector, ...]:
    return BUILTIN_DETECTORS + tuple(_custom)
