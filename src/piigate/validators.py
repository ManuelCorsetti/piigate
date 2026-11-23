"""Pure checksum / format validators. Each takes the matched text, returns bool."""

from __future__ import annotations

import ipaddress
import re

_NON_DIGIT = re.compile(r"\D")
_NI_BAD_PREFIXES = {"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"}


def luhn(text: str) -> bool:
    digits = [int(c) for c in _NON_DIGIT.sub("", text)]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ni_number(text: str) -> bool:
    s = re.sub(r"\s", "", text).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{6}[A-D]", s):
        return False
    if s[0] in "DFIQUV" or s[1] in "DFIOQUV":
        return False
    return s[:2] not in _NI_BAD_PREFIXES


def iban(text: str) -> bool:
    """Mod-97 check; also tries dropping trailing words (an IBAN followed by prose)."""
    words = text.split()
    return any(_iban("".join(words[:k])) for k in range(len(words), 0, -1))


def _iban(s: str) -> bool:
    s = s.upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


def sort_code(text: str) -> bool:
    m = re.fullmatch(r"(\d{2})([- ])(\d{2})\2(\d{2})", text)
    return m is not None and text.replace(m.group(2), "") != "000000"


def uk_phone(text: str) -> bool:
    digits = _NON_DIGIT.sub("", text)
    if digits.startswith("0044"):
        digits = digits[2:]
    if digits.startswith("44"):
        rest = digits[2:]
        digits = rest if rest.startswith("0") else "0" + rest
    return len(digits) == 11 and digits[0] == "0" and digits[1] in "123789"


def ip_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def intl_phone(text: str) -> bool:
    """Non-UK international number (``+`` or ``00`` prefix). UK numbers are left to uk_phone."""
    digits = _NON_DIGIT.sub("", text)
    if text.lstrip().startswith("00"):
        digits = digits[2:]
    if digits.startswith("44"):
        return False
    return 8 <= len(digits) <= 15 and digits[0] != "0" and len(set(digits)) > 2


def _mod11(digits: str) -> bool:
    """NHS / CHI check digit: weights 10..2 over the first 9 digits."""
    if len(digits) != 10 or len(set(digits)) == 1:
        return False
    check = 11 - sum(int(c) * w for c, w in zip(digits[:9], range(10, 1, -1), strict=True)) % 11
    check = 0 if check == 11 else check
    return check != 10 and check == int(digits[9])


def nhs_number(text: str) -> bool:
    return _mod11(_NON_DIGIT.sub("", text))


def chi_number(text: str) -> bool:
    """Scottish CHI: DDMMYY + 4 digits, mod-11 check digit."""
    d = _NON_DIGIT.sub("", text)
    return _mod11(d) and 1 <= int(d[:2]) <= 31 and 1 <= int(d[2:4]) <= 12


_DL = re.compile(r"([A-Z][A-Z9]{4})\d(\d{2})(\d{2})\d([A-Z9]{2})\d[A-Z0-9]{2}")


def uk_driving_licence(text: str) -> bool:
    """DVLA format: surname(5) decade month(+50 if female) day year initials(2) digit check(2)."""
    m = _DL.fullmatch(re.sub(r"\s", "", text).upper()[:16])
    if m is None:
        return False
    surname, month, day, initials = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
    month = month - 50 if month > 50 else month
    padded_ok = all(re.fullmatch(r"[A-Z]+9*", p) for p in (surname, initials))
    return 1 <= month <= 12 and 1 <= day <= 31 and padded_ok


def vin(text: str) -> bool:
    """17-char VIN (no I/O/Q): mixed letters and digits, serial (last 4) numeric."""
    s = text.upper()
    return (
        len(s) == 17
        and s[-4:].isdigit()
        and sum(c.isalpha() for c in s) >= 2
        and sum(c.isdigit() for c in s) >= 6
    )


def swift_code(text: str) -> bool:
    from ._wordlists import ISO_COUNTRIES

    s = text.upper()
    return len(s) in (8, 11) and s[4:6] in ISO_COUNTRIES


def mac_address(text: str) -> bool:
    hexd = re.sub(r"[^0-9a-fA-F]", "", text)
    return len(hexd) == 12 and len(set(hexd.lower())) > 1


def coordinates(text: str) -> bool:
    try:
        lat, lon = (float(p) for p in text.split(","))
    except ValueError:
        return False
    return abs(lat) <= 90 and abs(lon) <= 180 and (lat, lon) != (0.0, 0.0)


_PLACEHOLDERS = {"null", "none", "nil", "undefined", "redacted", "changeme", "xxx"}


def password_value(text: str) -> bool:
    """Reject obvious placeholders (``password: ****``, ``pwd=null``)."""
    s = text.strip("'\",;").lower()
    return len(s) >= 3 and len(set(s)) > 1 and s not in _PLACEHOLDERS
