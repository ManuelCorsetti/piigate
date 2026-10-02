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


VALIDATORS = {
    "luhn": luhn,
    "ni_number": ni_number,
    "iban": iban,
    "sort_code": sort_code,
    "uk_phone": uk_phone,
    "ip_address": ip_address,
}
