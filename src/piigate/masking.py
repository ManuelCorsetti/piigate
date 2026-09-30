"""Shape masking. The only way matched data may appear in results."""

from __future__ import annotations

MAX_SHAPE_LEN = 64


def mask_shape(text: str, max_len: int = MAX_SHAPE_LEN) -> str:
    """Replace digits with ``D`` and letters with ``L``; keep spaces/punctuation.

    Long inputs are truncated (with a trailing ``…``) so free text can't bloat results.
    """
    out = []
    for ch in text[:max_len]:
        if ch.isdigit():
            out.append("D")
        elif ch.isalpha():
            out.append("L")
        else:
            out.append(ch)
    if len(text) > max_len:
        out.append("…")
    return "".join(out)
