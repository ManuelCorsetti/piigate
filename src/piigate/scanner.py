"""pandas DataFrame scanning."""

from __future__ import annotations

import math
import re
import warnings
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

import numpy as np
import pandas as pd

from .detectors import SENSITIVITY_LEVELS, Detector, default_detectors, normalise_name
from .masking import mask_shape
from .models import ColumnFinding, PIIFoundError, ReidentificationRisk, ScanResult

_RANK = {s: i for i, s in enumerate(SENSITIVITY_LEVELS)}


@dataclass
class _Hits:
    n: int
    positions: np.ndarray
    counts: dict[str, int] = field(default_factory=dict)
    rows: dict[str, np.ndarray] = field(default_factory=dict)
    shapes: dict[str, Counter[str]] = field(default_factory=dict)
    hinted: set[str] = field(default_factory=set)
    truncated: bool = False


def _value_span(m: re.Match[str]) -> tuple[str, tuple[int, int]]:
    """The reported part of a match: named group ``v`` (or ``v2``...) if present and set."""
    for key, val in m.groupdict().items():
        if val is not None and (key == "v" or (key[0] == "v" and key[1:].isdigit())):
            return val, m.span(key)
    return m.group(0), m.span()


def _scan_column(
    name: object,
    series: pd.Series,
    positions: np.ndarray,
    detectors: Sequence[Detector],
    name_heuristics: bool,
    max_findings: int | None,
) -> _Hits:
    notna = series.notna().to_numpy()
    values = series[notna].astype(str)
    arr = values.to_numpy()
    hits = _Hits(n=len(values), positions=positions[notna])
    n = hits.n
    norm = normalise_name(name)
    seen: dict[tuple[str, int], list[tuple[int, int]]] = {}  # (tag, row) -> counted spans

    def total() -> int:
        return sum(hits.counts.values())

    for det in detectors:
        if max_findings is not None and total() >= max_findings:
            hits.truncated = True
            break
        if det.tag in hits.hinted:
            continue
        if name_heuristics and det.name_hint is not None and det.name_hint(norm):
            # Column name says it's this tag: count every non-null value, shape the whole value.
            hits.hinted.add(det.tag)
            hits.counts[det.tag] = n
            hits.rows[det.tag] = np.ones(n, dtype=bool)
            hits.shapes[det.tag] = Counter(mask_shape(v) for v in arr)
            continue
        if det.pattern is None or n == 0:
            continue
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)  # capture groups in patterns
            candidates = np.flatnonzero(values.str.contains(det.pattern, regex=True).to_numpy())
        tag_rows = hits.rows.setdefault(det.tag, np.zeros(n, dtype=bool))
        tag_shapes = hits.shapes.setdefault(det.tag, Counter())
        for i in candidates:
            for m in det.pattern.finditer(arr[i]):
                text, (start, end) = _value_span(m)
                if det.validator is not None and not det.validator(text):
                    continue
                spans = seen.setdefault((det.tag, int(i)), [])
                if any(start < e and s < end for s, e in spans):
                    continue  # same text already counted for this tag by another detector
                spans.append((start, end))
                hits.counts[det.tag] = hits.counts.get(det.tag, 0) + 1
                tag_rows[i] = True
                tag_shapes[mask_shape(text)] += 1
                if max_findings is not None and total() >= max_findings:
                    hits.truncated = True
                    break
            if hits.truncated:
                break
    return hits


def _finding(
    hits: _Hits, tags: list[str], sens: Mapping[str, str], top_n: int, include_rows: bool
) -> ColumnFinding:
    hit = np.zeros(hits.n, dtype=bool)
    agg: Counter[str] = Counter()
    for t in tags:
        hit |= hits.rows[t]
        agg.update(hits.shapes[t])
    return ColumnFinding(
        tags=tuple(tags),
        match_count=sum(hits.counts[t] for t in tags),
        match_rate=float(hit.sum()) / hits.n if hits.n else 0.0,
        masked_shapes=tuple(agg.most_common(top_n)),
        tag_counts={t: hits.counts[t] for t in tags},
        name_hint_tags=tuple(t for t in tags if t in hits.hinted),
        sensitivity=max((sens[t] for t in tags), key=_RANK.__getitem__),
        tag_sensitivity={t: sens[t] for t in tags},
        row_positions=tuple(hits.positions[hit].tolist()) if include_rows else None,
        truncated=hits.truncated,
    )


def _select_rows(
    df: pd.DataFrame,
    timestamp_column: str | None,
    since: Any,
    until: Any,
    sample: int | float | None,
    sample_method: str,
    random_state: int | None,
) -> tuple[np.ndarray, bool]:
    """Positional indices of rows to scan, after the time window and sampling."""
    idx = np.arange(len(df))
    if since is not None or until is not None:
        if timestamp_column is None:
            raise ValueError("since/until require timestamp_column")
        ts = df[timestamp_column]
        keep = np.ones(len(df), dtype=bool)
        if since is not None:
            keep &= (ts >= since).to_numpy(dtype=bool, na_value=False)
        if until is not None:
            keep &= (ts < until).to_numpy(dtype=bool, na_value=False)
        idx = idx[keep]
    if sample is None:
        return idx, False
    if isinstance(sample, float):
        if not 0 < sample <= 1:
            raise ValueError("float sample is a fraction in (0, 1]")
        size = math.ceil(sample * len(idx))
    else:
        size = int(sample)
    if size >= len(idx):
        return idx, False
    if sample_method == "head":
        return idx[:size], True
    if sample_method == "random":
        rng = np.random.default_rng(random_state)
        return np.sort(rng.choice(idx, size=size, replace=False)), True
    raise ValueError("sample_method must be 'random' or 'head'")


def _reidentification_risk(
    data: pd.DataFrame,
    findings: Iterable[Mapping[str, ColumnFinding]],
    qi_tags: frozenset[str],
    min_k: int | None,
) -> ReidentificationRisk | None:
    tags: dict[str, set[str]] = {}
    for group in findings:
        for c, f in group.items():
            tags.setdefault(c, set()).update(t for t in f.tags if t in qi_tags)
    qi_cols = {c: tuple(sorted(t)) for c, t in tags.items() if t}
    if len(qi_cols) < 2 or data.empty:
        return None
    sizes = data[list(qi_cols)].astype(str).groupby(list(qi_cols), dropna=False).size()
    unique = int((sizes == 1).sum())
    return ReidentificationRisk(
        columns=qi_cols,
        k=int(sizes.min()),
        unique_rows=unique,
        unique_rate=unique / len(data),
        rows_considered=len(data),
        min_k=min_k,
    )


def scan_dataframe(
    df: pd.DataFrame,
    columns: Iterable[str] | None = None,
    *,
    exclude_columns: Iterable[str] = (),
    detectors: Sequence[Detector] | None = None,
    thresholds: Mapping[str, int] | None = None,
    fail_sensitivity: str = "LOW",
    name_heuristics: bool = True,
    top_n: int = 5,
    sample: int | float | None = None,
    sample_method: Literal["random", "head"] = "random",
    random_state: int | None = None,
    timestamp_column: str | None = None,
    since: Any = None,
    until: Any = None,
    max_findings: int | None = None,
    fail_fast: bool = False,
    include_rows: bool = False,
    min_k: int | None = None,
    raise_on_fail: bool = False,
) -> ScanResult:
    """Scan ``df`` for PII. Full column by default; sampling is opt-in.

    Columns: ``columns`` (default: all) minus ``exclude_columns``.
    Rows: ``timestamp_column`` + ``since`` (inclusive) / ``until`` (exclusive) scan a window only
    (incremental scans); then ``sample`` (int rows, or float fraction) by ``sample_method``.
    Failing: a tag fails a column when its count exceeds ``thresholds[tag]`` (default 0) and its
    sensitivity is at least ``fail_sensitivity`` (default ``LOW``: everything fails). Tags over
    threshold but below ``fail_sensitivity`` are reported in ``result.warnings``.
    Limits: ``max_findings`` stops scanning a column after N findings (finding is ``truncated``);
    ``fail_fast`` stops at the first failing column (rest listed in ``skipped_columns``).
    ``include_rows`` adds 0-based row positions to findings.
    ``min_k``: fail if k-anonymity over quasi-identifier columns is below this. The risk is
    reported whenever 2+ scanned columns carry quasi-identifier tags.
    ``detectors``: replaces the default set (built-ins + registered custom detectors).
    """
    if fail_sensitivity not in _RANK:
        raise ValueError(f"fail_sensitivity must be one of {SENSITIVITY_LEVELS}")
    thr = dict(thresholds or {})
    if max_findings is not None:
        if max_findings < 1:
            raise ValueError("max_findings must be >= 1")
        if any(v >= max_findings for v in thr.values()):
            raise ValueError("max_findings must exceed every threshold, or tags could pass")
    excluded = set(exclude_columns)
    cols = [c for c in (df.columns if columns is None else columns) if c not in excluded]
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise KeyError(f"columns not in DataFrame: {missing}")
    dets = tuple(detectors) if detectors is not None else default_detectors()
    sens: dict[str, str] = {}
    for d in dets:
        if d.tag not in sens or _RANK[d.sensitivity] > _RANK[sens[d.tag]]:
            sens[d.tag] = d.sensitivity
    qi_tags = frozenset(d.tag for d in dets if d.quasi_identifier)
    bar = _RANK[fail_sensitivity]

    idx, sampled = _select_rows(
        df, timestamp_column, since, until, sample, sample_method, random_state
    )
    data = df.iloc[idx]

    passed: list[str] = []
    failed: dict[str, ColumnFinding] = {}
    warned: dict[str, ColumnFinding] = {}
    skipped: list[str] = []
    for pos, col in enumerate(cols):
        hits = _scan_column(col, data[col], idx, dets, name_heuristics, max_findings)
        over = sorted(t for t, c in hits.counts.items() if c > thr.get(t, 0))
        fail_tags = [t for t in over if _RANK[sens[t]] >= bar]
        warn_tags = [t for t in over if _RANK[sens[t]] < bar]
        if fail_tags:
            failed[col] = _finding(hits, fail_tags, sens, top_n, include_rows)
        else:
            passed.append(col)
        if warn_tags:
            warned[col] = _finding(hits, warn_tags, sens, top_n, include_rows)
        if fail_tags and fail_fast:
            skipped = cols[pos + 1 :]
            break

    risk = _reidentification_risk(data, (failed, warned), qi_tags, min_k)
    result = ScanResult(
        passed,
        failed,
        rows_scanned=len(data),
        sampled=sampled,
        warnings=warned,
        skipped_columns=skipped,
        reidentification_risk=risk,
        rows_total=len(df),
    )
    if raise_on_fail and not result.ok:
        raise PIIFoundError(result)
    return result
