"""pandas DataFrame scanning."""

from __future__ import annotations

import warnings
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence

import numpy as np
import pandas as pd

from .detectors import Detector, default_detectors, normalise_name
from .masking import mask_shape
from .models import ColumnFinding, PIIFoundError, ScanResult


def _scan_column(
    name: object,
    series: pd.Series,
    detectors: Sequence[Detector],
    name_heuristics: bool,
    top_n: int,
    thresholds: Mapping[str, int],
) -> ColumnFinding | None:
    values = series.dropna().astype(str)
    n = len(values)
    norm = normalise_name(name)
    arr = values.to_numpy()

    counts: dict[str, int] = {}
    rows: dict[str, np.ndarray] = {}
    shapes: dict[str, Counter[str]] = {}
    hinted: list[str] = []

    for det in detectors:
        if name_heuristics and det.name_hint is not None and det.name_hint(norm):
            # Column name says it's this tag: count every non-null value, shape the whole value.
            hinted.append(det.tag)
            counts[det.tag] = max(counts.get(det.tag, 0), n)
            rows[det.tag] = np.ones(n, dtype=bool)
            shapes[det.tag] = Counter(mask_shape(v) for v in arr)
            continue
        if det.pattern is None or n == 0:
            continue
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)  # capture groups in custom patterns
            candidates = np.flatnonzero(values.str.contains(det.pattern, regex=True).to_numpy())
        tag_rows = rows.setdefault(det.tag, np.zeros(n, dtype=bool))
        tag_shapes = shapes.setdefault(det.tag, Counter())
        for i in candidates:
            for m in det.pattern.finditer(arr[i]):
                text = m.group(0)
                if det.validator is None or det.validator(text):
                    counts[det.tag] = counts.get(det.tag, 0) + 1
                    tag_rows[i] = True
                    tag_shapes[mask_shape(text)] += 1

    failing = sorted(t for t, c in counts.items() if c > thresholds.get(t, 0))
    if not failing:
        return None
    hit = np.zeros(n, dtype=bool)
    agg: Counter[str] = Counter()
    for t in failing:
        hit |= rows[t]
        agg.update(shapes[t])
    return ColumnFinding(
        tags=tuple(failing),
        match_count=sum(counts[t] for t in failing),
        match_rate=float(hit.sum()) / n if n else 0.0,
        masked_shapes=tuple(agg.most_common(top_n)),
        tag_counts={t: counts[t] for t in failing},
        name_hint_tags=tuple(t for t in failing if t in hinted),
    )


def scan_dataframe(
    df: pd.DataFrame,
    columns: Iterable[str],
    *,
    detectors: Sequence[Detector] | None = None,
    thresholds: Mapping[str, int] | None = None,
    name_heuristics: bool = True,
    top_n: int = 5,
    sample: int | None = None,
    random_state: int | None = None,
    raise_on_fail: bool = False,
) -> ScanResult:
    """Scan ``columns`` of ``df`` for PII. Full column by default; ``sample=N`` is opt-in.

    ``thresholds``: per-tag max tolerated match count (default 0 everywhere, i.e. strict).
    ``detectors``: replaces the default set (built-ins + registered custom detectors).
    """
    cols = list(columns)
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise KeyError(f"columns not in DataFrame: {missing}")
    dets = tuple(detectors) if detectors is not None else default_detectors()
    thr = thresholds or {}

    sampled = sample is not None and sample < len(df)
    data = df.sample(n=sample, random_state=random_state) if sampled else df

    passed: list[str] = []
    failed: dict[str, ColumnFinding] = {}
    for col in cols:
        finding = _scan_column(col, data[col], dets, name_heuristics, top_n, thr)
        if finding is None:
            passed.append(col)
        else:
            failed[col] = finding

    result = ScanResult(passed, failed, rows_scanned=len(data), sampled=sampled)
    if raise_on_fail and not result.ok:
        raise PIIFoundError(result)
    return result
