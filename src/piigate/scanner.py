"""pandas DataFrame scanning."""

from __future__ import annotations

import re
import warnings
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from functools import lru_cache
from typing import Literal

import numpy as np
import pandas as pd

from .detectors import Detector, default_detectors, normalise_name
from .masking import mask_shape
from .models import ColumnFinding, PIIFoundError, ScanResult


def _have_re2() -> bool:
    try:
        import re2  # noqa: F401
    except ImportError:
        return False
    return True


@lru_cache(maxsize=8)
def _re2_set(patterns: tuple[str, ...]):  # type: ignore[no-untyped-def]
    import re2

    s = re2.Set.SearchSet(re2.Options())
    for p in patterns:
        s.Add(p)
    s.Compile()
    return s


def _re2_candidates(arr: np.ndarray, patterns: tuple[str, ...]) -> list[np.ndarray]:
    """One pass of all ``patterns`` over ``arr`` (RE2 multi-pattern DFA): for each pattern, the
    indices of values it matches somewhere. Validators/shapes still run in Python on those."""
    match = _re2_set(patterns).Match
    hits: list[list[int]] = [[] for _ in patterns]
    for j, ks in enumerate(map(match, arr)):
        if ks:  # RE2 returns None when nothing matched
            for k in ks:
                hits[k].append(j)
    return [np.asarray(h, dtype=np.intp) for h in hits]


def _scan_column(
    name: object,
    series: pd.Series,
    detectors: Sequence[Detector],
    name_heuristics: bool,
    top_n: int,
    thresholds: Mapping[str, int],
    use_re2: bool,
) -> ColumnFinding | None:
    # Scan each distinct value once, weighted by how many rows hold it.
    counted = series.dropna().astype(str).value_counts(sort=False)
    uniq = pd.Series(counted.index.to_numpy(dtype=object))
    arr = uniq.to_numpy()
    weight = counted.to_numpy()
    u = len(arr)
    n = int(weight.sum())
    norm = normalise_name(name)

    counts: dict[str, int] = {}
    rows: dict[str, np.ndarray] = {}  # per tag: which distinct values matched
    shapes: dict[str, Counter[str]] = {}
    hinted: list[str] = []
    gate_masks: dict[tuple[str, ...], np.ndarray] = {}

    def gate_mask(chain: tuple[re.Pattern[str], ...]) -> np.ndarray:
        """Rows passing every gate in ``chain``. Each gate runs only on rows that passed the
        previous ones, and each distinct prefix is evaluated once per column."""
        if not chain:
            return np.ones(u, dtype=bool)
        key = tuple(g.pattern for g in chain)
        if key not in gate_masks:
            mask = np.zeros(u, dtype=bool)
            idx = np.flatnonzero(gate_mask(chain[:-1]))
            if idx.size:
                last = chain[-1]
                literal = re.escape(last.pattern) == last.pattern
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    hits = uniq.iloc[idx].str.contains(
                        last.pattern if literal else last, regex=not literal
                    )
                mask[idx] = hits.to_numpy()
            gate_masks[key] = mask
        return gate_masks[key]

    # With RE2, every portable pattern of every detector is matched in a single pass.
    re2_cands: dict[tuple[int, int], np.ndarray] = {}
    if use_re2 and u:
        keys = [
            (d, i)
            for d, det in enumerate(detectors)
            if det.portable
            for i in range(len(det.patterns))
        ]
        if keys:
            pats = tuple(detectors[d].patterns[i].pattern for d, i in keys)
            try:
                re2_cands = dict(zip(keys, _re2_candidates(arr, pats), strict=True))
            except UnicodeEncodeError:  # e.g. lone surrogates: fall back to the Python path
                re2_cands = {}

    for d_idx, det in enumerate(detectors):
        if name_heuristics and det.name_hint is not None and det.name_hint(norm):
            # Column name says it's this tag: count every non-null value, shape the whole value.
            hinted.append(det.tag)
            counts[det.tag] = max(counts.get(det.tag, 0), n)
            rows[det.tag] = np.ones(u, dtype=bool)
            tag_shapes: Counter[str] = Counter()
            for v, w in zip(arr, weight, strict=True):
                tag_shapes[mask_shape(v)] += int(w)
            shapes[det.tag] = tag_shapes
            continue
        if not det.patterns or u == 0:
            continue
        tag_rows = rows.setdefault(det.tag, np.zeros(u, dtype=bool))
        tag_shapes = shapes.setdefault(det.tag, Counter())
        for i, pat in enumerate(det.patterns):
            cand = re2_cands.get((d_idx, i))
            if cand is None:
                cand = np.flatnonzero(gate_mask(det.gate_for(i)))
            for j in cand:
                for text in det.matches_pattern(pat, arr[j]):
                    w = int(weight[j])
                    counts[det.tag] = counts.get(det.tag, 0) + w
                    tag_rows[j] = True
                    tag_shapes[mask_shape(text)] += w

    failing = sorted(t for t, c in counts.items() if c > thresholds.get(t, 0))
    if not failing:
        return None
    hit = np.zeros(u, dtype=bool)
    agg: Counter[str] = Counter()
    for t in failing:
        hit |= rows[t]
        agg.update(shapes[t])
    return ColumnFinding(
        tags=tuple(failing),
        match_count=sum(counts[t] for t in failing),
        match_rate=float(weight[hit].sum()) / n if n else 0.0,
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
    engine: Literal["auto", "re2", "python"] = "auto",
) -> ScanResult:
    """Scan ``columns`` of ``df`` for PII. Full column by default; ``sample=N`` is opt-in.

    ``thresholds``: per-tag max tolerated match count (default 0 everywhere, i.e. strict).
    ``detectors``: replaces the default set (built-ins + registered custom detectors).
    ``engine``: ``"re2"`` scans all ruleset patterns in one pass (needs ``piigate[fast]``);
    ``"python"`` is dependency-free; ``"auto"`` uses RE2 when installed. Results are identical.
    """
    if engine == "re2" and not _have_re2():
        raise ImportError("engine='re2' needs google-re2: pip install piigate[fast]")
    use_re2 = engine == "re2" or (engine == "auto" and _have_re2())
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
        finding = _scan_column(col, data[col], dets, name_heuristics, top_n, thr, use_re2)
        if finding is None:
            passed.append(col)
        else:
            failed[col] = finding

    result = ScanResult(passed, failed, rows_scanned=len(data), sampled=sampled)
    if raise_on_fail and not result.ok:
        raise PIIFoundError(result)
    return result
