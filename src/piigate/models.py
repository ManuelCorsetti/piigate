"""Result types. Nothing here may hold raw data values."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ColumnFinding:
    """Why a column failed (or warned).

    ``masked_shapes`` is the top-N ``(shape, count)`` pairs, most common first.
    ``name_hint_tags`` are tags raised by the column name alone (every non-null value counted).
    ``sensitivity`` is the highest sensitivity among ``tags``.
    ``row_positions``: 0-based positions in the input DataFrame of matching rows (only with
    ``include_rows=True``; positional, never index labels, which could themselves be PII).
    ``truncated``: scanning stopped early because ``max_findings`` was reached.
    """

    tags: tuple[str, ...]
    match_count: int
    match_rate: float
    masked_shapes: tuple[tuple[str, int], ...]
    tag_counts: dict[str, int] = field(default_factory=dict)
    name_hint_tags: tuple[str, ...] = ()
    sensitivity: str = "HIGH"
    tag_sensitivity: dict[str, str] = field(default_factory=dict)
    row_positions: tuple[int, ...] | None = None
    truncated: bool = False


@dataclass(frozen=True)
class ReidentificationRisk:
    """k-anonymity over the scanned columns that carry quasi-identifier tags.

    ``k`` is the size of the smallest group of rows sharing the same combination of values;
    ``unique_rows`` are rows whose combination appears once (k=1). Computed on the scanned rows,
    so on a sample it overstates uniqueness. Only counts, never values.
    """

    columns: dict[str, tuple[str, ...]]
    k: int
    unique_rows: int
    unique_rate: float
    rows_considered: int
    min_k: int | None = None

    @property
    def failed(self) -> bool:
        return self.min_k is not None and self.k < self.min_k


@dataclass(frozen=True)
class ScanResult:
    passed_columns: list[str]
    failed_columns: dict[str, ColumnFinding]
    rows_scanned: int = 0
    sampled: bool = False
    warnings: dict[str, ColumnFinding] = field(default_factory=dict)
    skipped_columns: list[str] = field(default_factory=list)
    reidentification_risk: ReidentificationRisk | None = None
    rows_total: int = 0

    @property
    def ok(self) -> bool:
        risk = self.reidentification_risk
        return not self.failed_columns and not (risk is not None and risk.failed)

    def to_dict(self) -> dict[str, Any]:
        """JSON-shaped dict (lists, str keys) for logs and orchestrator alerts."""
        d = asdict(self)
        d["ok"] = self.ok
        if self.reidentification_risk is not None:
            d["reidentification_risk"]["failed"] = self.reidentification_risk.failed
        return json.loads(json.dumps(d, default=str))

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), **kwargs)


class PIIFoundError(Exception):
    """Raised by ``scan_dataframe(raise_on_fail=True)``. Carries the (masked) result."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        parts = [f"{col}: {', '.join(f.tags)}" for col, f in result.failed_columns.items()]
        risk = result.reidentification_risk
        if risk is not None and risk.failed:
            parts.append(
                f"re-identification risk k={risk.k} < {risk.min_k} over {', '.join(risk.columns)}"
            )
        super().__init__(
            f"PII found in {len(result.failed_columns)} column(s): {'; '.join(parts)}"
        )
