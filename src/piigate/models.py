"""Result types. Nothing here may hold raw data values."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ColumnFinding:
    """Why a column failed.

    ``masked_shapes`` is the top-N ``(shape, count)`` pairs, most common first.
    ``name_hint_tags`` are tags raised by the column name alone (every non-null value counted).
    """

    tags: tuple[str, ...]
    match_count: int
    match_rate: float
    masked_shapes: tuple[tuple[str, int], ...]
    tag_counts: dict[str, int] = field(default_factory=dict)
    name_hint_tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanResult:
    passed_columns: list[str]
    failed_columns: dict[str, ColumnFinding]
    rows_scanned: int = 0
    sampled: bool = False

    @property
    def ok(self) -> bool:
        return not self.failed_columns


class PIIFoundError(Exception):
    """Raised by ``scan_dataframe(raise_on_fail=True)``. Carries the (masked) result."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        detail = "; ".join(
            f"{col}: {', '.join(f.tags)}" for col, f in result.failed_columns.items()
        )
        super().__init__(f"PII found in {len(result.failed_columns)} column(s): {detail}")
