"""piigate: lightweight PII scanning gate for ingestion pipelines."""

from .detectors import SENSITIVITY_LEVELS, Detector, register_detector
from .masking import mask_shape
from .models import ColumnFinding, PIIFoundError, ReidentificationRisk, ScanResult
from .scanner import scan_dataframe

__all__ = [
    "SENSITIVITY_LEVELS",
    "ColumnFinding",
    "Detector",
    "PIIFoundError",
    "ReidentificationRisk",
    "ScanResult",
    "mask_shape",
    "register_detector",
    "scan_dataframe",
]
