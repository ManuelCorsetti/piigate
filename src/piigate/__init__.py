"""piigate: lightweight PII scanning gate for ingestion pipelines."""

from .detectors import Detector, register_detector
from .masking import mask_shape
from .models import ColumnFinding, PIIFoundError, ScanResult
from .scanner import scan_dataframe

__all__ = [
    "ColumnFinding",
    "Detector",
    "PIIFoundError",
    "ScanResult",
    "mask_shape",
    "register_detector",
    "scan_dataframe",
]
