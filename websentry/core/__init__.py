"""
WebSentry Core Package
Developer: Isha Sonaria
"""

from websentry.core.finding import Finding, Severity
from websentry.core.config import ScanConfig
from websentry.core.http_client import HttpClient, WebResponse
from websentry.core.safety import validate_target_safety, TargetSafetyRefusalError, InvalidTargetURLError
from websentry.core.engine import ScanEngine
from websentry.core.colors import Colors

__all__ = [
    "Finding",
    "Severity",
    "ScanConfig",
    "HttpClient",
    "WebResponse",
    "validate_target_safety",
    "TargetSafetyRefusalError",
    "InvalidTargetURLError",
    "ScanEngine",
    "Colors",
]
