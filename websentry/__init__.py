"""
WebSentry - Web Server Security Assessment Tool
Developer: Isha Sonaria
GitHub: https://github.com/ishasonaria568-prog
"""

__title__ = "WebSentry"
__version__ = "1.2.0"
__author__ = "Isha Sonaria"
__github__ = "https://github.com/ishasonaria568-prog"
__tagline__ = "Web Server Security Assessment Tool"
__license__ = "MIT"

from websentry.core.finding import Finding, Severity
from websentry.core.config import ScanConfig
from websentry.core.engine import ScanEngine

__all__ = ["Finding", "Severity", "ScanConfig", "ScanEngine", "__version__", "__author__", "__github__"]
