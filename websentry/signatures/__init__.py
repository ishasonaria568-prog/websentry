"""
WebSentry Signatures Package
Developer: Isha Sonaria
"""

from pathlib import Path

DEFAULT_SIGNATURES_FILE = Path(__file__).parent / "default_signatures.json"

__all__ = ["DEFAULT_SIGNATURES_FILE"]
