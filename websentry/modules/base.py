"""
WebSentry Base Scanner Module
Developer: Isha Sonaria
"""

from abc import ABC, abstractmethod
from typing import List, Callable, Optional
from websentry.core.finding import Finding
from websentry.core.http_client import HttpClient
from websentry.core.config import ScanConfig

ProgressCallback = Optional[Callable[[str, int, int], None]]

class BaseScanner(ABC):
    name: str = "BaseScanner"
    description: str = "Base scanning module"
    category: str = "General"

    @abstractmethod
    def run(
        self,
        target_url: str,
        client: HttpClient,
        config: ScanConfig,
        progress_callback: ProgressCallback = None
    ) -> List[Finding]:
        """
        Executes the scan module logic and returns a list of Findings.
        """
        pass
