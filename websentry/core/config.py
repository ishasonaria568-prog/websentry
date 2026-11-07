"""
WebSentry Scan Configuration
Developer: Isha Sonaria
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict

DEFAULT_USER_AGENT = (
    "WebSentry/1.2.0 (Security Scanner; Built by Isha Sonaria; "
    "+https://github.com/ishasonaria568-prog/websentry)"
)

@dataclass
class ScanConfig:
    url: str
    mode: str = "standard"  # "quick", "standard", "full"
    modules: List[str] = field(default_factory=lambda: [
        "headers", "methods", "server_info", "sensitive_files", "ssl_tls", "misconfigs", "nikto"
    ])
    timeout: float = 8.0
    threads: int = 6
    delay: float = 0.05
    retries: int = 2
    user_agent: str = DEFAULT_USER_AGENT
    allow_public: bool = False
    output_file: Optional[str] = None
    output_format: str = "json"  # "json", "html", "txt", "all"
    signatures_path: Optional[str] = None
    verify_ssl: bool = True
    verbose: bool = False
    no_color: bool = False
    custom_headers: Dict[str, str] = field(default_factory=dict)
