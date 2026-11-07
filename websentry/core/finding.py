"""
WebSentry Finding and Risk Classification Data Structures
Developer: Isha Sonaria
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any
from datetime import datetime
from websentry.core.colors import format_severity, bold, white, gray, cyan, yellow, bright_red, crimson

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @classmethod
    def from_string(cls, val: str) -> "Severity":
        val_upper = val.strip().upper()
        if val_upper in ("CRITICAL", "CRIT"):
            return cls.CRITICAL
        elif val_upper in ("HIGH", "H"):
            return cls.HIGH
        elif val_upper in ("MEDIUM", "MED", "M"):
            return cls.MEDIUM
        elif val_upper in ("LOW", "L"):
            return cls.LOW
        else:
            return cls.INFORMATIONAL

    @property
    def score(self) -> int:
        """Numeric rank for sorting findings (highest risk first)."""
        mapping = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFORMATIONAL: 1,
        }
        return mapping[self]

@dataclass
class Finding:
    title: str
    severity: Severity
    url: str
    description: str
    remediation: str
    category: str
    id: Optional[str] = None
    status_code: Optional[int] = None
    evidence: str = ""
    reference: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    def format_cli(self, show_evidence: bool = True) -> str:
        """Renders finding in clean black/red terminal format."""
        lines = []
        sev_badge = format_severity(self.severity.value)
        status_part = f" {gray(f'[{self.status_code}]')}" if self.status_code else ""
        lines.append(f"  {sev_badge} {bold(white(self.title))}{status_part}")
        lines.append(f"    {gray('Target:')} {cyan(self.url)}")
        lines.append(f"    {gray('Category:')} {yellow(self.category)}")
        
        if self.description:
            lines.append(f"    {gray('Detail:')} {self.description}")
            
        if self.evidence and show_evidence:
            ev_clean = self.evidence.replace("\n", "\n      ")
            lines.append(f"    {gray('Evidence:')} {crimson(ev_clean)}")
            
        if self.remediation:
            lines.append(f"    {gray('Remediation:')} {self.remediation}")
            
        if self.reference:
            lines.append(f"    {gray('Reference:')} {self.reference}")
            
        return "\n".join(lines)
