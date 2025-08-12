"""Domain models for scan results."""
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum


class ScanStatus(Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Target:
    """Scan target model."""
    address: str
    port: Optional[int] = None
    protocol: str = "tcp"
    description: Optional[str] = None


@dataclass
class Vulnerability:
    """Vulnerability model."""
    id: str
    name: str
    description: str
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


@dataclass
class ScanResultModel:
    """Domain model for scan results."""
    id: str
    target: Target
    scanner_type: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    data: Dict[str, Any] = None
    vulnerabilities: List[Vulnerability] = None
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if self.vulnerabilities is None:
            self.vulnerabilities = []
    
    @property
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.completed_at and self.started_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    @property
    def is_completed(self) -> bool:
        """Check if scan is completed."""
        return self.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]