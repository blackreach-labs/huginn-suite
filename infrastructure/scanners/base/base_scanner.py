"""Base scanner interface and implementation."""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import uuid
from datetime import datetime

from shared.exceptions.scanner_exceptions import ScannerException
from shared.events.event_bus import get_event_bus, ScanStartedEvent, ScanCompletedEvent, ScanErrorEvent


@dataclass
class ScanResult:
    """Base scan result structure."""
    scan_id: str
    target: str
    scanner_type: str
    timestamp: datetime
    data: Dict[str, Any]
    success: bool = True
    error: Optional[str] = None


class BaseScanner(ABC):
    """Base scanner interface."""
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        self.target = target
        self.config = config or {}
        self.scan_id = str(uuid.uuid4())
        self.results: List[ScanResult] = []
    
    @abstractmethod
    async def scan(self) -> ScanResult:
        """Perform the scan operation."""
        pass
    
    @abstractmethod
    def get_scanner_type(self) -> str:
        """Get the scanner type identifier."""
        pass
    
    async def execute_scan(self) -> ScanResult:
        """Execute scan with event publishing."""
        # Publish scan started event
        get_event_bus().publish(ScanStartedEvent(
            scan_id=self.scan_id,
            target=self.target,
            scanner_type=self.get_scanner_type()
        ))
        
        try:
            result = await self.scan()
            
            # Publish scan completed event
            get_event_bus().publish(ScanCompletedEvent(
                scan_id=self.scan_id,
                results=result.data
            ))
            
            return result
            
        except Exception as e:
            error_msg = str(e)
            
            # Publish scan error event
            get_event_bus().publish(ScanErrorEvent(
                scan_id=self.scan_id,
                error=error_msg
            ))
            
            # Return error result
            return ScanResult(
                scan_id=self.scan_id,
                target=self.target,
                scanner_type=self.get_scanner_type(),
                timestamp=datetime.now(),
                data={},
                success=False,
                error=error_msg
            )
    
    def _create_result(self, data: Dict[str, Any], success: bool = True, error: Optional[str] = None) -> ScanResult:
        """Create a scan result."""
        return ScanResult(
            scan_id=self.scan_id,
            target=self.target,
            scanner_type=self.get_scanner_type(),
            timestamp=datetime.now(),
            data=data,
            success=success,
            error=error
        )