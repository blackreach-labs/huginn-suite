"""Repository interface for scan data."""
from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime

from domain.models.scan_result import ScanResultModel, ScanStatus


class ScanRepository(ABC):
    """Abstract repository for scan data."""
    
    @abstractmethod
    async def save_scan_result(self, scan_result: ScanResultModel) -> None:
        """Save a scan result."""
        pass
    
    @abstractmethod
    async def get_scan_result(self, scan_id: str) -> Optional[ScanResultModel]:
        """Get a scan result by ID."""
        pass
    
    @abstractmethod
    async def get_scan_results(self, 
                             tenant_id: Optional[str] = None,
                             scanner_type: Optional[str] = None,
                             status: Optional[ScanStatus] = None,
                             limit: int = 100) -> List[ScanResultModel]:
        """Get scan results with optional filters."""
        pass
    
    @abstractmethod
    async def update_scan_status(self, scan_id: str, status: ScanStatus, 
                               completed_at: Optional[datetime] = None,
                               error_message: Optional[str] = None) -> None:
        """Update scan status."""
        pass
    
    @abstractmethod
    async def delete_scan_result(self, scan_id: str) -> None:
        """Delete a scan result."""
        pass
    
    @abstractmethod
    async def get_scan_statistics(self, tenant_id: Optional[str] = None) -> dict:
        """Get scan statistics."""
        pass