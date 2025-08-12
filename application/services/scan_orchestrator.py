"""Scan orchestration service for coordinating multiple scanners."""
import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from domain.models.scan_result import ScanResultModel as ScanResult
from infrastructure.scanners.base.scanner_factory import ScannerFactory
from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository
from shared.events.event_bus import EventBus, ScanStartedEvent, ScanCompletedEvent


@dataclass
class ScanRequest:
    """Scan request configuration."""
    scanner_type: str
    target: str
    config: Optional[Dict[str, Any]] = None
    tenant_id: str = "default"


class ScanOrchestrator:
    """Orchestrates scan execution and result collection."""
    
    def __init__(self, repository: SQLiteScanRepository, event_bus: EventBus):
        self.repository = repository
        self.event_bus = event_bus
        self.scanner_factory = ScannerFactory()
    
    async def execute_scan(self, scan_request: ScanRequest) -> ScanResult:
        """Execute a single scan."""
        # Create scanner
        scanner = self.scanner_factory.create_scanner(
            scan_request.scanner_type,
            scan_request.target,
            scan_request.config
        )
        
        # Publish scan started event
        scan_started_event = ScanStartedEvent(
            scan_id=scanner.scan_id,
            target=scan_request.target,
            scanner_type=scan_request.scanner_type
        )
        self.event_bus.publish(scan_started_event)
        
        try:
            # Execute scan
            result = await scanner.scan()
            
            # Store result
            await self.repository.save_scan_result(result)
            
            # Publish scan completed event
            scan_completed_event = ScanCompletedEvent(
                scan_id=scanner.scan_id,
                results=result.data
            )
            self.event_bus.publish(scan_completed_event)
            
            return result
            
        except Exception as e:
            # Publish scan error event
            from shared.events.event_bus import ScanErrorEvent
            scan_error_event = ScanErrorEvent(
                scan_id=scanner.scan_id,
                error=str(e)
            )
            self.event_bus.publish(scan_error_event)
            raise
    
    async def execute_multi_scan(self, scan_requests: List[ScanRequest]) -> List[ScanResult]:
        """Execute multiple scans concurrently."""
        tasks = [self.execute_scan(request) for request in scan_requests]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    async def execute_comprehensive_scan(self, target: str, tenant_id: str = "default") -> Dict[str, ScanResult]:
        """Execute a comprehensive scan with multiple scanner types."""
        scan_requests = [
            ScanRequest("network_sweep", target, tenant_id=tenant_id),
            ScanRequest("port_scanner", target, {"ports": [80, 443, 22, 21, 25, 53, 135, 139, 445]}, tenant_id),
            ScanRequest("udp_port_scanner", target, {"ports": [53, 123, 161, 500]}, tenant_id),
        ]
        
        results = await self.execute_multi_scan(scan_requests)
        
        # Return results by scanner type
        result_dict = {}
        for i, request in enumerate(scan_requests):
            if not isinstance(results[i], Exception):
                result_dict[request.scanner_type] = results[i]
        
        return result_dict