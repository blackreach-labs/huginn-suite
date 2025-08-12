"""Scan handler for UI integration with new architecture."""
import asyncio
from typing import Dict, Any, Optional, Callable
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable, QThreadPool

from application.services.scan_orchestrator import ScanOrchestrator, ScanRequest
from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository
from shared.events.event_bus import EventBus
from shared.configuration.config_manager import ConfigManager


class ScanSignals(QObject):
    """Qt signals for scan operations."""
    output = pyqtSignal(str)
    status = pyqtSignal(str)
    finished = pyqtSignal()
    results_ready = pyqtSignal(dict)
    progress_update = pyqtSignal(int, int)
    progress_start = pyqtSignal(int)


class AsyncScanWorker(QRunnable):
    """Worker to run async scans in Qt thread pool."""
    
    def __init__(self, orchestrator: ScanOrchestrator, scan_request: ScanRequest):
        super().__init__()
        self.orchestrator = orchestrator
        self.scan_request = scan_request
        self.signals = ScanSignals()
        self.is_running = True
    
    def run(self):
        """Execute the async scan."""
        try:
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run the scan
            result = loop.run_until_complete(self.orchestrator.execute_scan(self.scan_request))
            
            # Convert and emit results
            from application.handlers.scan_handler import convert_port_scan_results, convert_network_sweep_results
            
            if self.scan_request.scanner_type == "port_scanner" or self.scan_request.scanner_type == "udp_port_scanner":
                converted_results = convert_port_scan_results(result.data, self.scan_request.target)
            elif self.scan_request.scanner_type == "network_sweep":
                converted_results = convert_network_sweep_results(result.data)
            else:
                converted_results = result.data
            
            self.signals.results_ready.emit(converted_results)
            self.signals.status.emit("Scan completed")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Scan failed: {str(e)}</p>")
            self.signals.status.emit("Scan error")
        finally:
            self.signals.finished.emit()


class ScanHandler:
    """Handler for integrating new architecture with UI."""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.config_manager = ConfigManager()
        
        # Initialize components
        self.repository = SQLiteScanRepository()
        self.event_bus = EventBus()
        self.orchestrator = ScanOrchestrator(self.repository, self.event_bus)
        
        # Setup event handlers
        self._setup_event_handlers()
    
    def _setup_event_handlers(self):
        """Setup event bus handlers."""
        from shared.events.event_bus import ScanStartedEvent, ScanCompletedEvent, ScanErrorEvent
        
        self.event_bus.subscribe("scan_started", self._on_scan_started)
        self.event_bus.subscribe("scan_completed", self._on_scan_completed)
        self.event_bus.subscribe("scan_error", self._on_scan_error)
    
    def _on_scan_started(self, event):
        """Handle scan started event."""
        print(f"Scan started: {event.scan_id} for {event.target}")
    
    def _on_scan_completed(self, event):
        """Handle scan completed event."""
        print(f"Scan completed: {event.scan_id}")
    
    def _on_scan_error(self, event):
        """Handle scan error event."""
        print(f"Scan error: {event.scan_id} - {event.error}")
    
    def create_port_scan_worker(self, target: str, ports: list, protocol: str = "tcp") -> AsyncScanWorker:
        """Create port scan worker using new architecture."""
        scanner_type = "port_scanner" if protocol == "tcp" else "udp_port_scanner"
        config = {"ports": ports}
        
        scan_request = ScanRequest(
            scanner_type=scanner_type,
            target=target,
            config=config,
            tenant_id=self.tenant_id
        )
        
        return AsyncScanWorker(self.orchestrator, scan_request)
    
    def create_network_sweep_worker(self, target: str) -> AsyncScanWorker:
        """Create network sweep worker using new architecture."""
        scan_request = ScanRequest(
            scanner_type="network_sweep",
            target=target,
            tenant_id=self.tenant_id
        )
        
        return AsyncScanWorker(self.orchestrator, scan_request)
    
    def create_comprehensive_scan_worker(self, target: str) -> AsyncScanWorker:
        """Create comprehensive scan worker."""
        # For comprehensive scans, we'll use a special request type
        scan_request = ScanRequest(
            scanner_type="comprehensive",
            target=target,
            tenant_id=self.tenant_id
        )
        
        # Override the worker to handle comprehensive scans
        class ComprehensiveScanWorker(AsyncScanWorker):
            def run(self):
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    # Execute comprehensive scan
                    results = loop.run_until_complete(
                        self.orchestrator.execute_comprehensive_scan(
                            self.scan_request.target,
                            self.scan_request.tenant_id
                        )
                    )
                    
                    # Combine all results
                    combined_results = {}
                    for scanner_type, result in results.items():
                        combined_results[scanner_type] = result.data
                    
                    self.signals.results_ready.emit(combined_results)
                    self.signals.status.emit("Comprehensive scan completed")
                    
                except Exception as e:
                    self.signals.output.emit(f"<p style='color: #FF4500;'>[ERROR] Comprehensive scan failed: {str(e)}</p>")
                    self.signals.status.emit("Comprehensive scan error")
                finally:
                    self.signals.finished.emit()
        
        return ComprehensiveScanWorker(self.orchestrator, scan_request)


# Result conversion utilities for UI compatibility
def convert_port_scan_results(results, target):
    """Convert new architecture port scan results to UI format."""
    if 'open_ports' in results:
        return {target: {'open_ports': results['open_ports']}}
    return {}

def convert_network_sweep_results(results):
    """Convert new architecture network sweep results to UI format."""
    legacy_results = {}
    if 'alive_hosts' in results:
        for host_info in results['alive_hosts']:
            if isinstance(host_info, dict) and 'ip' in host_info:
                legacy_results[host_info['ip']] = {'status': 'Up'}
    return legacy_results

# Global scan handler instance
_scan_handler = None

def get_scan_handler(tenant_id: str = "default") -> ScanHandler:
    """Get global scan handler instance."""
    global _scan_handler
    if _scan_handler is None:
        _scan_handler = ScanHandler(tenant_id)
    return _scan_handler