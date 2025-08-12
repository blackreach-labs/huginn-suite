from typing import Dict, Any, List
from .scan_orchestrator import ScanOrchestrator
from .plugin_service import PluginService
from shared.events.event_bus import EventBus
from shared.utilities.performance_monitor import PerformanceMonitor
from shared.utilities.error_handler import ErrorHandler

class EnhancedScanOrchestrator(ScanOrchestrator):
    """Enhanced scan orchestrator with plugin support and performance monitoring"""
    
    def __init__(self, data_collector, scanner_factory, plugin_service: PluginService, 
                 event_bus: EventBus, performance_monitor: PerformanceMonitor):
        super().__init__(data_collector, scanner_factory)
        self.plugin_service = plugin_service
        self.event_bus = event_bus
        self.performance_monitor = performance_monitor
        self.error_handler = ErrorHandler(event_bus=event_bus)
    
    @ErrorHandler().with_error_handling("scan_execution")
    async def execute_enhanced_scan(self, scan_request) -> Dict[str, Any]:
        """Execute scan with plugin enhancement and monitoring"""
        
        # Start performance monitoring
        self.performance_monitor.start_monitoring()
        
        try:
            # Execute base scan
            results = await super().execute_scan(scan_request)
            
            # Apply scanner plugins
            scanner_plugins = self.plugin_service.get_plugins_by_category("scanner")
            for plugin_name in scanner_plugins:
                enhanced_results = self.plugin_service.execute_plugin(plugin_name, results)
                if enhanced_results:
                    results.update(enhanced_results)
            
            # Apply analysis plugins
            analysis_plugins = self.plugin_service.get_plugins_by_category("analysis")
            for plugin_name in analysis_plugins:
                analysis_results = self.plugin_service.execute_plugin(plugin_name, results)
                if analysis_results:
                    results['analysis'] = results.get('analysis', {})
                    results['analysis'].update(analysis_results)
            
            # Add performance metrics
            metrics = self.performance_monitor.get_recent_metrics(1)
            if metrics:
                results['performance_metrics'] = {
                    'cpu_percent': metrics[0].cpu_percent,
                    'memory_mb': metrics[0].memory_mb,
                    'execution_time': metrics[0].timestamp.isoformat()
                }
            
            return results
            
        finally:
            self.performance_monitor.stop_monitoring()