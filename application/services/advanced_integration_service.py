from typing import Dict, Any, List
from shared.plugins.plugin_manager import PluginManager
from shared.analytics.analytics_engine import AnalyticsEngine
from shared.distributed.node_manager import NodeManager
from shared.distributed.task_distributor import TaskDistributor, ScanTask
from shared.utilities.performance_profiler import PerformanceProfiler
from shared.events.event_bus import EventBus

class AdvancedIntegrationService:
    """Service integrating all Phase 5 advanced features"""
    
    def __init__(self, plugin_manager: PluginManager, event_bus: EventBus):
        self.plugin_manager = plugin_manager
        self.event_bus = event_bus
        self.analytics_engine = AnalyticsEngine()
        self.node_manager = NodeManager()
        self.task_distributor = TaskDistributor(self.node_manager)
        self.profiler = PerformanceProfiler()
    
    @PerformanceProfiler().profile("advanced_scan_analysis")
    def perform_advanced_analysis(self, scan_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform advanced analysis using analytics engine"""
        trends = self.analytics_engine.analyze_scan_trends(scan_data)
        
        if len(scan_data) > 1:
            anomalies = self.analytics_engine.detect_anomalies(
                scan_data[-1], scan_data[:-1]
            )
        else:
            anomalies = []
        
        return {
            'trends': [
                {
                    'metric': trend.metric_name,
                    'value': trend.value,
                    'confidence': trend.confidence,
                    'metadata': trend.metadata
                }
                for trend in trends
            ],
            'anomalies': [
                {
                    'metric': anomaly.metric_name,
                    'value': anomaly.value,
                    'confidence': anomaly.confidence,
                    'metadata': anomaly.metadata
                }
                for anomaly in anomalies
            ]
        }
    
    def setup_distributed_scanning(self, nodes: List[Dict[str, Any]]) -> int:
        """Setup distributed scanning nodes"""
        from shared.distributed.node_manager import ScanNode
        
        registered_count = 0
        for node_config in nodes:
            node = ScanNode(
                node_id=node_config['id'],
                host=node_config['host'],
                port=node_config['port'],
                capabilities=node_config.get('capabilities', [])
            )
            
            if self.node_manager.register_node(node):
                registered_count += 1
        
        self.node_manager.start_monitoring()
        return registered_count
    
    async def execute_distributed_scan(self, scan_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute scans across distributed nodes"""
        tasks = []
        
        for i, request in enumerate(scan_requests):
            task = ScanTask(
                task_id=f"task_{i}",
                scanner_type=request['scanner_type'],
                target=request['target'],
                config=request.get('config', {}),
                priority=request.get('priority', 1)
            )
            tasks.append(task)
            self.task_distributor.submit_task(task)
        
        distributed_count = await self.task_distributor.distribute_tasks()
        
        return {
            'total_tasks': len(tasks),
            'distributed_tasks': distributed_count,
            'pending_tasks': len(self.task_distributor.pending_tasks),
            'active_tasks': len(self.task_distributor.active_tasks)
        }
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        profile_results = self.profiler.get_profile_results()
        
        return {
            'profiled_functions': len(profile_results),
            'top_functions': [
                {
                    'name': result.function_name,
                    'total_time': result.execution_time,
                    'call_count': result.call_count,
                    'avg_time': result.avg_time
                }
                for result in profile_results[:10]  # Top 10
            ],
            'total_execution_time': sum(r.execution_time for r in profile_results)
        }
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        return {
            'plugins_loaded': len(self.plugin_manager.get_available_plugins()),
            'active_nodes': len(self.node_manager.get_available_nodes()),
            'pending_tasks': len(self.task_distributor.pending_tasks),
            'active_tasks': len(self.task_distributor.active_tasks),
            'profiler_enabled': self.profiler.enabled
        }