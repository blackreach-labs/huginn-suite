#!/usr/bin/env python3
"""
Phase 4 Advanced Features Demo
Demonstrates plugin architecture, event-driven communication, and performance monitoring
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.plugins.plugin_manager import PluginManager
from shared.events.event_bus import EventBus
from shared.configuration.config_manager import ConfigManager
from shared.utilities.performance_monitor import PerformanceMonitor
from application.services.plugin_service import PluginService

def demo_plugin_system():
    """Demonstrate plugin system functionality"""
    print("=== Phase 4: Plugin System Demo ===")
    
    # Initialize components
    event_bus = EventBus()
    config_manager = ConfigManager()
    plugin_service = PluginService(config_manager, event_bus)
    
    # Load plugins
    loaded_count = plugin_service.load_all_plugins()
    print(f"Loaded {loaded_count} plugins")
    
    # List available plugins
    plugins = plugin_service.get_available_plugins()
    print(f"Available plugins: {plugins}")
    
    # Test plugin execution
    test_data = {
        'open_ports': [{'port': 22, 'service': 'ssh'}, {'port': 80, 'service': 'http'}],
        'vulnerabilities': [{'name': 'SSH Weak Config', 'port': 22, 'severity': 'medium'}]
    }
    
    for plugin_name in plugins:
        try:
            result = plugin_service.execute_plugin(plugin_name, test_data)
            print(f"Plugin {plugin_name} result: {result}")
        except Exception as e:
            print(f"Plugin {plugin_name} error: {e}")

def demo_performance_monitoring():
    """Demonstrate performance monitoring"""
    print("\n=== Performance Monitoring Demo ===")
    
    monitor = PerformanceMonitor(collection_interval=0.5)
    
    def metrics_callback(metrics):
        print(f"CPU: {metrics.cpu_percent:.1f}%, Memory: {metrics.memory_mb:.1f}MB")
    
    monitor.add_callback(metrics_callback)
    monitor.start_monitoring()
    
    # Simulate some work
    import time
    time.sleep(3)
    
    # Get metrics
    recent = monitor.get_recent_metrics(5)
    print(f"Collected {len(recent)} metrics samples")
    
    average = monitor.get_average_metrics(1)
    if average:
        print(f"Average metrics: CPU {average.cpu_percent:.1f}%, Memory {average.memory_mb:.1f}MB")
    
    monitor.stop_monitoring()

if __name__ == "__main__":
    demo_plugin_system()
    demo_performance_monitoring()
    print("\n=== Phase 4 Demo Complete ===")