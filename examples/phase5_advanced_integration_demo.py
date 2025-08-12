#!/usr/bin/env python3
"""
Phase 5 Advanced Integration Demo
Demonstrates UI plugins, analytics, distributed execution, and performance profiling
"""

import sys
import os
import asyncio
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.plugins.plugin_manager import PluginManager
from shared.events.event_bus import EventBus
from shared.configuration.config_manager import ConfigManager
from application.services.advanced_integration_service import AdvancedIntegrationService

def demo_analytics_engine():
    """Demonstrate analytics capabilities"""
    print("=== Phase 5: Analytics Engine Demo ===")
    
    # Initialize components
    event_bus = EventBus()
    config_manager = ConfigManager()
    plugin_manager = PluginManager(['plugins'], event_bus)
    
    integration_service = AdvancedIntegrationService(plugin_manager, event_bus)
    
    # Sample scan data
    scan_data = [
        {'open_ports': [{'port': 22}, {'port': 80}], 'vulnerabilities': []},
        {'open_ports': [{'port': 22}, {'port': 80}, {'port': 443}], 'vulnerabilities': [{'severity': 'medium'}]},
        {'open_ports': [{'port': 22}], 'vulnerabilities': [{'severity': 'high'}]}
    ]
    
    # Perform analysis
    analysis = integration_service.perform_advanced_analysis(scan_data)
    print(f"Analysis results: {analysis}")

def demo_distributed_execution():
    """Demonstrate distributed execution"""
    print("\n=== Distributed Execution Demo ===")
    
    event_bus = EventBus()
    plugin_manager = PluginManager(['plugins'], event_bus)
    integration_service = AdvancedIntegrationService(plugin_manager, event_bus)
    
    # Setup nodes
    nodes = [
        {'id': 'node1', 'host': '192.168.1.10', 'port': 8080, 'capabilities': ['port_scanner', 'dns_scanner']},
        {'id': 'node2', 'host': '192.168.1.11', 'port': 8080, 'capabilities': ['http_scanner', 'rpc_scanner']}
    ]
    
    registered = integration_service.setup_distributed_scanning(nodes)
    print(f"Registered {registered} nodes")
    
    # Create scan requests
    scan_requests = [
        {'scanner_type': 'port_scanner', 'target': '192.168.1.100', 'priority': 2},
        {'scanner_type': 'dns_scanner', 'target': 'example.com', 'priority': 1},
        {'scanner_type': 'http_scanner', 'target': 'https://example.com', 'priority': 3}
    ]
    
    # Execute distributed scan
    async def run_distributed_scan():
        result = await integration_service.execute_distributed_scan(scan_requests)
        print(f"Distributed scan result: {result}")
        return result
    
    return asyncio.run(run_distributed_scan())

def demo_performance_profiling():
    """Demonstrate performance profiling"""
    print("\n=== Performance Profiling Demo ===")
    
    event_bus = EventBus()
    plugin_manager = PluginManager(['plugins'], event_bus)
    integration_service = AdvancedIntegrationService(plugin_manager, event_bus)
    
    # Generate some profiled activity
    scan_data = [{'open_ports': [{'port': i}]} for i in range(10)]
    integration_service.perform_advanced_analysis(scan_data)
    
    # Get performance report
    report = integration_service.get_performance_report()
    print(f"Performance report: {report}")

def demo_system_status():
    """Demonstrate system status monitoring"""
    print("\n=== System Status Demo ===")
    
    event_bus = EventBus()
    plugin_manager = PluginManager(['plugins'], event_bus)
    plugin_manager.load_plugins()
    
    integration_service = AdvancedIntegrationService(plugin_manager, event_bus)
    
    status = integration_service.get_system_status()
    print(f"System status: {status}")

if __name__ == "__main__":
    demo_analytics_engine()
    demo_distributed_execution()
    demo_performance_profiling()
    demo_system_status()
    print("\n=== Phase 5 Demo Complete ===")