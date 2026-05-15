"""Demonstration of the new layered architecture."""
import asyncio
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from application.services.scan_orchestrator import ScanOrchestrator
from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository
from infrastructure.scanners.base.scanner_factory import ScannerFactory
from shared.events.event_bus import event_bus, Event
from shared.configuration.config_manager import ConfigManager


def setup_event_handlers():
    """Setup event handlers for demonstration."""
    
    def on_scan_started(event: Event):
        print(f"Scan started: {event.scan_id} targeting {event.target}")
    
    def on_scan_completed(event: Event):
        print(f"Scan completed: {event.scan_id}")
        if event.results:
            open_ports = event.results.get('open_ports', [])
            print(f"   Found {len(open_ports)} open ports")
    
    def on_scan_error(event: Event):
        print(f"Scan error: {event.scan_id} - {event.error}")
    
    # Subscribe to events
    event_bus.subscribe("scan_started", on_scan_started)
    event_bus.subscribe("scan_completed", on_scan_completed)
    event_bus.subscribe("scan_error", on_scan_error)


async def demonstrate_port_scan():
    """Demonstrate port scanning with new architecture."""
    print("Demonstrating New Layered Architecture")
    print("=" * 50)
    
    # Setup event handlers
    setup_event_handlers()
    
    # Initialize repository
    repository = SQLiteScanRepository()
    
    # Initialize scan orchestrator
    orchestrator = ScanOrchestrator(repository)
    
    # Configure scan
    scan_config = {
        'ports': [80, 443, 22, 21, 25],
        'timeout': 3,
        'max_concurrent': 10
    }
    
    print(f"Configuration loaded:")
    config_manager = ConfigManager()
    scanner_config = config_manager.get_scanner_config()
    print(f"   Default timeout: {scanner_config.timeout}s")
    print(f"   Max concurrent: {scanner_config.max_concurrent}")
    print(f"   User agent: {scanner_config.user_agent}")
    print()
    
    # Execute scan
    target = "google.com"
    print(f"Starting port scan on {target}")
    
    try:
        # Import the scanner to register it
        from infrastructure.scanners.network.port_scanner import PortScanner
        
        result = await orchestrator.execute_scan(
            scanner_type="port_scanner",
            target_address=target,
            config=scan_config
        )
        
        print(f"\nScan Results:")
        print(f"   Scan ID: {result.id}")
        print(f"   Target: {result.target.address}")
        print(f"   Status: {result.status.value}")
        print(f"   Duration: {result.duration:.2f}s" if result.duration else "   Duration: N/A")
        
        if result.data.get('open_ports'):
            print(f"   Open ports:")
            for port_info in result.data['open_ports']:
                print(f"     - {port_info['port']}/{port_info['protocol']} ({port_info['service']})")
        else:
            print("   No open ports found")
        
        # Demonstrate retrieving scan results
        print(f"\nRetrieving scan from database...")
        retrieved_result = await orchestrator.get_scan_result(result.id)
        if retrieved_result:
            print(f"   Successfully retrieved scan: {retrieved_result.id}")
        
        # Get scan statistics
        stats = await repository.get_scan_statistics()
        print(f"\nScan Statistics:")
        for scanner_type, status_counts in stats.items():
            print(f"   {scanner_type}:")
            for status, count in status_counts.items():
                print(f"     {status}: {count}")
        
    except Exception as e:
        print(f"Scan failed: {e}")
        import traceback
        traceback.print_exc()


async def demonstrate_multiple_scanners():
    """Demonstrate multiple scanner types."""
    print(f"\nAvailable Scanners:")
    available_scanners = ScannerFactory.get_available_scanners()
    for scanner_type in available_scanners:
        print(f"   - {scanner_type}")
    
    if len(available_scanners) > 1:
        print(f"\nTesting UDP scanner...")
        
        # Import UDP scanner to register it
        from infrastructure.scanners.network.port_scanner import UDPPortScanner
        
        repository = SQLiteScanRepository()
        orchestrator = ScanOrchestrator(repository)
        
        udp_config = {
            'ports': [53, 123, 161],
            'timeout': 2,
            'max_concurrent': 5
        }
        
        try:
            result = await orchestrator.execute_scan(
                scanner_type="udp_port_scanner",
                target_address="8.8.8.8",
                config=udp_config
            )
            
            print(f"   UDP Scan completed: {result.status.value}")
            if result.data.get('open_ports'):
                for port_info in result.data['open_ports']:
                    print(f"     - {port_info['port']}/{port_info['protocol']} ({port_info['service']}) [{port_info['state']}]")
            
        except Exception as e:
            print(f"   UDP Scan failed: {e}")


if __name__ == "__main__":
    print("Huginn New Architecture Demo")
    print("=" * 40)
    
    asyncio.run(demonstrate_port_scan())
    asyncio.run(demonstrate_multiple_scanners())
    
    print("\nDemo completed!")
    print("This demonstrates:")
    print("  - Layered architecture separation")
    print("  - Event-driven communication")
    print("  - Configuration management")
    print("  - Repository pattern for data access")
    print("  - Scanner factory pattern")
    print("  - Async/await support")
    print("  - Exception handling")