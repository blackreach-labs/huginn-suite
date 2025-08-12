"""Demonstration of Phase 2 architecture improvements."""
import asyncio
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from application.services.scan_orchestrator import ScanOrchestrator
from application.handlers.scan_handler import ScanHandler, ScanRequest
from domain.services.scanner_service import ScannerService
from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository
from shared.events.event_bus import event_bus, Event


def setup_event_handlers():
    """Setup event handlers for demonstration."""
    
    def on_scan_started(event: Event):
        print(f"[EVENT] Scan started: {event.scan_id} targeting {event.target} using {event.scanner_type}")
    
    def on_scan_completed(event: Event):
        print(f"[EVENT] Scan completed: {event.scan_id}")
        if event.results:
            if 'open_ports' in event.results:
                print(f"        Found {len(event.results['open_ports'])} open ports")
            elif 'dns_records' in event.results:
                print(f"        Found {len(event.results['dns_records'])} DNS records")
    
    def on_scan_error(event: Event):
        print(f"[EVENT] Scan error: {event.scan_id} - {event.error}")
    
    # Subscribe to events
    event_bus.subscribe("scan_started", on_scan_started)
    event_bus.subscribe("scan_completed", on_scan_completed)
    event_bus.subscribe("scan_error", on_scan_error)


async def demonstrate_layered_architecture():
    """Demonstrate the complete layered architecture."""
    print("Phase 2: Layered Architecture Demo")
    print("=" * 50)
    
    # Setup event handlers
    setup_event_handlers()
    
    # Initialize layers from bottom up
    print("1. Initializing Infrastructure Layer...")
    repository = SQLiteScanRepository()
    
    print("2. Initializing Application Layer...")
    orchestrator = ScanOrchestrator(repository)
    
    print("3. Initializing Domain Layer...")
    scanner_service = ScannerService(orchestrator)
    
    print("4. Initializing Application Handlers...")
    scan_handler = ScanHandler(scanner_service)
    
    print("\\nArchitecture initialized successfully!")
    print("=" * 50)
    
    # Import scanners to register them
    from infrastructure.scanners.network.port_scanner import PortScanner, UDPPortScanner
    from infrastructure.scanners.network.dns_scanner import DNSScanner
    
    print("\\nRegistered Scanners:")
    from infrastructure.scanners.base.scanner_factory import ScannerFactory
    for scanner_type in ScannerFactory.get_available_scanners():
        print(f"  - {scanner_type}")
    
    return scan_handler


async def demonstrate_single_scan():
    """Demonstrate single scan execution."""
    print("\\n" + "=" * 50)
    print("DEMO 1: Single Scan Execution")
    print("=" * 50)
    
    scan_handler = await demonstrate_layered_architecture()
    
    # Create scan request
    request = ScanRequest(
        scanner_type="port_scanner",
        target="google.com",
        config={
            'ports': [80, 443, 22, 21],
            'timeout': 3,
            'max_concurrent': 10
        }
    )
    
    print(f"\\nExecuting single scan: {request.scanner_type} on {request.target}")
    result = await scan_handler.handle_single_scan(request)
    
    print(f"\\nScan Result:")
    print(f"  Success: {result['success']}")
    if result['success']:
        print(f"  Scan ID: {result['scan_id']}")
        print(f"  Status: {result['status']}")
        print(f"  Message: {result['message']}")
        
        # Get detailed status
        status = await scan_handler.get_scan_status(result['scan_id'])
        if status['success']:
            print(f"  Duration: {status['duration']:.2f}s" if status['duration'] else "  Duration: N/A")
            open_ports = status['data'].get('open_ports', [])
            print(f"  Open Ports: {len(open_ports)}")
            for port in open_ports[:3]:  # Show first 3
                print(f"    - {port['port']}/{port['protocol']} ({port['service']})")
    else:
        print(f"  Error: {result['error']}")


async def demonstrate_comprehensive_scan():
    """Demonstrate comprehensive multi-scanner execution."""
    print("\\n" + "=" * 50)
    print("DEMO 2: Comprehensive Scan")
    print("=" * 50)
    
    scan_handler = await demonstrate_layered_architecture()
    
    target = "google.com"
    scan_types = ["port_scanner", "dns_scanner"]
    
    print(f"\\nExecuting comprehensive scan on {target}")
    print(f"Scanner types: {', '.join(scan_types)}")
    
    result = await scan_handler.handle_comprehensive_scan(target, scan_types)
    
    print(f"\\nComprehensive Scan Result:")
    print(f"  Success: {result['success']}")
    if result['success']:
        print(f"  Total Scans: {result['total_scans']}")
        print(f"  Successful: {result['successful_scans']}")
        print(f"  Failed: {result['failed_scans']}")
        print(f"  Message: {result['message']}")
        
        print(f"\\n  Individual Results:")
        for scan_result in result['results']:
            print(f"    {scan_result['scanner_type']}: {scan_result['status']}")
            if scan_result['status'] == 'completed':
                if 'open_ports' in scan_result['data']:
                    ports = len(scan_result['data']['open_ports'])
                    print(f"      -> {ports} open ports found")
                elif 'dns_records' in scan_result['data']:
                    records = len(scan_result['data']['dns_records'])
                    print(f"      -> {records} DNS records found")
    else:
        print(f"  Error: {result['error']}")


async def demonstrate_scan_history():
    """Demonstrate scan history retrieval."""
    print("\\n" + "=" * 50)
    print("DEMO 3: Scan History")
    print("=" * 50)
    
    scan_handler = await demonstrate_layered_architecture()
    
    # Get scan history
    history = await scan_handler.get_scan_history(limit=10)
    
    print(f"\\nScan History:")
    print(f"  Success: {history['success']}")
    if history['success']:
        print(f"  Total Scans: {history['total_scans']}")
        
        if history['scans']:
            print(f"\\n  Recent Scans:")
            for scan in history['scans'][:5]:  # Show first 5
                duration_str = f"{scan['duration']:.2f}s" if scan['duration'] else "N/A"
                print(f"    {scan['scanner_type']} -> {scan['target']} ({scan['status']}) - {duration_str}")
                print(f"      {scan['summary']}")
        else:
            print("  No scans found in history")


async def demonstrate_component_separation():
    """Demonstrate component separation and modularity."""
    print("\\n" + "=" * 50)
    print("DEMO 4: Component Separation")
    print("=" * 50)
    
    print("\\nDemonstrating layered architecture separation:")
    
    # Show how each layer can be tested independently
    print("\\n1. Infrastructure Layer (Scanners):")
    from infrastructure.scanners.network.port_scanner import PortScanner
    scanner = PortScanner("google.com", {'ports': [80, 443]})
    print(f"   Scanner Type: {scanner.get_scanner_type()}")
    print(f"   Target: {scanner.target}")
    print(f"   Config: {scanner.config}")
    
    print("\\n2. Domain Layer (Models):")
    from domain.models.scan_result import Target, ScanStatus
    target = Target(address="example.com", port=80, protocol="tcp")
    print(f"   Target: {target.address}:{target.port}/{target.protocol}")
    print(f"   Available Statuses: {[status.value for status in ScanStatus]}")
    
    print("\\n3. Application Layer (Services):")
    repository = SQLiteScanRepository()
    orchestrator = ScanOrchestrator(repository)
    print(f"   Orchestrator initialized with repository")
    from infrastructure.scanners.base.scanner_factory import ScannerFactory
    print(f"   Available scanner types: {len(ScannerFactory.get_available_scanners())}")
    
    print("\\n4. Shared Components:")
    from shared.configuration.config_manager import ConfigManager
    config_manager = ConfigManager()
    scanner_config = config_manager.get_scanner_config()
    print(f"   Default timeout: {scanner_config.timeout}s")
    print(f"   Max concurrent: {scanner_config.max_concurrent}")
    
    print("\\nAll layers working independently and together!")


if __name__ == "__main__":
    print("Phase 2: Advanced Architecture Demo")
    print("Demonstrating layered architecture with component separation")
    print("=" * 60)
    
    asyncio.run(demonstrate_single_scan())
    asyncio.run(demonstrate_comprehensive_scan())
    asyncio.run(demonstrate_scan_history())
    asyncio.run(demonstrate_component_separation())
    
    print("\\n" + "=" * 60)
    print("Phase 2 Demo Completed!")
    print("\\nKey Improvements Demonstrated:")
    print("  - Component-based main window architecture")
    print("  - Layered service architecture")
    print("  - Domain-driven design patterns")
    print("  - Application handlers for UI integration")
    print("  - Comprehensive scanner service")
    print("  - Event-driven communication")
    print("  - Repository pattern implementation")
    print("  - Configuration management")
    print("  - Modular scanner implementations")