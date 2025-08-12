#!/usr/bin/env python3
# test_centralized_data.py - Test script for centralized data collection system

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.centralized_scan_data import centralized_scan_data
from app.core.rpc_data_collector import create_rpc_collector
from app.core.dns_data_collector import create_dns_collector
from app.core.port_data_collector import create_port_collector
from app.core.centralized_reporting import create_reporting_engine

def test_rpc_data_collection():
    """Test RPC data collection"""
    print("🔧 Testing RPC Data Collection...")
    
    collector = create_rpc_collector("test_tenant")
    
    # Start scan
    scan_id = collector.start_rpc_scan("192.168.1.100", "test_scanner")
    print(f"Started RPC scan: {scan_id}")
    
    # Collect sample data
    endpoints = [
        {"protocol": "Service Control Manager", "uuid": "367abb81-9844-35f1-ad32-98f038001003", "port": 445},
        {"protocol": "LSA RPC", "uuid": "12345678-1234-abcd-ef00-0123456789ab", "port": 445}
    ]
    collector.collect_rpc_endpoints("192.168.1.100", endpoints)
    
    services = [
        {"name": "Spooler", "display_name": "Print Spooler", "state": "RUNNING"},
        {"name": "BITS", "display_name": "Background Intelligent Transfer Service", "state": "STOPPED"}
    ]
    collector.collect_rpc_services("192.168.1.100", services)
    
    vulnerabilities = [
        {"name": "PrintNightmare", "severity": "Critical", "cve": "CVE-2021-1675", "exploitable": True}
    ]
    collector.collect_rpc_vulnerabilities("192.168.1.100", vulnerabilities)
    
    # Complete scan
    collector.complete_rpc_scan(total_results=4)
    print("✅ RPC data collection completed")

def test_dns_data_collection():
    """Test DNS data collection"""
    print("🌐 Testing DNS Data Collection...")
    
    collector = create_dns_collector("test_tenant")
    
    # Start scan
    scan_id = collector.start_dns_scan("example.com", "dns_enumerator")
    print(f"Started DNS scan: {scan_id}")
    
    # Collect sample data
    subdomains = ["www.example.com", "mail.example.com", "ftp.example.com"]
    collector.collect_subdomains("example.com", subdomains)
    
    dns_records = [
        {"type": "A", "name": "example.com", "value": "93.184.216.34", "ttl": 3600},
        {"type": "MX", "name": "example.com", "value": "10 mail.example.com", "ttl": 3600}
    ]
    collector.collect_dns_records("example.com", dns_records)
    
    # Complete scan
    collector.complete_dns_scan(total_results=5)
    print("✅ DNS data collection completed")

def test_port_data_collection():
    """Test port data collection"""
    print("🔍 Testing Port Data Collection...")
    
    collector = create_port_collector("test_tenant")
    
    # Start scan
    scan_id = collector.start_port_scan("192.168.1.100", "port_scanner")
    print(f"Started port scan: {scan_id}")
    
    # Collect sample data
    open_ports = [
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "banner": "Apache/2.4.41"},
        {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "banner": "nginx/1.18.0"},
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "banner": "OpenSSH_8.2"}
    ]
    collector.collect_open_ports("192.168.1.100", open_ports)
    
    services = [
        {"port": 80, "service": "Apache HTTP Server", "version": "2.4.41", "confidence": 95},
        {"port": 443, "service": "nginx", "version": "1.18.0", "confidence": 90}
    ]
    collector.collect_service_detection("192.168.1.100", services)
    
    os_info = {"os_family": "Linux", "os_version": "Ubuntu 20.04", "accuracy": 85}
    collector.collect_os_detection("192.168.1.100", os_info)
    
    # Complete scan
    collector.complete_port_scan(total_results=6)
    print("✅ Port data collection completed")

def test_data_retrieval():
    """Test data retrieval and UI formatting"""
    print("📊 Testing Data Retrieval...")
    
    # Test RPC data retrieval
    rpc_collector = create_rpc_collector("test_tenant")
    rpc_data = rpc_collector.get_rpc_data_for_ui("rpc_endpoints")
    print(f"RPC endpoints: {len(rpc_data['table_data'])} entries")
    
    # Test DNS data retrieval
    dns_collector = create_dns_collector("test_tenant")
    dns_data = dns_collector.get_dns_data_for_ui("dns_subdomains")
    print(f"DNS subdomains: {len(dns_data['table_data'])} entries")
    
    # Test port data retrieval
    port_collector = create_port_collector("test_tenant")
    port_data = port_collector.get_port_data_for_ui("port_open_ports")
    print(f"Open ports: {len(port_data['table_data'])} entries")
    
    print("✅ Data retrieval completed")

def test_reporting():
    """Test centralized reporting"""
    print("📋 Testing Centralized Reporting...")
    
    reporter = create_reporting_engine("test_tenant")
    
    # Generate executive summary
    exec_summary = reporter.generate_executive_summary()
    print(f"Executive summary generated: {len(exec_summary.get('scan_type_breakdown', {}))} scan types")
    
    # Generate technical report
    tech_report = reporter.generate_technical_report()
    print(f"Technical report generated: {len(tech_report.get('scan_types', {}))} scan types")
    
    # Generate RPC security report
    rpc_report = reporter.generate_rpc_security_report()
    print(f"RPC security report generated: {len(rpc_report.get('sections', {}))} sections")
    
    print("✅ Reporting completed")

def test_tenant_overview():
    """Test tenant overview functionality"""
    print("🏢 Testing Tenant Overview...")
    
    overview = centralized_scan_data.get_tenant_overview("test_tenant")
    print(f"Tenant overview: {len(overview.get('scan_types', {}))} scan types")
    
    for scan_type, data in overview.get('scan_types', {}).items():
        print(f"  - {scan_type}: {data.get('total_results', 0)} results, {data.get('unique_targets', 0)} targets")
    
    print("✅ Tenant overview completed")

def cleanup_test_data():
    """Clean up test data"""
    print("🧹 Cleaning up test data...")
    
    deleted = centralized_scan_data.cleanup_old_data("test_tenant", days_to_keep=0)
    print(f"Deleted {deleted} old records")
    
    print("✅ Cleanup completed")

def main():
    """Run all tests"""
    print("🚀 Starting Centralized Data Collection System Tests\n")
    
    try:
        # Test data collection
        test_rpc_data_collection()
        print()
        
        test_dns_data_collection()
        print()
        
        test_port_data_collection()
        print()
        
        # Test data retrieval
        test_data_retrieval()
        print()
        
        # Test reporting
        test_reporting()
        print()
        
        # Test tenant overview
        test_tenant_overview()
        print()
        
        # Cleanup
        cleanup_test_data()
        print()
        
        print("🎉 All tests completed successfully!")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()