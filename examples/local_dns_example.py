# examples/local_dns_example.py
"""
Local DNS Server Usage Example

This example demonstrates how to use the Local DNS Server feature
for Professional and Enterprise license holders.
"""

import sys
import os
import time

# Add the app directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.local_dns_server import local_dns_server
from app.core.license_manager import license_manager

def main():
    """Demonstrate Local DNS Server usage"""
    
    print("=== Local DNS Server Example ===\n")
    
    # Check license status
    license_info = license_manager.get_license_info()
    print(f"License Status: {license_info.get('license_type', 'Free')}")
    
    if not license_info.get("licensed") or license_info.get("license_type") not in ["Professional", "Enterprise"]:
        print("❌ Local DNS Server requires Professional or Enterprise license")
        print("   Use License Manager to upgrade your license")
        return
    
    print("✅ License validated - Local DNS Server available\n")
    
    # Start the DNS server
    print("Starting Local DNS Server...")
    if local_dns_server.start_server():
        print(f"✅ DNS Server started on 127.0.0.1:{local_dns_server.port}\n")
    else:
        print("❌ Failed to start DNS server")
        return
    
    try:
        # Add some example DNS records
        print("Adding DNS records...")
        
        # Add A records
        local_dns_server.add_record("test.local", "A", "192.168.1.100")
        local_dns_server.add_record("app.local", "A", "192.168.1.200")
        local_dns_server.add_record("db.local", "A", "192.168.1.300")
        
        # Add CNAME records
        local_dns_server.add_record("www.test.local", "CNAME", "test.local")
        local_dns_server.add_record("mail.test.local", "CNAME", "app.local")
        
        # Add AAAA record (IPv6)
        local_dns_server.add_record("ipv6.local", "AAAA", "::1")
        
        print("✅ DNS records added successfully\n")
        
        # Display current records
        records = local_dns_server.get_records()
        print("Current DNS Records:")
        print("-" * 40)
        
        for domain, types in records.items():
            print(f"Domain: {domain}")
            for record_type, values in types.items():
                for value in values:
                    print(f"  {record_type}: {value}")
            print()
        
        # Usage instructions
        print("Usage Instructions:")
        print("-" * 40)
        print("1. In any DNS enumeration tool, set DNS Server to 'LocalDNS'")
        print("2. Query domains like 'test.local' to get custom responses")
        print("3. Use for testing subdomain enumeration, DNS spoofing, etc.")
        print()
        
        # Example DNS queries you can now perform
        print("Example Queries (using LocalDNS):")
        print("-" * 40)
        print("• test.local → 192.168.1.100")
        print("• www.test.local → test.local (CNAME)")
        print("• app.local → 192.168.1.200")
        print("• ipv6.local → ::1 (IPv6)")
        print()
        
        # Keep server running for demonstration
        print("DNS Server is running. Press Ctrl+C to stop...")
        
        # In a real application, the server would run in the background
        # Here we'll just wait a bit for demonstration
        time.sleep(10)
        
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    
    finally:
        # Stop the DNS server
        local_dns_server.stop_server()
        print("✅ DNS Server stopped")

def demonstrate_dns_tools_integration():
    """Show how LocalDNS integrates with DNS tools"""
    
    print("\n=== DNS Tools Integration ===\n")
    
    print("To use LocalDNS in DNS enumeration tools:")
    print()
    print("1. DNS Enumeration Tool:")
    print("   Target: test.local")
    print("   DNS Server: LocalDNS")
    print("   → Will resolve using local DNS server")
    print()
    print("2. Subdomain Brute Force:")
    print("   Target: local")
    print("   DNS Server: LocalDNS")
    print("   → Will find: test.local, app.local, db.local")
    print()
    print("3. Custom Testing Scenarios:")
    print("   Add record: google.com → 192.168.1.100")
    print("   DNS Server: LocalDNS")
    print("   → Simulate DNS spoofing for testing")
    print()

if __name__ == "__main__":
    main()
    demonstrate_dns_tools_integration()