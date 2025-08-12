#!/usr/bin/env python3
"""
Test script for Advanced Reporting functionality
"""
import sys
import os
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.advanced_reporting import advanced_reporting

def test_advanced_reporting():
    """Test the advanced reporting functionality"""
    print("Testing Advanced Reporting Engine...")
    
    # Sample scan data
    sample_data = {
        'target': 'example.com',
        'scan_type': 'dns_enum',
        'timestamp': datetime.now().isoformat(),
        'duration': '45 seconds',
        'results': {
            'example.com': {
                'A': ['93.184.216.34'],
                'AAAA': ['2606:2800:220:1:248:1893:25c8:1946'],
                'MX': ['mail.example.com'],
                'TXT': ['v=spf1 -all']
            },
            'www.example.com': {
                'A': ['93.184.216.34'],
                'CNAME': ['example.com']
            },
            'mail.example.com': {
                'A': ['93.184.216.35']
            },
            'ftp.example.com': {
                'A': ['93.184.216.36']
            },
            'admin.example.com': {
                'A': ['93.184.216.37']
            },
            'test.example.com': {
                'A': ['93.184.216.38']
            }
        },
        'wildcard_detected': False,
        'open_ports': [80, 443, 22, 25]
    }
    
    print(f"Sample data loaded for target: {sample_data['target']}")
    print(f"Results count: {len(sample_data['results'])}")
    
    # Test JSON report generation
    print("\n1. Testing JSON Report Generation...")
    success, filepath, message = advanced_reporting.generate_comprehensive_report(
        sample_data, 'technical', 'json'
    )
    print(f"JSON Report - Success: {success}")
    print(f"JSON Report - Message: {message}")
    if success:
        print(f"JSON Report - File: {filepath}")
    
    # Test HTML report generation
    print("\n2. Testing HTML Report Generation...")
    success, filepath, message = advanced_reporting.generate_comprehensive_report(
        sample_data, 'executive', 'html'
    )
    print(f"HTML Report - Success: {success}")
    print(f"HTML Report - Message: {message}")
    if success:
        print(f"HTML Report - File: {filepath}")
    
    # Test PDF report generation (if ReportLab is available)
    print("\n3. Testing PDF Report Generation...")
    success, filepath, message = advanced_reporting.generate_comprehensive_report(
        sample_data, 'vulnerability', 'pdf'
    )
    print(f"PDF Report - Success: {success}")
    print(f"PDF Report - Message: {message}")
    if success:
        print(f"PDF Report - File: {filepath}")
    
    print("\nAdvanced Reporting Test Complete!")
    print("Check the 'exports' directory for generated reports.")

if __name__ == "__main__":
    test_advanced_reporting()