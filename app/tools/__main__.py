#!/usr/bin/env python3
"""
Command-line interface for Huginn Scanner
"""

import argparse
import asyncio
import sys
import json

async def main():
    parser = argparse.ArgumentParser(description='Huginn Advanced Security Scanner')
    parser.add_argument('--target', '-t', required=True, help='Target URL to scan')
    parser.add_argument('--profile', '-p', default='normal', 
                       choices=['light', 'normal', 'aggressive', 'insane'],
                       help='Scan profile intensity')
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--format', '-f', default='json',
                       choices=['json', 'html', 'executive', 'owasp', 'pci'],
                       help='Output format')
    parser.add_argument('--config', '-c', help='Custom config file path')
    parser.add_argument('--webhook', help='Webhook URL for notifications')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    
    args = parser.parse_args()
    
    # Import here to avoid circular imports
    from .huginn_vuln_scanner import HuginnVulnScanner
    
    if not args.quiet:
        print(f"🔍 Starting Huginn scan of {args.target}")
        print(f"📊 Profile: {args.profile}")
    
    # Initialize scanner
    scanner = HuginnVulnScanner(args.target, profile=args.profile, config_path=args.config)
    
    # Configure webhook if provided
    if args.webhook:
        scanner.webhook_notifier.set_webhook_url(args.webhook)
    
    # Run scan
    try:
        results = await scanner.scan()
        
        if not args.quiet:
            print(f"✅ Scan completed: {len(results['vulnerabilities'])} vulnerabilities found")
            
            # Show severity breakdown
            severity_counts = {}
            for vuln in results['vulnerabilities']:
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity, count in severity_counts.items():
                print(f"   {severity}: {count}")
        
        # Export results
        output_data = scanner.export_results(args.format)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_data)
            if not args.quiet:
                print(f"📄 Results saved to {args.output}")
        else:
            print(output_data)
        
        # Exit with error code if critical vulnerabilities found
        critical_count = sum(1 for v in results['vulnerabilities'] if v.get('severity') == 'Critical')
        if critical_count > 0:
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())