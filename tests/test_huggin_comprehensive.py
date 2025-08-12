#!/usr/bin/env python3
"""Comprehensive test of Huggin Advanced Security Scanner"""

import asyncio
import sys
import os
import time
from datetime import datetime

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.tools.huggin_vuln_scanner import HugginVulnScanner

class HugginTester:
    def __init__(self, target="https://dvwa.lab.local"):
        self.target = target
        self.results = {}
    
    async def test_profile(self, profile_name):
        """Test a specific scan profile"""
        print(f"\n{'='*60}")
        print(f"🚀 TESTING PROFILE: {profile_name.upper()}")
        print(f"Target: {self.target}")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        try:
            scanner = HugginVulnScanner(self.target, profile=profile_name.lower(), verify_ssl=False)
            results = await scanner.scan()
            
            scan_time = time.time() - start_time
            vuln_count = len(results.get('vulnerabilities', []))
            
            # Count by severity
            critical = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'CRITICAL'])
            high = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'HIGH'])
            medium = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'MEDIUM'])
            low = len([v for v in results.get('vulnerabilities', []) if v.get('severity') == 'LOW'])
            
            print(f"\n📊 SCAN RESULTS:")
            print(f"  • Total Vulnerabilities: {vuln_count}")
            print(f"  • Critical: {critical}")
            print(f"  • High: {high}")
            print(f"  • Medium: {medium}")
            print(f"  • Low: {low}")
            print(f"  • Scan Duration: {scan_time:.2f}s")
            
            # Show vulnerabilities
            if vuln_count > 0:
                print(f"\n🔍 VULNERABILITIES FOUND:")
                for vuln in results.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'UNKNOWN')
                    vuln_type = vuln.get('type', 'Unknown')
                    description = vuln.get('description', 'No description')
                    print(f"  🔴 {severity}: {vuln_type}")
                    print(f"     {description}")
            else:
                print(f"\n⚠️  NO VULNERABILITIES DETECTED")
            
            # Store results
            self.results[profile_name] = {
                'vulnerabilities': vuln_count,
                'critical': critical,
                'high': high,
                'medium': medium,
                'low': low,
                'scan_time': scan_time,
                'success': True,
                'details': results
            }
            
            return True
            
        except Exception as e:
            print(f"\n❌ SCAN FAILED: {str(e)}")
            import traceback
            traceback.print_exc()
            
            self.results[profile_name] = {
                'vulnerabilities': 0,
                'success': False,
                'error': str(e),
                'scan_time': time.time() - start_time
            }
            
            return False
    
    async def run_comprehensive_test(self):
        """Run comprehensive test across all profiles"""
        print(f"🎯 HUGGIN ADVANCED SECURITY SCANNER - COMPREHENSIVE TEST")
        print(f"Target: {self.target}")
        print(f"Test Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")
        
        profiles = ['light', 'normal', 'aggressive', 'insane']
        
        for profile in profiles:
            success = await self.test_profile(profile)
            if not success:
                print(f"⚠️  Profile {profile} failed, continuing with next profile...")
            
            # Small delay between tests
            await asyncio.sleep(2)
        
        # Generate summary report
        self.generate_summary_report()
    
    def generate_summary_report(self):
        """Generate comprehensive summary report"""
        print(f"\n{'='*80}")
        print(f"📋 COMPREHENSIVE TEST SUMMARY")
        print(f"{'='*80}")
        
        total_vulns = 0
        successful_scans = 0
        
        print(f"{'Profile':<12} {'Status':<8} {'Vulns':<6} {'Critical':<8} {'High':<6} {'Medium':<8} {'Low':<6} {'Time':<8}")
        print(f"{'-'*70}")
        
        for profile, data in self.results.items():
            if data['success']:
                status = "✅ PASS"
                vulns = data['vulnerabilities']
                critical = data['critical']
                high = data['high']
                medium = data['medium']
                low = data['low']
                scan_time = f"{data['scan_time']:.1f}s"
                total_vulns += vulns
                successful_scans += 1
            else:
                status = "❌ FAIL"
                vulns = critical = high = medium = low = 0
                scan_time = f"{data['scan_time']:.1f}s"
            
            print(f"{profile.capitalize():<12} {status:<8} {vulns:<6} {critical:<8} {high:<6} {medium:<8} {low:<6} {scan_time:<8}")
        
        print(f"{'-'*70}")
        print(f"{'TOTAL':<12} {successful_scans}/{len(self.results):<8} {total_vulns:<6}")
        
        # Performance analysis
        if successful_scans > 0:
            avg_time = sum(data['scan_time'] for data in self.results.values() if data['success']) / successful_scans
            print(f"\n📈 PERFORMANCE METRICS:")
            print(f"  • Average Scan Time: {avg_time:.2f}s")
            print(f"  • Total Vulnerabilities Found: {total_vulns}")
            print(f"  • Success Rate: {successful_scans}/{len(self.results)} ({successful_scans/len(self.results)*100:.1f}%)")
        
        # Detailed findings by profile
        print(f"\n🔍 DETAILED FINDINGS BY PROFILE:")
        for profile, data in self.results.items():
            if data['success'] and data['vulnerabilities'] > 0:
                print(f"\n{profile.upper()} Profile:")
                details = data['details']
                for vuln in details.get('vulnerabilities', [])[:5]:  # Show top 5
                    print(f"  • {vuln.get('severity', 'UNKNOWN')}: {vuln.get('type', 'Unknown')}")
                if len(details.get('vulnerabilities', [])) > 5:
                    print(f"  ... and {len(details.get('vulnerabilities', [])) - 5} more")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if total_vulns == 0:
            print("  • No vulnerabilities detected - verify target is accessible")
            print("  • Check scanner configuration and network connectivity")
            print("  • Consider testing against a known vulnerable target")
        else:
            print(f"  • {total_vulns} total vulnerabilities found across all profiles")
            print("  • Review critical and high severity findings first")
            print("  • Use aggressive/insane profiles for comprehensive testing")
        
        print(f"\n{'='*80}")
        print(f"Test Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")

async def main():
    """Main test function"""
    target = "https://dvwa.lab.local"
    
    # Allow custom target via command line
    if len(sys.argv) > 1:
        target = sys.argv[1]
    
    tester = HugginTester(target)
    await tester.run_comprehensive_test()

if __name__ == "__main__":
    asyncio.run(main())