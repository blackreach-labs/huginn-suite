#!/usr/bin/env python3
"""
Production Validation Test for Huginn Advanced Security Scanner
Validates the scanner against your actual DVWA and IIS targets
"""

import asyncio
import json
import time
from datetime import datetime
from app.tools.huginn_vuln_scanner import HuginnVulnScanner

class ProductionValidationTest:
    def __init__(self):
        # Your actual test targets from the scan results
        self.targets = {
            'dvwa': 'http://192.168.1.108',  # DVWA target
            'iis': 'http://192.168.1.106'    # Windows IIS target
        }
        
        # Expected vulnerabilities based on your scan results
        self.expected_results = {
            'dvwa': {
                'min_vulnerabilities': 7,
                'expected_critical': ['SQL Injection'],
                'expected_high': ['Cross-Site Scripting'],
                'expected_medium': ['Weak SSL/TLS Configuration', 'Missing Security Headers'],
                'owasp_compliance': 50  # 5/10
            },
            'iis': {
                'min_vulnerabilities': 5,
                'expected_critical': ['Remote Code Execution via file upload'],
                'expected_high': ['Local File Inclusion'],
                'expected_medium': ['Missing Security Headers'],
                'owasp_compliance': 90  # 9/10
            }
        }
    
    async def validate_production_readiness(self):
        """Validate scanner against production targets"""
        print("=" * 80)
        print("HUGINN SCANNER - PRODUCTION VALIDATION TEST")
        print("=" * 80)
        
        validation_results = {}
        
        for target_name, target_url in self.targets.items():
            print(f"\n[VALIDATING] {target_name.upper()} - {target_url}")
            print("-" * 60)
            
            # Test all profiles against this target
            for profile in ['light', 'normal', 'aggressive']:
                print(f"\nProfile: {profile}")
                
                try:
                    start_time = time.time()
                    scanner = HuginnVulnScanner(target_url, profile)
                    results = await scanner.scan()
                    duration = time.time() - start_time
                    
                    # Validate results
                    validation = self.validate_scan_results(target_name, results, profile)
                    validation['duration'] = duration
                    validation['profile'] = profile
                    
                    validation_results[f"{target_name}_{profile}"] = validation
                    
                    # Print validation summary
                    status = "✓ PASS" if validation['overall_pass'] else "✗ FAIL"
                    print(f"  {status} - {len(results.get('vulnerabilities', []))} vulns, {duration:.1f}s")
                    
                    if not validation['overall_pass']:
                        for issue in validation['issues']:
                            print(f"    ! {issue}")
                    
                except Exception as e:
                    validation_results[f"{target_name}_{profile}"] = {
                        'overall_pass': False,
                        'error': str(e),
                        'profile': profile
                    }
                    print(f"  ✗ FAIL - Exception: {str(e)[:50]}...")
        
        # Generate validation report
        self.generate_validation_report(validation_results)
        
        return validation_results
    
    def validate_scan_results(self, target_name, results, profile):
        """Validate scan results against expected outcomes"""
        validation = {
            'overall_pass': True,
            'issues': [],
            'checks': {}
        }
        
        expected = self.expected_results.get(target_name, {})
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Check 1: Minimum vulnerability count
        min_vulns = expected.get('min_vulnerabilities', 0)
        if len(vulnerabilities) < min_vulns:
            validation['overall_pass'] = False
            validation['issues'].append(f"Expected ≥{min_vulns} vulns, found {len(vulnerabilities)}")
        validation['checks']['vulnerability_count'] = len(vulnerabilities)
        
        # Check 2: Critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        expected_critical = expected.get('expected_critical', [])
        
        for expected_vuln in expected_critical:
            found = any(expected_vuln.lower() in v.get('type', '').lower() for v in critical_vulns)
            if not found:
                validation['overall_pass'] = False
                validation['issues'].append(f"Missing critical vulnerability: {expected_vuln}")
        
        validation['checks']['critical_vulnerabilities'] = [v.get('type') for v in critical_vulns]
        
        # Check 3: High severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'High']
        expected_high = expected.get('expected_high', [])
        
        for expected_vuln in expected_high:
            found = any(expected_vuln.lower() in v.get('type', '').lower() for v in high_vulns)
            if not found and profile in ['normal', 'aggressive']:  # Only check for comprehensive profiles
                validation['issues'].append(f"Missing high vulnerability: {expected_vuln}")
        
        validation['checks']['high_vulnerabilities'] = [v.get('type') for v in high_vulns]
        
        # Check 4: OWASP compliance (if available)
        owasp_report = results.get('owasp_report', {})
        if owasp_report:
            compliance_score = owasp_report.get('compliance_score', 0)
            expected_compliance = expected.get('owasp_compliance', 0)
            
            # Allow 10% variance in compliance scoring
            if abs(compliance_score - expected_compliance) > 10:
                validation['issues'].append(f"OWASP compliance variance: expected ~{expected_compliance}%, got {compliance_score}%")
            
            validation['checks']['owasp_compliance'] = compliance_score
        
        # Check 5: Scan completeness
        scan_stats = results.get('scan_stats', {})
        if profile == 'aggressive' and len(scan_stats) < 15:
            validation['issues'].append(f"Aggressive profile completed only {len(scan_stats)} phases")
        elif profile == 'normal' and len(scan_stats) < 10:
            validation['issues'].append(f"Normal profile completed only {len(scan_stats)} phases")
        
        validation['checks']['phases_completed'] = len(scan_stats)
        
        # Check 6: Response time validation
        if profile == 'light' and validation.get('duration', 0) > 300:  # 5 minutes
            validation['issues'].append(f"Light profile took too long: {validation.get('duration', 0):.1f}s")
        
        return validation
    
    async def test_specific_vulnerabilities(self):
        """Test specific vulnerability detection capabilities"""
        print("\n[TESTING] Specific Vulnerability Detection")
        print("-" * 60)
        
        # Test SQL Injection detection on DVWA
        print("\nTesting SQL Injection Detection (DVWA):")
        try:
            scanner = HuginnVulnScanner(self.targets['dvwa'], 'normal')
            results = await scanner.scan()
            
            sql_vulns = [v for v in results.get('vulnerabilities', []) 
                        if 'sql' in v.get('type', '').lower()]
            
            if sql_vulns:
                print(f"  ✓ Detected {len(sql_vulns)} SQL injection vulnerabilities")
                for vuln in sql_vulns:
                    print(f"    - {vuln.get('type')}: {vuln.get('severity')}")
            else:
                print("  ✗ No SQL injection vulnerabilities detected")
        
        except Exception as e:
            print(f"  ✗ SQL injection test failed: {e}")
        
        # Test File Upload vulnerability on IIS
        print("\nTesting File Upload Detection (IIS):")
        try:
            scanner = HuginnVulnScanner(self.targets['iis'], 'normal')
            results = await scanner.scan()
            
            upload_vulns = [v for v in results.get('vulnerabilities', []) 
                           if 'upload' in v.get('type', '').lower() or 'execution' in v.get('type', '').lower()]
            
            if upload_vulns:
                print(f"  ✓ Detected {len(upload_vulns)} file upload/execution vulnerabilities")
                for vuln in upload_vulns:
                    print(f"    - {vuln.get('type')}: {vuln.get('severity')}")
            else:
                print("  ✗ No file upload vulnerabilities detected")
        
        except Exception as e:
            print(f"  ✗ File upload test failed: {e}")
    
    async def test_ai_components_production(self):
        """Test AI components against production targets"""
        print("\n[TESTING] AI Components on Production Targets")
        print("-" * 60)
        
        ai_phases = ['ml_prediction', 'neural_analysis', 'ai_analysis']
        
        for target_name, target_url in self.targets.items():
            print(f"\nTesting AI on {target_name.upper()}:")
            
            try:
                scanner = HuginnVulnScanner(target_url, 'insane')  # Use insane profile for AI
                results = await scanner.scan()
                
                # Check AI-specific results
                ai_insights = results.get('ai_insights', [])
                correlations = results.get('vulnerability_correlations', {})
                proof_of_concepts = results.get('proof_of_concepts', [])
                
                print(f"  AI Insights: {len(ai_insights)}")
                print(f"  Correlations: {len(correlations.get('attack_chains', []))}")
                print(f"  PoCs Generated: {len(proof_of_concepts)}")
                
                if ai_insights:
                    print("  ✓ AI analysis completed successfully")
                else:
                    print("  ! AI analysis produced no insights")
            
            except Exception as e:
                print(f"  ✗ AI testing failed: {e}")
    
    def generate_validation_report(self, validation_results):
        """Generate comprehensive validation report"""
        print("\n" + "=" * 80)
        print("PRODUCTION VALIDATION REPORT")
        print("=" * 80)
        
        # Overall statistics
        total_tests = len(validation_results)
        passed_tests = len([r for r in validation_results.values() if r.get('overall_pass', False)])
        
        print(f"\nOVERALL RESULTS:")
        print(f"  Total Tests: {total_tests}")
        print(f"  Passed: {passed_tests}")
        print(f"  Failed: {total_tests - passed_tests}")
        print(f"  Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        # Target-specific results
        for target in ['dvwa', 'iis']:
            target_results = {k: v for k, v in validation_results.items() if k.startswith(target)}
            if target_results:
                print(f"\n{target.upper()} RESULTS:")
                for test_name, result in target_results.items():
                    status = "PASS" if result.get('overall_pass', False) else "FAIL"
                    duration = result.get('duration', 0)
                    profile = result.get('profile', 'unknown')
                    print(f"  {profile}: {status} ({duration:.1f}s)")
                    
                    if not result.get('overall_pass', False) and 'issues' in result:
                        for issue in result['issues'][:3]:  # Show first 3 issues
                            print(f"    ! {issue}")
        
        # Production readiness assessment
        print(f"\nPRODUCTION READINESS ASSESSMENT:")
        
        if passed_tests / total_tests >= 0.9:
            print("  ✓ FULLY PRODUCTION READY")
            print("    - High success rate across all profiles")
            print("    - Consistent vulnerability detection")
            print("    - Reliable performance")
        elif passed_tests / total_tests >= 0.75:
            print("  ⚠ MOSTLY PRODUCTION READY")
            print("    - Good success rate with minor issues")
            print("    - Review failed tests before deployment")
        else:
            print("  ✗ NOT PRODUCTION READY")
            print("    - Too many validation failures")
            print("    - Requires debugging and fixes")
        
        # Save detailed report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"huginn_production_validation_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                'validation_timestamp': timestamp,
                'targets_tested': list(self.targets.keys()),
                'expected_results': self.expected_results,
                'validation_results': validation_results,
                'summary': {
                    'total_tests': total_tests,
                    'passed_tests': passed_tests,
                    'success_rate': (passed_tests/total_tests)*100
                }
            }, f, indent=2, default=str)
        
        print(f"\nDetailed validation report saved to: {filename}")

async def main():
    """Run production validation tests"""
    validator = ProductionValidationTest()
    
    # Run main validation
    await validator.validate_production_readiness()
    
    # Test specific vulnerabilities
    await validator.test_specific_vulnerabilities()
    
    # Test AI components
    await validator.test_ai_components_production()

if __name__ == "__main__":
    asyncio.run(main())