#!/usr/bin/env python3
"""
Integration tests for detector classes - validates core logic without complex async mocking
"""
import sys
import os

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.cors_detector import CORSDetector
from app.core.idor_detector import IDORDetector
from app.core.js_secrets_analyzer import JSSecretsAnalyzer
from app.core.error_debug_detector import ErrorDebugDetector
from app.core.mixed_content_detector import MixedContentDetector
from app.core.redirect_ssrf_detector import RedirectSSRFDetector
from app.core.advanced_ssl_analyzer import AdvancedSSLAnalyzer
from app.core.http_methods_enumerator import HTTPMethodsEnumerator
from app.core.ssrf_tester import SSRFTester
from app.core.virtual_host_scanner import VirtualHostScanner
from app.core.directory_fuzzer import DirectoryFuzzer
from app.core.parameter_bruteforcer import ParameterBruteforcer
from app.core.advanced_ssti_tester import AdvancedSSTITester
from app.core.deserialization_tester import DeserializationTester
from app.core.business_logic_tester import BusinessLogicTester

def test_cors_detector():
    """Test CORS detector initialization and basic functionality"""
    detector = CORSDetector()
    assert detector.dangerous_origins == ['*', 'null']
    print("[PASS] CORSDetector: Initialization and configuration correct")

def test_idor_detector():
    """Test IDOR detector pattern matching"""
    detector = IDORDetector()
    
    # Test numeric ID detection
    parameters = {
        'https://example.com/user/123': [
            {'action': 'https://example.com/user/123', 'method': 'get', 'inputs': []}
        ]
    }
    findings = detector.analyze_endpoints(parameters)
    assert len(findings) == 1
    assert 'Numeric: 1' in findings[0]['description']
    
    # Test UUID detection
    parameters = {
        'https://example.com/api/550e8400-e29b-41d4-a716-446655440000': [
            {'action': 'https://example.com/api/550e8400-e29b-41d4-a716-446655440000', 'method': 'get', 'inputs': []}
        ]
    }
    findings = detector.analyze_endpoints(parameters)
    assert len(findings) == 1
    assert 'UUID: 1' in findings[0]['description']
    
    print("[PASS] IDORDetector: Pattern matching works correctly")

def test_js_secrets_analyzer():
    """Test JavaScript secrets analyzer pattern matching"""
    analyzer = JSSecretsAnalyzer()
    
    # Test API pattern matching
    content = 'fetch("/api/users"); axios.get("/api/orders");'
    api_endpoints = set()
    for pattern in analyzer.api_patterns:
        matches = pattern.findall(content)
        api_endpoints.update(matches)
    
    assert '/api/users' in api_endpoints or '/api/orders' in api_endpoints
    
    # Test secret pattern matching
    content = 'var api_key = "sk_live_abcdef123456789";'
    secrets_found = []
    for pattern in analyzer.secret_patterns:
        matches = pattern.findall(content)
        secrets_found.extend(matches)
    
    assert len(secrets_found) > 0
    print("[PASS] JSSecretsAnalyzer: Pattern matching works correctly")

def test_error_debug_detector():
    """Test error debug detector pattern matching"""
    detector = ErrorDebugDetector()
    
    # Test Python traceback detection
    content = """
    Traceback (most recent call last):
      File "/app/views.py", line 42, in view_function
        result = process_data(user_input)
    ValueError: Invalid input provided
    """
    findings = detector.analyze_response('https://example.com', content, 500)
    assert len(findings) >= 1
    # Check if any finding is a Python Stack Trace
    python_trace_found = any(f.get('error_type') == 'Python Stack Trace' for f in findings)
    assert python_trace_found, f"Expected Python Stack Trace, got: {[f.get('error_type') for f in findings]}"
    
    # Test SQL error detection
    content = "SQL syntax error near 'SELECT' - check your query"
    findings = detector.analyze_response('https://example.com', content, 500)
    assert len(findings) >= 1
    # Check if any finding is a SQL Syntax Error
    sql_error_found = any(f.get('error_type') == 'SQL Syntax Error' for f in findings)
    assert sql_error_found, f"Expected SQL Syntax Error, got: {[f.get('error_type') for f in findings]}"
    
    print("[PASS] ErrorDebugDetector: Error pattern matching works correctly")

def test_mixed_content_detector():
    """Test mixed content detector"""
    detector = MixedContentDetector()
    
    # Test mixed content detection on HTTPS page
    content = '''
    <script src="http://example.com/script.js"></script>
    <img src="http://example.com/image.jpg">
    <form action="http://example.com/submit">
    '''
    findings = detector.analyze_mixed_content('https://secure.com', content)
    assert len(findings) == 1
    assert findings[0]['type'] == 'Mixed Content Vulnerability'
    assert findings[0]['severity'] == 'HIGH'  # Scripts and forms = HIGH
    
    # Test no mixed content on HTTP page
    findings = detector.analyze_mixed_content('http://example.com', content)
    assert len(findings) == 0
    
    print("[PASS] MixedContentDetector: Mixed content detection works correctly")

def test_redirect_ssrf_detector():
    """Test redirect/SSRF detector parameter identification"""
    detector = RedirectSSRFDetector()
    
    parameters = {
        'https://example.com/login': [
            {
                'action': 'https://example.com/login',
                'method': 'post',
                'inputs': [
                    {'name': 'username', 'type': 'text'},
                    {'name': 'redirect', 'type': 'hidden'},
                    {'name': 'next', 'type': 'text'}
                ]
            }
        ]
    }
    
    findings = detector.analyze_parameters(parameters)
    assert len(findings) == 1
    assert findings[0]['type'] == 'Open Redirect/SSRF Surface'
    assert len(findings[0]['candidates']) == 2  # redirect and next
    
    print("[PASS] RedirectSSRFDetector: Parameter identification works correctly")

def test_advanced_ssl_analyzer():
    """Test SSL analyzer initialization"""
    analyzer = AdvancedSSLAnalyzer()
    assert 'RC4' in analyzer.weak_ciphers
    assert 'SSLv3' in analyzer.weak_protocols
    print("[PASS] AdvancedSSLAnalyzer: Initialization and configuration correct")

def test_http_methods_enumerator():
    """Test HTTP methods enumerator configuration"""
    enumerator = HTTPMethodsEnumerator()
    assert 'PUT' in enumerator.dangerous_methods
    assert 'DELETE' in enumerator.dangerous_methods
    assert 'PROPFIND' in enumerator.webdav_methods
    print("[PASS] HTTPMethodsEnumerator: Configuration correct")

def test_ssrf_tester():
    """Test SSRF tester configuration"""
    tester = SSRFTester()
    assert 'http://169.254.169.254/' in tester.ssrf_payloads  # AWS metadata
    assert 'url' in tester.url_params
    assert 'redirect' in tester.url_params
    print("[PASS] SSRFTester: Configuration and payloads correct")

def test_virtual_host_scanner():
    """Test virtual host scanner configuration"""
    scanner = VirtualHostScanner()
    assert 'admin' in scanner.common_vhosts
    assert 'api' in scanner.common_vhosts
    print("[PASS] VirtualHostScanner: Configuration correct")

def test_directory_fuzzer():
    """Test directory fuzzer configuration and logic"""
    fuzzer = DirectoryFuzzer()
    assert 'admin' in fuzzer.common_dirs
    assert 'robots.txt' in fuzzer.common_files
    
    # Test sensitive path detection
    assert fuzzer._is_sensitive_path('/admin/config.php')
    assert fuzzer._is_sensitive_path('/backup/database.sql')
    assert not fuzzer._is_sensitive_path('/images/logo.png')
    
    print("[PASS] DirectoryFuzzer: Configuration and logic correct")

def test_parameter_bruteforcer():
    """Test parameter bruteforcer configuration and logic"""
    bruteforcer = ParameterBruteforcer()
    assert 'admin' in bruteforcer.common_params
    assert 'debug' in bruteforcer.common_params
    
    # Test difference classification
    diff_type = bruteforcer._classify_difference(200, 500, 1000, 1000)
    assert 'status_change' in diff_type
    
    print("[PASS] ParameterBruteforcer: Configuration and logic correct")

def test_advanced_ssti_tester():
    """Test SSTI tester configuration and logic"""
    tester = AdvancedSSTITester()
    assert 'jinja2' in tester.ssti_payloads
    assert 'twig' in tester.ssti_payloads
    assert '{{7*7}}' in tester.ssti_payloads['jinja2']
    
    # Test response analysis
    result = tester._analyze_ssti_response(
        'Result: 49', '{{7*7}}', 
        {'action': 'test', 'method': 'post'}, 
        {'name': 'query', 'type': 'text'}, 
        'jinja2'
    )
    assert result is not None
    assert result['type'] == 'Server-Side Template Injection (SSTI)'
    
    print("[PASS] AdvancedSSTITester: Configuration and logic correct")

def test_deserialization_tester():
    """Test deserialization tester configuration and logic"""
    tester = DeserializationTester()
    assert 'java' in tester.deserialization_payloads
    assert 'php' in tester.deserialization_payloads
    
    # Test serialization candidate detection
    assert tester._is_serialization_candidate({'name': 'data', 'type': 'text'})
    assert tester._is_serialization_candidate({'name': 'serialized_object', 'type': 'hidden'})
    assert not tester._is_serialization_candidate({'name': 'username', 'type': 'text'})
    
    print("[PASS] DeserializationTester: Configuration and logic correct")

def test_business_logic_tester():
    """Test business logic tester configuration and logic"""
    tester = BusinessLogicTester()
    assert 'price_manipulation' in tester.logic_tests
    assert 'quantity_bypass' in tester.logic_tests
    
    # Test field type detection
    assert tester._is_price_field('price')
    assert tester._is_price_field('total_amount')
    assert not tester._is_price_field('username')
    
    assert tester._is_quantity_field('quantity')
    assert tester._is_quantity_field('qty')
    assert not tester._is_quantity_field('username')
    
    # Test success indication
    assert tester._indicates_success('Order confirmed! Thank you for your purchase.', 200)
    assert not tester._indicates_success('Error occurred', 400)
    
    print("[PASS] BusinessLogicTester: Configuration and logic correct")

def main():
    """Run all integration tests"""
    print("Running Detector Integration Tests...")
    print("=" * 50)
    
    tests = [
        test_cors_detector,
        test_idor_detector,
        test_js_secrets_analyzer,
        test_error_debug_detector,
        test_mixed_content_detector,
        test_redirect_ssrf_detector,
        test_advanced_ssl_analyzer,
        test_http_methods_enumerator,
        test_ssrf_tester,
        test_virtual_host_scanner,
        test_directory_fuzzer,
        test_parameter_bruteforcer,
        test_advanced_ssti_tester,
        test_deserialization_tester,
        test_business_logic_tester
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: {str(e)}")
            import traceback
            print(f"  Details: {traceback.format_exc().split('AssertionError: ')[-1].split('\n')[0] if 'AssertionError' in str(e) else str(e)}")
            failed += 1
    
    print("=" * 50)
    print(f"INTEGRATION TEST RESULTS")
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed / len(tests) * 100):.1f}%")
    
    if failed == 0:
        print("SUCCESS: ALL DETECTOR CLASSES WORKING CORRECTLY!")
        return True
    else:
        print("WARNING: Some detector classes need attention")
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)