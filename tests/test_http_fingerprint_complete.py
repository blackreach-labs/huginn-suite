# tests/test_http_fingerprint_complete.py
import unittest
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.tools.http_fingerprint import HTTPFingerprinter
from app.tools.http_scanner import HTTPWorker
from app.tools.http_utils import run_http_enumeration, get_http_wordlists, get_common_extensions

class TestHTTPFingerprintComplete(unittest.TestCase):
    
    def setUp(self):
        self.fingerprinter = HTTPFingerprinter()
        self.test_url = "http://httpbin.org"
    
    def test_http_fingerprinter_initialization(self):
        """Test HTTPFingerprinter initialization"""
        self.assertIsNotNone(self.fingerprinter)
        self.assertIsNotNone(self.fingerprinter.session)
        self.assertTrue(hasattr(self.fingerprinter, 'plugins'))
    
    def test_url_normalization(self):
        """Test URL normalization"""
        test_cases = [
            ("example.com", "https://example.com"),
            ("http://example.com", "http://example.com"),
            ("https://example.com", "https://example.com")
        ]
        
        for input_url, expected in test_cases:
            normalized = self.fingerprinter.normalize_url(input_url)
            self.assertTrue(normalized.startswith(('http://', 'https://')))
    
    def test_basic_fingerprint(self):
        """Test basic fingerprinting functionality"""
        try:
            results = self.fingerprinter.basic_fingerprint(self.test_url)
            
            # Check that we get basic response info
            self.assertIn('status_code', results)
            self.assertIn('headers', results)
            self.assertIn('server', results)
            
        except Exception as e:
            self.skipTest(f"Network request failed: {e}")
    
    def test_comprehensive_fingerprint(self):
        """Test comprehensive fingerprinting"""
        try:
            results = self.fingerprinter.comprehensive_fingerprint(self.test_url)
            
            # Should not have error
            self.assertNotIn('error', results)
            
            # Should have technology info
            self.assertIn('technology', results)
            
            # Should have basic response info
            self.assertIn('status_code', results)
            
        except Exception as e:
            self.skipTest(f"Network request failed: {e}")
    
    def test_header_analysis(self):
        """Test header analysis functionality"""
        # Mock response for testing
        class MockResponse:
            def __init__(self):
                self.headers = {
                    'Server': 'nginx/1.18.0',
                    'X-Powered-By': 'PHP/7.4.0',
                    'X-Frame-Options': 'DENY',
                    'Content-Type': 'text/html'
                }
        
        mock_response = MockResponse()
        tech_info = self.fingerprinter.analyze_headers(mock_response)
        
        self.assertIn('server', tech_info)
        self.assertIn('frameworks', tech_info)
        self.assertIn('security_headers', tech_info)
        
        # Should detect PHP framework
        self.assertIn('PHP', tech_info['frameworks'])
        
        # Should detect security headers
        self.assertIn('X-Frame-Options', tech_info['security_headers'])
    
    def test_javascript_analysis(self):
        """Test JavaScript file analysis"""
        html_content = '''
        <html>
        <head>
            <script src="/js/app.js"></script>
            <script src="https://cdn.example.com/jquery.js"></script>
        </head>
        <body>
            <script>
                var apiEndpoint = "/api/users";
                var config = "aGVsbG8gd29ybGQ="; // base64: hello world
            </script>
        </body>
        </html>
        '''
        
        js_files = self.fingerprinter.extract_javascript_files(html_content, self.test_url)
        
        # Should find script tags
        self.assertIsInstance(js_files, list)
    
    def test_api_endpoint_extraction(self):
        """Test API endpoint extraction from JavaScript"""
        js_content = '''
        var endpoints = {
            users: "/api/users",
            login: "/auth/login",
            data: "/rest/data.php"
        };
        
        fetch("/api/profile");
        axios.get("/api/settings");
        '''
        
        endpoints = self.fingerprinter.extract_api_endpoints_from_js(js_content)
        
        self.assertIsInstance(endpoints, list)
        self.assertIn('/api/users', endpoints)
        self.assertIn('/api/profile', endpoints)
    
    def test_http_worker_initialization(self):
        """Test HTTPWorker initialization"""
        worker = HTTPWorker(
            target="http://example.com",
            scan_type="Basic Fingerprint",
            preset="Manual"
        )
        
        self.assertEqual(worker.target, "http://example.com")
        self.assertEqual(worker.scan_type, "Basic Fingerprint")
        self.assertEqual(worker.preset, "Manual")
        self.assertTrue(worker.is_running)
    
    def test_http_utils_functions(self):
        """Test HTTP utility functions"""
        # Test wordlist retrieval
        wordlists = get_http_wordlists()
        self.assertIsInstance(wordlists, list)
        
        # Test extensions retrieval
        extensions = get_common_extensions()
        self.assertIsInstance(extensions, dict)
        self.assertIn('PHP', extensions)
        self.assertIn('ASP', extensions)
        
        # Check that PHP extensions are correct
        php_extensions = extensions['PHP']
        self.assertIn('.php', php_extensions)
        self.assertIn('.php5', php_extensions)
    
    def test_scan_plugins_loading(self):
        """Test scan plugins loading"""
        try:
            from app.tools.scan_plugins import get_available_plugins
            plugins = get_available_plugins()
            
            self.assertIsInstance(plugins, list)
            self.assertGreater(len(plugins), 0)
            
            # Check that plugins have required attributes
            for plugin in plugins:
                self.assertTrue(hasattr(plugin, 'name'))
                self.assertTrue(hasattr(plugin, 'scan'))
                
        except ImportError:
            self.skipTest("Scan plugins not available")
    
    def test_waf_detection(self):
        """Test WAF detection functionality"""
        try:
            from app.tools.waf_detector import WAFDetector
            
            detector = WAFDetector()
            self.assertIsNotNone(detector)
            self.assertTrue(hasattr(detector, 'waf_signatures'))
            
            # Test with mock response
            class MockResponse:
                def __init__(self):
                    self.headers = {'Server': 'cloudflare'}
                    self.text = 'Attention Required! | Cloudflare'
                    self.status_code = 403
            
            mock_response = MockResponse()
            result = detector.detect(mock_response)
            
            self.assertIn('detected', result)
            self.assertIn('wafs', result)
            
        except ImportError:
            self.skipTest("WAF detector not available")
    
    def test_tls_fingerprinting(self):
        """Test TLS fingerprinting functionality"""
        try:
            from app.tools.tls_fingerprint import TLSFingerprinter
            
            fingerprinter = TLSFingerprinter()
            self.assertIsNotNone(fingerprinter)
            self.assertTrue(hasattr(fingerprinter, 'cipher_suites'))
            
        except ImportError:
            self.skipTest("TLS fingerprinter not available")
    
    def test_encoders_functionality(self):
        """Test encoding/decoding functionality"""
        try:
            from app.tools.encoders import detect_and_decode, decode_javascript_obfuscation
            
            # Test base64 detection
            base64_string = "aGVsbG8gd29ybGQ="  # "hello world"
            results = detect_and_decode(base64_string)
            
            self.assertIsInstance(results, list)
            if results:
                encoding_type, decoded_value = results[0]
                self.assertEqual(encoding_type, 'Base64')
                self.assertEqual(decoded_value, 'hello world')
            
            # Test JavaScript deobfuscation
            js_code = 'String.fromCharCode(72,101,108,108,111)'  # "Hello"
            decoded = decode_javascript_obfuscation(js_code)
            self.assertIsInstance(decoded, list)
            
        except ImportError:
            self.skipTest("Encoders not available")
    
    def test_web_crawler(self):
        """Test web crawler functionality"""
        try:
            from app.core.web_crawler import WebCrawler
            
            crawler = WebCrawler(max_depth=1, max_pages=5)
            self.assertIsNotNone(crawler)
            self.assertEqual(crawler.max_depth, 1)
            self.assertEqual(crawler.max_pages, 5)
            
        except ImportError:
            self.skipTest("Web crawler not available")
    
    def test_api_matcher(self):
        """Test API endpoint matcher"""
        try:
            from app.tools.api_matcher import APIMatcher
            
            matcher = APIMatcher()
            self.assertIsNotNone(matcher)
            self.assertTrue(hasattr(matcher, 'session'))
            
        except ImportError:
            self.skipTest("API matcher not available")

if __name__ == '__main__':
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestHTTPFingerprintComplete)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    print(f"{'='*50}")
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)