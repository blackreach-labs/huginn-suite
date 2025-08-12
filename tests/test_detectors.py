import unittest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
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

class TestCORSDetector(unittest.TestCase):
    def setUp(self):
        self.detector = CORSDetector()
    
    def test_cors_wildcard_with_credentials(self):
        """Test detection of critical CORS misconfiguration"""
        async def run_test():
            mock_session = Mock()
            mock_response = Mock()
            mock_response.headers = {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': 'true'
            }
            mock_session.options = AsyncMock(return_value=mock_response)
            mock_session.options.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.options.return_value.__aexit__ = AsyncMock(return_value=None)
            
            findings = await self.detector.check_cors(mock_session, ['https://example.com'])
            
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]['type'], 'Critical CORS Misconfiguration')
            self.assertEqual(findings[0]['severity'], 'CRITICAL')
        
        asyncio.run(run_test())
    
    def test_cors_origin_reflection(self):
        """Test detection of CORS origin reflection"""
        async def run_test():
            mock_session = Mock()
            mock_response = Mock()
            mock_response.headers = {
                'Access-Control-Allow-Origin': 'https://evil.com',
                'Access-Control-Allow-Credentials': 'false'
            }
            mock_session.options = AsyncMock(return_value=mock_response)
            mock_session.options.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.options.return_value.__aexit__ = AsyncMock(return_value=None)
            
            findings = await self.detector.check_cors(mock_session, ['https://example.com'])
            
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]['type'], 'CORS Origin Reflection')
            self.assertEqual(findings[0]['severity'], 'HIGH')
        
        asyncio.run(run_test())

class TestIDORDetector(unittest.TestCase):
    def setUp(self):
        self.detector = IDORDetector()
    
    def test_numeric_id_detection(self):
        """Test detection of numeric ID patterns"""
        parameters = {
            'https://example.com/user/123': [
                {'action': 'https://example.com/user/123', 'method': 'get', 'inputs': []}
            ]
        }
        discovered_paths = ['https://example.com/profile/456', 'https://example.com/order/789']
        
        findings = self.detector.analyze_endpoints(parameters, discovered_paths)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'IDOR Attack Surface')
        self.assertIn('Numeric: 3', findings[0]['description'])
    
    def test_uuid_detection(self):
        """Test detection of UUID patterns"""
        parameters = {
            'https://example.com/api/user/550e8400-e29b-41d4-a716-446655440000': [
                {'action': 'https://example.com/api/user/550e8400-e29b-41d4-a716-446655440000', 'method': 'get', 'inputs': []}
            ]
        }
        
        findings = self.detector.analyze_endpoints(parameters)
        
        self.assertEqual(len(findings), 1)
        self.assertIn('UUID: 1', findings[0]['description'])

class TestJSSecretsAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = JSSecretsAnalyzer()
    
    def test_api_endpoint_extraction(self):
        """Test extraction of API endpoints from JavaScript"""
        async def run_test():
            mock_session = Mock()
            mock_response = Mock()
            mock_response.content_type = 'application/javascript'
            mock_response.text = AsyncMock(return_value='fetch("/api/users"); axios.get("/api/orders");')
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.get.return_value.__aexit__ = AsyncMock(return_value=None)
            
            content = '<script src="/js/app.js"></script>'
            findings = await self.analyzer.analyze_javascript(mock_session, 'https://example.com', content)
            
            self.assertTrue(any(f['type'] == 'Hidden API Endpoints' for f in findings))
        
        asyncio.run(run_test())
    
    def test_secrets_detection(self):
        """Test detection of hardcoded secrets"""
        async def run_test():
            mock_session = Mock()
            content = '<script>var api_key = "sk_live_abcdef123456789";</script>'
            
            findings = await self.analyzer.analyze_javascript(mock_session, 'https://example.com', content)
            
            self.assertTrue(any(f['type'] == 'Potential Secrets in JavaScript' for f in findings))
        
        asyncio.run(run_test())

class TestErrorDebugDetector(unittest.TestCase):
    def setUp(self):
        self.detector = ErrorDebugDetector()
    
    def test_python_traceback_detection(self):
        """Test detection of Python stack traces"""
        content = """
        Traceback (most recent call last):
          File "/app/views.py", line 42, in view_function
            result = process_data(user_input)
        ValueError: Invalid input provided
        """
        
        findings = self.detector.analyze_response('https://example.com', content, 500)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['error_type'], 'Python Stack Trace')
    
    def test_sql_error_detection(self):
        """Test detection of SQL errors"""
        content = "You have an error in your SQL syntax; check the manual"
        
        findings = self.detector.analyze_response('https://example.com', content, 500)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['error_type'], 'SQL Syntax Error')

class TestMixedContentDetector(unittest.TestCase):
    def setUp(self):
        self.detector = MixedContentDetector()
    
    def test_mixed_content_detection(self):
        """Test detection of HTTP resources on HTTPS pages"""
        content = '''
        <script src="http://example.com/script.js"></script>
        <img src="http://example.com/image.jpg">
        <form action="http://example.com/submit">
        '''
        
        findings = self.detector.analyze_mixed_content('https://secure.com', content)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'Mixed Content Vulnerability')
        self.assertEqual(findings[0]['severity'], 'HIGH')  # Scripts and forms = HIGH
    
    def test_no_mixed_content_on_http(self):
        """Test that HTTP pages don't trigger mixed content warnings"""
        content = '<script src="http://example.com/script.js"></script>'
        
        findings = self.detector.analyze_mixed_content('http://example.com', content)
        
        self.assertEqual(len(findings), 0)

class TestRedirectSSRFDetector(unittest.TestCase):
    def setUp(self):
        self.detector = RedirectSSRFDetector()
    
    def test_redirect_parameter_detection(self):
        """Test detection of redirect parameters"""
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
        
        findings = self.detector.analyze_parameters(parameters)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'Open Redirect/SSRF Surface')
        self.assertEqual(len(findings[0]['candidates']), 2)  # redirect and next

class TestAdvancedSSLAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = AdvancedSSLAnalyzer()
    
    def test_non_https_url(self):
        """Test that non-HTTPS URLs return no findings"""
        async def run_test():
            findings = await self.analyzer.analyze_ssl_advanced('http://example.com')
            self.assertEqual(len(findings), 0)
        
        asyncio.run(run_test())
    
    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_certificate_analysis(self, mock_ssl_context, mock_socket):
        """Test certificate analysis"""
        async def run_test():
            # Mock certificate that expires soon
            import datetime
            future_date = datetime.datetime.now() + datetime.timedelta(days=5)
            mock_cert = {
                'notAfter': future_date.strftime('%b %d %H:%M:%S %Y %Z')
            }
            
            mock_ssl_sock = Mock()
            mock_ssl_sock.getpeercert.return_value = mock_cert
            mock_ssl_sock.cipher.return_value = ('AES256-SHA', 'TLSv1.2', 256)
            
            mock_context = Mock()
            mock_context.wrap_socket.return_value.__enter__ = Mock(return_value=mock_ssl_sock)
            mock_context.wrap_socket.return_value.__exit__ = Mock(return_value=None)
            mock_ssl_context.return_value = mock_context
            
            mock_sock = Mock()
            mock_socket.return_value.__enter__ = Mock(return_value=mock_sock)
            mock_socket.return_value.__exit__ = Mock(return_value=None)
            
            findings = await self.analyzer.analyze_ssl_advanced('https://example.com')
            
            # Should detect certificate expiring soon
            self.assertTrue(any(f['type'] == 'Certificate Expiry Warning' for f in findings))
        
        asyncio.run(run_test())

class TestHTTPMethodsEnumerator(unittest.TestCase):
    def setUp(self):
        self.enumerator = HTTPMethodsEnumerator()
    
    def test_dangerous_method_detection(self):
        """Test detection of dangerous HTTP methods"""
        async def run_test():
            mock_session = Mock()
            
            # Mock responses for different methods
            responses = {
                'GET': Mock(status=200),
                'PUT': Mock(status=200),  # Dangerous method allowed
                'DELETE': Mock(status=405),  # Not allowed
                'TRACE': Mock(status=200)  # Dangerous method allowed
            }
            
            async def mock_request(method, url):
                mock_resp = responses.get(method, Mock(status=405))
                mock_resp.text = AsyncMock(return_value='')
                return mock_resp
            
            mock_session.request = mock_request
            mock_session.post = AsyncMock(return_value=Mock(status=405))
            mock_session.post.return_value.__aenter__ = AsyncMock(return_value=Mock(status=405))
            mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)
            
            findings = await self.enumerator.enumerate_methods(mock_session, 'https://example.com')
            
            # Should detect PUT and TRACE as dangerous
            dangerous_findings = [f for f in findings if f['type'] == 'Dangerous HTTP Method']
            self.assertEqual(len(dangerous_findings), 2)
        
        asyncio.run(run_test())

class TestSSRFTester(unittest.TestCase):
    def setUp(self):
        self.tester = SSRFTester()
    
    def test_ssrf_parameter_identification(self):
        """Test identification of SSRF-vulnerable parameters"""
        async def run_test():
            mock_session = Mock()
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"ami-id": "ami-12345"}')  # AWS metadata response
            mock_session.post = AsyncMock(return_value=mock_response)
            mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)
            
            parameters = {
                'https://example.com/fetch': [
                    {
                        'action': 'https://example.com/fetch',
                        'method': 'post',
                        'inputs': [{'name': 'url', 'type': 'text'}]
                    }
                ]
            }
            
            findings = await self.tester.test_ssrf(mock_session, parameters)
            
            self.assertTrue(any(f['type'] == 'SSRF to AWS Metadata' for f in findings))
        
        asyncio.run(run_test())

class TestVirtualHostScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = VirtualHostScanner()
    
    def test_host_header_injection(self):
        """Test detection of Host header injection"""
        async def run_test():
            mock_session = Mock()
            
            # Mock baseline response
            baseline_response = Mock()
            baseline_response.status = 200
            baseline_response.text = AsyncMock(return_value='Welcome to example.com')
            
            # Mock malicious host response
            malicious_response = Mock()
            malicious_response.status = 200
            malicious_response.text = AsyncMock(return_value='Welcome to evil.com')  # Reflects malicious host
            
            call_count = 0
            async def mock_get(url, headers=None):
                nonlocal call_count
                call_count += 1
                if call_count == 1:  # Baseline request
                    return baseline_response
                else:  # Malicious host request
                    return malicious_response
            
            mock_session.get = mock_get
            mock_session.get.return_value = Mock()
            mock_session.get.return_value.__aenter__ = AsyncMock()
            mock_session.get.return_value.__aexit__ = AsyncMock()
            
            findings = await self.scanner.test_vhost_attacks(mock_session, 'https://example.com')
            
            self.assertTrue(any(f['type'] == 'Host Header Injection' for f in findings))
        
        asyncio.run(run_test())

class TestDirectoryFuzzer(unittest.TestCase):
    def setUp(self):
        self.fuzzer = DirectoryFuzzer()
    
    def test_sensitive_path_detection(self):
        """Test detection of sensitive paths"""
        self.assertTrue(self.fuzzer._is_sensitive_path('/admin/config.php'))
        self.assertTrue(self.fuzzer._is_sensitive_path('/backup/database.sql'))
        self.assertFalse(self.fuzzer._is_sensitive_path('/images/logo.png'))
    
    def test_directory_fuzzing(self):
        """Test directory fuzzing functionality"""
        async def run_test():
            mock_session = Mock()
            
            # Mock responses for different paths
            async def mock_get(url):
                mock_resp = Mock()
                if 'admin' in url:
                    mock_resp.status = 200
                    mock_resp.text = AsyncMock(return_value='Admin Panel')
                    mock_resp.headers = {'Content-Type': 'text/html'}
                else:
                    mock_resp.status = 404
                    mock_resp.text = AsyncMock(return_value='Not Found')
                return mock_resp
            
            mock_session.get = mock_get
            mock_session.get.return_value = Mock()
            mock_session.get.return_value.__aenter__ = AsyncMock()
            mock_session.get.return_value.__aexit__ = AsyncMock()
            
            findings = await self.fuzzer.fuzz_directories(mock_session, 'https://example.com')
            
            self.assertTrue(any(f['type'] == 'Sensitive Directory/File Discovery' for f in findings))
        
        asyncio.run(run_test())

class TestParameterBruteforcer(unittest.TestCase):
    def setUp(self):
        self.bruteforcer = ParameterBruteforcer()
    
    def test_parameter_discovery(self):
        """Test hidden parameter discovery"""
        async def run_test():
            mock_session = Mock()
            
            # Mock baseline response
            baseline_response = Mock()
            baseline_response.status = 200
            baseline_response.text = AsyncMock(return_value='Normal page content')
            
            # Mock response with debug parameter
            debug_response = Mock()
            debug_response.status = 200
            debug_response.text = AsyncMock(return_value='Normal page content with debug info: SQL queries shown')
            
            call_count = 0
            async def mock_get(url, params=None):
                nonlocal call_count
                call_count += 1
                if call_count == 1:  # Baseline
                    return baseline_response
                elif params and 'debug' in params:
                    return debug_response
                else:
                    return baseline_response
            
            mock_session.get = mock_get
            
            findings = await self.bruteforcer.bruteforce_parameters(mock_session, 'https://example.com')
            
            self.assertTrue(any(f['type'] == 'High-Impact Hidden Parameters' for f in findings))
        
        asyncio.run(run_test())

class TestAdvancedSSTITester(unittest.TestCase):
    def setUp(self):
        self.tester = AdvancedSSTITester()
    
    def test_ssti_detection(self):
        """Test SSTI vulnerability detection"""
        async def run_test():
            mock_session = Mock()
            mock_response = Mock()
            mock_response.text = AsyncMock(return_value='Result: 49')  # 7*7 = 49
            mock_session.post = AsyncMock(return_value=mock_response)
            mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)
            
            parameters = {
                'https://example.com/search': [
                    {
                        'action': 'https://example.com/search',
                        'method': 'post',
                        'inputs': [{'name': 'query', 'type': 'text'}]
                    }
                ]
            }
            
            findings = await self.tester.test_ssti_advanced(mock_session, parameters)
            
            self.assertTrue(any(f['type'] == 'Server-Side Template Injection (SSTI)' for f in findings))
        
        asyncio.run(run_test())

class TestDeserializationTester(unittest.TestCase):
    def setUp(self):
        self.tester = DeserializationTester()
    
    def test_serialization_candidate_detection(self):
        """Test identification of serialization candidates"""
        self.assertTrue(self.tester._is_serialization_candidate({'name': 'data', 'type': 'text'}))
        self.assertTrue(self.tester._is_serialization_candidate({'name': 'serialized_object', 'type': 'hidden'}))
        self.assertFalse(self.tester._is_serialization_candidate({'name': 'username', 'type': 'text'}))
    
    def test_deserialization_detection(self):
        """Test deserialization vulnerability detection"""
        async def run_test():
            mock_session = Mock()
            mock_response = Mock()
            mock_response.text = AsyncMock(return_value='java.io.InvalidClassException: Invalid class')
            mock_session.post = AsyncMock(return_value=mock_response)
            mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)
            
            parameters = {
                'https://example.com/process': [
                    {
                        'action': 'https://example.com/process',
                        'method': 'post',
                        'inputs': [{'name': 'data', 'type': 'text'}]
                    }
                ]
            }
            
            findings = await self.tester.test_deserialization(mock_session, parameters)
            
            self.assertTrue(any(f['type'] == 'Deserialization Vulnerability' for f in findings))
        
        asyncio.run(run_test())

class TestBusinessLogicTester(unittest.TestCase):
    def setUp(self):
        self.tester = BusinessLogicTester()
    
    def test_price_field_detection(self):
        """Test identification of price fields"""
        self.assertTrue(self.tester._is_price_field('price'))
        self.assertTrue(self.tester._is_price_field('total_amount'))
        self.assertFalse(self.tester._is_price_field('username'))
    
    def test_price_manipulation_detection(self):
        """Test price manipulation vulnerability detection"""
        async def run_test():
            mock_session = Mock()
            mock_response = Mock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='Order confirmed! Thank you for your purchase.')
            mock_session.post = AsyncMock(return_value=mock_response)
            mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)
            
            form = {
                'action': 'https://example.com/checkout',
                'method': 'post',
                'inputs': [
                    {'name': 'price', 'type': 'hidden'},
                    {'name': 'item', 'type': 'text'}
                ]
            }
            
            findings = await self.tester._test_price_manipulation(mock_session, form)
            
            self.assertTrue(any(f['type'] == 'Price Manipulation' for f in findings))
        
        asyncio.run(run_test())

if __name__ == '__main__':
    # Create test suite
    test_classes = [
        TestCORSDetector, TestIDORDetector, TestJSSecretsAnalyzer,
        TestErrorDebugDetector, TestMixedContentDetector, TestRedirectSSRFDetector,
        TestAdvancedSSLAnalyzer, TestHTTPMethodsEnumerator, TestSSRFTester,
        TestVirtualHostScanner, TestDirectoryFuzzer, TestParameterBruteforcer,
        TestAdvancedSSTITester, TestDeserializationTester, TestBusinessLogicTester
    ]
    
    suite = unittest.TestSuite()
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"DETECTOR TESTS SUMMARY")
    print(f"{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError: ')[-1].split('\\n')[0]}")
    
    if result.errors:
        print(f"\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('\\n')[-2]}")