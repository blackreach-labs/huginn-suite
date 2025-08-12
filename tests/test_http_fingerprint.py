# tests/test_http_fingerprint.py
import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from tools.http_fingerprint import HTTPFingerprinter

class TestHTTPFingerprinter(unittest.TestCase):
    
    def setUp(self):
        self.fingerprinter = HTTPFingerprinter()
    
    def test_normalize_url_with_scheme(self):
        """Test URL normalization with existing scheme"""
        url = "https://example.com"
        result = self.fingerprinter.normalize_url(url)
        self.assertEqual(result, "https://example.com")
    
    def test_normalize_url_without_scheme(self):
        """Test URL normalization without scheme"""
        with patch.object(self.fingerprinter.session, 'head') as mock_head:
            mock_head.return_value = Mock()
            url = "example.com"
            result = self.fingerprinter.normalize_url(url)
            self.assertEqual(result, "https://example.com")
    
    def test_normalize_url_https_fails(self):
        """Test URL normalization when HTTPS fails"""
        with patch.object(self.fingerprinter.session, 'head') as mock_head:
            mock_head.side_effect = Exception("Connection failed")
            url = "example.com"
            result = self.fingerprinter.normalize_url(url)
            self.assertEqual(result, "http://example.com")
    
    def test_parse_response(self):
        """Test response parsing"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Server': 'nginx', 'Content-Type': 'text/html'}
        mock_response.content = b'<html>test</html>'
        mock_response.text = '<html>test</html>'
        
        result = self.fingerprinter.parse_response(mock_response)
        
        self.assertEqual(result['status_code'], 200)
        self.assertEqual(result['server'], 'nginx')
        self.assertEqual(result['content_type'], 'text/html')
        self.assertEqual(result['content_length'], 18)
    
    def test_analyze_headers_framework_detection(self):
        """Test framework detection from headers"""
        mock_response = Mock()
        mock_response.headers = {
            'X-Powered-By': 'PHP/7.4',
            'Server': 'Apache/2.4'
        }
        
        result = self.fingerprinter.analyze_headers(mock_response)
        
        self.assertIn('PHP', result['frameworks'])
        self.assertEqual(result['server'], 'Apache/2.4')
    
    @patch('tools.http_fingerprint.requests.Session')
    def test_basic_fingerprint(self, mock_session_class):
        """Test basic fingerprinting"""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Server': 'nginx'}
        mock_response.content = b'test'
        mock_response.text = 'test'
        
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        fingerprinter = HTTPFingerprinter(mock_session)
        result = fingerprinter.basic_fingerprint("example.com")
        
        self.assertEqual(result['status_code'], 200)
        self.assertEqual(result['server'], 'nginx')
        self.assertIn('technology', result)

if __name__ == '__main__':
    unittest.main()