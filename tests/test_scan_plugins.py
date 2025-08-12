# tests/test_scan_plugins.py
import unittest
from unittest.mock import Mock
import sys
import os

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from tools.scan_plugins.ssrf_plugin import SSRFPlugin
from tools.scan_plugins.xss_plugin import XSSPlugin
from tools.scan_plugins.idor_plugin import IDORPlugin

class TestScanPlugins(unittest.TestCase):
    
    def test_ssrf_plugin_initialization(self):
        """Test SSRF plugin initialization"""
        plugin = SSRFPlugin()
        self.assertEqual(plugin.name, "SSRF Scanner")
        self.assertEqual(plugin.description, "Server-Side Request Forgery detection")
    
    def test_ssrf_plugin_parameter_detection(self):
        """Test SSRF plugin parameter detection"""
        plugin = SSRFPlugin()
        mock_response = Mock()
        mock_response.text = '<form><input name="callback_url" type="text"></form>'
        
        result = plugin.scan("http://example.com", mock_response, Mock())
        
        self.assertIsNotNone(result)
        self.assertIn('callback_url', result['parameters'])
    
    def test_xss_plugin_initialization(self):
        """Test XSS plugin initialization"""
        plugin = XSSPlugin()
        self.assertEqual(plugin.name, "XSS Scanner")
        self.assertEqual(plugin.description, "Cross-Site Scripting detection")
    
    def test_xss_plugin_parameter_detection(self):
        """Test XSS plugin parameter detection"""
        plugin = XSSPlugin()
        mock_response = Mock()
        mock_response.text = '<input name="search" type="text">'
        
        result = plugin.scan("http://example.com", mock_response, Mock())
        
        self.assertIsNotNone(result)
        self.assertIn('search', result['parameters'])
    
    def test_idor_plugin_initialization(self):
        """Test IDOR plugin initialization"""
        plugin = IDORPlugin()
        self.assertEqual(plugin.name, "IDOR Scanner")
        self.assertEqual(plugin.description, "Insecure Direct Object Reference detection")
    
    def test_idor_plugin_id_detection(self):
        """Test IDOR plugin ID detection"""
        plugin = IDORPlugin()
        mock_response = Mock()
        
        result = plugin.scan("http://example.com?user_id=123", mock_response, Mock())
        
        self.assertIsNotNone(result)
        self.assertIn('user_id=123', result['parameters'])

if __name__ == '__main__':
    unittest.main()