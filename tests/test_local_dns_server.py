# tests/test_local_dns_server.py
import unittest
import socket
import time
import threading
from unittest.mock import patch, MagicMock
from app.core.local_dns_server import LocalDNSServer

class TestLocalDNSServer(unittest.TestCase):
    """Test cases for Local DNS Server functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.dns_server = LocalDNSServer(port=55354)  # Use different port for testing
        
    def tearDown(self):
        """Clean up after tests"""
        if self.dns_server.running:
            self.dns_server.stop_server()
    
    @patch('app.core.license_manager.license_manager')
    def test_license_check(self, mock_license_manager):
        """Test license validation"""
        # Test with valid license
        mock_license_manager.get_license_info.return_value = {
            "licensed": True,
            "license_type": "Professional"
        }
        self.assertTrue(self.dns_server.is_licensed())
        
        # Test with invalid license
        mock_license_manager.get_license_info.return_value = {
            "licensed": False,
            "license_type": "Free"
        }
        self.assertFalse(self.dns_server.is_licensed())
        
        # Test with Enterprise license
        mock_license_manager.get_license_info.return_value = {
            "licensed": True,
            "license_type": "Enterprise"
        }
        self.assertTrue(self.dns_server.is_licensed())
    
    @patch('app.core.license_manager.license_manager')
    def test_add_remove_records(self, mock_license_manager):
        """Test adding and removing DNS records"""
        # Mock valid license
        mock_license_manager.get_license_info.return_value = {
            "licensed": True,
            "license_type": "Professional"
        }
        
        # Test adding A record
        result = self.dns_server.add_record("test.local", "A", "192.168.1.100")
        self.assertTrue(result)
        
        # Test adding CNAME record
        result = self.dns_server.add_record("www.test.local", "CNAME", "test.local")
        self.assertTrue(result)
        
        # Test duplicate record (should return False)
        result = self.dns_server.add_record("test.local", "A", "192.168.1.100")
        self.assertFalse(result)
        
        # Verify records exist
        records = self.dns_server.get_records()
        self.assertIn("test.local", records)
        self.assertIn("A", records["test.local"])
        self.assertEqual(records["test.local"]["A"], ["192.168.1.100"])
        
        # Test removing record
        result = self.dns_server.remove_record("test.local", "A", "192.168.1.100")
        self.assertTrue(result)
        
        # Verify record removed
        records = self.dns_server.get_records()
        self.assertNotIn("test.local", records)
    
    @patch('app.core.license_manager.license_manager')
    def test_server_start_stop(self, mock_license_manager):
        """Test server start and stop functionality"""
        # Mock valid license
        mock_license_manager.get_license_info.return_value = {
            "licensed": True,
            "license_type": "Professional"
        }
        
        # Test server start
        result = self.dns_server.start_server()
        self.assertTrue(result)
        self.assertTrue(self.dns_server.running)
        
        # Test server stop
        self.dns_server.stop_server()
        self.assertFalse(self.dns_server.running)
    
    @patch('app.core.license_manager.license_manager')
    def test_server_start_without_license(self, mock_license_manager):
        """Test server start fails without proper license"""
        # Mock invalid license
        mock_license_manager.get_license_info.return_value = {
            "licensed": False,
            "license_type": "Free"
        }
        
        # Test server start fails
        result = self.dns_server.start_server()
        self.assertFalse(result)
        self.assertFalse(self.dns_server.running)
    
    def test_domain_encoding(self):
        """Test DNS domain name encoding"""
        # Test domain encoding
        encoded = self.dns_server._encode_domain("test.local")
        expected = b'\x04test\x05local\x00'
        self.assertEqual(encoded, expected)
        
        # Test single label domain
        encoded = self.dns_server._encode_domain("localhost")
        expected = b'\x09localhost\x00'
        self.assertEqual(encoded, expected)
    
    @patch('app.core.license_manager.license_manager')
    def test_clear_records(self, mock_license_manager):
        """Test clearing all DNS records"""
        # Mock valid license
        mock_license_manager.get_license_info.return_value = {
            "licensed": True,
            "license_type": "Professional"
        }
        
        # Add some records
        self.dns_server.add_record("test1.local", "A", "192.168.1.1")
        self.dns_server.add_record("test2.local", "A", "192.168.1.2")
        
        # Verify records exist
        records = self.dns_server.get_records()
        self.assertEqual(len(records), 2)
        
        # Clear all records
        self.dns_server.clear_records()
        
        # Verify records cleared
        records = self.dns_server.get_records()
        self.assertEqual(len(records), 0)
    
    def test_record_persistence(self):
        """Test record save and load functionality"""
        # Add a record
        self.dns_server.records = {
            "test.local": {
                "A": ["192.168.1.100"]
            }
        }
        
        # Save records
        self.dns_server.save_records()
        
        # Clear in-memory records
        self.dns_server.records = {}
        
        # Load records
        self.dns_server.load_records()
        
        # Verify records loaded
        self.assertIn("test.local", self.dns_server.records)
        self.assertEqual(self.dns_server.records["test.local"]["A"], ["192.168.1.100"])

if __name__ == '__main__':
    unittest.main()