# tests/integration/test_scan_workflow.py
import unittest
import tempfile
import os
from unittest.mock import Mock, patch
from app.core.cache_manager import CacheManager
from app.core.validators import InputValidator
# from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository

class TestScanWorkflow(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache = CacheManager(cache_dir=self.temp_dir, ttl=3600)
        self.validator = InputValidator()
        self.scan_db = ScanDatabase(db_path=os.path.join(self.temp_dir, "test.db"))
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_complete_scan_workflow(self):
        """Test complete scan workflow: validate -> scan -> cache -> store"""
        target = "example.com"
        
        # Step 1: Validate input
        self.assertTrue(self.validator.validate_domain(target))
        
        # Step 2: Mock scan results
        scan_results = {"A": ["93.184.216.34"], "CNAME": ["example.com"]}
        
        # Step 3: Cache results
        self.cache.set("dns", target, scan_results)
        cached = self.cache.get("dns", target)
        self.assertEqual(cached, scan_results)
        
        # Step 4: Store in database
        scan_id = self.scan_db.save_scan(target, "dns_enum", scan_results)
        self.assertIsNotNone(scan_id)
        
        # Step 5: Retrieve from database
        stored_scan = self.scan_db.get_scan(scan_id)
        self.assertEqual(stored_scan["target"], target)
        self.assertEqual(stored_scan["scan_type"], "dns_enum")

if __name__ == '__main__':
    unittest.main()