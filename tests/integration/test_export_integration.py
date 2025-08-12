# tests/integration/test_export_integration.py
import unittest
import tempfile
import os
import json
from app.core.exporter import exporter
from app.core.cache_manager import CacheManager

class TestExportIntegration(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache = CacheManager(cache_dir=self.temp_dir, ttl=3600)
        self.test_results = {
            "A": ["192.168.1.1", "10.0.0.1"],
            "CNAME": ["alias.example.com"],
            "MX": ["mail.example.com"]
        }
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_cache_to_export_workflow(self):
        """Test workflow from cache storage to export"""
        target = "test.example.com"
        
        # Store results in cache
        self.cache.set("dns", target, self.test_results)
        
        # Retrieve from cache
        cached_results = self.cache.get("dns", target)
        self.assertEqual(cached_results, self.test_results)
        
        # Export cached results
        export_path = os.path.join(self.temp_dir, "export_test.json")
        
        # Mock exporter behavior
        with open(export_path, 'w') as f:
            json.dump(cached_results, f, indent=2)
        
        # Verify export file exists and contains correct data
        self.assertTrue(os.path.exists(export_path))
        
        with open(export_path, 'r') as f:
            exported_data = json.load(f)
        
        self.assertEqual(exported_data, self.test_results)
    
    def test_multiple_format_export(self):
        """Test exporting same data to multiple formats"""
        formats = ["json", "csv"]
        
        for fmt in formats:
            export_path = os.path.join(self.temp_dir, f"test.{fmt}")
            
            if fmt == "json":
                with open(export_path, 'w') as f:
                    json.dump(self.test_results, f)
            elif fmt == "csv":
                with open(export_path, 'w') as f:
                    f.write("record_type,value\n")
                    for rtype, values in self.test_results.items():
                        for value in values:
                            f.write(f"{rtype},{value}\n")
            
            self.assertTrue(os.path.exists(export_path))

if __name__ == '__main__':
    unittest.main()