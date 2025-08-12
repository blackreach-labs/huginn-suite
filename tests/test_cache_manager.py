# tests/test_cache_manager.py
import unittest
import tempfile
import os
from app.core.cache_manager import CacheManager

class TestCacheManager(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache = CacheManager(cache_dir=self.temp_dir, ttl=1)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_cache_set_get(self):
        data = {"test": "data"}
        self.cache.set("dns", "example.com", data)
        result = self.cache.get("dns", "example.com")
        self.assertEqual(result, data)
    
    def test_cache_miss(self):
        result = self.cache.get("dns", "nonexistent.com")
        self.assertIsNone(result)
    
    def test_cache_clear(self):
        self.cache.set("dns", "example.com", {"test": "data"})
        self.cache.clear()
        result = self.cache.get("dns", "example.com")
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()