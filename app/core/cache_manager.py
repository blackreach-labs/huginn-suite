class CacheManager:
    def __init__(self):
        self.cache = {}
    
    def get(self, scan_type, target, params=None):
        key = f"{scan_type}_{target}"
        return self.cache.get(key)
    
    def set(self, scan_type, target, results, params=None):
        key = f"{scan_type}_{target}"
        self.cache[key] = results

cache_manager = CacheManager()