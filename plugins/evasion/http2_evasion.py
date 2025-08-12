# plugins/evasion/http2_evasion.py
import random
from typing import Dict, Any

class EvasionPlugin:
    """HTTP/2 fingerprint evasion plugin"""
    
    def __init__(self):
        self.name = "HTTP/2 Evasion"
        self.description = "Randomizes HTTP/2 settings and frame ordering to avoid detection"
        self.version = "1.0"
        
    def get_info(self) -> Dict[str, str]:
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version
        }
    
    def apply_evasion(self, request_config: Dict[str, Any]) -> Dict[str, Any]:
        """Apply HTTP/2 evasion to request configuration"""
        
        # Randomize HTTP/2 settings
        http2_settings = {
            'HEADER_TABLE_SIZE': random.choice([4096, 8192, 16384, 32768]),
            'ENABLE_PUSH': random.choice([0, 1]),
            'MAX_CONCURRENT_STREAMS': random.choice([100, 128, 256, 1000]),
            'INITIAL_WINDOW_SIZE': random.choice([65535, 131072, 262144]),
            'MAX_FRAME_SIZE': random.choice([16384, 32768, 65536]),
            'MAX_HEADER_LIST_SIZE': random.choice([8192, 16384, 32768])
        }
        
        # Randomize pseudo-header order
        pseudo_headers_order = [':method', ':path', ':scheme', ':authority']
        random.shuffle(pseudo_headers_order)
        
        request_config['http2_config'] = {
            'settings': http2_settings,
            'pseudo_header_order': pseudo_headers_order,
            'window_update_increment': random.randint(1024, 8192),
            'priority_weight': random.randint(1, 256)
        }
        
        return request_config