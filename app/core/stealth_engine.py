# app/core/stealth_engine.py
import random
import time
import threading
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.vpn_manager import vpn_manager

class StealthEngine(QObject):
    """Advanced stealth and evasion engine for professional pentesting"""
    
    stealth_event = pyqtSignal(str, str)  # event_type, message
    
    def __init__(self):
        super().__init__()
        self.stealth_enabled = False
        self.evasion_level = "medium"  # low, medium, high, extreme
        self.decoy_ips = []
        self.timing_profiles = {
            "paranoid": {"delay": (5, 15), "jitter": 0.8, "rate": 1},
            "sneaky": {"delay": (2, 8), "jitter": 0.6, "rate": 5},
            "polite": {"delay": (1, 3), "jitter": 0.4, "rate": 10},
            "normal": {"delay": (0.1, 1), "jitter": 0.2, "rate": 50}
        }
        
        # Dynamic rate limiting
        self.dynamic_rate_enabled = False
        self.base_rate = 10
        self.current_rate = 10
        self.error_threshold = 0.1
        self.response_time_threshold = 2.0
        self.recent_responses = []
        self.recent_errors = []
        
        # User-Agent and header randomization
        self.randomize_headers = False
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101"
        ]
        
        # Jitter and sleep intervals
        self.jitter_enabled = False
        self.jitter_range = (0.5, 2.0)
        
        # Proxy rotation
        self.proxy_rotation = False
        self.proxy_pool = []
        self.current_proxy_index = 0
        
        # VPN rotation (missing attribute)
        self.vpn_rotation = False
        
        # Advanced evasion features
        self.target_type = "generic"
        self.tls_fingerprint = "chrome_latest"
        self.dns_resolver = "system"
        self.detection_risk_score = 50
        self.evasion_plugins = {}
        
        # Threat profile presets
        self.threat_profiles = {
            "generic": {"rate": 10, "jitter": True, "headers": True, "tls": "standard"},
            "cloudflare_waf": {"rate": 3, "jitter": True, "headers": True, "tls": "ja3_evasion", "dns": "doh"},
            "aws_cloudfront": {"rate": 5, "jitter": True, "headers": True, "tls": "aws_optimized"},
            "akamai_cdn": {"rate": 2, "jitter": True, "headers": True, "tls": "akamai_evasion"},
            "ids_ips": {"rate": 1, "jitter": True, "headers": True, "fragmentation": True}
        }
        
    def enable_stealth_mode(self, level: str = "medium"):
        """Enable stealth mode with specified evasion level"""
        self.stealth_enabled = True
        self.evasion_level = level
        self.stealth_event.emit('stealth_enabled', f'Stealth mode activated: {level}')
        
    def get_nmap_stealth_flags(self) -> List[str]:
        """Generate nmap stealth flags based on evasion level"""
        flags = []
        
        if self.evasion_level == "extreme":
            flags.extend(["-f", "-f", "--mtu", "8", "-T0", "--scan-delay", "10s"])
            flags.extend(["--max-retries", "1", "--host-timeout", "300s"])
        elif self.evasion_level == "high":
            flags.extend(["-f", "-T1", "--scan-delay", "5s"])
            flags.extend(["--max-retries", "2", "--randomize-hosts"])
        elif self.evasion_level == "medium":
            flags.extend(["-T2", "--randomize-hosts"])
            
        if self.decoy_ips:
            flags.extend(["-D", ",".join(self.decoy_ips)])
            
        return flags
        
    def get_timing_delay(self, profile: str = "polite") -> float:
        """Get randomized timing delay for requests with jitter"""
        if not self.stealth_enabled:
            return 0.1
            
        timing = self.timing_profiles.get(profile, self.timing_profiles["polite"])
        base_delay = random.uniform(*timing["delay"])
        
        # Apply profile jitter
        profile_jitter = random.uniform(-timing["jitter"], timing["jitter"])
        delay = base_delay + profile_jitter
        
        # Apply additional jitter if enabled
        if self.jitter_enabled:
            extra_jitter = random.uniform(*self.jitter_range)
            delay += extra_jitter
            
        return max(0.1, delay)
        
    def generate_decoy_ips(self, target_ip: str, count: int = 5) -> List[str]:
        """Generate decoy IPs for scan obfuscation"""
        import ipaddress
        
        try:
            target = ipaddress.ip_address(target_ip)
            network = ipaddress.ip_network(f"{target}/24", strict=False)
            
            decoys = []
            for _ in range(count):
                decoy = random.choice(list(network.hosts()))
                if str(decoy) != target_ip:
                    decoys.append(str(decoy))
                    
            self.decoy_ips = decoys[:count]
            return self.decoy_ips
            
        except Exception:
            # Fallback to random private IPs
            self.decoy_ips = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" 
                             for _ in range(count)]
            return self.decoy_ips
    
    def update_dynamic_rate(self, response_time: float, is_error: bool):
        """Update rate limiting based on target response"""
        if not self.dynamic_rate_enabled:
            return
            
        current_time = time.time()
        
        # Track recent responses (last 60 seconds)
        self.recent_responses = [(t, rt) for t, rt in self.recent_responses 
                               if current_time - t < 60]
        self.recent_responses.append((current_time, response_time))
        
        # Track recent errors
        if is_error:
            self.recent_errors = [t for t in self.recent_errors 
                                if current_time - t < 60]
            self.recent_errors.append(current_time)
        
        # Calculate error rate
        error_rate = len(self.recent_errors) / max(len(self.recent_responses), 1)
        
        # Calculate average response time
        if self.recent_responses:
            avg_response_time = sum(rt for _, rt in self.recent_responses) / len(self.recent_responses)
        else:
            avg_response_time = 0
        
        # Adjust rate based on conditions
        if error_rate > self.error_threshold or avg_response_time > self.response_time_threshold:
            # Slow down
            self.current_rate = max(1, int(self.current_rate * 0.7))
            self.stealth_event.emit('rate_adjusted', f'Rate reduced to {self.current_rate}/s')
        elif error_rate < self.error_threshold / 2 and avg_response_time < self.response_time_threshold / 2:
            # Speed up gradually
            self.current_rate = min(self.base_rate, int(self.current_rate * 1.1))
    
    def get_random_headers(self) -> Dict[str, str]:
        """Generate randomized HTTP headers based on target type"""
        if not self.randomize_headers:
            return {}
        
        # Base headers
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            ]),
            'Accept-Language': random.choice([
                'en-US,en;q=0.5',
                'en-GB,en;q=0.9',
                'en-US,en;q=0.9,es;q=0.8'
            ]),
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        # Target-specific header modifications
        if self.target_type == "cloudflare_waf":
            headers['CF-Connecting-IP'] = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
            headers['X-Forwarded-For'] = headers['CF-Connecting-IP']
        elif self.target_type == "aws_cloudfront":
            headers['CloudFront-Viewer-Country'] = random.choice(['US', 'GB', 'CA'])
        
        # Randomly add optional headers
        if random.random() < 0.3:
            headers['DNT'] = '1'
        if random.random() < 0.2:
            headers['Cache-Control'] = 'no-cache'
            
        return headers
    
    def get_next_proxy(self) -> Optional[str]:
        """Get next proxy from rotation pool"""
        if not self.proxy_rotation or not self.proxy_pool:
            return None
            
        proxy = self.proxy_pool[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_pool)
        return proxy
    
    def configure_dynamic_rate(self, enabled: bool, base_rate: int = 10, 
                             error_threshold: float = 0.1, response_threshold: float = 2.0):
        """Configure dynamic rate limiting"""
        self.dynamic_rate_enabled = enabled
        self.base_rate = base_rate
        self.current_rate = base_rate
        self.error_threshold = error_threshold
        self.response_time_threshold = response_threshold
    
    def configure_header_randomization(self, enabled: bool, custom_agents: List[str] = None):
        """Configure header randomization"""
        self.randomize_headers = enabled
        if custom_agents:
            self.user_agents.extend(custom_agents)
    
    def configure_jitter(self, enabled: bool, jitter_range: tuple = (0.5, 2.0)):
        """Configure jitter settings"""
        self.jitter_enabled = enabled
        self.jitter_range = jitter_range
    
    def configure_proxy_rotation(self, enabled: bool, proxy_list: List[str] = None):
        """Configure proxy rotation"""
        self.proxy_rotation = enabled
        if proxy_list:
            self.proxy_pool = proxy_list
            self.current_proxy_index = 0
    
    def integrate_vpn_rotation(self, vpn_configs: List[str]):
        """Integrate with VPN manager for IP rotation"""
        if not vpn_configs:
            return
            
        self.vpn_rotation = True
        
        def rotate_vpn():
            for config in vpn_configs:
                vpn_manager.disconnect()
                time.sleep(2)
                result = vpn_manager.connect_openvpn(config)
                if result['success']:
                    self.stealth_event.emit('vpn_rotated', f'Switched to VPN: {config}')
                    time.sleep(30)  # Use VPN for 30 seconds
                else:
                    self.stealth_event.emit('vpn_error', f'Failed to connect: {config}')
        
        threading.Thread(target=rotate_vpn, daemon=True).start()
    
    def apply_threat_profile(self, target_type: str):
        """Apply threat profile based on target type"""
        if target_type in self.threat_profiles:
            profile = self.threat_profiles[target_type]
            self.target_type = target_type
            self.base_rate = profile.get('rate', 10)
            self.current_rate = self.base_rate
            self.jitter_enabled = profile.get('jitter', True)
            self.randomize_headers = profile.get('headers', True)
            self.tls_fingerprint = profile.get('tls', 'standard')
            if 'dns' in profile:
                self.dns_resolver = profile['dns']
            self.calculate_risk_score()
    
    def calculate_risk_score(self) -> int:
        """Calculate detection risk score (0-100)"""
        score = 50  # Base score
        
        # Rate factor
        if self.current_rate > 20:
            score += 30
        elif self.current_rate > 10:
            score += 15
        elif self.current_rate < 3:
            score -= 10
        
        # Jitter factor
        if self.jitter_enabled:
            score -= 10
        
        # Header randomization
        if self.randomize_headers:
            score -= 15
        
        # Proxy rotation
        if self.proxy_rotation and len(self.proxy_pool) > 3:
            score -= 20
        
        # VPN rotation
        if self.vpn_rotation:
            score -= 25
        
        # Target-specific adjustments
        if self.target_type in ['cloudflare_waf', 'akamai_cdn']:
            score += 10  # These are harder to evade
        
        self.detection_risk_score = max(0, min(100, score))
        return self.detection_risk_score
    
    def get_traffic_preview(self) -> Dict[str, str]:
        """Get preview of current traffic signature"""
        headers = self.get_random_headers()
        return {
            'user_agent': headers.get('User-Agent', 'Not randomized'),
            'dns_resolver': self.dns_resolver,
            'tls_fingerprint': self.tls_fingerprint,
            'headers': headers,
            'rate_limit': f"{self.current_rate} req/s",
            'jitter_range': f"{self.jitter_range[0]}-{self.jitter_range[1]}s" if self.jitter_enabled else "Disabled",
            'proxy_count': len(self.proxy_pool),
            'risk_score': self.detection_risk_score
        }
    
    def load_evasion_plugins(self, plugins_dir: str):
        """Load evasion plugins from directory"""
        import os
        import importlib.util
        
        if not os.path.exists(plugins_dir):
            return
        
        for filename in os.listdir(plugins_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                plugin_path = os.path.join(plugins_dir, filename)
                plugin_name = filename[:-3]
                
                try:
                    spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    if hasattr(module, 'EvasionPlugin'):
                        self.evasion_plugins[plugin_name] = module.EvasionPlugin()
                        self.stealth_event.emit('plugin_loaded', f'Loaded evasion plugin: {plugin_name}')
                except Exception as e:
                    self.stealth_event.emit('plugin_error', f'Failed to load {plugin_name}: {str(e)}')

# Global stealth engine instance
stealth_engine = StealthEngine()