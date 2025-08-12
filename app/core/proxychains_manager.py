# app/core/proxychains_manager.py
import os
import tempfile
import subprocess
from typing import List, Dict, Optional
from PyQt6.QtCore import QObject, pyqtSignal

class ProxyChainsManager(QObject):
    """Advanced proxy chaining for stealth operations"""
    
    proxy_event = pyqtSignal(str, str)  # event_type, message
    
    def __init__(self):
        super().__init__()
        self.proxy_chains = []
        self.config_file = None
        self.tor_enabled = False
        self.chain_type = "dynamic"  # strict, dynamic, random
        
    def add_proxy(self, proxy_type: str, host: str, port: int, 
                  username: str = "", password: str = ""):
        """Add proxy to chain"""
        proxy = {
            "type": proxy_type.lower(),  # http, socks4, socks5
            "host": host,
            "port": port,
            "username": username,
            "password": password
        }
        self.proxy_chains.append(proxy)
        self.proxy_event.emit('proxy_added', f'Added {proxy_type} proxy {host}:{port}')
        
    def enable_tor(self, tor_port: int = 9050):
        """Enable Tor integration"""
        self.tor_enabled = True
        self.add_proxy("socks5", "127.0.0.1", tor_port)
        self.proxy_event.emit('tor_enabled', f'Tor enabled on port {tor_port}')
        
    def generate_proxychains_config(self) -> str:
        """Generate proxychains configuration"""
        config_content = f"""
# Huggin ProxyChains Configuration
{self.chain_type}_chain

# Proxy DNS requests
proxy_dns

# Quiet mode
quiet_mode

# TCP read/write timeout
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
"""
        
        for proxy in self.proxy_chains:
            if proxy["username"] and proxy["password"]:
                config_content += f"{proxy['type']} {proxy['host']} {proxy['port']} {proxy['username']} {proxy['password']}\n"
            else:
                config_content += f"{proxy['type']} {proxy['host']} {proxy['port']}\n"
                
        return config_content
        
    def create_config_file(self) -> str:
        """Create temporary proxychains config file"""
        config_content = self.generate_proxychains_config()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write(config_content)
            self.config_file = f.name
            
        return self.config_file
        
    def execute_with_proxychains(self, command: List[str]) -> subprocess.Popen:
        """Execute command through proxy chain"""
        if not self.proxy_chains:
            raise ValueError("No proxy chains configured")
            
        config_file = self.create_config_file()
        
        # Build proxychains command
        proxychains_cmd = ["proxychains", "-f", config_file] + command
        
        self.proxy_event.emit('command_executed', f'Executing: {" ".join(command)}')
        
        return subprocess.Popen(
            proxychains_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
    def test_proxy_chain(self) -> Dict:
        """Test proxy chain connectivity"""
        if not self.proxy_chains:
            return {"success": False, "error": "No proxy chains configured"}
            
        try:
            # Test with curl to check external IP
            process = self.execute_with_proxychains(["curl", "-s", "http://httpbin.org/ip"])
            stdout, stderr = process.communicate(timeout=30)
            
            if process.returncode == 0:
                return {
                    "success": True,
                    "output": stdout,
                    "chain_length": len(self.proxy_chains)
                }
            else:
                return {
                    "success": False,
                    "error": stderr,
                    "chain_length": len(self.proxy_chains)
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
            
    def get_nmap_proxy_command(self, target: str, scan_options: List[str]) -> List[str]:
        """Generate nmap command with proxy chain"""
        if not self.proxy_chains:
            return ["nmap"] + scan_options + [target]
            
        config_file = self.create_config_file()
        return ["proxychains", "-f", config_file, "nmap"] + scan_options + [target]
        
    def clear_chains(self):
        """Clear all proxy chains"""
        self.proxy_chains.clear()
        if self.config_file and os.path.exists(self.config_file):
            os.unlink(self.config_file)
        self.proxy_event.emit('chains_cleared', 'All proxy chains cleared')
        
    def set_chain_type(self, chain_type: str):
        """Set proxy chain type"""
        valid_types = ["strict", "dynamic", "random"]
        if chain_type in valid_types:
            self.chain_type = chain_type
            self.proxy_event.emit('chain_type_set', f'Chain type set to {chain_type}')
        else:
            raise ValueError(f"Invalid chain type. Must be one of: {valid_types}")
            
    def get_chain_status(self) -> Dict:
        """Get current proxy chain status"""
        return {
            "chain_count": len(self.proxy_chains),
            "chain_type": self.chain_type,
            "tor_enabled": self.tor_enabled,
            "config_file": self.config_file,
            "proxies": [
                {
                    "type": p["type"],
                    "endpoint": f"{p['host']}:{p['port']}",
                    "authenticated": bool(p["username"])
                }
                for p in self.proxy_chains
            ]
        }

# Global proxychains manager instance
proxychains_manager = ProxyChainsManager()