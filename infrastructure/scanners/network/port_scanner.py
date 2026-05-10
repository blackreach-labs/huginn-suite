"""Port scanner implementation using the new architecture."""
import socket
import asyncio
import concurrent.futures
from typing import Dict, Any, List, Optional

from infrastructure.scanners.base.base_scanner import BaseScanner
from shared.configuration.config_manager import ConfigManager
from shared.exceptions.scanner_exceptions import NetworkException
import logging


class PortScanner(BaseScanner):
    """TCP port scanner implementation."""
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self.config_manager = ConfigManager()
        self.scanner_config = self.config_manager.get_scanner_config()
        
        # Scanner-specific configuration
        self.ports = config.get('ports', [80, 443, 22, 21, 25, 53, 135, 139, 445])
        self.timeout = config.get('timeout', self.scanner_config.timeout)
        self.max_concurrent = config.get('max_concurrent', self.scanner_config.max_concurrent)
    
    def get_scanner_type(self) -> str:
        """Get scanner type identifier."""
        return "port_scanner"
    
    async def scan(self) -> 'ScanResult':
        """Perform port scan."""
        try:
            resolved_target = await self._resolve_target()
            open_ports = await self._scan_ports(resolved_target)
            
            scan_data = {
                'target': self.target,
                'resolved_target': resolved_target,
                'open_ports': open_ports,
                'total_ports_scanned': len(self.ports),
                'open_port_count': len(open_ports)
            }
            
            return self._create_result(scan_data)
            
        except Exception as e:
            raise NetworkException(f"Port scan failed: {e}")
    
    async def _resolve_target(self) -> str:
        """Resolve target hostname to IP address."""
        try:
            import ipaddress
            # Check if already an IP
            ipaddress.ip_address(self.target)
            return self.target
        except ValueError as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
        
        try:
            loop = asyncio.get_event_loop()
            resolved = await loop.getaddrinfo(self.target, None)
            return resolved[0][4][0]
        except Exception:
            return self.target
    
    async def _scan_ports(self, target_ip: str) -> List[Dict[str, Any]]:
        """Scan ports concurrently."""
        loop = asyncio.get_event_loop()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            tasks = [
                loop.run_in_executor(executor, self._scan_single_port, target_ip, port)
                for port in self.ports
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful results
            open_ports = []
            for result in results:
                if isinstance(result, dict):
                    open_ports.append(result)
            
            return open_ports
    
    def _scan_single_port(self, target_ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            
            if result == 0:
                # Try to get service name
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                return {
                    'port': port,
                    'protocol': 'tcp',
                    'service': service,
                    'state': 'open',
                    'banner': ''
                }
        except Exception as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
        
        return None


class UDPPortScanner(BaseScanner):
    """UDP port scanner implementation."""
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self.config_manager = ConfigManager()
        self.scanner_config = self.config_manager.get_scanner_config()
        
        # Scanner-specific configuration
        self.ports = config.get('ports', [53, 67, 68, 123, 161, 500, 1900, 5353])
        self.timeout = config.get('timeout', 2)  # Shorter timeout for UDP
        self.max_concurrent = config.get('max_concurrent', 20)  # Lower concurrency for UDP
    
    def get_scanner_type(self) -> str:
        """Get scanner type identifier."""
        return "udp_port_scanner"
    
    async def scan(self) -> 'ScanResult':
        """Perform UDP port scan."""
        try:
            resolved_target = await self._resolve_target()
            open_ports = await self._scan_udp_ports(resolved_target)
            
            scan_data = {
                'target': self.target,
                'resolved_target': resolved_target,
                'open_ports': open_ports,
                'total_ports_scanned': len(self.ports),
                'open_port_count': len(open_ports)
            }
            
            return self._create_result(scan_data)
            
        except Exception as e:
            raise NetworkException(f"UDP port scan failed: {e}")
    
    async def _resolve_target(self) -> str:
        """Resolve target hostname to IP address."""
        try:
            import ipaddress
            ipaddress.ip_address(self.target)
            return self.target
        except ValueError as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
        
        try:
            loop = asyncio.get_event_loop()
            resolved = await loop.getaddrinfo(self.target, None)
            return resolved[0][4][0]
        except Exception:
            return self.target
    
    async def _scan_udp_ports(self, target_ip: str) -> List[Dict[str, Any]]:
        """Scan UDP ports concurrently."""
        loop = asyncio.get_event_loop()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            tasks = [
                loop.run_in_executor(executor, self._scan_single_udp_port, target_ip, port)
                for port in self.ports
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful results
            open_ports = []
            for result in results:
                if isinstance(result, dict):
                    open_ports.append(result)
            
            return open_ports
    
    def _scan_single_udp_port(self, target_ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single UDP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send probe based on port
            probe = self._get_udp_probe(port)
            sock.sendto(probe, (target_ip, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                banner = data.decode('utf-8', errors='ignore').strip()[:100]
                
                try:
                    service = socket.getservbyport(port, 'udp')
                except:
                    service = "unknown"
                
                return {
                    'port': port,
                    'protocol': 'udp',
                    'service': service,
                    'state': 'open',
                    'banner': banner
                }
            except socket.timeout:
                # For common UDP services, timeout might indicate open|filtered
                if port in [53, 123, 161, 500]:
                    try:
                        service = socket.getservbyport(port, 'udp')
                    except:
                        service = "unknown"
                    
                    return {
                        'port': port,
                        'protocol': 'udp',
                        'service': service,
                        'state': 'open|filtered',
                        'banner': ''
                    }
            finally:
                sock.close()
                
        except Exception as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
        
        return None
    
    def _get_udp_probe(self, port: int) -> bytes:
        """Get UDP probe for specific port."""
        probes = {
            53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",  # DNS
            123: b'\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x89\x9c\x0b\x00\x00\x00\x00',  # NTP
            161: b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
            500: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # IKE
            1900: b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n',  # SSDP
            5353: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01',  # mDNS
        }
        return probes.get(port, b"\x00")


class NetworkSweepScanner(BaseScanner):
    """Network sweep scanner for host discovery."""
    
    def __init__(self, target: str, config: Optional[Dict[str, Any]] = None):
        super().__init__(target, config)
        self.config_manager = ConfigManager()
        self.scanner_config = self.config_manager.get_scanner_config()
        self.timeout = config.get('timeout', 1)
        self.max_concurrent = config.get('max_concurrent', 100)
    
    def get_scanner_type(self) -> str:
        return "network_sweep"
    
    async def scan(self) -> 'ScanResult':
        """Perform network sweep."""
        try:
            from app.core.ip_range_parser import parse_ip_range
            ips = parse_ip_range(self.target)
            if not ips:
                raise NetworkException(f"Invalid network range: {self.target}")
            
            alive_hosts = await self._sweep_hosts(ips)
            
            scan_data = {
                'target': self.target,
                'alive_hosts': alive_hosts,
                'total_hosts_scanned': len(ips),
                'alive_host_count': len(alive_hosts)
            }
            
            return self._create_result(scan_data)
            
        except Exception as e:
            raise NetworkException(f"Network sweep failed: {e}")
    
    async def _sweep_hosts(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Sweep hosts concurrently."""
        loop = asyncio.get_event_loop()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            tasks = [
                loop.run_in_executor(executor, self._ping_host, ip)
                for ip in ips
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            alive_hosts = []
            for result in results:
                if isinstance(result, dict):
                    alive_hosts.append(result)
            
            return alive_hosts
    
    def _ping_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check if host is alive."""
        # Try ICMP ping first
        try:
            import subprocess
            import platform
            
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(cmd, capture_output=True, timeout=2)
            if result.returncode == 0:
                return {'ip': ip, 'status': 'alive', 'method': 'icmp'}
        except Exception as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
        
        # Fallback to TCP connect on common ports
        for port in [80, 443, 22, 135, 445]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    return {'ip': ip, 'status': 'alive', 'method': f'tcp:{port}'}
            except:
                continue
        
        return None


# Register scanners with factory
try:
    from infrastructure.scanners.base.scanner_factory import ScannerFactory
    ScannerFactory.register_scanner("port_scanner", PortScanner)
    ScannerFactory.register_scanner("udp_port_scanner", UDPPortScanner)
    ScannerFactory.register_scanner("network_sweep", NetworkSweepScanner)
except ImportError as _exc:
    pass  # Factory not available yet    logging.debug("Suppressed exception", exc_info=True)
    logging.debug("Suppressed exception", exc_info=True)
