"""Domain service for scanner operations."""
from typing import List, Dict, Any, Optional
from datetime import datetime

from application.services.scan_orchestrator import ScanOrchestrator
from domain.models.scan_result import ScanResultModel, Target, ScanStatus
from shared.events.event_bus import event_bus, Event


class ScannerService:
    """Domain service for coordinating scanner operations."""
    
    def __init__(self, scan_orchestrator: ScanOrchestrator):
        self.scan_orchestrator = scan_orchestrator
    
    async def perform_comprehensive_scan(self, target_address: str, 
                                       scan_types: List[str] = None) -> List[ScanResultModel]:
        """Perform a comprehensive scan using multiple scanner types."""
        if not scan_types:
            scan_types = ['port_scanner', 'dns_scanner']
        
        results = []
        
        for scanner_type in scan_types:
            try:
                config = self._get_scanner_config(scanner_type, target_address)
                result = await self.scan_orchestrator.execute_scan(
                    scanner_type=scanner_type,
                    target_address=target_address,
                    config=config
                )
                results.append(result)
                
            except Exception as e:
                # Log error but continue with other scanners
                print(f"Scanner {scanner_type} failed for {target_address}: {e}")
                continue
        
        return results
    
    async def perform_network_discovery(self, network_range: str) -> List[ScanResultModel]:
        """Perform network discovery and enumeration."""
        # First, discover live hosts
        ping_config = {
            'network_range': network_range,
            'timeout': 2
        }
        
        ping_result = await self.scan_orchestrator.execute_scan(
            scanner_type="ping_scanner",
            target_address=network_range,
            config=ping_config
        )
        
        results = [ping_result]
        
        # Then scan open ports on discovered hosts
        if ping_result.data.get('alive_hosts'):
            for host in ping_result.data['alive_hosts']:
                port_config = {
                    'ports': [22, 80, 443, 135, 139, 445],
                    'timeout': 3
                }
                
                try:
                    port_result = await self.scan_orchestrator.execute_scan(
                        scanner_type="port_scanner",
                        target_address=host,
                        config=port_config
                    )
                    results.append(port_result)
                except Exception as e:
                    print(f"Port scan failed for {host}: {e}")
                    continue
        
        return results
    
    async def perform_service_enumeration(self, target_address: str, 
                                        open_ports: List[int]) -> List[ScanResultModel]:
        """Perform service-specific enumeration based on open ports."""
        results = []
        
        # DNS enumeration if port 53 is open
        if 53 in open_ports:
            dns_config = {
                'record_types': ['A', 'AAAA', 'MX', 'NS', 'TXT'],
                'wordlist_path': None
            }
            
            try:
                dns_result = await self.scan_orchestrator.execute_scan(
                    scanner_type="dns_scanner",
                    target_address=target_address,
                    config=dns_config
                )
                results.append(dns_result)
            except Exception as e:
                print(f"DNS enumeration failed for {target_address}: {e}")
        
        # HTTP enumeration if web ports are open
        web_ports = [80, 443, 8080, 8443]
        if any(port in open_ports for port in web_ports):
            http_config = {
                'ports': [port for port in web_ports if port in open_ports],
                'timeout': 10,
                'user_agent': 'Huggin-Scanner/1.0'
            }
            
            try:
                http_result = await self.scan_orchestrator.execute_scan(
                    scanner_type="http_scanner",
                    target_address=target_address,
                    config=http_config
                )
                results.append(http_result)
            except Exception as e:
                print(f"HTTP enumeration failed for {target_address}: {e}")
        
        return results
    
    def _get_scanner_config(self, scanner_type: str, target: str) -> Dict[str, Any]:
        """Get default configuration for a scanner type."""
        configs = {
            'port_scanner': {
                'ports': [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389],
                'timeout': 3,
                'max_concurrent': 50
            },
            'dns_scanner': {
                'record_types': ['A', 'AAAA', 'MX', 'NS', 'TXT'],
                'timeout': 5
            },
            'udp_port_scanner': {
                'ports': [53, 67, 68, 123, 161, 500, 1900, 5353],
                'timeout': 2,
                'max_concurrent': 20
            }
        }
        
        return configs.get(scanner_type, {})
    
    async def get_scan_history(self, scanner_type: Optional[str] = None, 
                             limit: int = 50) -> List[ScanResultModel]:
        """Get scan history with optional filtering."""
        return await self.scan_orchestrator.get_scan_results(
            scanner_type=scanner_type,
            status=None
        )
    
    async def get_active_scans(self) -> List[ScanResultModel]:
        """Get currently running scans."""
        return await self.scan_orchestrator.get_scan_results(
            status=ScanStatus.RUNNING
        )