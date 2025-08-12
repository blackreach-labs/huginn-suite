"""Scanner factory for creating scanner instances."""
from typing import Dict, Type, Any, Optional
from infrastructure.scanners.base.base_scanner import BaseScanner


class ScannerFactory:
    """Factory for creating scanner instances."""
    
    _scanners: Dict[str, Type[BaseScanner]] = {}
    
    @classmethod
    def register_scanner(cls, scanner_type: str, scanner_class: Type[BaseScanner]):
        """Register a scanner class."""
        cls._scanners[scanner_type] = scanner_class
    
    @classmethod
    def create_scanner(cls, scanner_type: str, target: str, config: Optional[Dict[str, Any]] = None) -> BaseScanner:
        """Create a scanner instance."""
        scanner_class = cls._scanners.get(scanner_type)
        if not scanner_class:
            raise ValueError(f"Unknown scanner type: {scanner_type}")
        
        return scanner_class(target, config)
    
    @classmethod
    def get_available_scanners(cls) -> list:
        """Get list of available scanner types."""
        return list(cls._scanners.keys())
    
    @classmethod
    def is_scanner_available(cls, scanner_type: str) -> bool:
        """Check if a scanner type is available."""
        return scanner_type in cls._scanners


# Auto-register scanners when imported
def _register_default_scanners():
    """Register default scanners."""
    try:
        from infrastructure.scanners.network.port_scanner import PortScanner, UDPPortScanner, NetworkSweepScanner
        ScannerFactory.register_scanner("port_scanner", PortScanner)
        ScannerFactory.register_scanner("udp_port_scanner", UDPPortScanner)
        ScannerFactory.register_scanner("network_sweep", NetworkSweepScanner)
    except ImportError:
        pass
    
    try:
        from infrastructure.scanners.network.dns_scanner import DNSScanner
        ScannerFactory.register_scanner("dns_scanner", DNSScanner)
    except ImportError:
        pass
    
    try:
        from infrastructure.scanners.service.rpc_scanner import RPCScanner
        ScannerFactory.register_scanner("rpc_scanner", RPCScanner)
    except ImportError:
        pass
    
    try:
        from infrastructure.scanners.service.http_scanner import HTTPScanner
        ScannerFactory.register_scanner("http_scanner", HTTPScanner)
    except ImportError:
        pass


# Register scanners on import
_register_default_scanners()