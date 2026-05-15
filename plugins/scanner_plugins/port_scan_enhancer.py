from shared.plugins.plugin_interface import PluginInterface, PluginMetadata
from typing import Dict, Any

class PortScanEnhancer(PluginInterface):
    """Plugin to enhance port scan results with additional analysis"""
    
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="port_scan_enhancer",
            version="1.0.0",
            description="Enhances port scan results with service analysis",
            author="Huginn Team",
            category="scanner",
            dependencies=["nmap"]
        )
    
    def initialize(self, context: Dict[str, Any]) -> bool:
        """Initialize plugin with context"""
        self.context = context
        return True
    
    def execute(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance port scan results"""
        if not scan_results.get('open_ports'):
            return scan_results
        
        enhanced_results = scan_results.copy()
        enhanced_results['enhanced_analysis'] = []
        
        for port_info in scan_results['open_ports']:
            port = port_info.get('port')
            service = port_info.get('service', 'unknown')
            
            analysis = {
                'port': port,
                'service': service,
                'risk_level': self._assess_risk(port, service),
                'recommendations': self._get_recommendations(port, service)
            }
            enhanced_results['enhanced_analysis'].append(analysis)
        
        return enhanced_results
    
    def _assess_risk(self, port: int, service: str) -> str:
        """Assess risk level for port/service combination"""
        high_risk_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995]
        medium_risk_ports = [110, 143, 993, 995, 1433, 3389, 5432]
        
        if port in high_risk_ports:
            return "high"
        elif port in medium_risk_ports:
            return "medium"
        else:
            return "low"
    
    def _get_recommendations(self, port: int, service: str) -> list:
        """Get security recommendations for port/service"""
        recommendations = []
        
        if port == 22:
            recommendations.extend([
                "Ensure SSH uses key-based authentication",
                "Disable root login",
                "Use non-standard port if possible"
            ])
        elif port == 80:
            recommendations.extend([
                "Redirect HTTP to HTTPS",
                "Implement proper security headers",
                "Regular security scanning"
            ])
        elif port == 445:
            recommendations.extend([
                "Ensure SMB signing is enabled",
                "Disable SMBv1 protocol",
                "Restrict SMB access to necessary hosts"
            ])
        
        return recommendations
    
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass