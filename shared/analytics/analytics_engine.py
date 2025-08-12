from typing import Dict, List, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class AnalyticsResult:
    metric_name: str
    value: float
    confidence: float
    timestamp: datetime
    metadata: Dict[str, Any] = None

class AnalyticsEngine:
    """Advanced analytics engine for scan data analysis"""
    
    def __init__(self):
        self.historical_data: Dict[str, List[float]] = {}
    
    def analyze_scan_trends(self, scan_data: List[Dict[str, Any]]) -> List[AnalyticsResult]:
        """Analyze trends in scan data"""
        results = []
        
        port_counts = [len(scan.get('open_ports', [])) for scan in scan_data]
        if port_counts:
            trend = self._calculate_trend(port_counts)
            results.append(AnalyticsResult(
                metric_name="port_discovery_trend",
                value=trend,
                confidence=0.8,
                timestamp=datetime.now(),
                metadata={"sample_size": len(port_counts)}
            ))
        
        return results
    
    def detect_anomalies(self, current_scan: Dict[str, Any], 
                        historical_scans: List[Dict[str, Any]]) -> List[AnalyticsResult]:
        """Detect anomalies in current scan"""
        results = []
        
        if not historical_scans:
            return results
        
        current_ports = len(current_scan.get('open_ports', []))
        historical_ports = [len(scan.get('open_ports', [])) for scan in historical_scans]
        
        if historical_ports:
            mean_ports = sum(historical_ports) / len(historical_ports)
            if abs(current_ports - mean_ports) > mean_ports * 0.5:  # 50% deviation
                results.append(AnalyticsResult(
                    metric_name="port_count_anomaly",
                    value=abs(current_ports - mean_ports),
                    confidence=0.8,
                    timestamp=datetime.now(),
                    metadata={"current_ports": current_ports, "historical_mean": mean_ports}
                ))
        
        return results
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate simple trend direction"""
        if len(values) < 2:
            return 0.0
        
        increases = sum(1 for i in range(1, len(values)) if values[i] > values[i-1])
        total_changes = len(values) - 1
        
        return (increases / total_changes) * 2 - 1  # Scale to -1 to 1