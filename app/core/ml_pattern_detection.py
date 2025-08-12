# app/core/ml_pattern_detection.py
import json
import re
from collections import Counter
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal

class MLPatternDetection(QObject):
    """Machine learning-based pattern detection for scan results."""
    
    pattern_detected = pyqtSignal(str, dict)
    
    def __init__(self):
        super().__init__()
        self.patterns = {}
        self.anomaly_threshold = 0.7
        
    def analyze_scan_results(self, results, scan_type):
        """Analyze scan results for patterns and anomalies."""
        analysis = {
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat(),
            "patterns": [],
            "anomalies": [],
            "insights": []
        }
        
        if scan_type == "dns_enum":
            analysis.update(self._analyze_dns_patterns(results))
        elif scan_type == "port_scan":
            analysis.update(self._analyze_port_patterns(results))
        elif scan_type == "http_enum":
            analysis.update(self._analyze_http_patterns(results))
        
        self.pattern_detected.emit(scan_type, analysis)
        return analysis
    
    def _analyze_dns_patterns(self, results):
        """Analyze DNS enumeration patterns."""
        patterns = []
        anomalies = []
        insights = []
        
        if isinstance(results, dict):
            # Analyze subdomain patterns
            subdomains = []
            for record_type, values in results.items():
                if isinstance(values, list):
                    subdomains.extend([v for v in values if '.' in str(v)])
            
            if subdomains:
                # Common subdomain pattern detection
                common_prefixes = self._extract_common_prefixes(subdomains)
                if common_prefixes:
                    patterns.append({
                        "type": "subdomain_naming",
                        "pattern": f"Common prefixes: {', '.join(common_prefixes[:5])}",
                        "confidence": 0.8
                    })
                
                # Detect potential wildcard responses
                if len(set(subdomains)) < len(subdomains) * 0.3:
                    anomalies.append({
                        "type": "potential_wildcard",
                        "description": "High number of duplicate responses detected",
                        "severity": "medium"
                    })
                
                insights.append(f"Found {len(set(subdomains))} unique subdomains")
        
        return {"patterns": patterns, "anomalies": anomalies, "insights": insights}
    
    def _analyze_port_patterns(self, results):
        """Analyze port scan patterns."""
        patterns = []
        anomalies = []
        insights = []
        
        if isinstance(results, dict) and "open_ports" in results:
            ports = results["open_ports"]
            
            # Common service patterns
            web_ports = [p for p in ports if p in [80, 443, 8080, 8443, 8000]]
            if len(web_ports) >= 2:
                patterns.append({
                    "type": "web_services",
                    "pattern": f"Multiple web ports: {web_ports}",
                    "confidence": 0.9
                })
            
            # Unusual port combinations
            if 22 in ports and 3389 in ports:
                patterns.append({
                    "type": "dual_remote_access",
                    "pattern": "Both SSH (22) and RDP (3389) detected",
                    "confidence": 0.8
                })
            
            # High port count anomaly
            if len(ports) > 50:
                anomalies.append({
                    "type": "excessive_open_ports",
                    "description": f"{len(ports)} open ports detected",
                    "severity": "high"
                })
            
            insights.append(f"Detected {len(ports)} open ports")
        
        return {"patterns": patterns, "anomalies": anomalies, "insights": insights}
    
    def _analyze_http_patterns(self, results):
        """Analyze HTTP enumeration patterns."""
        patterns = []
        anomalies = []
        insights = []
        
        if isinstance(results, dict):
            # Analyze response codes
            if "responses" in results:
                codes = [r.get("status_code") for r in results["responses"] if "status_code" in r]
                code_counts = Counter(codes)
                
                # High 403 rate might indicate WAF
                if code_counts.get(403, 0) > len(codes) * 0.5:
                    patterns.append({
                        "type": "waf_detection",
                        "pattern": "High 403 response rate suggests WAF presence",
                        "confidence": 0.7
                    })
                
                # Unusual response patterns
                if len(set(codes)) == 1 and codes[0] == 200:
                    anomalies.append({
                        "type": "uniform_responses",
                        "description": "All requests returned same status code",
                        "severity": "medium"
                    })
            
            insights.append("HTTP pattern analysis completed")
        
        return {"patterns": patterns, "anomalies": anomalies, "insights": insights}
    
    def _extract_common_prefixes(self, domains):
        """Extract common prefixes from domain list."""
        prefixes = []
        for domain in domains:
            parts = domain.split('.')
            if len(parts) > 1:
                prefixes.append(parts[0])
        
        # Return most common prefixes
        prefix_counts = Counter(prefixes)
        return [prefix for prefix, count in prefix_counts.most_common(10) if count > 1]
    
    def detect_scan_anomalies(self, current_results, historical_results):
        """Detect anomalies by comparing with historical data."""
        anomalies = []
        
        if not historical_results:
            return anomalies
        
        # Compare result counts
        current_count = len(current_results) if isinstance(current_results, (list, dict)) else 0
        historical_counts = [len(r) if isinstance(r, (list, dict)) else 0 for r in historical_results]
        
        if historical_counts:
            avg_count = sum(historical_counts) / len(historical_counts)
            
            # Significant deviation from historical average
            if current_count > avg_count * 2:
                anomalies.append({
                    "type": "result_count_spike",
                    "description": f"Current results ({current_count}) significantly higher than average ({avg_count:.1f})",
                    "severity": "medium"
                })
            elif current_count < avg_count * 0.5 and avg_count > 5:
                anomalies.append({
                    "type": "result_count_drop",
                    "description": f"Current results ({current_count}) significantly lower than average ({avg_count:.1f})",
                    "severity": "low"
                })
        
        return anomalies
    
    def generate_insights(self, analysis_results):
        """Generate actionable insights from pattern analysis."""
        insights = []
        
        patterns = analysis_results.get("patterns", [])
        anomalies = analysis_results.get("anomalies", [])
        
        # High-confidence patterns
        high_conf_patterns = [p for p in patterns if p.get("confidence", 0) > 0.8]
        if high_conf_patterns:
            insights.append(f"Detected {len(high_conf_patterns)} high-confidence patterns")
        
        # Security-relevant anomalies
        high_sev_anomalies = [a for a in anomalies if a.get("severity") == "high"]
        if high_sev_anomalies:
            insights.append(f"⚠️ {len(high_sev_anomalies)} high-severity anomalies detected")
        
        return insights

# Global ML pattern detection instance
ml_pattern_detection = MLPatternDetection()