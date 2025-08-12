# app/core/executive_summary.py
from datetime import datetime
from collections import defaultdict
import json

class ExecutiveSummary:
    """Generate executive summary from scan results"""
    
    def __init__(self):
        self.risk_levels = {
            'critical': {'color': '#FF0000', 'weight': 4},
            'high': {'color': '#FF6600', 'weight': 3},
            'medium': {'color': '#FFAA00', 'weight': 2},
            'low': {'color': '#00AA00', 'weight': 1},
            'info': {'color': '#0066FF', 'weight': 0}
        }
    
    def analyze_results(self, results, scan_type, target):
        """Analyze scan results and generate summary"""
        summary = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'total_findings': 0,
            'risk_breakdown': defaultdict(int),
            'key_findings': [],
            'recommendations': [],
            'executive_overview': ''
        }
        
        if scan_type == 'dns_enum':
            summary.update(self._analyze_dns_results(results))
        elif scan_type == 'port_scan':
            summary.update(self._analyze_port_results(results))
        else:
            summary.update(self._analyze_generic_results(results))
        
        summary['executive_overview'] = self._generate_overview(summary)
        return summary
    
    def _analyze_dns_results(self, results):
        """Analyze DNS enumeration results"""
        findings = []
        recommendations = []
        risk_counts = defaultdict(int)
        
        if isinstance(results, dict):
            subdomain_count = len(results)
            
            # Risk assessment based on subdomain exposure
            if subdomain_count > 50:
                risk_counts['high'] += 1
                findings.append(f"High subdomain exposure: {subdomain_count} subdomains discovered")
                recommendations.append("Review and secure exposed subdomains")
            elif subdomain_count > 20:
                risk_counts['medium'] += 1
                findings.append(f"Moderate subdomain exposure: {subdomain_count} subdomains found")
                recommendations.append("Audit subdomain configurations")
            else:
                risk_counts['low'] += 1
                findings.append(f"Limited subdomain exposure: {subdomain_count} subdomains")
            
            # Check for sensitive subdomains
            sensitive_patterns = ['admin', 'test', 'dev', 'staging', 'backup', 'api']
            sensitive_found = []
            for domain in results.keys():
                for pattern in sensitive_patterns:
                    if pattern in domain.lower():
                        sensitive_found.append(domain)
            
            if sensitive_found:
                risk_counts['high'] += len(sensitive_found)
                findings.append(f"Sensitive subdomains exposed: {', '.join(sensitive_found[:3])}")
                recommendations.append("Secure or remove sensitive development/admin subdomains")
        
        return {
            'total_findings': sum(risk_counts.values()),
            'risk_breakdown': dict(risk_counts),
            'key_findings': findings,
            'recommendations': recommendations
        }
    
    def _analyze_port_results(self, results):
        """Analyze port scan results"""
        findings = []
        recommendations = []
        risk_counts = defaultdict(int)
        
        # Simplified port analysis
        if isinstance(results, dict) and 'status' in results:
            risk_counts['info'] += 1
            findings.append("Port scan completed successfully")
            recommendations.append("Review open ports and services")
        
        return {
            'total_findings': sum(risk_counts.values()),
            'risk_breakdown': dict(risk_counts),
            'key_findings': findings,
            'recommendations': recommendations
        }
    
    def _analyze_generic_results(self, results):
        """Analyze generic scan results"""
        findings = []
        recommendations = []
        risk_counts = defaultdict(int)
        
        if results:
            count = len(results) if isinstance(results, (list, dict)) else 1
            risk_counts['info'] += count
            findings.append(f"Scan completed with {count} results")
            recommendations.append("Review scan results for security implications")
        
        return {
            'total_findings': sum(risk_counts.values()),
            'risk_breakdown': dict(risk_counts),
            'key_findings': findings,
            'recommendations': recommendations
        }
    
    def _generate_overview(self, summary):
        """Generate executive overview text"""
        total = summary['total_findings']
        risks = summary['risk_breakdown']
        
        if total == 0:
            return "No significant security findings identified during the scan."
        
        overview = f"Security assessment of {summary['target']} identified {total} findings. "
        
        if risks.get('critical', 0) > 0:
            overview += f"CRITICAL: {risks['critical']} critical issues require immediate attention. "
        if risks.get('high', 0) > 0:
            overview += f"HIGH: {risks['high']} high-risk issues should be addressed promptly. "
        if risks.get('medium', 0) > 0:
            overview += f"MEDIUM: {risks['medium']} medium-risk issues need review. "
        
        overview += "Detailed recommendations are provided below."
        return overview
    
    def generate_json_summary(self, results, scan_type, target, output_path):
        """Generate JSON executive summary"""
        try:
            summary = self.analyze_results(results, scan_type, target)
            
            with open(output_path, 'w') as f:
                json.dump(summary, f, indent=2)
            
            return True, output_path, "Executive summary generated"
        except Exception as e:
            return False, None, f"Summary generation failed: {str(e)}"

# Global instance
executive_summary = ExecutiveSummary()