# app/core/centralized_reporting.py
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
from .centralized_scan_data import centralized_scan_data
from .rpc_data_collector import create_rpc_collector
from .dns_data_collector import create_dns_collector
from .port_data_collector import create_port_collector
from .http_data_collector import create_http_collector
from .smb_data_collector import create_smb_collector

class CentralizedReporting:
    """Advanced reporting system using centralized scan data"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.rpc_collector = create_rpc_collector(tenant_id)
        self.dns_collector = create_dns_collector(tenant_id)
        self.port_collector = create_port_collector(tenant_id)
        self.http_collector = create_http_collector(tenant_id)
        self.smb_collector = create_smb_collector(tenant_id)
    
    def generate_executive_summary(self) -> Dict:
        """Generate executive summary report"""
        overview = centralized_scan_data.get_tenant_overview(self.tenant_id)
        
        # Calculate key metrics
        total_targets = 0
        total_vulnerabilities = 0
        critical_issues = 0
        
        scan_types = overview.get('scan_types', {})
        
        for scan_type, data in scan_types.items():
            total_targets += data.get('unique_targets', 0)
            
            if 'vulnerabilities' in scan_type:
                total_vulnerabilities += data.get('total_results', 0)
            
            # Get detailed data to count critical issues
            detailed_data = centralized_scan_data.get_scan_data(
                tenant_id=self.tenant_id,
                scan_type=scan_type,
                limit=1000
            )
            
            for item in detailed_data:
                severity = item.get('data', {}).get('severity', '').lower()
                if severity in ['critical', 'high']:
                    critical_issues += 1
        
        # Risk assessment
        risk_level = "Low"
        if critical_issues > 10:
            risk_level = "Critical"
        elif critical_issues > 5:
            risk_level = "High"
        elif critical_issues > 0:
            risk_level = "Medium"
        
        return {
            'tenant_id': self.tenant_id,
            'report_date': datetime.now().isoformat(),
            'summary': {
                'total_scan_types': len(scan_types),
                'unique_targets': len(set([data.get('unique_targets', 0) for data in scan_types.values()])),
                'total_findings': sum([data.get('total_results', 0) for data in scan_types.values()]),
                'critical_issues': critical_issues,
                'overall_risk_level': risk_level
            },
            'scan_type_breakdown': scan_types,
            'recent_activity': overview.get('recent_scans', {}),
            'recommendations': self._generate_recommendations(scan_types, critical_issues)
        }
    
    def generate_technical_report(self, scan_type: str = None) -> Dict:
        """Generate detailed technical report"""
        if scan_type:
            scan_types = [scan_type]
        else:
            # Get all scan types for tenant
            overview = centralized_scan_data.get_tenant_overview(self.tenant_id)
            scan_types = list(overview.get('scan_types', {}).keys())
        
        report = {
            'tenant_id': self.tenant_id,
            'report_date': datetime.now().isoformat(),
            'report_type': 'technical',
            'scan_types': {}
        }
        
        for st in scan_types:
            # Get summary
            summary = centralized_scan_data.get_scan_summary(self.tenant_id, st)
            
            # Get detailed data
            detailed_data = centralized_scan_data.get_scan_data(
                tenant_id=self.tenant_id,
                scan_type=st,
                limit=500
            )
            
            # Analyze data
            analysis = self._analyze_scan_data(st, detailed_data)
            
            report['scan_types'][st] = {
                'summary': summary,
                'analysis': analysis,
                'sample_findings': detailed_data[:10]  # First 10 findings
            }
        
        return report
    
    def generate_rpc_security_report(self) -> Dict:
        """Generate RPC-specific security report"""
        rpc_scan_types = [
            "rpc_endpoints", "rpc_services", "rpc_vulnerabilities",
            "rpc_security_issues", "rpc_network_endpoints"
        ]
        
        report = {
            'tenant_id': self.tenant_id,
            'report_date': datetime.now().isoformat(),
            'report_type': 'rpc_security',
            'sections': {}
        }
        
        # RPC Endpoints Analysis
        endpoints_data = centralized_scan_data.get_scan_data(
            tenant_id=self.tenant_id,
            scan_type="rpc_endpoints"
        )
        
        report['sections']['rpc_endpoints'] = {
            'total_endpoints': len(endpoints_data),
            'unique_protocols': len(set([item['data'].get('protocol', 'Unknown') for item in endpoints_data])),
            'critical_services': self._identify_critical_rpc_services(endpoints_data),
            'protocol_breakdown': self._analyze_rpc_protocols(endpoints_data)
        }
        
        # Vulnerability Analysis
        vuln_data = centralized_scan_data.get_scan_data(
            tenant_id=self.tenant_id,
            scan_type="rpc_vulnerabilities"
        )
        
        report['sections']['vulnerabilities'] = {
            'total_vulnerabilities': len(vuln_data),
            'severity_breakdown': self._analyze_vulnerability_severity(vuln_data),
            'top_vulnerabilities': self._get_top_vulnerabilities(vuln_data),
            'exploitable_count': len([v for v in vuln_data if v['data'].get('exploitable')])
        }
        
        # Security Issues Analysis
        issues_data = centralized_scan_data.get_scan_data(
            tenant_id=self.tenant_id,
            scan_type="rpc_security_issues"
        )
        
        report['sections']['security_issues'] = {
            'total_issues': len(issues_data),
            'category_breakdown': self._analyze_security_categories(issues_data),
            'high_priority_issues': [i for i in issues_data if i['data'].get('severity', '').lower() in ['critical', 'high']]
        }
        
        # Risk Assessment
        report['risk_assessment'] = self._calculate_rpc_risk_score(report['sections'])
        
        # Recommendations
        report['recommendations'] = self._generate_rpc_recommendations(report['sections'])
        
        return report
    
    def _analyze_scan_data(self, scan_type: str, data: List[Dict]) -> Dict:
        """Analyze scan data for patterns and insights"""
        if not data:
            return {'total': 0, 'insights': []}
        
        analysis = {
            'total': len(data),
            'unique_targets': len(set([item['target'] for item in data])),
            'date_range': {
                'first': min([item['first_seen'] for item in data]),
                'last': max([item['last_seen'] for item in data])
            },
            'insights': []
        }
        
        # Add scan-type specific analysis
        if 'vulnerability' in scan_type:
            severities = [item['data'].get('severity', 'unknown').lower() for item in data]
            analysis['severity_distribution'] = {
                'critical': severities.count('critical'),
                'high': severities.count('high'),
                'medium': severities.count('medium'),
                'low': severities.count('low')
            }
        
        return analysis
    
    def _identify_critical_rpc_services(self, endpoints_data: List[Dict]) -> List[str]:
        """Identify critical RPC services"""
        critical_services = []
        critical_protocols = ['lsarpc', 'samr', 'svcctl', 'winreg', 'spoolss']
        
        for item in endpoints_data:
            protocol = item['data'].get('protocol', '').lower()
            if any(crit in protocol for crit in critical_protocols):
                critical_services.append(protocol)
        
        return list(set(critical_services))
    
    def _analyze_rpc_protocols(self, endpoints_data: List[Dict]) -> Dict:
        """Analyze RPC protocol distribution"""
        protocols = {}
        for item in endpoints_data:
            protocol = item['data'].get('protocol', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + item['count']
        
        return protocols
    
    def _analyze_vulnerability_severity(self, vuln_data: List[Dict]) -> Dict:
        """Analyze vulnerability severity distribution"""
        severities = {}
        for item in vuln_data:
            severity = item['data'].get('severity', 'unknown').lower()
            severities[severity] = severities.get(severity, 0) + item['count']
        
        return severities
    
    def _get_top_vulnerabilities(self, vuln_data: List[Dict], limit: int = 10) -> List[Dict]:
        """Get top vulnerabilities by count"""
        sorted_vulns = sorted(vuln_data, key=lambda x: x['count'], reverse=True)
        return [{
            'name': item['data'].get('name', 'Unknown'),
            'severity': item['data'].get('severity', 'unknown'),
            'count': item['count'],
            'cve': item['data'].get('cve', '')
        } for item in sorted_vulns[:limit]]
    
    def _analyze_security_categories(self, issues_data: List[Dict]) -> Dict:
        """Analyze security issue categories"""
        categories = {}
        for item in issues_data:
            category = item['data'].get('category', 'general')
            categories[category] = categories.get(category, 0) + item['count']
        
        return categories
    
    def _calculate_rpc_risk_score(self, sections: Dict) -> Dict:
        """Calculate overall RPC risk score"""
        score = 0
        factors = []
        
        # Critical RPC services exposed
        critical_services = len(sections.get('rpc_endpoints', {}).get('critical_services', []))
        if critical_services > 0:
            score += critical_services * 15
            factors.append(f"{critical_services} critical RPC services exposed")
        
        # High/Critical vulnerabilities
        vuln_severity = sections.get('vulnerabilities', {}).get('severity_breakdown', {})
        critical_vulns = vuln_severity.get('critical', 0)
        high_vulns = vuln_severity.get('high', 0)
        
        score += critical_vulns * 25 + high_vulns * 15
        if critical_vulns > 0:
            factors.append(f"{critical_vulns} critical vulnerabilities")
        if high_vulns > 0:
            factors.append(f"{high_vulns} high severity vulnerabilities")
        
        # Exploitable vulnerabilities
        exploitable = sections.get('vulnerabilities', {}).get('exploitable_count', 0)
        if exploitable > 0:
            score += exploitable * 20
            factors.append(f"{exploitable} exploitable vulnerabilities")
        
        # Risk level determination
        if score >= 80:
            risk_level = "Critical"
        elif score >= 60:
            risk_level = "High"
        elif score >= 40:
            risk_level = "Medium"
        elif score >= 20:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        return {
            'score': min(score, 100),
            'level': risk_level,
            'factors': factors
        }
    
    def _generate_recommendations(self, scan_types: Dict, critical_issues: int) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if critical_issues > 0:
            recommendations.append("Immediately address all critical and high severity vulnerabilities")
        
        if 'rpc_endpoints' in scan_types:
            recommendations.append("Review RPC endpoint exposure and disable unnecessary services")
        
        if 'rpc_vulnerabilities' in scan_types:
            recommendations.append("Implement RPC signing and sealing to prevent MITM attacks")
        
        recommendations.extend([
            "Regularly update and patch all systems",
            "Implement network segmentation to limit RPC exposure",
            "Monitor RPC traffic for suspicious activity",
            "Conduct regular security assessments"
        ])
        
        return recommendations
    
    def _generate_rpc_recommendations(self, sections: Dict) -> List[str]:
        """Generate RPC-specific recommendations"""
        recommendations = []
        
        # RPC endpoint recommendations
        endpoints = sections.get('rpc_endpoints', {})
        if endpoints.get('critical_services'):
            recommendations.append("Restrict access to critical RPC services (LSA, SAMR, SVCCTL)")
        
        # Vulnerability recommendations
        vulns = sections.get('vulnerabilities', {})
        if vulns.get('exploitable_count', 0) > 0:
            recommendations.append("Prioritize patching of exploitable RPC vulnerabilities")
        
        # Security issue recommendations
        issues = sections.get('security_issues', {})
        if issues.get('high_priority_issues'):
            recommendations.append("Address high-priority RPC security configuration issues")
        
        return recommendations

# Factory function
def create_reporting_engine(tenant_id: str = "default") -> CentralizedReporting:
    """Create reporting engine for specific tenant"""
    return CentralizedReporting(tenant_id)