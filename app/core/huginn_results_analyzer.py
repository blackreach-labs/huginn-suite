# app/core/huginn_results_analyzer.py
import json
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass
from .centralized_scan_data import centralized_scan_data

@dataclass
class VulnerabilityAnalysis:
    """Enhanced vulnerability analysis with risk scoring"""
    vulnerability_id: str
    type: str
    severity: str
    cvss_score: float
    target: str
    description: str
    remediation: str
    exploit_available: bool = False
    business_impact: str = "Unknown"
    remediation_priority: int = 1

class HuginnResultsAnalyzer:
    """Advanced analysis and reporting for Huginn scanner results"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 1
        }
    
    def analyze_scan_results(self, scan_results: Dict) -> Dict[str, Any]:
        """Comprehensive analysis of Huginn scan results"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        analysis = {
            'scan_summary': self._generate_scan_summary(scan_results),
            'vulnerability_breakdown': self._analyze_vulnerabilities(vulnerabilities),
            'risk_assessment': self._calculate_risk_score(vulnerabilities),
            'compliance_status': self._analyze_compliance(scan_results),
            'remediation_roadmap': self._generate_remediation_roadmap(vulnerabilities),
            'executive_insights': self._generate_executive_insights(scan_results),
            'technical_recommendations': self._generate_technical_recommendations(vulnerabilities)
        }
        
        # Store analysis in centralized database
        self._store_analysis_results(scan_results.get('target'), analysis)
        
        return analysis
    
    def _generate_scan_summary(self, scan_results: Dict) -> Dict:
        """Generate comprehensive scan summary"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'target': scan_results.get('target'),
            'scan_time': scan_results.get('scan_time'),
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'tech_stack': scan_results.get('tech_stack', []),
            'server_info': scan_results.get('server_info', {}),
            'scan_phases_completed': len(scan_results.get('scan_stats', {})),
            'ai_insights_available': bool(scan_results.get('ai_insights')),
            'osint_data_collected': bool(scan_results.get('osint_intelligence'))
        }
    
    def _analyze_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict:
        """Detailed vulnerability analysis"""
        analysis = {
            'by_type': {},
            'by_severity': {'Critical': [], 'High': [], 'Medium': [], 'Low': []},
            'exploitable_vulnerabilities': [],
            'web_application_issues': [],
            'infrastructure_issues': [],
            'configuration_issues': []
        }
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'Low')
            
            # Count by type
            analysis['by_type'][vuln_type] = analysis['by_type'].get(vuln_type, 0) + 1
            
            # Group by severity
            analysis['by_severity'][severity].append({
                'type': vuln_type,
                'description': vuln.get('description', ''),
                'cvss_score': vuln.get('cvss_score', 0),
                'remediation': vuln.get('remediation', '')
            })
            
            # Identify exploitable vulnerabilities
            if severity in ['Critical', 'High'] and any(keyword in vuln_type.lower() 
                for keyword in ['injection', 'execution', 'overflow', 'upload']):
                analysis['exploitable_vulnerabilities'].append(vuln)
            
            # Categorize by issue type
            if any(keyword in vuln_type.lower() 
                for keyword in ['xss', 'injection', 'csrf', 'redirect']):
                analysis['web_application_issues'].append(vuln)
            elif any(keyword in vuln_type.lower() 
                for keyword in ['ssl', 'tls', 'certificate', 'protocol']):
                analysis['infrastructure_issues'].append(vuln)
            elif any(keyword in vuln_type.lower() 
                for keyword in ['header', 'method', 'directory', 'file']):
                analysis['configuration_issues'].append(vuln)
        
        return analysis
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate comprehensive risk score"""
        total_score = 0
        max_possible_score = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            cvss_score = vuln.get('cvss_score', 0)
            
            # Use CVSS if available, otherwise use severity weight
            if cvss_score > 0:
                total_score += cvss_score
                max_possible_score += 10
            else:
                weight = self.severity_weights.get(severity, 1)
                total_score += weight
                max_possible_score += 10
        
        if max_possible_score == 0:
            risk_percentage = 0
        else:
            risk_percentage = (total_score / max_possible_score) * 100
        
        # Determine risk level
        if risk_percentage >= 80:
            risk_level = "CRITICAL"
        elif risk_percentage >= 60:
            risk_level = "HIGH"
        elif risk_percentage >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'overall_risk_score': round(risk_percentage, 2),
            'risk_level': risk_level,
            'total_score': total_score,
            'max_possible_score': max_possible_score,
            'vulnerability_count': len(vulnerabilities)
        }
    
    def _analyze_compliance(self, scan_results: Dict) -> Dict:
        """Analyze compliance status"""
        owasp_report = scan_results.get('owasp_report', {})
        pci_report = scan_results.get('pci_dss_report', {})
        
        return {
            'owasp_top_10': {
                'score': owasp_report.get('compliance_score', 0),
                'status': 'COMPLIANT' if owasp_report.get('compliance_score', 0) >= 80 else 'NON_COMPLIANT',
                'findings': owasp_report.get('findings', [])
            },
            'pci_dss': {
                'status': pci_report.get('compliance_status', 'Unknown'),
                'requirements_met': pci_report.get('requirements_met', 0),
                'total_requirements': pci_report.get('total_requirements', 12)
            },
            'security_gate': scan_results.get('security_gate', {})
        }
    
    def _generate_remediation_roadmap(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation roadmap"""
        roadmap = []
        
        # Sort vulnerabilities by severity and CVSS score
        sorted_vulns = sorted(vulnerabilities, 
            key=lambda v: (self.severity_weights.get(v.get('severity', 'Low'), 0), 
                          v.get('cvss_score', 0)), reverse=True)
        
        for i, vuln in enumerate(sorted_vulns[:10]):  # Top 10 priorities
            priority = i + 1
            effort_estimate = self._estimate_remediation_effort(vuln)
            
            roadmap.append({
                'priority': priority,
                'vulnerability_type': vuln.get('type'),
                'severity': vuln.get('severity'),
                'description': vuln.get('description'),
                'remediation': vuln.get('remediation'),
                'effort_estimate': effort_estimate,
                'business_impact': self._assess_business_impact(vuln),
                'timeline': self._suggest_timeline(vuln.get('severity'))
            })
        
        return roadmap
    
    def _generate_executive_insights(self, scan_results: Dict) -> List[str]:
        """Generate executive-level insights"""
        insights = []
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Critical findings
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        if critical_vulns:
            insights.append(f"🚨 URGENT: {len(critical_vulns)} critical vulnerabilities require immediate attention")
        
        # Compliance status
        owasp_score = scan_results.get('owasp_report', {}).get('compliance_score', 0)
        if owasp_score < 70:
            insights.append(f"⚠️ OWASP compliance at {owasp_score}% - below industry standards")
        
        # Technology risks
        tech_stack = scan_results.get('tech_stack', [])
        if any(tech in ['WordPress', 'Drupal', 'Joomla'] for tech in tech_stack):
            insights.append("🔍 CMS platform detected - ensure plugins and themes are updated")
        
        # Infrastructure concerns
        server_info = scan_results.get('server_info', {})
        if server_info.get('security_score', '0/9').split('/')[0] < '7':
            insights.append("🛡️ Security headers implementation below best practices")
        
        return insights
    
    def _generate_technical_recommendations(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Generate technical recommendations"""
        recommendations = []
        
        # Group similar vulnerabilities
        vuln_groups = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(vuln)
        
        # Generate recommendations for each group
        for vuln_type, vulns in vuln_groups.items():
            if len(vulns) > 1:
                recommendations.append({
                    'category': 'Pattern Detection',
                    'issue': f"Multiple {vuln_type} vulnerabilities detected",
                    'count': len(vulns),
                    'recommendation': f"Implement systematic {vuln_type.lower()} prevention measures",
                    'priority': 'High' if any(v.get('severity') in ['Critical', 'High'] for v in vulns) else 'Medium'
                })
        
        return recommendations
    
    def _estimate_remediation_effort(self, vulnerability: Dict) -> str:
        """Estimate remediation effort"""
        vuln_type = vulnerability.get('type', '').lower()
        
        if any(keyword in vuln_type for keyword in ['header', 'configuration']):
            return "Low (1-2 hours)"
        elif any(keyword in vuln_type for keyword in ['injection', 'xss']):
            return "Medium (1-3 days)"
        elif any(keyword in vuln_type for keyword in ['execution', 'upload']):
            return "High (1-2 weeks)"
        else:
            return "Medium (2-5 days)"
    
    def _assess_business_impact(self, vulnerability: Dict) -> str:
        """Assess business impact"""
        severity = vulnerability.get('severity', 'Low')
        vuln_type = vulnerability.get('type', '').lower()
        
        if severity == 'Critical':
            if any(keyword in vuln_type for keyword in ['execution', 'injection']):
                return "SEVERE - Data breach, system compromise"
            else:
                return "HIGH - Service disruption, reputation damage"
        elif severity == 'High':
            return "MEDIUM - Potential data exposure, compliance issues"
        else:
            return "LOW - Minor security weakness"
    
    def _suggest_timeline(self, severity: str) -> str:
        """Suggest remediation timeline"""
        timelines = {
            'Critical': 'Immediate (24-48 hours)',
            'High': 'Urgent (1 week)',
            'Medium': 'Standard (2-4 weeks)',
            'Low': 'Planned (1-3 months)'
        }
        return timelines.get(severity, 'Standard (2-4 weeks)')
    
    def _store_analysis_results(self, target: str, analysis: Dict):
        """Store analysis results in centralized database"""
        try:
            scan_id = f"huginn_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            centralized_scan_data.add_scan_result(
                scan_id=scan_id,
                tenant_id=self.tenant_id,
                scan_type="huginn_analysis",
                target=target,
                scanner="huginn_results_analyzer",
                result_data=analysis
            )
        except Exception as e:
            print(f"Failed to store analysis results: {e}")
    
    def generate_detailed_report(self, analysis: Dict) -> str:
        """Generate detailed HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Huginn Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .risk-critical {{ background: #e74c3c; color: white; padding: 10px; border-radius: 5px; }}
                .risk-high {{ background: #f39c12; color: white; padding: 10px; border-radius: 5px; }}
                .risk-medium {{ background: #f1c40f; color: black; padding: 10px; border-radius: 5px; }}
                .risk-low {{ background: #27ae60; color: white; padding: 10px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .vuln-item {{ margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #007bff; }}
                .remediation {{ background: #e8f4fd; padding: 10px; margin: 10px 0; border-radius: 3px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Huginn Security Assessment Report</h1>
                <p><strong>Target:</strong> {analysis['scan_summary']['target']}</p>
                <p><strong>Assessment Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section risk-{analysis['risk_assessment']['risk_level'].lower()}">
                <h2>🎯 Executive Summary</h2>
                <p><strong>Overall Risk Level:</strong> {analysis['risk_assessment']['risk_level']}</p>
                <p><strong>Risk Score:</strong> {analysis['risk_assessment']['overall_risk_score']}%</p>
                <p><strong>Total Vulnerabilities:</strong> {analysis['scan_summary']['total_vulnerabilities']}</p>
                
                <h3>Key Insights:</h3>
                <ul>
                    {''.join(f'<li>{insight}</li>' for insight in analysis['executive_insights'])}
                </ul>
            </div>
            
            <div class="section">
                <h2>📊 Vulnerability Breakdown</h2>
                <table>
                    <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
        """
        
        total_vulns = analysis['scan_summary']['total_vulnerabilities']
        for severity, count in analysis['scan_summary']['severity_breakdown'].items():
            percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
            html += f"<tr><td>{severity}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"
        
        html += """
                </table>
            </div>
            
            <div class="section">
                <h2>🚨 Critical & High Priority Issues</h2>
        """
        
        critical_high = (analysis['vulnerability_breakdown']['by_severity']['Critical'] + 
                        analysis['vulnerability_breakdown']['by_severity']['High'])
        
        for vuln in critical_high[:5]:  # Top 5 critical/high issues
            html += f"""
                <div class="vuln-item">
                    <h4>{vuln['type']}</h4>
                    <p><strong>CVSS Score:</strong> {vuln['cvss_score']}</p>
                    <p>{vuln['description']}</p>
                    <div class="remediation">
                        <strong>Remediation:</strong> {vuln['remediation']}
                    </div>
                </div>
            """
        
        html += """
            </div>
            
            <div class="section">
                <h2>🛠️ Remediation Roadmap</h2>
                <table>
                    <tr><th>Priority</th><th>Vulnerability</th><th>Effort</th><th>Timeline</th></tr>
        """
        
        for item in analysis['remediation_roadmap'][:10]:
            html += f"""
                <tr>
                    <td>{item['priority']}</td>
                    <td>{item['vulnerability_type']}</td>
                    <td>{item['effort_estimate']}</td>
                    <td>{item['timeline']}</td>
                </tr>
            """
        
        html += """
                </table>
            </div>
            
            <div class="section">
                <h2>📋 Compliance Status</h2>
                <p><strong>OWASP Top 10:</strong> {owasp_score}% - {owasp_status}</p>
                <p><strong>PCI DSS:</strong> {pci_status}</p>
            </div>
            
        </body>
        </html>
        """.format(
            owasp_score=analysis['compliance_status']['owasp_top_10']['score'],
            owasp_status=analysis['compliance_status']['owasp_top_10']['status'],
            pci_status=analysis['compliance_status']['pci_dss']['status']
        )
        
        return html

# Global instance
huginn_analyzer = HuginnResultsAnalyzer()