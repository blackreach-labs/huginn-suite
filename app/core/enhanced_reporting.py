# app/core/enhanced_reporting.py
import json
import datetime
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.license_manager import license_manager

class EnhancedReporting(QObject):
    """Enhanced reporting engine with executive dashboards"""
    
    report_event = pyqtSignal(str, str, dict)  # event_type, message, data
    
    def __init__(self):
        super().__init__()
        self.scan_data = {}
        self.compliance_frameworks = {
            'NIST': ['AC-1', 'AC-2', 'AC-3', 'SI-2', 'SI-3'],
            'ISO27001': ['A.9.1.1', 'A.9.2.1', 'A.12.6.1', 'A.14.2.1'],
            'PCI-DSS': ['2.1', '6.1', '6.2', '11.2', '11.3']
        }
        
    def generate_executive_summary(self, scan_results: Dict) -> Dict:
        """Generate executive summary report"""
        if not license_manager.is_feature_enabled('enhanced_reporting'):
            return {'error': 'Enhanced reporting requires Enterprise license'}
            
        summary = {
            'report_type': 'Executive Summary',
            'generated_at': datetime.datetime.now().isoformat(),
            'organization': scan_results.get('organization', 'Unknown'),
            'assessment_period': scan_results.get('period', '1 day'),
            'overall_risk_score': self._calculate_risk_score(scan_results),
            'key_findings': self._extract_key_findings(scan_results),
            'risk_breakdown': self._analyze_risk_breakdown(scan_results),
            'compliance_status': self._assess_compliance(scan_results),
            'recommendations': self._generate_recommendations(scan_results),
            'business_impact': self._assess_business_impact(scan_results)
        }
        
        self.report_event.emit('report_generated', 'Executive summary generated', summary)
        return summary
        
    def generate_technical_report(self, scan_results: Dict) -> Dict:
        """Generate detailed technical report"""
        if not license_manager.is_feature_enabled('enhanced_reporting'):
            return {'error': 'Enhanced reporting requires Enterprise license'}
            
        report = {
            'report_type': 'Technical Assessment',
            'generated_at': datetime.datetime.now().isoformat(),
            'scope': scan_results.get('targets', []),
            'methodology': 'OWASP Testing Guide v4.0, NIST SP 800-115',
            'vulnerabilities': self._categorize_vulnerabilities(scan_results),
            'attack_vectors': self._identify_attack_vectors(scan_results),
            'proof_of_concept': self._generate_poc(scan_results),
            'remediation_steps': self._detailed_remediation(scan_results),
            'timeline': self._create_remediation_timeline(scan_results)
        }
        
        return report
        
    def generate_compliance_report(self, scan_results: Dict, framework: str) -> Dict:
        """Generate compliance-specific report"""
        if not license_manager.is_feature_enabled('enhanced_reporting'):
            return {'error': 'Enhanced reporting requires Enterprise license'}
            
        if framework not in self.compliance_frameworks:
            return {'error': f'Unsupported framework: {framework}'}
            
        controls = self.compliance_frameworks[framework]
        
        report = {
            'report_type': f'{framework} Compliance Assessment',
            'generated_at': datetime.datetime.now().isoformat(),
            'framework': framework,
            'controls_assessed': len(controls),
            'compliance_score': self._calculate_compliance_score(scan_results, controls),
            'control_status': self._assess_controls(scan_results, controls),
            'gaps_identified': self._identify_compliance_gaps(scan_results, controls),
            'remediation_roadmap': self._create_compliance_roadmap(scan_results, controls)
        }
        
        return report
        
    def _calculate_risk_score(self, scan_results: Dict) -> float:
        """Calculate overall risk score (0-10)"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        if not vulnerabilities:
            return 0.0
            
        severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        total_score = sum(severity_weights.get(v.get('severity', 'Low'), 1) for v in vulnerabilities)
        max_possible = len(vulnerabilities) * 10
        
        return round((total_score / max_possible) * 10, 1) if max_possible > 0 else 0.0
        
    def _extract_key_findings(self, scan_results: Dict) -> List[Dict]:
        """Extract key security findings"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Get top 5 critical/high severity issues
        critical_high = [v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']]
        critical_high.sort(key=lambda x: {'Critical': 3, 'High': 2, 'Medium': 1, 'Low': 0}.get(x.get('severity', 'Low'), 0), reverse=True)
        
        findings = []
        for vuln in critical_high[:5]:
            findings.append({
                'title': vuln.get('type', 'Unknown Vulnerability'),
                'severity': vuln.get('severity', 'Unknown'),
                'impact': self._describe_impact(vuln),
                'affected_systems': vuln.get('url', 'Unknown'),
                'business_risk': self._assess_business_risk(vuln)
            })
            
        return findings
        
    def _analyze_risk_breakdown(self, scan_results: Dict) -> Dict:
        """Analyze risk by category"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        categories = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            vuln_type = vuln.get('type', 'Other')
            
            breakdown[severity] = breakdown.get(severity, 0) + 1
            categories[vuln_type] = categories.get(vuln_type, 0) + 1
            
        return {
            'severity_distribution': breakdown,
            'vulnerability_categories': categories,
            'total_issues': len(vulnerabilities)
        }
        
    def _assess_compliance(self, scan_results: Dict) -> Dict:
        """Assess compliance status across frameworks"""
        compliance = {}
        
        for framework in self.compliance_frameworks:
            score = self._calculate_compliance_score(scan_results, self.compliance_frameworks[framework])
            status = 'Compliant' if score >= 80 else 'Non-Compliant' if score < 60 else 'Partially Compliant'
            
            compliance[framework] = {
                'score': score,
                'status': status,
                'gaps': max(0, len(self.compliance_frameworks[framework]) - int(score/20))
            }
            
        return compliance
        
    def _generate_recommendations(self, scan_results: Dict) -> List[Dict]:
        """Generate prioritized recommendations"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        recommendations = [
            {
                'priority': 'Critical',
                'title': 'Implement Web Application Firewall',
                'description': 'Deploy WAF to protect against common web attacks',
                'effort': 'Medium',
                'cost': 'Medium',
                'timeline': '2-4 weeks'
            },
            {
                'priority': 'High',
                'title': 'Patch Management Program',
                'description': 'Establish regular patching schedule for all systems',
                'effort': 'High',
                'cost': 'Low',
                'timeline': '1-2 weeks'
            },
            {
                'priority': 'Medium',
                'title': 'Security Awareness Training',
                'description': 'Implement comprehensive security training program',
                'effort': 'Medium',
                'cost': 'Low',
                'timeline': '4-6 weeks'
            }
        ]
        
        return recommendations
        
    def _assess_business_impact(self, scan_results: Dict) -> Dict:
        """Assess business impact of findings"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        critical_high = len([v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']])
        
        impact_score = min(10, critical_high * 2)
        
        return {
            'impact_score': impact_score,
            'financial_risk': 'High' if impact_score >= 7 else 'Medium' if impact_score >= 4 else 'Low',
            'reputation_risk': 'High' if critical_high >= 3 else 'Medium' if critical_high >= 1 else 'Low',
            'operational_risk': 'Medium',  # Default assessment
            'estimated_cost': f"${impact_score * 50000:,}" if impact_score > 0 else "$0"
        }
        
    def _categorize_vulnerabilities(self, scan_results: Dict) -> Dict:
        """Categorize vulnerabilities by type"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        categories = {}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Other')
            if vuln_type not in categories:
                categories[vuln_type] = []
            categories[vuln_type].append(vuln)
            
        return categories
        
    def _identify_attack_vectors(self, scan_results: Dict) -> List[str]:
        """Identify potential attack vectors"""
        vectors = [
            'Web Application Attacks',
            'Network Service Exploitation',
            'Social Engineering',
            'Physical Access',
            'Insider Threats'
        ]
        return vectors
        
    def _generate_poc(self, scan_results: Dict) -> List[Dict]:
        """Generate proof of concept examples"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        poc_examples = []
        
        for vuln in vulnerabilities[:3]:  # Top 3 vulnerabilities
            poc_examples.append({
                'vulnerability': vuln.get('type', 'Unknown'),
                'payload': vuln.get('payload', 'N/A'),
                'steps': [
                    'Identify vulnerable parameter',
                    'Craft malicious payload',
                    'Execute attack',
                    'Verify exploitation'
                ],
                'evidence': vuln.get('evidence', 'No evidence available')
            })
            
        return poc_examples
        
    def _detailed_remediation(self, scan_results: Dict) -> List[Dict]:
        """Generate detailed remediation steps"""
        return [
            {
                'vulnerability': 'SQL Injection',
                'steps': [
                    'Implement parameterized queries',
                    'Input validation and sanitization',
                    'Least privilege database access',
                    'Regular security testing'
                ],
                'priority': 'Critical',
                'effort': 'Medium'
            }
        ]
        
    def _create_remediation_timeline(self, scan_results: Dict) -> Dict:
        """Create remediation timeline"""
        return {
            'immediate': ['Patch critical vulnerabilities', 'Disable unnecessary services'],
            'short_term': ['Implement WAF', 'Update security policies'],
            'medium_term': ['Security training', 'Monitoring enhancement'],
            'long_term': ['Architecture review', 'Compliance certification']
        }
        
    def _calculate_compliance_score(self, scan_results: Dict, controls: List[str]) -> float:
        """Calculate compliance score for framework"""
        # Simplified compliance scoring
        vulnerabilities = scan_results.get('vulnerabilities', [])
        critical_high = len([v for v in vulnerabilities if v.get('severity') in ['Critical', 'High']])
        
        base_score = 100
        penalty = min(80, critical_high * 10)  # Max 80% penalty
        
        return max(20, base_score - penalty)
        
    def _assess_controls(self, scan_results: Dict, controls: List[str]) -> Dict:
        """Assess individual control compliance"""
        control_status = {}
        
        for control in controls:
            # Simplified control assessment
            status = 'Implemented' if len(scan_results.get('vulnerabilities', [])) < 5 else 'Partially Implemented'
            control_status[control] = {
                'status': status,
                'evidence': 'Security scan results',
                'gaps': [] if status == 'Implemented' else ['Vulnerabilities detected']
            }
            
        return control_status
        
    def _identify_compliance_gaps(self, scan_results: Dict, controls: List[str]) -> List[str]:
        """Identify compliance gaps"""
        return [
            'Insufficient access controls',
            'Missing security monitoring',
            'Inadequate patch management',
            'Weak authentication mechanisms'
        ]
        
    def _create_compliance_roadmap(self, scan_results: Dict, controls: List[str]) -> List[Dict]:
        """Create compliance remediation roadmap"""
        return [
            {
                'phase': 'Phase 1 (0-3 months)',
                'activities': ['Address critical vulnerabilities', 'Implement basic controls'],
                'controls': controls[:2]
            },
            {
                'phase': 'Phase 2 (3-6 months)', 
                'activities': ['Enhance monitoring', 'Policy updates'],
                'controls': controls[2:4]
            }
        ]
        
    def _describe_impact(self, vuln: Dict) -> str:
        """Describe vulnerability impact"""
        severity = vuln.get('severity', 'Low')
        impacts = {
            'Critical': 'Complete system compromise possible',
            'High': 'Significant security breach risk',
            'Medium': 'Moderate security exposure',
            'Low': 'Limited security impact'
        }
        return impacts.get(severity, 'Unknown impact')
        
    def _assess_business_risk(self, vuln: Dict) -> str:
        """Assess business risk of vulnerability"""
        severity = vuln.get('severity', 'Low')
        risks = {
            'Critical': 'Severe business disruption',
            'High': 'Major operational impact',
            'Medium': 'Moderate business risk',
            'Low': 'Minimal business impact'
        }
        return risks.get(severity, 'Unknown risk')

# Global enhanced reporting instance
enhanced_reporting = EnhancedReporting()