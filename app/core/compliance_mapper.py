# app/core/compliance_mapper.py
from typing import Dict, List, Any
from datetime import datetime
from app.core.logger import logger

class ComplianceMapper:
    """Map security findings to compliance frameworks"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.frameworks = {
            'OWASP_TOP_10': {
                'name': 'OWASP Top 10 2021',
                'categories': {
                    'A01_2021': 'Broken Access Control',
                    'A02_2021': 'Cryptographic Failures', 
                    'A03_2021': 'Injection',
                    'A04_2021': 'Insecure Design',
                    'A05_2021': 'Security Misconfiguration',
                    'A06_2021': 'Vulnerable and Outdated Components',
                    'A07_2021': 'Identification and Authentication Failures',
                    'A08_2021': 'Software and Data Integrity Failures',
                    'A09_2021': 'Security Logging and Monitoring Failures',
                    'A10_2021': 'Server-Side Request Forgery'
                }
            },
            'NIST_CSF': {
                'name': 'NIST Cybersecurity Framework',
                'categories': {
                    'ID': 'Identify',
                    'PR': 'Protect',
                    'DE': 'Detect', 
                    'RS': 'Respond',
                    'RC': 'Recover'
                }
            },
            'PCI_DSS': {
                'name': 'PCI DSS v4.0',
                'categories': {
                    'REQ_1': 'Install and maintain network security controls',
                    'REQ_2': 'Apply secure configurations',
                    'REQ_3': 'Protect stored cardholder data',
                    'REQ_4': 'Protect cardholder data with strong cryptography',
                    'REQ_5': 'Protect all systems and networks from malicious software',
                    'REQ_6': 'Develop and maintain secure systems and software'
                }
            }
        }
    
    def map_findings_to_owasp(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Map findings to OWASP Top 10 categories"""
        mapping = {category: [] for category in self.frameworks['OWASP_TOP_10']['categories'].keys()}
        
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            
            if 'injection' in finding_type or 'sqli' in finding_type or 'xss' in finding_type:
                mapping['A03_2021'].append(finding)
            elif 'auth' in finding_type or 'login' in finding_type:
                mapping['A07_2021'].append(finding)
            elif 'config' in finding_type or 'default' in finding_type:
                mapping['A05_2021'].append(finding)
            elif 'access' in finding_type or 'permission' in finding_type:
                mapping['A01_2021'].append(finding)
            elif 'crypto' in finding_type or 'ssl' in finding_type or 'tls' in finding_type:
                mapping['A02_2021'].append(finding)
            elif 'log' in finding_type or 'monitor' in finding_type:
                mapping['A09_2021'].append(finding)
            elif 'ssrf' in finding_type:
                mapping['A10_2021'].append(finding)
            else:
                mapping['A04_2021'].append(finding)  # Default to Insecure Design
        
        return mapping
    
    def map_findings_to_nist(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Map findings to NIST CSF categories"""
        mapping = {category: [] for category in self.frameworks['NIST_CSF']['categories'].keys()}
        
        for finding in findings:
            finding_type = finding.get('type', '').lower()
            
            if 'enum' in finding_type or 'discovery' in finding_type:
                mapping['ID'].append(finding)
            elif 'vuln' in finding_type or 'exploit' in finding_type:
                mapping['PR'].append(finding)
            elif 'log' in finding_type or 'monitor' in finding_type:
                mapping['DE'].append(finding)
            else:
                mapping['PR'].append(finding)  # Default to Protect
        
        return mapping
    
    def generate_compliance_report(self, framework: str) -> Dict[str, Any]:
        """Generate compliance report for specified framework"""
        from .centralized_scan_data import centralized_scan_data
        
        # Get all findings
        all_findings = []
        scan_types = ["rpc_vulnerabilities", "http_directories", "smb_shares", "ldap_users"]
        
        for scan_type in scan_types:
            try:
                data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type)
                for item in data:
                    all_findings.append({
                        'type': scan_type,
                        'target': item['target'],
                        'data': item['data'],
                        'count': item['count']
                    })
            except Exception:
                continue
        
        if framework == 'OWASP_TOP_10':
            mapping = self.map_findings_to_owasp(all_findings)
        elif framework == 'NIST_CSF':
            mapping = self.map_findings_to_nist(all_findings)
        else:
            mapping = {}
        
        # Calculate compliance score
        total_categories = len(self.frameworks[framework]['categories'])
        covered_categories = sum(1 for findings in mapping.values() if findings)
        compliance_score = (covered_categories / total_categories) * 100 if total_categories > 0 else 0
        
        return {
            'framework': self.frameworks[framework]['name'],
            'generated_at': datetime.now().isoformat(),
            'compliance_score': compliance_score,
            'total_findings': len(all_findings),
            'categories': mapping,
            'summary': {
                'total_categories': total_categories,
                'covered_categories': covered_categories,
                'uncovered_categories': total_categories - covered_categories
            }
        }

def create_compliance_mapper(tenant_id: str = "default") -> ComplianceMapper:
    """Create compliance mapper for specific tenant"""
    return ComplianceMapper(tenant_id=tenant_id)