# app/core/source_patterns.py
import re
import math
from typing import Dict, List, Tuple, Any
from collections import Counter

class PatternScanner:
    def __init__(self):
        self.patterns = self._create_patterns()
    
    def _create_patterns(self):
        return {
            'API Keys': {
                'pattern': r'(?i)(api[_-]?key|secret|token)[\'"]?\s*[:=]\s*[\'"]?[A-Za-z0-9_\-]{16,}[\'"]?',
                'weight': 10,
                'context': 'High-risk credential exposure',
                'category': 'sensitive'
            },
            'Hardcoded Secrets': {
                'pattern': r'["\']?(AKIA|AIza|AIzaSy|sk_live|ghp_|xoxb-)[A-Za-z0-9]{10,}["\']?',
                'weight': 10,
                'context': 'Cloud service or platform API keys',
                'category': 'sensitive'
            },
            'Database Credentials': {
                'pattern': r'(?i)(user(name)?|password|pwd|pass)["\']?\s*[:=]\s*["\']?[^"\':\n]{3,}["\']?',
                'weight': 9,
                'context': 'Database access credentials',
                'category': 'sensitive'
            },
            'Test Credentials': {
                'pattern': r'["\']?(admin|test|root|user)["\']?\s*[:=]\s*["\']?(admin|1234|password|test)["\']?',
                'weight': 8,
                'context': 'Default or test credentials',
                'category': 'sensitive'
            },
            'JWT Tokens': {
                'pattern': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
                'weight': 8,
                'context': 'JSON Web Token - may contain sensitive claims',
                'category': 'sensitive'
            },
            'License Keys': {
                'pattern': r'(?i)(license|serial|activation)[-_ ]?(key|code)?["\']?\s*[:=]\s*["\']?[A-Z0-9\-]{15,}["\']?',
                'weight': 7,
                'context': 'Software license or activation keys',
                'category': 'sensitive'
            },
            'Potential SSRF': {
                'pattern': r'https?://(localhost|127\.0\.0\.1|169\.254\.\d+\.\d+)',
                'weight': 7,
                'context': 'URLs pointing to internal services',
                'category': 'security'
            },
            'Source Maps Available': {
                'pattern': r'//# sourceMappingURL=',
                'weight': 6,
                'context': 'Source maps exposed - original code readable',
                'category': 'technology'
            },
            'Internal IPs': {
                'pattern': r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b|localhost|::1|127\.0\.0\.1',
                'weight': 6,
                'context': 'Internal network addresses',
                'category': 'information'
            },
            'Debug Statements': {
                'pattern': r'\b(console\.log|debugger|print)\s*\(',
                'weight': 5,
                'context': 'Debug code in production',
                'category': 'technology'
            },
            'CORS Configuration': {
                'pattern': r'Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*["\']?|cors\(\)|allowedOrigins|Access-Control-Allow-Credentials["\']?\s*[:=]\s*["\']?true',
                'weight': 6,
                'context': 'CORS misconfiguration - wildcard origins or credentials',
                'category': 'security'
            },
            'React SPA': {
                'pattern': r'<div id="root"></div>|React|ReactDOM|react\.production\.min\.js|Symbol\.for\("react\.',
                'weight': 4,
                'context': 'SPA - API endpoints may be in JS bundles',
                'category': 'technology'
            },
            'Vue SPA': {
                'pattern': r'<div id="app"></div>|Vue\.js|vue@',
                'weight': 4,
                'context': 'Vue application - check for dev mode',
                'category': 'technology'
            },
            'Angular SPA': {
                'pattern': r'<app-root></app-root>|angular|@angular',
                'weight': 4,
                'context': 'Angular app - may expose API endpoints',
                'category': 'technology'
            },
            'Package Managers': {
                'pattern': r'package\.json|requirements\.txt|Pipfile|Gemfile|composer\.json',
                'weight': 4,
                'context': 'Dependency files exposed',
                'category': 'technology'
            },
            'Vite Build Tool': {
                'pattern': r'/vite\.svg|/assets/index-[A-Za-z0-9]+\.js',
                'weight': 4,
                'context': 'Modern bundler - check for source maps',
                'category': 'technology'
            },
            'Email Addresses': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'weight': 3,
                'context': 'Email addresses for reconnaissance',
                'category': 'information'
            },
            'Minified JavaScript': {
                'pattern': r'function [A-Za-z]{1,2}\(|var [a-z]{1,2}=',
                'weight': 3,
                'context': 'Production build - may contain secrets',
                'category': 'technology'
            },
            'Phone Numbers': {
                'pattern': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'weight': 2,
                'context': 'Phone numbers for social engineering',
                'category': 'information'
            }
        }
    
    def scan_content(self, content: str, script_content: str = "") -> Tuple[List[str], Dict[str, List[str]], Dict[str, Any]]:
        findings = []
        detailed_findings = {}
        risk_score = 0
        high_risk_findings = []
        file_findings = {'main': [], 'scripts': []}
        
        full_content = content + "\n" + script_content
        
        for pattern_name, pattern_info in self.patterns.items():
            matches = re.findall(pattern_info['pattern'], full_content, re.IGNORECASE)
            if matches:
                clean_matches = list(set([str(match) if isinstance(match, str) else str(match[0]) for match in matches]))[:10]
                findings.append(f'{pattern_name} found ({len(matches)} instances)')
                detailed_findings[pattern_name] = clean_matches
                
                main_matches = re.findall(pattern_info['pattern'], content, re.IGNORECASE)
                script_matches = re.findall(pattern_info['pattern'], script_content, re.IGNORECASE) if script_content else []
                
                if main_matches:
                    file_findings['main'].append(pattern_name)
                if script_matches:
                    file_findings['scripts'].append(pattern_name)
                
                risk_score += pattern_info['weight']
                if pattern_info['weight'] >= 8:
                    high_risk_findings.append(pattern_name)
        
        risk_level = 'Low'
        if risk_score >= 30:
            risk_level = 'High'
        elif risk_score >= 15:
            risk_level = 'Medium'
        
        risk_assessment = {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'high_risk_findings': high_risk_findings,
            'file_findings': file_findings,
            'top_findings': self._get_top_findings(findings, detailed_findings)
        }
        
        return findings, detailed_findings, risk_assessment
    
    def _get_top_findings(self, findings: List[str], detailed_findings: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        scored_findings = []
        
        # HTML structure finding weights
        html_weights = {
            'Inline scripts found': {'weight': 3, 'context': 'JavaScript code in HTML - check for secrets', 'category': 'technology'},
            'HTML forms found': {'weight': 3, 'context': 'Forms detected - potential attack surface', 'category': 'information'},
            'Login forms detected': {'weight': 4, 'context': 'Authentication forms - security testing target', 'category': 'information'},
            'Developer comments': {'weight': 5, 'context': 'Developer comments with sensitive keywords', 'category': 'information'},
            'JWT tokens in inline scripts': {'weight': 8, 'context': 'JWT tokens exposed in client-side code', 'category': 'sensitive'},
            'API keys in inline scripts': {'weight': 8, 'context': 'API keys exposed in client-side code', 'category': 'sensitive'},
            'Environment meta tags': {'weight': 4, 'context': 'Environment information in meta tags', 'category': 'information'}
        }
        
        for finding in findings:
            pattern_name = finding.split(' found')[0].split(' (')[0]
            
            # Check pattern scanner patterns first
            if pattern_name in self.patterns:
                scored_findings.append({
                    'name': pattern_name,
                    'score': self.patterns[pattern_name]['weight'],
                    'context': self.patterns[pattern_name]['context'],
                    'category': self.patterns[pattern_name]['category'],
                    'count': len(detailed_findings.get(pattern_name, []))
                })
            # Check HTML structure findings
            elif pattern_name in html_weights:
                scored_findings.append({
                    'name': pattern_name,
                    'score': html_weights[pattern_name]['weight'],
                    'context': html_weights[pattern_name]['context'],
                    'category': html_weights[pattern_name]['category'],
                    'count': len(detailed_findings.get(finding.split(' (')[0], []))
                })
        
        return sorted(scored_findings, key=lambda x: x['score'], reverse=True)[:3]
    
    def analyze_comments(self, content: str) -> Tuple[List[str], Dict[str, List[str]], int]:
        findings = []
        detailed_findings = {}
        comment_score = 0
        
        if '<!--' in content:
            comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
            if comments:
                todo_comments = [c for c in comments if re.search(r'(TODO|FIXME|HACK|BUG)', c, re.IGNORECASE)]
                cred_comments = [c for c in comments if re.search(r'(password|key|secret|token)', c, re.IGNORECASE)]
                debug_comments = [c for c in comments if re.search(r'(debug|test|dev)', c, re.IGNORECASE)]
                
                clean_comments = [comment.strip()[:100] + ('...' if len(comment.strip()) > 100 else '') for comment in comments[:5]]
                findings.append(f'HTML comments found ({len(comments)} instances)')
                detailed_findings['HTML comments found'] = clean_comments
                comment_score += 2
                
                if todo_comments:
                    findings.append(f'TODO/FIXME comments ({len(todo_comments)} instances)')
                    detailed_findings['TODO/FIXME comments'] = [c.strip()[:80] for c in todo_comments[:3]]
                    comment_score += 3
                
                if cred_comments:
                    findings.append(f'Credential-related comments ({len(cred_comments)} instances)')
                    detailed_findings['Credential-related comments'] = [c.strip()[:80] for c in cred_comments[:3]]
                    comment_score += 6
                
                if debug_comments:
                    findings.append(f'Debug-related comments ({len(debug_comments)} instances)')
                    detailed_findings['Debug-related comments'] = [c.strip()[:80] for c in debug_comments[:3]]
                    comment_score += 4
        
        return findings, detailed_findings, comment_score
    
    def detect_high_entropy_strings(self, content: str, min_length: int = 20) -> List[str]:
        high_entropy_strings = []
        
        potential_secrets = re.findall(r'["\']([A-Za-z0-9+/=]{20,})["\']', content)
        
        for string in potential_secrets:
            if len(string) >= min_length:
                counter = Counter(string)
                length = len(string)
                entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
                
                if entropy > 4.0:
                    high_entropy_strings.append(string[:50] + '...' if len(string) > 50 else string)
        
        return high_entropy_strings[:5]