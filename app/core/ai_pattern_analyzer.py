import re
import json
from typing import Dict, List, Tuple
from collections import Counter

class AIPatternAnalyzer:
    """AI-powered pattern analysis for vulnerability correlation"""
    
    def __init__(self):
        self.vulnerability_patterns = {}
        self.response_signatures = {}
    
    def analyze_response_patterns(self, responses: List[Dict]) -> Dict:
        """Analyze response patterns to identify potential vulnerabilities"""
        patterns = {
            'error_patterns': [],
            'timing_anomalies': [],
            'content_variations': [],
            'header_inconsistencies': []
        }
        
        # Error pattern detection
        error_indicators = [
            r'sql.*error', r'mysql.*error', r'oracle.*error',
            r'stack\s+trace', r'exception.*occurred',
            r'warning.*line\s+\d+', r'fatal.*error'
        ]
        
        for response in responses:
            content = response.get('content', '').lower()
            for pattern in error_indicators:
                if re.search(pattern, content):
                    patterns['error_patterns'].append({
                        'url': response.get('url'),
                        'pattern': pattern,
                        'confidence': 0.8
                    })
        
        # Timing analysis for blind vulnerabilities
        response_times = [r.get('response_time', 0) for r in responses]
        avg_time = sum(response_times) / len(response_times) if response_times else 0
        
        for i, response in enumerate(responses):
            if response.get('response_time', 0) > avg_time * 3:
                patterns['timing_anomalies'].append({
                    'url': response.get('url'),
                    'delay': response.get('response_time'),
                    'confidence': 0.6
                })
        
        return patterns
    
    def correlate_vulnerabilities(self, vulnerabilities: List[Dict]) -> Dict:
        """Correlate vulnerabilities to identify attack chains"""
        correlations = {
            'attack_chains': [],
            'risk_amplifiers': [],
            'common_vectors': []
        }
        
        # Group by vulnerability type
        vuln_types = Counter([v['type'] for v in vulnerabilities])
        
        # Identify attack chains
        if 'SQL Injection' in vuln_types and 'Local File Inclusion' in vuln_types:
            correlations['attack_chains'].append({
                'chain': 'SQLi -> LFI -> RCE',
                'description': 'SQL injection can lead to file read, combined with LFI for code execution',
                'severity': 'Critical',
                'impact': 'Complete system compromise'
            })
        
        if 'Cross-Site Scripting' in vuln_types and 'Missing Security Header' in vuln_types:
            correlations['risk_amplifiers'].append({
                'amplifier': 'XSS + Missing CSP',
                'description': 'XSS impact amplified by missing Content Security Policy',
                'risk_increase': '40%'
            })
        
        return correlations
    
    def generate_insights(self, scan_results: Dict) -> List[str]:
        """Generate AI-powered insights from scan results"""
        insights = []
        vulns = scan_results.get('vulnerabilities', [])
        
        # Technology-specific insights
        tech_stack = scan_results.get('tech_stack', [])
        if 'WordPress' in tech_stack:
            wp_vulns = [v for v in vulns if 'wp-' in v.get('url', '')]
            if wp_vulns:
                insights.append(f"WordPress installation detected with {len(wp_vulns)} plugin-related vulnerabilities")
        
        # Severity distribution analysis
        severity_counts = Counter([v.get('severity') for v in vulns])
        if severity_counts.get('Critical', 0) > 3:
            insights.append("High concentration of critical vulnerabilities suggests systemic security issues")
        
        # Common vulnerability patterns
        if len([v for v in vulns if 'injection' in v.get('type', '').lower()]) > 2:
            insights.append("Multiple injection vulnerabilities indicate insufficient input validation")
        
        return insights