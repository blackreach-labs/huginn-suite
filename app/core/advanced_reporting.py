# app/core/advanced_reporting.py
"""
Advanced Reporting System
Generates comprehensive reports from collected vulnerability data
"""
import json
import os
from datetime import datetime
from typing import Dict, List
from .vulnerability_database import vuln_db, VulnerabilityFinding
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

class AdvancedReportGenerator:
    """Advanced report generator for vulnerability findings"""
    
    def __init__(self):
        self.report_templates = {
            'executive': self._generate_executive_report,
            'executive_summary': self._generate_executive_report,
            'technical': self._generate_technical_report,
            'compliance': self._generate_compliance_report,
            'remediation': self._generate_remediation_report,
            'vulnerability_assessment': self._generate_technical_report
        }
    
    def generate_report(self, report_type: str, session_id: str = None, output_path: str = None, target_filter: str = None) -> str:
        """Generate comprehensive report"""
        if report_type not in self.report_templates:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Get vulnerability data
        vulnerabilities = vuln_db.get_all_vulnerabilities(session_id)
        
        # Filter by target if specified
        if target_filter:
            vulnerabilities = [v for v in vulnerabilities if 
                             (hasattr(v, 'target') and v.target == target_filter) or 
                             (isinstance(v, dict) and v.get('target') == target_filter)]
        
        session_stats = vuln_db.get_session_statistics(session_id) if session_id else None
        
        # Generate report content
        report_content = self.report_templates[report_type](vulnerabilities, session_stats)
        
        # Save to file if path provided
        if output_path:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Determine output format from file extension
            file_ext = os.path.splitext(output_path)[1].lower()
            
            if file_ext == '.pdf':
                self._generate_pdf_report(report_content, output_path)
            elif file_ext == '.html':
                self._generate_html_report(report_content, output_path)
            elif file_ext == '.json':
                self._generate_json_report(vulnerabilities, session_stats, output_path)
            else:
                # Default to text format
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(report_content)
        
        return report_content
    
    def _generate_executive_report(self, vulnerabilities: List[VulnerabilityFinding], stats: Dict) -> str:
        """Generate executive summary report"""
        report = []
        
        # Header
        report.append("# EXECUTIVE SECURITY ASSESSMENT SUMMARY")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")
        
        # Executive Summary
        if vulnerabilities:
            # Group by target
            targets = {}
            for vuln in vulnerabilities:
                target = getattr(vuln, 'target', 'Unknown') if hasattr(vuln, 'target') else vuln.get('target', 'Unknown')
                if target not in targets:
                    targets[target] = []
                targets[target].append(vuln)
            
            report.append("## EXECUTIVE SUMMARY")
            report.append(f"• **Targets Assessed**: {len(targets)}")
            report.append(f"• **Total Vulnerabilities**: {len(vulnerabilities)}")
            
            # Count by severity
            critical = sum(1 for v in vulnerabilities if self._get_severity(v) == 'Critical')
            high = sum(1 for v in vulnerabilities if self._get_severity(v) == 'High')
            medium = sum(1 for v in vulnerabilities if self._get_severity(v) == 'Medium')
            
            report.append(f"• **Critical Issues**: {critical}")
            report.append(f"• **High Risk Issues**: {high}")
            report.append(f"• **Medium Risk Issues**: {medium}")
            report.append("")
            
            # Per-target breakdown
            for target, target_vulns in targets.items():
                report.append(f"## TARGET: {target}")
                report.append(f"• Vulnerabilities Found: {len(target_vulns)}")
                
                # Top vulnerabilities for this target
                critical_vulns = [v for v in target_vulns if self._get_severity(v) == 'Critical']
                if critical_vulns:
                    report.append("• **CRITICAL ISSUES:**")
                    for vuln in critical_vulns[:3]:  # Top 3
                        name = self._get_name(vuln)
                        report.append(f"  - {name}")
                
                high_vulns = [v for v in target_vulns if self._get_severity(v) == 'High']
                if high_vulns:
                    report.append("• **HIGH RISK ISSUES:**")
                    for vuln in high_vulns[:3]:  # Top 3
                        name = self._get_name(vuln)
                        report.append(f"  - {name}")
                
                report.append("")
        else:
            report.append("## EXECUTIVE SUMMARY")
            report.append("• No vulnerabilities found in current scan data")
            report.append("")
        
        return "\n".join(report)
    
    def _generate_technical_report(self, vulnerabilities: List[VulnerabilityFinding], stats: Dict) -> str:
        """Generate detailed technical report"""
        report = []
        
        # Header
        report.append("# TECHNICAL VULNERABILITY ASSESSMENT REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 70)
        report.append("")
        
        if vulnerabilities:
            # Group by target
            targets = {}
            for vuln in vulnerabilities:
                target = getattr(vuln, 'target', 'Unknown') if hasattr(vuln, 'target') else vuln.get('target', 'Unknown')
                if target not in targets:
                    targets[target] = []
                targets[target].append(vuln)
            
            for target, target_vulns in targets.items():
                report.append(f"## TARGET: {target}")
                report.append("")
                
                # Group by severity
                by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
                for vuln in target_vulns:
                    severity = self._get_severity(vuln)
                    if severity in by_severity:
                        by_severity[severity].append(vuln)
                
                for severity, vulns in by_severity.items():
                    if vulns:
                        report.append(f"### {severity.upper()} SEVERITY ({len(vulns)} issues)")
                        for vuln in vulns:
                            name = self._get_name(vuln)
                            desc = self._get_description(vuln)
                            cve = self._get_cve(vuln)
                            
                            report.append(f"**{name}**")
                            if cve:
                                report.append(f"CVE: {cve}")
                            report.append(f"Description: {desc}")
                            report.append("")
                
                report.append("")
        else:
            report.append("No vulnerabilities found in current scan data.")
        
        return "\n".join(report)
    
    def _generate_compliance_report(self, vulnerabilities: List[VulnerabilityFinding], stats: Dict) -> str:
        """Generate compliance-focused report"""
        report = []
        
        # Header
        report.append("# SECURITY COMPLIANCE ASSESSMENT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 50)
        report.append("")
        
        return "\n".join(report)
    
    def _generate_remediation_report(self, vulnerabilities: List[VulnerabilityFinding], stats: Dict) -> str:
        """Generate remediation-focused report"""
        report = []
        
        # Header
        report.append("# VULNERABILITY REMEDIATION GUIDE")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 50)
        report.append("")
        
        return "\n".join(report)
    
    def generate_json_export(self, session_id: str = None) -> str:
        """Generate JSON export of vulnerability data"""
        vulnerabilities = vuln_db.get_all_vulnerabilities(session_id)
        stats = vuln_db.get_session_statistics(session_id) if session_id else None
        
        export_data = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'session_id': session_id,
                'total_vulnerabilities': len(vulnerabilities)
            },
            'statistics': stats,
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities]
        }
        
        return json.dumps(export_data, indent=2)
    
    def _get_severity(self, vuln) -> str:
        """Extract severity from vulnerability object"""
        if hasattr(vuln, 'severity'):
            return vuln.severity
        elif isinstance(vuln, dict):
            return vuln.get('severity', 'Unknown')
        return 'Unknown'
    
    def _get_name(self, vuln) -> str:
        """Extract name from vulnerability object"""
        if hasattr(vuln, 'name'):
            return vuln.name
        elif isinstance(vuln, dict):
            return vuln.get('name', 'Unknown Vulnerability')
        return 'Unknown Vulnerability'
    
    def _get_description(self, vuln) -> str:
        """Extract description from vulnerability object"""
        if hasattr(vuln, 'description'):
            return vuln.description
        elif isinstance(vuln, dict):
            return vuln.get('description', 'No description available')
        return 'No description available'
    
    def _get_cve(self, vuln) -> str:
        """Extract CVE from vulnerability object"""
        if hasattr(vuln, 'cve_id'):
            return vuln.cve_id
        elif isinstance(vuln, dict):
            return vuln.get('cve_id', '')
        return ''

    def _generate_pdf_report(self, content: str, output_path: str):
        """Generate PDF report using reportlab"""
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF generation. Install with: pip install reportlab")
        
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Split content into lines and convert to PDF elements
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                story.append(Spacer(1, 12))
            elif line.startswith('# '):
                # Main heading
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=16,
                    spaceAfter=30,
                    textColor='black'
                )
                story.append(Paragraph(line[2:], title_style))
            elif line.startswith('## '):
                # Sub heading
                story.append(Paragraph(line[3:], styles['Heading2']))
            elif line.startswith('• '):
                # Bullet point
                story.append(Paragraph(line, styles['Normal']))
            elif line.startswith('='):
                # Skip separator lines
                continue
            else:
                # Normal text
                story.append(Paragraph(line, styles['Normal']))
        
        doc.build(story)
    
    def _generate_html_report(self, content: str, output_path: str):
        """Generate HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
{self._markdown_to_html(content)}
</body>
</html>"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_json_report(self, vulnerabilities: List, session_stats: Dict, output_path: str):
        """Generate JSON report"""
        json_data = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities)
            },
            'statistics': session_stats,
            'vulnerabilities': [vuln.to_dict() if hasattr(vuln, 'to_dict') else str(vuln) for vuln in vulnerabilities]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2)
    
    def _markdown_to_html(self, content: str) -> str:
        """Convert markdown-like content to HTML"""
        html_lines = []
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('# '):
                html_lines.append(f'<h1>{line[2:]}</h1>')
            elif line.startswith('## '):
                html_lines.append(f'<h2>{line[3:]}</h2>')
            elif line.startswith('• '):
                html_lines.append(f'<li>{line[2:]}</li>')
            elif line.startswith('**') and line.endswith('**'):
                html_lines.append(f'<strong>{line[2:-2]}</strong>')
            elif line.startswith('='):
                continue
            elif line:
                html_lines.append(f'<p>{line}</p>')
            else:
                html_lines.append('<br>')
        
        return '\n'.join(html_lines)

# Global report generator instance
report_generator = AdvancedReportGenerator()