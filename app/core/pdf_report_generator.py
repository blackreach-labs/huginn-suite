# app/core/pdf_report_generator.py
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os
from typing import Dict, List, Any
from app.core.logger import logger

class PDFReportGenerator:
    """Generate professional PDF reports from centralized scan data"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkred
        ))
        
        self.styles.add(ParagraphStyle(
            name='Finding',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            spaceAfter=6
        ))
    
    def generate_executive_report(self, output_path: str) -> bool:
        """Generate executive summary PDF report"""
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            
            # Title
            story.append(Paragraph("Security Assessment Executive Summary", self.styles['CustomTitle']))
            story.append(Spacer(1, 20))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
            
            # Get data from centralized system
            from .centralized_scan_data import centralized_scan_data
            try:
                overview = centralized_scan_data.get_tenant_overview(self.tenant_id)
                total_results = overview.get('total_results', 0)
                total_scans = overview.get('total_scans', 0)
            except Exception:
                total_results = 0
                total_scans = 0
            
            summary_text = f"""
            This report summarizes the security assessment conducted on {datetime.now().strftime('%B %d, %Y')}. 
            The assessment identified {total_results} findings across {total_scans} different scan types.
            """
            story.append(Paragraph(summary_text, self.styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Key Findings
            story.append(Paragraph("Key Findings", self.styles['SectionHeader']))
            
            # Get scan summaries
            scan_types = ["rpc_vulnerabilities", "dns_subdomains", "port_open_ports", "smb_shares", "http_directories", "ldap_users", "snmp_communities"]
            
            findings_data = []
            for scan_type in scan_types:
                try:
                    summary = centralized_scan_data.get_scan_summary(self.tenant_id, scan_type)
                    if summary.get('total_results', 0) > 0:
                        findings_data.append([
                            scan_type.replace('_', ' ').title(),
                            str(summary.get('total_results', 0)),
                            str(summary.get('unique_targets', 0)),
                            summary.get('last_scan_time', 'Never')[:10] if summary.get('last_scan_time', 'Never') != 'Never' else 'Never'
                        ])
                except Exception:
                    continue
            
            if findings_data:
                findings_table = Table([['Scan Type', 'Results', 'Targets', 'Last Scan']] + findings_data)
                findings_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(findings_table)
            
            story.append(Spacer(1, 20))
            
            # Recommendations
            story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
            recommendations = [
                "Implement network segmentation to limit lateral movement",
                "Enable logging and monitoring for all critical services",
                "Apply security patches to identified vulnerable services",
                "Implement strong authentication mechanisms",
                "Regular security assessments and penetration testing"
            ]
            
            for rec in recommendations:
                story.append(Paragraph(f"• {rec}", self.styles['Finding']))
            
            doc.build(story)
            return True
            
        except Exception as e:
            print(f"Error generating PDF report: {e}")
            return False
    
    def generate_technical_report(self, output_path: str) -> bool:
        """Generate detailed technical PDF report"""
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            
            # Title
            story.append(Paragraph("Technical Security Assessment Report", self.styles['CustomTitle']))
            story.append(Spacer(1, 20))
            
            # Get data
            from .centralized_scan_data import centralized_scan_data
            
            scan_types = [
                ("rpc_endpoints", "RPC Endpoints"),
                ("dns_subdomains", "DNS Subdomains"), 
                ("port_open_ports", "Open Ports"),
                ("smb_shares", "SMB Shares"),
                ("http_directories", "HTTP Directories"),
                ("ldap_users", "LDAP Users"),
                ("snmp_communities", "SNMP Communities")
            ]
            
            for scan_type, title in scan_types:
                try:
                    data = centralized_scan_data.get_scan_data(self.tenant_id, scan_type)
                except Exception:
                    data = []
                if data:
                    story.append(Paragraph(title, self.styles['SectionHeader']))
                    
                    # Create table data
                    if scan_type == "rpc_endpoints":
                        table_data = [['Target', 'Protocol', 'UUID', 'Port', 'Count']]
                        for item in data[:10]:  # Limit to 10 items
                            table_data.append([
                                item['target'],
                                item['data'].get('protocol', 'Unknown'),
                                item['data'].get('uuid', 'N/A')[:20] + '...' if len(item['data'].get('uuid', '')) > 20 else item['data'].get('uuid', 'N/A'),
                                str(item['data'].get('port', 'unknown')),
                                str(item['count'])
                            ])
                    elif scan_type == "dns_subdomains":
                        table_data = [['Target', 'Subdomain', 'Domain', 'Count']]
                        for item in data[:10]:
                            table_data.append([
                                item['target'],
                                item['data'].get('subdomain', 'Unknown'),
                                item['data'].get('domain', 'Unknown'),
                                str(item['count'])
                            ])
                    elif scan_type == "port_open_ports":
                        table_data = [['Target', 'Port', 'Service', 'Protocol', 'Count']]
                        for item in data[:10]:
                            table_data.append([
                                item['target'],
                                str(item['data'].get('port', 0)),
                                item['data'].get('service', 'unknown'),
                                item['data'].get('protocol', 'tcp'),
                                str(item['count'])
                            ])
                    else:
                        # Generic format
                        table_data = [['Target', 'Data', 'Count']]
                        for item in data[:10]:
                            table_data.append([
                                item['target'],
                                str(item['data'])[:50] + '...' if len(str(item['data'])) > 50 else str(item['data']),
                                str(item['count'])
                            ])
                    
                    if len(table_data) > 1:
                        table = Table(table_data)
                        table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        story.append(table)
                        story.append(Spacer(1, 15))
            
            doc.build(story)
            return True
            
        except Exception as e:
            print(f"Error generating technical PDF report: {e}")
            return False
    
    def generate_compliance_report(self, output_path: str, framework: str = 'OWASP_TOP_10') -> bool:
        """Generate compliance framework PDF report"""
        try:
            from .compliance_mapper import create_compliance_mapper
            
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            
            # Get compliance data
            mapper = create_compliance_mapper(self.tenant_id)
            compliance_data = mapper.generate_compliance_report(framework)
            
            # Title
            story.append(Paragraph(f"{compliance_data['framework']} Compliance Report", self.styles['CustomTitle']))
            story.append(Spacer(1, 20))
            
            # Compliance Score
            story.append(Paragraph("Compliance Overview", self.styles['SectionHeader']))
            score_text = f"""
            Compliance Score: {compliance_data['compliance_score']:.1f}%<br/>
            Total Findings: {compliance_data['total_findings']}<br/>
            Categories Covered: {compliance_data['summary']['covered_categories']}/{compliance_data['summary']['total_categories']}
            """
            story.append(Paragraph(score_text, self.styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Category Breakdown
            story.append(Paragraph("Category Analysis", self.styles['SectionHeader']))
            
            framework_info = mapper.frameworks[framework]
            for category_id, category_name in framework_info['categories'].items():
                findings = compliance_data['categories'].get(category_id, [])
                status = "✓ Covered" if findings else "✗ Not Covered"
                
                story.append(Paragraph(f"<b>{category_id}: {category_name}</b> - {status} ({len(findings)} findings)", self.styles['Normal']))
                
                if findings:
                    for finding in findings[:3]:  # Show first 3 findings
                        story.append(Paragraph(f"• {finding['target']}: {finding['type']}", self.styles['Finding']))
                    if len(findings) > 3:
                        story.append(Paragraph(f"• ... and {len(findings) - 3} more", self.styles['Finding']))
                
                story.append(Spacer(1, 10))
            
            doc.build(story)
            return True
            
        except Exception as e:
            print(f"Error generating compliance PDF report: {e}")
            return False

def create_pdf_generator(tenant_id: str = "default") -> PDFReportGenerator:
    """Create PDF report generator for specific tenant"""
    return PDFReportGenerator(tenant_id=tenant_id)