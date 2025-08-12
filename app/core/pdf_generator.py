# app/core/pdf_generator.py
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from datetime import datetime
import os

class PDFGenerator:
    """Generate PDF reports from scan results"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1  # Center
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkgreen,
            borderWidth=1,
            borderColor=colors.darkgreen,
            borderPadding=5
        ))
    
    def generate_report(self, results, target, scan_type, output_path):
        """Generate PDF report from scan results"""
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            
            # Title
            title = Paragraph(f"Huggin Scan Report", self.styles['CustomTitle'])
            story.append(title)
            story.append(Spacer(1, 20))
            
            # Scan info table
            scan_info = [
                ['Target:', target],
                ['Scan Type:', scan_type.replace('_', ' ').title()],
                ['Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Results Found:', str(len(results)) if isinstance(results, dict) else 'N/A']
            ]
            
            info_table = Table(scan_info, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 12),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(info_table)
            story.append(Spacer(1, 30))
            
            # Results section
            story.append(Paragraph("Scan Results", self.styles['SectionHeader']))
            story.append(Spacer(1, 12))
            
            if isinstance(results, dict) and results:
                self._add_dict_results(story, results)
            elif isinstance(results, list) and results:
                self._add_list_results(story, results)
            else:
                story.append(Paragraph("No results found.", self.styles['Normal']))
            
            # Build PDF
            doc.build(story)
            return True, output_path, "PDF generated successfully"
            
        except Exception as e:
            return False, None, f"PDF generation failed: {str(e)}"
    
    def generate_executive_pdf(self, summary_data, output_path):
        """Generate executive summary PDF"""
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            story = []
            
            # Title
            title = Paragraph("Executive Security Summary", self.styles['CustomTitle'])
            story.append(title)
            story.append(Spacer(1, 20))
            
            # Executive overview
            story.append(Paragraph("Executive Overview", self.styles['SectionHeader']))
            story.append(Paragraph(summary_data.get('executive_overview', ''), self.styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Risk breakdown
            risks = summary_data.get('risk_breakdown', {})
            if risks:
                story.append(Paragraph("Risk Assessment", self.styles['SectionHeader']))
                risk_data = [['Risk Level', 'Count']]
                for risk, count in risks.items():
                    risk_data.append([risk.title(), str(count)])
                
                risk_table = Table(risk_data, colWidths=[2*inch, 1*inch])
                risk_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(risk_table)
                story.append(Spacer(1, 20))
            
            # Key findings
            findings = summary_data.get('key_findings', [])
            if findings:
                story.append(Paragraph("Key Findings", self.styles['SectionHeader']))
                for finding in findings:
                    story.append(Paragraph(f"• {finding}", self.styles['Normal']))
                    story.append(Spacer(1, 6))
                story.append(Spacer(1, 20))
            
            # Recommendations
            recommendations = summary_data.get('recommendations', [])
            if recommendations:
                story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
                for rec in recommendations:
                    story.append(Paragraph(f"• {rec}", self.styles['Normal']))
                    story.append(Spacer(1, 6))
            
            doc.build(story)
            return True, output_path, "Executive summary PDF generated"
            
        except Exception as e:
            return False, None, f"Executive PDF generation failed: {str(e)}"
    
    def _add_dict_results(self, story, results):
        """Add dictionary results to PDF"""
        for domain, records in results.items():
            # Domain header
            story.append(Paragraph(f"<b>{domain}</b>", self.styles['Heading3']))
            
            # Records table
            table_data = [['Record Type', 'Value']]
            for record_type, values in records.items():
                if isinstance(values, list):
                    for value in values:
                        table_data.append([record_type, str(value)])
                else:
                    table_data.append([record_type, str(values)])
            
            if len(table_data) > 1:  # Has data beyond header
                table = Table(table_data, colWidths=[1.5*inch, 4*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(table)
            
            story.append(Spacer(1, 12))
    
    def _add_list_results(self, story, results):
        """Add list results to PDF"""
        for i, item in enumerate(results, 1):
            story.append(Paragraph(f"{i}. {str(item)}", self.styles['Normal']))
            story.append(Spacer(1, 6))

# Global instance
pdf_generator = PDFGenerator()