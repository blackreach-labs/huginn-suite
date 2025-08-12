# app/widgets/summary_widget.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QProgressBar
from PyQt6.QtCore import Qt
import json

class SummaryWidget(QWidget):
    """Widget to display executive summary"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = QLabel("📊 Executive Summary")
        header.setStyleSheet("color: #64C8FF; font-size: 14pt; font-weight: bold;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Risk overview section
        risk_layout = QHBoxLayout()
        
        # Risk breakdown
        self.risk_label = QLabel("Risk Assessment:")
        self.risk_label.setStyleSheet("color: #FFAA00; font-weight: bold;")
        
        self.risk_bar = QProgressBar()
        self.risk_bar.setFixedHeight(20)
        self.risk_bar.setRange(0, 100)
        self.risk_bar.setValue(0)
        
        risk_layout.addWidget(self.risk_label)
        risk_layout.addWidget(self.risk_bar)
        
        # Summary text area
        self.summary_text = QTextEdit()
        self.summary_text.setFixedHeight(150)
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 8px;
            }
        """)
        
        layout.addWidget(header)
        layout.addLayout(risk_layout)
        layout.addWidget(self.summary_text)
        
    def display_summary(self, summary_data):
        """Display executive summary data"""
        if isinstance(summary_data, str):
            try:
                summary_data = json.loads(summary_data)
            except:
                self.summary_text.setPlainText("Invalid summary data")
                return
        
        # Update risk assessment
        risks = summary_data.get('risk_breakdown', {})
        total_findings = summary_data.get('total_findings', 0)
        
        if total_findings > 0:
            # Calculate risk score (weighted)
            risk_score = 0
            risk_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
            for risk_type, count in risks.items():
                risk_score += count * risk_weights.get(risk_type, 0)
            
            # Normalize to percentage
            max_possible = total_findings * 4  # All critical
            risk_percentage = min(100, (risk_score / max_possible * 100)) if max_possible > 0 else 0
            
            self.risk_bar.setValue(int(risk_percentage))
            self.risk_label.setText(f"Risk Level: {self._get_risk_level(risk_percentage)}")
            
            # Set color based on risk
            if risk_percentage > 75:
                color = "#FF4444"
            elif risk_percentage > 50:
                color = "#FF6600"
            elif risk_percentage > 25:
                color = "#FFAA00"
            else:
                color = "#00AA00"
                
            self.risk_bar.setStyleSheet(f"""
                QProgressBar::chunk {{
                    background-color: {color};
                }}
            """)
        
        # Format summary text
        summary_html = f"""
        <h3 style='color: #64C8FF;'>Executive Overview</h3>
        <p>{summary_data.get('executive_overview', 'No overview available')}</p>
        
        <h4 style='color: #FFAA00;'>Key Findings ({total_findings} total):</h4>
        <ul>
        """
        
        for finding in summary_data.get('key_findings', [])[:5]:  # Limit to 5
            summary_html += f"<li>{finding}</li>"
        
        summary_html += "</ul><h4 style='color: #00FF41;'>Recommendations:</h4><ul>"
        
        for rec in summary_data.get('recommendations', [])[:3]:  # Limit to 3
            summary_html += f"<li>{rec}</li>"
        
        summary_html += "</ul>"
        
        self.summary_text.setHtml(summary_html)
    
    def _get_risk_level(self, percentage):
        """Get risk level text from percentage"""
        if percentage > 75:
            return "CRITICAL"
        elif percentage > 50:
            return "HIGH"
        elif percentage > 25:
            return "MEDIUM"
        else:
            return "LOW"