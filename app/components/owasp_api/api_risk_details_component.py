# app/components/owasp_api/api_risk_details_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit
from PyQt6.QtCore import pyqtSignal

class APIRiskDetailsComponent(QWidget):
    """OWASP API risk details display component"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.show_default_content()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Details text area
        self.details_area = QTextEdit()
        self.details_area.setReadOnly(True)
        self.details_area.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 100);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 12pt;
                padding: 15px;
            }
        """)
        layout.addWidget(self.details_area)
    
    def show_default_content(self):
        """Show default OWASP API content"""
        self.details_area.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 20px;'>
            OWASP API Security Top 10 - 2023
        </div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
            The OWASP API Security Top 10 represents the most critical security risks to APIs.
            <br><br>
            <i>Click on any risk category to view detailed information, attack scenarios, and prevention methods.</i>
            <br><br>
            <b>Key Areas Covered:</b>
            <ul>
                <li>Authorization and Authentication Issues</li>
                <li>Data Exposure and Mass Assignment</li>
                <li>Resource Consumption and Rate Limiting</li>
                <li>Business Logic and Flow Protection</li>
                <li>Configuration and Inventory Management</li>
            </ul>
        </div>
        """)
    
    def show_risk_details(self, risk_data):
        """Display details for selected risk"""
        self.details_area.setHtml(f"""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold; margin-bottom: 15px;'>
            {risk_data["title"]}
        </div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
            {risk_data.get("details", "Detailed information not available.")}
        </div>
        """)
    
    def show_hover_info(self, title, description):
        """Show hover information"""
        self.details_area.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold; margin-bottom: 10px;'>
            {title}
        </div>
        <div style='color: #DCDCDC; font-size: 14pt; line-height: 150%;'>
            {description}
        </div>
        """)
    
    def clear_hover_info(self):
        """Clear hover information and return to default"""
        self.show_default_content()