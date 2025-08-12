# app/pages/owasp_api_page.py
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QFrame
from PyQt6.QtCore import pyqtSignal
from app.pages.components.base_page import BasePage
from app.components.owasp_api.api_risk_list_component import APIRiskListComponent
from app.components.owasp_api.api_risk_details_component import APIRiskDetailsComponent

class OWASPAPIPage(BasePage):
    """OWASP API Security Top 10 testing page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
    
    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        try:
            self.setup_page()
        except Exception:
            pass
    
    def setup_page(self):
        """Setup page layout and components"""
        # Create main layout
        layout = QVBoxLayout(self)
        
        # Create horizontal layout for two-panel design
        main_layout = QHBoxLayout()
        
        # Left panel - Risk list
        try:
            self.risk_list_component = APIRiskListComponent()
            main_layout.addWidget(self.risk_list_component)
        except Exception:
            pass
        
        # Right panel - Risk details
        try:
            self.details_component = APIRiskDetailsComponent()
            main_layout.addWidget(self.details_component)
        except Exception:
            pass
        
        layout.addLayout(main_layout)