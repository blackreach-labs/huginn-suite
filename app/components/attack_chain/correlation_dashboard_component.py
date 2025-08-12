# app/components/attack_chain/correlation_dashboard_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTabWidget
from PyQt6.QtCore import pyqtSignal

class CorrelationDashboardComponent(QWidget):
    """Cross-scan correlation dashboard component"""
    
    status_updated = pyqtSignal(str)
    
    def __init__(self, tenant_id="default", parent=None):
        super().__init__(parent)
        self.tenant_id = tenant_id
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Dashboard header
        header = QLabel("🔗 Correlation Dashboard")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # Correlation tabs
        tabs = QTabWidget()
        
        # Findings correlation tab
        findings_tab = QWidget()
        findings_layout = QVBoxLayout(findings_tab)
        findings_layout.addWidget(QLabel("Cross-scan findings correlation"))
        tabs.addTab(findings_tab, "Findings")
        
        # Attack paths tab
        paths_tab = QWidget()
        paths_layout = QVBoxLayout(paths_tab)
        paths_layout.addWidget(QLabel("Attack path analysis"))
        tabs.addTab(paths_tab, "Attack Paths")
        
        layout.addWidget(tabs)
    
    def refresh_correlations(self):
        """Refresh correlation data"""
        self.status_updated.emit("Correlations refreshed")