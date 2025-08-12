# app/pages/db_attacks_page.py
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout
from PyQt6.QtCore import pyqtSignal
from app.pages.components.base_page import BasePage
from app.components.db_attacks.sql_injection_component import SqlInjectionComponent
from app.components.db_attacks.database_enumeration_component import DatabaseEnumerationComponent
from app.components.db_attacks.privilege_escalation_component import PrivilegeEscalationComponent
from app.components.db_attacks.data_extraction_component import DataExtractionComponent
from app.components.progress_component import ProgressComponent

class DbAttacksPage(BasePage):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
    
    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        self.setup_components()
        self.setup_layout()

    def setup_components(self):
        try:
            self.sql_injection = SqlInjectionComponent()
        except Exception:
            pass
        try:
            self.db_enumeration = DatabaseEnumerationComponent()
        except Exception:
            pass
        try:
            self.privilege_escalation = PrivilegeEscalationComponent()
        except Exception:
            pass
        try:
            self.data_extraction = DataExtractionComponent()
        except Exception:
            pass
        try:
            self.progress = ProgressComponent()
        except Exception:
            pass

    def setup_layout(self):
        main_layout = QVBoxLayout(self)
        
        # Database enumeration gets full width (like File > Databases)
        if hasattr(self, 'db_enumeration'):
            main_layout.addWidget(self.db_enumeration)
        
        # Other components in horizontal layout
        other_layout = QHBoxLayout()
        if hasattr(self, 'sql_injection'):
            other_layout.addWidget(self.sql_injection)
        if hasattr(self, 'privilege_escalation'):
            other_layout.addWidget(self.privilege_escalation)
        if hasattr(self, 'data_extraction'):
            other_layout.addWidget(self.data_extraction)
        main_layout.addLayout(other_layout)
        
        # Progress component
        if hasattr(self, 'progress'):
            main_layout.addWidget(self.progress)

    def on_back_clicked(self):
        self.navigate_signal.emit("home")