# app/pages/cracking_page.py
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout
from PyQt6.QtCore import pyqtSignal
from app.pages.components.base_page import BasePage
from app.components.cracking.hash_analysis_component import HashAnalysisComponent
from app.components.cracking.attack_configuration_component import AttackConfigurationComponent
from app.components.cracking.live_attacks_component import LiveAttacksComponent
from app.components.cracking.results_management_component import ResultsManagementComponent
from app.components.cracking.hash_lookup_component import HashLookupComponent
from app.components.progress_component import ProgressComponent

class CrackingPage(BasePage):
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)


    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        try:
            self.setup_layout()
        except Exception:
            pass
        try:
            self.setup_components()
        except Exception:
            pass

    def setup_components(self):
        self.hash_analysis = HashAnalysisComponent()
        self.hash_lookup = HashLookupComponent()
        self.attack_config = AttackConfigurationComponent()
        self.live_attacks = LiveAttacksComponent()
        self.results_mgmt = ResultsManagementComponent()
        self.progress = ProgressComponent()

    def setup_layout(self):
        main_layout = QVBoxLayout()
        
        # Hash lookup at top
        main_layout.addWidget(self.hash_lookup)
        
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.hash_analysis)
        top_layout.addWidget(self.attack_config)
        main_layout.addLayout(top_layout)
        
        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.live_attacks)
        bottom_layout.addWidget(self.results_mgmt)
        main_layout.addLayout(bottom_layout)
        
        main_layout.addWidget(self.progress)
        
        self.content_area.setLayout(main_layout)

    def on_back_clicked(self):
        self.navigate_signal.emit("home")