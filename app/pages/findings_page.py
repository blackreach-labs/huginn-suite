# app/pages/findings_page_new.py
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QTabWidget, QFrame
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QShortcut, QKeySequence

from app.pages.components.base_page import BasePage
from app.components.findings.findings_list_component import FindingsListComponent
from app.components.findings.findings_details_component import FindingsDetailsComponent
from app.components.findings.advanced_reporting_component import AdvancedReportingComponent

class FindingsPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(parent)

    def setup_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        self.create_tab_widget()
        self.setup_shortcuts()
        self.apply_theme()

    def create_tab_widget(self):
        self.tab_widget = QTabWidget()
        
        # Findings tab
        findings_tab = self.create_findings_tab()
        self.tab_widget.addTab(findings_tab, "Common Findings")
        
        # Advanced Reporting tab
        reporting_tab = self.create_reporting_tab()
        self.tab_widget.addTab(reporting_tab, "Advanced Reporting")
        
        self.main_layout.addWidget(self.tab_widget)

    def create_findings_tab(self):
        tab = QFrame()
        content_layout = QHBoxLayout(tab)
        
        # Left panel - findings list
        self.findings_list = FindingsListComponent()
        self.findings_list.setFixedWidth(300)
        content_layout.addWidget(self.findings_list, 0)
        
        # Right panel - details
        self.findings_details = FindingsDetailsComponent()
        content_layout.addWidget(self.findings_details, 1)
        
        return tab

    def create_reporting_tab(self):
        self.reporting_component = AdvancedReportingComponent()
        return self.reporting_component

    def connect_signals(self):
        # Connect findings list to details
        self.findings_list.finding_selected.connect(self.findings_details.show_finding_details)
        self.findings_list.finding_hovered.connect(self.findings_details.show_hover_info)
        self.findings_list.finding_unhovered.connect(self.findings_details.show_default_content)
        
        # Connect reporting signals
        self.reporting_component.status_updated.connect(self.status_updated.emit)

    def apply_theme(self):
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QTabWidget::pane {
                border: 1px solid rgba(100, 200, 255, 50);
                background-color: rgba(0, 0, 0, 50);
            }
            QTabBar::tab {
                background-color: rgba(30, 40, 50, 150);
                color: #DCDCDC;
                padding: 8px 16px;
                margin-right: 2px;
                border-radius: 4px 4px 0px 0px;
            }
            QTabBar::tab:selected {
                background-color: rgba(50, 70, 90, 200);
                color: #64C8FF;
                border: 2px solid rgba(100, 200, 255, 100);
                border-bottom: none;
            }
            QTabBar::tab:hover {
                background-color: rgba(40, 60, 80, 180);
            }
        """)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))

    def get_page_title(self):
        return "Findings & Reporting"

    def get_page_icon(self):
        return "findings_icon.png"