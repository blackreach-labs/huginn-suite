# app/pages/scripts_page_new.py
from PyQt6.QtWidgets import QVBoxLayout, QTabWidget
from PyQt6.QtGui import QShortcut, QKeySequence

from app.pages.components.base_page import BasePage
from app.components.scripts.reverse_shells_component import ReverseShellsComponent
from app.components.scripts.exploitation_tools_component import ExploitationToolsComponent
from app.components.scripts.code_templates_component import CodeTemplatesComponent

class ScriptsPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(parent)

    def setup_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(20, 20, 20, 20)
        self.main_layout.setSpacing(15)

        self.create_content_area()
        self.setup_shortcuts()
        self.apply_theme()

    def create_content_area(self):
        self.tab_widget = QTabWidget()
        
        # Reverse Shells Tab
        self.shells_component = ReverseShellsComponent()
        self.tab_widget.addTab(self.shells_component, "Reverse Shells")
        
        # Exploitation Tab
        self.exploit_component = ExploitationToolsComponent()
        self.tab_widget.addTab(self.exploit_component, "Exploitation")
        
        # Code Templates Tab
        self.templates_component = CodeTemplatesComponent()
        self.tab_widget.addTab(self.templates_component, "Code Templates")
        
        self.main_layout.addWidget(self.tab_widget)

    def connect_signals(self):
        # Connect shell component signals
        self.shells_component.status_updated.connect(self.status_updated.emit)

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
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
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
            }
            QTabBar::tab:selected {
                background-color: rgba(50, 70, 90, 200);
                color: #64C8FF;
            }
        """)

    def setup_shortcuts(self):
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))

    def get_page_title(self):
        return "Scripts & Tools"

    def get_page_icon(self):
        return "scripts_icon.png"