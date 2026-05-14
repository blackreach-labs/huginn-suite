# app/components/findings/findings_list_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QPushButton, QSizePolicy
from PyQt6.QtCore import pyqtSignal

class HoverButton(QPushButton):
    enter_signal = pyqtSignal(str, str)
    leave_signal = pyqtSignal()

    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        self.title = title
        self.description = description

    def enterEvent(self, event):
        super().enterEvent(event)
        self.enter_signal.emit(self.title, self.description)

    def leaveEvent(self, event):
        super().leaveEvent(event)
        self.leave_signal.emit()

class FindingsListComponent(QWidget):
    finding_selected = pyqtSignal(dict)
    finding_hovered = pyqtSignal(str, str)
    finding_unhovered = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.findings_data = [
            {"id": "default_pages", "title": "Default Web Pages", "desc": "Identify default installation pages that reveal system information."},
            {"id": "historical_compromise", "title": "Historical Compromises", "desc": "Check for previously compromised accounts and credentials."},
            {"id": "insufficient_auth", "title": "Insufficient Authentication", "desc": "Weak or missing authentication controls."},
            {"id": "sql_injection", "title": "SQL Injection", "desc": "Database query manipulation vulnerabilities."},
            {"id": "weak_passwords", "title": "Weak Password Policy", "desc": "Inadequate password requirements and default credentials."},
        ]
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        for finding in self.findings_data:
            button = HoverButton(finding["title"], finding["desc"], self)
            button.setText(finding["title"])
            button.setMinimumHeight(50)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(lambda checked, f=finding: self.finding_selected.emit(f))
            button.enter_signal.connect(self.finding_hovered.emit)
            button.leave_signal.connect(self.finding_unhovered.emit)
            scroll_layout.addWidget(button)

        scroll_layout.addStretch()

        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)