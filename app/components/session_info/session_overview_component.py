# app/components/session_info/session_overview_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QGroupBox
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QFont

class SessionOverviewComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Session info group
        info_group = QGroupBox("Session Information")
        
        info_layout = QVBoxLayout(info_group)
        
        self.session_info_text = QTextEdit()
        self.session_info_text.setReadOnly(True)
        self.session_info_text.setMaximumHeight(200)
        
        info_layout.addWidget(self.session_info_text)
        
        # Quick stats group
        stats_group = QGroupBox("Quick Statistics")
        
        stats_layout = QHBoxLayout(stats_group)
        
        self.scans_count_label = QLabel("Scans: 0")
        self.exports_count_label = QLabel("Exports: 0")
        self.targets_count_label = QLabel("Targets: 0")
        self.results_count_label = QLabel("Results: 0")
        
        stats_layout.addWidget(self.scans_count_label)
        stats_layout.addWidget(self.exports_count_label)
        stats_layout.addWidget(self.targets_count_label)
        stats_layout.addWidget(self.results_count_label)
        
        layout.addWidget(info_group)
        layout.addWidget(stats_group)
        layout.addStretch()

    def update_session_info(self, session):
        """Update session information display"""
        info_text = f"Session: {session['name']}\n"
        info_text += f"ID: {session['id']}\n"
        info_text += f"Created: {session.get('created_date', 'N/A')}\n"
        info_text += f"Description: {session.get('description', 'N/A')}\n"
        info_text += f"Status: {session.get('status', 'active')}\n"
        
        targets = session.get('targets', [])
        if targets:
            info_text += f"\nTargets ({len(targets)}): {', '.join(targets)}"
        
        self.session_info_text.setPlainText(info_text)

    def update_statistics(self, stats):
        """Update quick statistics"""
        self.scans_count_label.setText(f"Scans: {stats.get('total_scans', 0)}")
        self.exports_count_label.setText(f"Exports: {stats.get('total_exports', 0)}")
        self.targets_count_label.setText(f"Targets: {stats.get('targets_scanned', 0)}")
        self.results_count_label.setText(f"Results: {stats.get('total_results', 0)}")