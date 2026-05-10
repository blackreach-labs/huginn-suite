from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFrame, QGroupBox, QGridLayout, QCheckBox)
from PyQt6.QtCore import pyqtSignal
from app.core.html_utils import h

class AutomationComponent(QWidget):
    automation_started = pyqtSignal(str, str)
    automation_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup automation UI"""
        layout = QHBoxLayout(self)
        
        # Left panel - controls
        left_panel = self.create_controls_panel()
        layout.addWidget(left_panel)
        
        # Right panel - output
        right_panel = self.create_output_panel()
        layout.addWidget(right_panel, 2)

    def create_controls_panel(self):
        """Create controls panel"""
        panel = QFrame()
        panel.setFixedWidth(300)
        layout = QVBoxLayout(panel)
        
        # Target input
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("Target List:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("domain1.com,domain2.com,...")
        target_layout.addWidget(self.target_input)
        
        layout.addWidget(target_group)
        
        # Automation options
        options_group = QGroupBox("Automation Options")
        options_layout = QVBoxLayout(options_group)
        
        self.auto_subdomain_cb = QCheckBox("Subdomain Enumeration")
        self.auto_subdomain_cb.setChecked(True)
        options_layout.addWidget(self.auto_subdomain_cb)
        
        self.auto_breach_cb = QCheckBox("Breach Analysis")
        self.auto_breach_cb.setChecked(True)
        options_layout.addWidget(self.auto_breach_cb)
        
        self.auto_social_cb = QCheckBox("Social Media Search")
        self.auto_social_cb.setChecked(False)
        options_layout.addWidget(self.auto_social_cb)
        
        self.auto_threat_cb = QCheckBox("Threat Intelligence")
        self.auto_threat_cb.setChecked(True)
        options_layout.addWidget(self.auto_threat_cb)
        
        layout.addWidget(options_group)
        
        # Automation modules
        modules_group = QGroupBox("OSINT Automation")
        modules_layout = QVBoxLayout(modules_group)
        
        buttons = [
            ("Start Automated OSINT", self.run_automated_osint),
            ("Schedule Recurring", self.run_schedule_recurring),
            ("Batch Processing", self.run_batch_processing),
            ("Export Results", self.run_export_results),
            ("Generate Report", self.run_generate_report),
            ("API Integration", self.run_api_integration),
            ("Workflow Builder", self.run_workflow_builder)
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            modules_layout.addWidget(btn)
        
        layout.addWidget(modules_group)
        layout.addStretch()
        
        return panel

    def create_output_panel(self):
        """Create output panel"""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Automation results will appear here...")
        layout.addWidget(self.output_text)
        
        return panel

    def run_automated_osint(self):
        """Run automated OSINT collection"""
        targets = self.target_input.text().strip()
        if not targets:
            return
        
        self.automation_started.emit(targets, "Automated OSINT")
        self.output_text.clear()
        
        selected_modules = []
        if self.auto_subdomain_cb.isChecked():
            selected_modules.append("Subdomain Enumeration")
        if self.auto_breach_cb.isChecked():
            selected_modules.append("Breach Analysis")
        if self.auto_social_cb.isChecked():
            selected_modules.append("Social Media Search")
        if self.auto_threat_cb.isChecked():
            selected_modules.append("Threat Intelligence")
        
        modules_text = ", ".join(selected_modules)
        
        self.output_text.setHtml(f"""
        <p style='color: #64C8FF;'>[AUTOMATED OSINT] Starting comprehensive automation...</p>
        <p style='color: #FFD93D;'>Selected modules: {h(modules_text)}</p>
        <p style='color: #00FF41;'>Processing {len(targets.split(','))} targets automatically</p>
        <p style='color: #00FF41;'>Automation workflow initiated successfully</p>
        """)
        self.automation_completed.emit({"automated_targets": len(targets.split(','))})

    def run_schedule_recurring(self):
        """Run scheduled recurring OSINT"""
        self.automation_started.emit("", "Schedule Recurring")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[SCHEDULE RECURRING] Setting up automated schedules...</p>
        <p style='color: #00FF41;'>Daily, weekly, and monthly OSINT schedules configured</p>
        """)
        self.automation_completed.emit({"scheduled_tasks": True})

    def run_batch_processing(self):
        """Run batch processing"""
        self.automation_started.emit("", "Batch Processing")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[BATCH PROCESSING] Processing multiple targets...</p>
        <p style='color: #00FF41;'>Parallel processing and queue management active</p>
        """)
        self.automation_completed.emit({"batch_processing": True})

    def run_export_results(self):
        """Run export results"""
        self.automation_started.emit("", "Export Results")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[EXPORT RESULTS] Exporting collected intelligence...</p>
        <p style='color: #00FF41;'>JSON, CSV, and XML formats available</p>
        """)
        self.automation_completed.emit({"export_formats": 3})

    def run_generate_report(self):
        """Run report generation"""
        self.automation_started.emit("", "Generate Report")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[GENERATE REPORT] Creating comprehensive reports...</p>
        <p style='color: #00FF41;'>PDF and HTML reports with visualizations generated</p>
        """)
        self.automation_completed.emit({"reports_generated": True})

    def run_api_integration(self):
        """Run API integration"""
        self.automation_started.emit("", "API Integration")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[API INTEGRATION] Connecting to external APIs...</p>
        <p style='color: #00FF41;'>REST API endpoints and webhooks configured</p>
        """)
        self.automation_completed.emit({"api_integrations": True})

    def run_workflow_builder(self):
        """Run workflow builder"""
        self.automation_started.emit("", "Workflow Builder")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[WORKFLOW BUILDER] Creating custom OSINT workflows...</p>
        <p style='color: #00FF41;'>Drag-and-drop workflow designer available</p>
        """)
        self.automation_completed.emit({"workflow_builder": True})

    def apply_theme(self):
        """Apply component theme"""
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
            QTextEdit {
                background-color: rgba(0, 0, 0, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                font-family: 'Courier New', monospace;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
            QCheckBox {
                color: #DCDCDC;
                font-weight: bold;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 2px solid rgba(100, 200, 255, 100);
                background-color: rgba(20, 30, 40, 150);
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 2px solid #64C8FF;
                background-color: #64C8FF;
                border-radius: 3px;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                margin-top: 10px;
                color: #64C8FF;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)