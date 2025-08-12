# app/widgets/anti_forensics_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QTextEdit, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QTabWidget, QLineEdit, QSpinBox, QCheckBox,
                            QListWidget, QFileDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from app.core.anti_forensics import anti_forensics
from app.core.license_manager import license_manager

class ForensicsWorker(QThread):
    """Worker thread for anti-forensics operations"""
    operation_completed = pyqtSignal(dict)
    
    def __init__(self, operation, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        
    def run(self):
        if self.operation == 'clear_logs':
            result = anti_forensics.clear_windows_logs(self.kwargs.get('log_types'))
        elif self.operation == 'secure_delete':
            result = anti_forensics.secure_file_deletion(
                self.kwargs['file_paths'], 
                self.kwargs.get('passes', 3)
            )
        elif self.operation == 'clear_browser':
            result = anti_forensics.clear_browser_artifacts(self.kwargs.get('browsers'))
        elif self.operation == 'modify_timestamps':
            result = anti_forensics.modify_file_timestamps(
                self.kwargs['file_paths'], 
                self.kwargs.get('timestamp_type', 'random')
            )
        elif self.operation == 'clear_registry':
            result = anti_forensics.clear_registry_traces(self.kwargs.get('registry_keys'))
        elif self.operation == 'obfuscate_traffic':
            result = anti_forensics.network_traffic_obfuscation(self.kwargs.get('techniques'))
        elif self.operation == 'memory_evasion':
            result = anti_forensics.memory_dump_evasion()
        else:
            result = {'error': 'Unknown operation'}
            
        self.operation_completed.emit(result)

class AntiForensicsWidget(QWidget):
    """Anti-forensics and evasion techniques widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.forensics_worker = None
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Anti-Forensics & Evasion Techniques")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #FF6B6B;")
        layout.addWidget(header)
        
        # Warning
        warning = QLabel("⚠️ EXTREME CAUTION - AUTHORIZED USE ONLY - ENTERPRISE LICENSE REQUIRED")
        warning.setStyleSheet("color: #FF0000; font-weight: bold; padding: 10px; background: rgba(255,0,0,0.1);")
        layout.addWidget(warning)
        
        # License warning
        self.license_warning = QLabel("❌ Anti-Forensics requires Enterprise license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Tabs
        self.tabs = QTabWidget()
        
        # Log Clearing Tab
        self.logs_tab = self.create_logs_tab()
        self.tabs.addTab(self.logs_tab, "Log Clearing")
        
        # File Operations Tab
        self.files_tab = self.create_files_tab()
        self.tabs.addTab(self.files_tab, "File Operations")
        
        # Network Evasion Tab
        self.network_tab = self.create_network_tab()
        self.tabs.addTab(self.network_tab, "Network Evasion")
        
        # System Cleanup Tab
        self.cleanup_tab = self.create_cleanup_tab()
        self.tabs.addTab(self.cleanup_tab, "System Cleanup")
        
        layout.addWidget(self.tabs)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(120)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def create_logs_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Windows Event Logs
        logs_group = QGroupBox("Windows Event Log Clearing")
        logs_layout = QVBoxLayout(logs_group)
        
        # Log type selection
        self.log_checkboxes = {}
        log_types = ['Application', 'Security', 'System', 'Setup', 'PowerShell']
        
        checkbox_layout = QHBoxLayout()
        for log_type in log_types:
            checkbox = QCheckBox(log_type)
            checkbox.setChecked(True)
            self.log_checkboxes[log_type] = checkbox
            checkbox_layout.addWidget(checkbox)
        logs_layout.addLayout(checkbox_layout)
        
        self.clear_logs_btn = QPushButton("Clear Selected Logs")
        self.clear_logs_btn.setStyleSheet("background-color: #FF6B6B; font-weight: bold;")
        logs_layout.addWidget(self.clear_logs_btn)
        
        layout.addWidget(logs_group)
        
        # Log Clearing Results
        results_group = QGroupBox("Clearing Results")
        results_layout = QVBoxLayout(results_group)
        
        self.log_results_table = QTableWidget()
        self.log_results_table.setColumnCount(3)
        self.log_results_table.setHorizontalHeaderLabels(["Log Type", "Status", "Timestamp"])
        self.log_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        results_layout.addWidget(self.log_results_table)
        
        layout.addWidget(results_group)
        
        return widget
        
    def create_files_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Secure File Deletion
        delete_group = QGroupBox("Secure File Deletion")
        delete_layout = QVBoxLayout(delete_group)
        
        # File selection
        file_select_layout = QHBoxLayout()
        self.file_paths_list = QListWidget()
        self.file_paths_list.setMaximumHeight(100)
        file_select_layout.addWidget(self.file_paths_list)
        
        file_buttons_layout = QVBoxLayout()
        self.add_files_btn = QPushButton("Add Files")
        self.remove_files_btn = QPushButton("Remove Selected")
        file_buttons_layout.addWidget(self.add_files_btn)
        file_buttons_layout.addWidget(self.remove_files_btn)
        file_select_layout.addLayout(file_buttons_layout)
        delete_layout.addLayout(file_select_layout)
        
        # Overwrite passes
        passes_layout = QHBoxLayout()
        passes_layout.addWidget(QLabel("Overwrite Passes:"))
        self.overwrite_passes = QSpinBox()
        self.overwrite_passes.setRange(1, 10)
        self.overwrite_passes.setValue(3)
        passes_layout.addWidget(self.overwrite_passes)
        delete_layout.addLayout(passes_layout)
        
        self.secure_delete_btn = QPushButton("Secure Delete Files")
        self.secure_delete_btn.setStyleSheet("background-color: #FF6B6B; font-weight: bold;")
        delete_layout.addWidget(self.secure_delete_btn)
        
        layout.addWidget(delete_group)
        
        # Timestamp Modification
        timestamp_group = QGroupBox("File Timestamp Modification")
        timestamp_layout = QVBoxLayout(timestamp_group)
        
        timestamp_type_layout = QHBoxLayout()
        timestamp_type_layout.addWidget(QLabel("Timestamp Type:"))
        self.timestamp_type = QComboBox()
        self.timestamp_type.addItems(["random", "old", "current"])
        timestamp_type_layout.addWidget(self.timestamp_type)
        timestamp_layout.addLayout(timestamp_type_layout)
        
        self.modify_timestamps_btn = QPushButton("Modify Timestamps")
        timestamp_layout.addWidget(self.modify_timestamps_btn)
        
        layout.addWidget(timestamp_group)
        
        return widget
        
    def create_network_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Traffic Obfuscation
        obfuscation_group = QGroupBox("Network Traffic Obfuscation")
        obfuscation_layout = QVBoxLayout(obfuscation_group)
        
        # Technique selection
        self.obfuscation_checkboxes = {}
        techniques = ['domain_fronting', 'traffic_padding', 'protocol_tunneling', 'dns_tunneling', 'steganography']
        
        for technique in techniques:
            checkbox = QCheckBox(technique.replace('_', ' ').title())
            checkbox.setChecked(True)
            self.obfuscation_checkboxes[technique] = checkbox
            obfuscation_layout.addWidget(checkbox)
            
        self.obfuscate_traffic_btn = QPushButton("Apply Obfuscation Techniques")
        self.obfuscate_traffic_btn.setStyleSheet("background-color: #64C8FF; font-weight: bold;")
        obfuscation_layout.addWidget(self.obfuscate_traffic_btn)
        
        layout.addWidget(obfuscation_group)
        
        # Memory Dump Evasion
        memory_group = QGroupBox("Memory Dump Evasion")
        memory_layout = QVBoxLayout(memory_group)
        
        memory_info = QLabel("Enable advanced memory protection techniques to evade forensic memory analysis.")
        memory_layout.addWidget(memory_info)
        
        self.memory_evasion_btn = QPushButton("Enable Memory Evasion")
        self.memory_evasion_btn.setStyleSheet("background-color: #64C8FF; font-weight: bold;")
        memory_layout.addWidget(self.memory_evasion_btn)
        
        layout.addWidget(memory_group)
        
        # Techniques Status
        status_group = QGroupBox("Active Techniques")
        status_layout = QVBoxLayout(status_group)
        
        self.techniques_table = QTableWidget()
        self.techniques_table.setColumnCount(3)
        self.techniques_table.setHorizontalHeaderLabels(["Technique", "Status", "Timestamp"])
        self.techniques_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        status_layout.addWidget(self.techniques_table)
        
        layout.addWidget(status_group)
        
        return widget
        
    def create_cleanup_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Browser Cleanup
        browser_group = QGroupBox("Browser Artifact Cleanup")
        browser_layout = QVBoxLayout(browser_group)
        
        # Browser selection
        self.browser_checkboxes = {}
        browsers = ['chrome', 'firefox', 'edge']
        
        browser_select_layout = QHBoxLayout()
        for browser in browsers:
            checkbox = QCheckBox(browser.title())
            checkbox.setChecked(True)
            self.browser_checkboxes[browser] = checkbox
            browser_select_layout.addWidget(checkbox)
        browser_layout.addLayout(browser_select_layout)
        
        self.clear_browser_btn = QPushButton("Clear Browser Artifacts")
        browser_layout.addWidget(self.clear_browser_btn)
        
        layout.addWidget(browser_group)
        
        # Registry Cleanup
        registry_group = QGroupBox("Registry Trace Cleanup")
        registry_layout = QVBoxLayout(registry_group)
        
        registry_info = QLabel("Clear registry traces including recent documents, run history, and typed paths.")
        registry_layout.addWidget(registry_info)
        
        self.clear_registry_btn = QPushButton("Clear Registry Traces")
        registry_layout.addWidget(self.clear_registry_btn)
        
        layout.addWidget(registry_group)
        
        # Cleanup Report
        report_group = QGroupBox("Cleanup Report")
        report_layout = QVBoxLayout(report_group)
        
        self.generate_report_btn = QPushButton("Generate Cleanup Report")
        report_layout.addWidget(self.generate_report_btn)
        
        self.cleanup_report = QTextEdit()
        self.cleanup_report.setReadOnly(True)
        self.cleanup_report.setMaximumHeight(200)
        report_layout.addWidget(self.cleanup_report)
        
        layout.addWidget(report_group)
        
        return widget
        
    def connect_signals(self):
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        self.add_files_btn.clicked.connect(self.add_files)
        self.remove_files_btn.clicked.connect(self.remove_files)
        self.secure_delete_btn.clicked.connect(self.secure_delete)
        self.modify_timestamps_btn.clicked.connect(self.modify_timestamps)
        self.obfuscate_traffic_btn.clicked.connect(self.obfuscate_traffic)
        self.memory_evasion_btn.clicked.connect(self.enable_memory_evasion)
        self.clear_browser_btn.clicked.connect(self.clear_browser)
        self.clear_registry_btn.clicked.connect(self.clear_registry)
        self.generate_report_btn.clicked.connect(self.generate_report)
        
        anti_forensics.forensics_event.connect(self.handle_forensics_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('anti_forensics'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def clear_logs(self):
        if not license_manager.is_feature_enabled('anti_forensics'):
            self.status_text.append("❌ Anti-Forensics requires Enterprise license")
            return
            
        selected_logs = [log_type for log_type, checkbox in self.log_checkboxes.items() if checkbox.isChecked()]
        
        if not selected_logs:
            self.status_text.append("❌ Please select at least one log type")
            return
            
        self.clear_logs_btn.setEnabled(False)
        self.status_text.append(f"🗑️ Clearing {len(selected_logs)} log types...")
        
        self.forensics_worker = ForensicsWorker('clear_logs', log_types=selected_logs)
        self.forensics_worker.operation_completed.connect(self.handle_clear_logs_completed)
        self.forensics_worker.start()
        
    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Delete", "", "All Files (*)")
        
        for file_path in files:
            self.file_paths_list.addItem(file_path)
            
        if files:
            self.status_text.append(f"📁 Added {len(files)} files for secure deletion")
            
    def remove_files(self):
        current_row = self.file_paths_list.currentRow()
        if current_row >= 0:
            item = self.file_paths_list.takeItem(current_row)
            self.status_text.append(f"🗑️ Removed {item.text()}")
            
    def secure_delete(self):
        if self.file_paths_list.count() == 0:
            self.status_text.append("❌ Please add files to delete")
            return
            
        file_paths = [self.file_paths_list.item(i).text() for i in range(self.file_paths_list.count())]
        passes = self.overwrite_passes.value()
        
        self.secure_delete_btn.setEnabled(False)
        self.status_text.append(f"🔥 Securely deleting {len(file_paths)} files with {passes} passes...")
        
        self.forensics_worker = ForensicsWorker('secure_delete', file_paths=file_paths, passes=passes)
        self.forensics_worker.operation_completed.connect(self.handle_secure_delete_completed)
        self.forensics_worker.start()
        
    def modify_timestamps(self):
        if self.file_paths_list.count() == 0:
            self.status_text.append("❌ Please add files to modify")
            return
            
        file_paths = [self.file_paths_list.item(i).text() for i in range(self.file_paths_list.count())]
        timestamp_type = self.timestamp_type.currentText()
        
        self.modify_timestamps_btn.setEnabled(False)
        self.status_text.append(f"⏰ Modifying timestamps for {len(file_paths)} files...")
        
        self.forensics_worker = ForensicsWorker('modify_timestamps', file_paths=file_paths, timestamp_type=timestamp_type)
        self.forensics_worker.operation_completed.connect(self.handle_modify_timestamps_completed)
        self.forensics_worker.start()
        
    def obfuscate_traffic(self):
        selected_techniques = [technique for technique, checkbox in self.obfuscation_checkboxes.items() if checkbox.isChecked()]
        
        if not selected_techniques:
            self.status_text.append("❌ Please select at least one obfuscation technique")
            return
            
        self.obfuscate_traffic_btn.setEnabled(False)
        self.status_text.append(f"🌐 Applying {len(selected_techniques)} obfuscation techniques...")
        
        self.forensics_worker = ForensicsWorker('obfuscate_traffic', techniques=selected_techniques)
        self.forensics_worker.operation_completed.connect(self.handle_obfuscate_traffic_completed)
        self.forensics_worker.start()
        
    def enable_memory_evasion(self):
        self.memory_evasion_btn.setEnabled(False)
        self.status_text.append("🧠 Enabling memory dump evasion techniques...")
        
        self.forensics_worker = ForensicsWorker('memory_evasion')
        self.forensics_worker.operation_completed.connect(self.handle_memory_evasion_completed)
        self.forensics_worker.start()
        
    def clear_browser(self):
        selected_browsers = [browser for browser, checkbox in self.browser_checkboxes.items() if checkbox.isChecked()]
        
        if not selected_browsers:
            self.status_text.append("❌ Please select at least one browser")
            return
            
        self.clear_browser_btn.setEnabled(False)
        self.status_text.append(f"🌐 Clearing artifacts from {len(selected_browsers)} browsers...")
        
        self.forensics_worker = ForensicsWorker('clear_browser', browsers=selected_browsers)
        self.forensics_worker.operation_completed.connect(self.handle_clear_browser_completed)
        self.forensics_worker.start()
        
    def clear_registry(self):
        self.clear_registry_btn.setEnabled(False)
        self.status_text.append("📝 Clearing registry traces...")
        
        self.forensics_worker = ForensicsWorker('clear_registry')
        self.forensics_worker.operation_completed.connect(self.handle_clear_registry_completed)
        self.forensics_worker.start()
        
    def generate_report(self):
        report = anti_forensics.generate_cleanup_report()
        
        if 'error' in report:
            self.status_text.append(f"❌ Report generation failed: {report['error']}")
            return
            
        # Format report
        report_text = f"""ANTI-FORENSICS CLEANUP REPORT
Generated: {report.get('generated_at', 'Unknown')}

OPERATIONS SUMMARY:
Total Operations: {report.get('total_operations', 0)}

"""
        
        for operation in report.get('operations_summary', []):
            report_text += f"Operation: {operation.get('operation', 'Unknown')}\n"
            report_text += f"  Success: {operation.get('success_count', 0)}\n"
            report_text += f"  Failures: {operation.get('failure_count', 0)}\n\n"
            
        report_text += "RECOMMENDATIONS:\n"
        for rec in report.get('recommendations', []):
            report_text += f"• {rec}\n"
            
        self.cleanup_report.setPlainText(report_text)
        self.status_text.append("📊 Cleanup report generated")
        
    def handle_clear_logs_completed(self, result):
        self.clear_logs_btn.setEnabled(True)
        
        if 'error' not in result:
            cleared = result.get('logs_cleared', [])
            failed = result.get('logs_failed', [])
            
            # Update results table
            self.log_results_table.setRowCount(len(cleared) + len(failed))
            
            row = 0
            for log in cleared:
                self.log_results_table.setItem(row, 0, QTableWidgetItem(log['log_type']))
                status_item = QTableWidgetItem("Cleared")
                status_item.setForeground(QColor("#00FF41"))
                self.log_results_table.setItem(row, 1, status_item)
                self.log_results_table.setItem(row, 2, QTableWidgetItem(log['timestamp'][:19]))
                row += 1
                
            for log in failed:
                self.log_results_table.setItem(row, 0, QTableWidgetItem(log['log_type']))
                status_item = QTableWidgetItem("Failed")
                status_item.setForeground(QColor("#FF6B6B"))
                self.log_results_table.setItem(row, 1, status_item)
                self.log_results_table.setItem(row, 2, QTableWidgetItem(log.get('timestamp', 'N/A')[:19]))
                row += 1
                
            self.status_text.append(f"✅ Log clearing completed: {len(cleared)} cleared, {len(failed)} failed")
        else:
            self.status_text.append(f"❌ Log clearing failed: {result['error']}")
            
    def handle_secure_delete_completed(self, result):
        self.secure_delete_btn.setEnabled(True)
        
        if 'error' not in result:
            deleted = len(result.get('files_deleted', []))
            failed = len(result.get('files_failed', []))
            passes = result.get('overwrite_passes', 0)
            
            self.status_text.append(f"🔥 Secure deletion completed: {deleted} files deleted with {passes} passes, {failed} failed")
            
            # Clear the file list
            self.file_paths_list.clear()
        else:
            self.status_text.append(f"❌ Secure deletion failed: {result['error']}")
            
    def handle_modify_timestamps_completed(self, result):
        self.modify_timestamps_btn.setEnabled(True)
        
        if 'error' not in result:
            modified = len(result.get('files_modified', []))
            failed = len(result.get('files_failed', []))
            
            self.status_text.append(f"⏰ Timestamp modification completed: {modified} files modified, {failed} failed")
        else:
            self.status_text.append(f"❌ Timestamp modification failed: {result['error']}")
            
    def handle_obfuscate_traffic_completed(self, result):
        self.obfuscate_traffic_btn.setEnabled(True)
        
        if 'error' not in result:
            applied = result.get('techniques_applied', [])
            
            # Update techniques table
            self.techniques_table.setRowCount(len(applied))
            
            for row, technique in enumerate(applied):
                self.techniques_table.setItem(row, 0, QTableWidgetItem(technique['technique']))
                status_item = QTableWidgetItem("Active")
                status_item.setForeground(QColor("#00FF41"))
                self.techniques_table.setItem(row, 1, status_item)
                self.techniques_table.setItem(row, 2, QTableWidgetItem(technique['timestamp'][:19]))
                
            self.status_text.append(f"🌐 Traffic obfuscation applied: {len(applied)} techniques active")
        else:
            self.status_text.append(f"❌ Traffic obfuscation failed: {result['error']}")
            
    def handle_memory_evasion_completed(self, result):
        self.memory_evasion_btn.setEnabled(True)
        
        if 'error' not in result:
            techniques = len(result.get('techniques_enabled', []))
            self.status_text.append(f"🧠 Memory evasion enabled: {techniques} techniques active")
        else:
            self.status_text.append(f"❌ Memory evasion failed: {result['error']}")
            
    def handle_clear_browser_completed(self, result):
        self.clear_browser_btn.setEnabled(True)
        
        if 'error' not in result:
            browsers = len(result.get('browsers_cleaned', []))
            artifacts = len(result.get('artifacts_cleared', []))
            
            self.status_text.append(f"🌐 Browser cleanup completed: {browsers} browsers, {artifacts} artifacts cleared")
        else:
            self.status_text.append(f"❌ Browser cleanup failed: {result['error']}")
            
    def handle_clear_registry_completed(self, result):
        self.clear_registry_btn.setEnabled(True)
        
        if 'error' not in result:
            cleared = len(result.get('keys_cleared', []))
            failed = len(result.get('keys_failed', []))
            
            self.status_text.append(f"📝 Registry cleanup completed: {cleared} keys cleared, {failed} failed")
        else:
            self.status_text.append(f"❌ Registry cleanup failed: {result['error']}")
            
    def handle_forensics_event(self, event_type, message, data):
        self.status_text.append(f"🔧 {message}")