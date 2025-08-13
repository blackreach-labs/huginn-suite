# app/pages/recon_enumeration/port_scanning.py
import os
from PyQt6.QtWidgets import (QHBoxLayout, QLabel, QLineEdit, QComboBox, QPushButton, 
                             QSpacerItem, QSizePolicy, QToolButton, QTableWidget)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon

class PortScanningMixin:
    """Mixin for port scanning functionality"""
    
    def create_port_scan_controls(self):
        """Create advanced port scan controls"""
        from PyQt6.QtWidgets import QVBoxLayout
        
        main_layout = QVBoxLayout()
        
        # Row 1 - Target
        row1_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        row1_layout.addWidget(target_label)
        self.port_target_input = QLineEdit()
        self.port_target_input.setPlaceholderText("Enter target (IP, range, or hostname)")
        self.port_target_input.returnPressed.connect(self.run_port_scan)
        row1_layout.addWidget(self.port_target_input)
        main_layout.addLayout(row1_layout)
        
        # Row 2 - Type + Detection options
        row2_layout = QHBoxLayout()
        scan_type_label = QLabel("Type:")
        row2_layout.addWidget(scan_type_label)
        self.port_scan_type = QComboBox()
        self.port_scan_type.addItems(["Ping Sweep", "Huggin Sweep", "Layer2 Sweep", "TCP Scan", "UDP Scan"])
        self.port_scan_type.currentTextChanged.connect(self.on_port_scan_type_changed)
        row2_layout.addWidget(self.port_scan_type)
        
        from PyQt6.QtWidgets import QCheckBox
        self.os_detection_cb = QCheckBox("OS Detection")
        self.service_detection_cb = QCheckBox("Service Detection")
        row2_layout.addWidget(self.os_detection_cb)
        row2_layout.addWidget(self.service_detection_cb)
        
        row2_layout.addStretch()
        main_layout.addLayout(row2_layout)
        
        # Row 3 - Ports + preset buttons
        self.port_row_layout = QHBoxLayout()
        self.port_label = QLabel("Ports:")
        self.port_row_layout.addWidget(self.port_label)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("80,443,8080 or 1-1000")
        self.port_row_layout.addWidget(self.port_input)
        
        self.common_btn = QPushButton("Common")
        self.common_btn.clicked.connect(lambda: self.port_input.setText("20,21,22,23,25,53,67,68,80,88,110,111,135,137,138,139,143,161,389,443,445,464,554,631,636,993,995,1433,1521,1723,1900,2181,2222,2375,2376,2525,27017,27018,27019,3000,3268,3269,3306,3389,3544,500,5000,5001,5040,5050,5432,5671,5672,5984,5985,5986,5987,6378,6379,6443,7000,7001,7474,7680,8000,8042,8080,8081,8086,8200,8443,8500,8554,8787,8880,8883,8888,9000,9001,9042,9090,9093,9100,9200,9220,9221,9222,9223,9224,9225,9226,9227,9228,9229,11211,15672"))
        self.port_row_layout.addWidget(self.common_btn)
        
        self.top1000_btn = QPushButton("Top 1000")
        self.top1000_btn.clicked.connect(lambda: self.port_input.setText("1-1000"))
        self.port_row_layout.addWidget(self.top1000_btn)
        
        self.all_btn = QPushButton("All")
        self.all_btn.clicked.connect(lambda: self.port_input.setText("1-65535"))
        self.port_row_layout.addWidget(self.all_btn)
        
        main_layout.addLayout(self.port_row_layout)
        
        # Row 4 - Run + Progress + Export
        row4_layout = QHBoxLayout()
        
        try:
            from app.ui.animations.universal_run_button import UniversalRunButton
            self.port_run_button = UniversalRunButton("Run")
        except ImportError:
            self.port_run_button = QPushButton("Run")
        self.port_run_button.clicked.connect(self.toggle_port_scan)
        row4_layout.addWidget(self.port_run_button)
        
        try:
            from app.widgets.progress_widget import ProgressWidget
            self.port_progress_widget = ProgressWidget()
            self.port_progress_widget.setVisible(False)
            row4_layout.addWidget(self.port_progress_widget, 1)
        except ImportError:
            self.port_progress_widget = None
        
        # Add spacer between Progress and view buttons
        self.port_spacer = QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        row4_layout.addItem(self.port_spacer)
        
        # View toggle buttons
        text_icon_path = os.path.join(self.main_window.project_root, "resources", "icons", "text.png")
        table_icon_path = os.path.join(self.main_window.project_root, "resources", "icons", "table.png")
        graph_icon_path = os.path.join(self.main_window.project_root, "resources", "icons", "graph.png")
        
        self.port_text_view_btn = QToolButton()
        if os.path.exists(text_icon_path):
            self.port_text_view_btn.setIcon(QIcon(text_icon_path))
        else:
            self.port_text_view_btn.setText("Text")
        self.port_text_view_btn.setCheckable(True)
        self.port_text_view_btn.setChecked(True)
        self.port_text_view_btn.clicked.connect(lambda: self.set_port_view("text"))
        row4_layout.addWidget(self.port_text_view_btn)
        
        self.port_tree_view_btn = QToolButton()
        if os.path.exists(graph_icon_path):
            self.port_tree_view_btn.setIcon(QIcon(graph_icon_path))
        else:
            self.port_tree_view_btn.setText("Tree")
        self.port_tree_view_btn.setCheckable(True)
        self.port_tree_view_btn.clicked.connect(lambda: self.set_port_view("tree"))
        self.port_tree_view_btn.setVisible(False)
        row4_layout.addWidget(self.port_tree_view_btn)
        
        self.port_table_view_btn = QToolButton()
        if os.path.exists(table_icon_path):
            self.port_table_view_btn.setIcon(QIcon(table_icon_path))
        else:
            self.port_table_view_btn.setText("Table")
        self.port_table_view_btn.setCheckable(True)
        self.port_table_view_btn.clicked.connect(lambda: self.set_port_view("table"))
        row4_layout.addWidget(self.port_table_view_btn)
        
        self.port_export_combo = QComboBox()
        self.port_export_combo.addItems(["JSON", "CSV", "XML", "HTML"])
        row4_layout.addWidget(self.port_export_combo)
        
        self.port_export_button = QPushButton("Export")
        self.port_export_button.setEnabled(False)
        self.port_export_button.clicked.connect(self.export_port_results)
        row4_layout.addWidget(self.port_export_button)
        
        main_layout.addLayout(row4_layout)
        
        # Set initial visibility based on scan type
        self.on_port_scan_type_changed("Ping Sweep")
        
        return main_layout
    
    def on_port_scan_type_changed(self, scan_type):
        """Handle port scan type change"""
        # Hide port row for Ping Sweep, Huggin Sweep, and Layer2 Sweep
        show_ports = (scan_type in ["TCP Scan", "UDP Scan"])
        if hasattr(self, 'port_label'):
            self.port_label.setVisible(show_ports)
        if hasattr(self, 'port_input'):
            self.port_input.setVisible(show_ports)
        if hasattr(self, 'common_btn'):
            self.common_btn.setVisible(show_ports)
        if hasattr(self, 'top1000_btn'):
            self.top1000_btn.setVisible(show_ports)
        if hasattr(self, 'all_btn'):
            self.all_btn.setVisible(show_ports)
        
        # Show detection options only for TCP/UDP Scan
        if hasattr(self, 'os_detection_cb'):
            self.os_detection_cb.setVisible(show_ports)
        if hasattr(self, 'service_detection_cb'):
            self.service_detection_cb.setVisible(show_ports)
        
        # Show tree view button only for TCP/UDP Scan
        if hasattr(self, 'port_tree_view_btn'):
            self.port_tree_view_btn.setVisible(show_ports)
        
        # Switch to appropriate terminal and table for scan type
        self.switch_port_scan_view(scan_type)
        
        # Update current scan type
        self.current_port_scan_type = scan_type
        
        # Load existing results for this scan type if available
        if hasattr(self, 'port_scan_results_by_type') and scan_type in self.port_scan_results_by_type:
            current_table = self.get_current_port_table()
            if current_table:
                self.update_port_table_for_type(current_table, self.port_scan_results_by_type[scan_type], scan_type)
    
    def toggle_port_scan(self):
        """Toggle port scan - start if not running, stop if running"""
        if getattr(self, 'port_scanning', False):
            self.cancel_port_scan()
        else:
            self.run_port_scan()
    
    def run_port_scan(self):
        """Run port scan using actual implementation"""
        target = self.port_target_input.text().strip()
        if not target:
            self.status_updated.emit("Please enter a target for port scanning")
            return
        
        scan_type = self.port_scan_type.currentText()
        ports = self.port_input.text().strip() if scan_type in ["TCP Scan", "UDP Scan"] else ""
        
        # Clear current scan type terminal before starting new scan
        current_terminal = self.get_current_port_terminal()
        if current_terminal:
            current_terminal.clear()
        
        # Set button state
        if hasattr(self.port_run_button, 'start_scan'):
            self.port_run_button.start_scan()
        else:
            self.port_run_button.setText("Stop")
        
        # Show progress widget and hide spacer
        if self.port_progress_widget:
            self.port_progress_widget.setVisible(True)
            self.port_progress_widget.reset_progress()
            if hasattr(self, 'port_spacer'):
                self.port_spacer.changeSize(0, 0, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)
        
        self.port_scanning = True
        
        try:
            from app.tools import port_utils
            
            # Get current tenant from main window
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            
            # Run port scan based on type
            if scan_type == "Ping Sweep":
                self.current_worker = port_utils.ping_sweep(
                    target,
                    self.append_port_output,
                    self.status_updated.emit,
                    self.on_port_scan_finished,
                    results_callback=self.store_port_results,
                    progress_callback=self.update_port_progress,
                    progress_start_callback=self.start_port_progress,
                    tenant_id=tenant_id
                )
            elif scan_type == "Huggin Sweep":
                self.current_worker = port_utils.huggin_sweep(
                    target,
                    self.append_port_output,
                    self.status_updated.emit,
                    self.on_port_scan_finished,
                    results_callback=self.store_port_results,
                    progress_callback=self.update_port_progress,
                    progress_start_callback=self.start_port_progress,
                    tenant_id=tenant_id
                )
            elif scan_type == "Layer2 Sweep":
                self.current_worker = port_utils.layer2_sweep(
                    target,
                    self.append_port_output,
                    self.status_updated.emit,
                    self.on_port_scan_finished,
                    results_callback=self.store_port_results,
                    progress_callback=self.update_port_progress,
                    progress_start_callback=self.start_port_progress,
                    tenant_id=tenant_id
                )
            elif scan_type == "TCP Scan":
                os_detection = self.os_detection_cb.isChecked()
                service_detection = self.service_detection_cb.isChecked()
                
                # Use enhanced port scan with built-in OS and service detection
                self.current_worker = port_utils.enhanced_targeted_scan(
                    target,
                    ports or "80,443",
                    os_detection=os_detection,
                    service_detection=service_detection,
                    output_callback=self.append_port_output,
                    status_callback=self.status_updated.emit,
                    finished_callback=self.on_port_scan_finished,
                    results_callback=self.store_port_results,
                    progress_callback=self.update_port_progress,
                    progress_start_callback=self.start_port_progress,
                    tenant_id=tenant_id
                )
            else:  # UDP Scan
                os_detection = self.os_detection_cb.isChecked()
                service_detection = self.service_detection_cb.isChecked()
                
                # Use enhanced port scan for UDP ports
                self.current_worker = port_utils.enhanced_targeted_scan(
                    target,
                    ports or "53,67,68,69,123,135,137,138,161,162,389,445,500,514,520,631,1434,1900,4500,5353",
                    os_detection=os_detection,
                    service_detection=service_detection,
                    output_callback=self.append_port_output,
                    status_callback=self.status_updated.emit,
                    finished_callback=self.on_port_scan_finished,
                    results_callback=self.store_port_results,
                    progress_callback=self.update_port_progress,
                    progress_start_callback=self.start_port_progress,
                    tenant_id=tenant_id
                )
            
            # Show detection options in output if enabled
            detection_info = ""
            if scan_type in ["TCP Scan", "UDP Scan"]:
                if self.os_detection_cb.isChecked():
                    detection_info += " with OS Detection"
                if self.service_detection_cb.isChecked():
                    detection_info += " with Service Detection"
            
            self.append_port_output(f"<p style='color: #00BFFF;'>[PORT SCAN] Starting {scan_type}{detection_info} on {target}</p><br>")
            
        except ImportError:
            # Fallback implementation
            self.append_port_output(f"<p style='color: #00BFFF;'>[PORT SCAN] Starting {scan_type} on {target}</p><br>")
            self.append_port_output(f"<p style='color: #FFAA00;'>[WARNING] Port scanner not available, using simulation</p><br>")
            
            # Simulate results
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(2000, self.simulate_port_scan_completion)
        
        self.status_updated.emit(f"Port scan started for {target}")
    
    def simulate_port_scan_completion(self):
        """Simulate port scan completion for fallback"""
        scan_type = self.port_scan_type.currentText()
        target = self.port_target_input.text().strip()
        
        if scan_type == "Ping Sweep":
            results = {
                'alive_hosts': [target],
                'scan_type': 'ping_sweep',
                'target': target
            }
        elif scan_type == "Huggin Sweep":
            results = {
                'alive_hosts': [target],
                'scan_type': 'huggin_sweep',
                'target': target
            }
        elif scan_type == "Layer2 Sweep":
            results = {
                'layer2_hosts': [
                    {'ip': target, 'mac': '00:11:22:33:44:55', 'vendor': 'Example Corp', 'protocol': 'ARP'},
                    {'ip': '192.168.1.1', 'mac': '00:aa:bb:cc:dd:ee', 'vendor': 'Router Vendor', 'protocol': 'mDNS'}
                ],
                'scan_type': 'layer2_sweep',
                'target': target
            }
        else:  # Targeted Scan
            dc_ports = [
                {'port': 53, 'service': 'DNS', 'confidence': 'high'},
                {'port': 88, 'service': 'Kerberos', 'confidence': 'high'},
                {'port': 135, 'service': 'RPC Endpoint', 'confidence': 'high'},
                {'port': 389, 'service': 'LDAP', 'confidence': 'high'},
                {'port': 445, 'service': 'SMB', 'confidence': 'high'},
                {'port': 464, 'service': 'Kerberos Password', 'confidence': 'high'},
                {'port': 636, 'service': 'LDAPS', 'confidence': 'high'},
                {'port': 3268, 'service': 'LDAP GC', 'confidence': 'high'},
                {'port': 3269, 'service': 'LDAP GC SSL', 'confidence': 'high'},
                {'port': 5985, 'service': 'WinRM HTTP', 'confidence': 'high'}
            ]
            
            os_detection = None
            if self.os_detection_cb.isChecked():
                os_detection = {
                    'os': 'Windows Server 2019',
                    'confidence': 'high',
                    'reason': 'Port pattern match: 88, 135, 389, 445, 5985',
                    'evidence': ['Port pattern match: 88, 135, 389, 445, 5985']
                }
            
            # Add server type detection
            server_type = 'Windows Domain Controller'
            
            results = {
                target: {
                    'open_ports': dc_ports,
                    'os_detection': os_detection,
                    'server_type': server_type
                },
                'scan_type': scan_type.lower().replace(' ', '_'),
                'target': target
            }
        
        self.store_port_results(results)
        self.append_port_output(f"<p style='color: #00FF41;'>[PORT SCAN] {scan_type} completed</p><br>")
        self.on_port_scan_finished()
    
    def cancel_port_scan(self):
        """Cancel running port scan"""
        if hasattr(self, 'current_worker') and self.current_worker:
            self.current_worker.is_running = False
        
        self.port_scanning = False
        
        # Reset button state
        if hasattr(self.port_run_button, 'stop_scan'):
            self.port_run_button.stop_scan()
        else:
            self.port_run_button.setText("Run")
        
        # Hide progress widget and show spacer
        if self.port_progress_widget:
            self.port_progress_widget.setVisible(False)
            if hasattr(self, 'port_spacer'):
                self.port_spacer.changeSize(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        
        self.append_port_output(f"<p style='color: #FFAA00;'>[SCAN] Port scan cancelled</p><br>")
        self.status_updated.emit("Port scan cancelled")
    
    def on_port_scan_finished(self):
        """Handle port scan completion"""
        self.port_scanning = False
        
        # Reset button state
        if hasattr(self.port_run_button, 'stop_scan'):
            self.port_run_button.stop_scan()
        else:
            self.port_run_button.setText("Run")
        
        # Hide progress widget and show spacer
        if self.port_progress_widget:
            self.port_progress_widget.setVisible(False)
            if hasattr(self, 'port_spacer'):
                self.port_spacer.changeSize(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        
        # Enable export button if we have results
        if hasattr(self, 'port_scan_results') and self.port_scan_results:
            self.port_export_button.setEnabled(True)
        
        self.status_updated.emit("Port scan completed")
    
    def store_port_results(self, results):
        """Store port scan results"""
        scan_type = self.port_scan_type.currentText()
        
        # Store results for current scan type
        if not hasattr(self, 'port_scan_results_by_type'):
            self.port_scan_results_by_type = {}
        self.port_scan_results_by_type[scan_type] = results
        
        # Update current results reference
        self.port_scan_results = results
        
        # Update table view with results
        current_table = self.get_current_port_table()
        if current_table:
            self.update_port_table_for_type(current_table, results, scan_type)
        
        # Update tree view if it's the current view
        if getattr(self, 'current_port_view', 'text') == 'tree':
            self.update_port_tree_view()
    
    def switch_port_scan_view(self, scan_type):
        """Switch to the appropriate terminal and table view for scan type"""
        if not hasattr(self, 'port_results_stacks'):
            return
        
        # Hide all scan type stacks
        for stack_type, stack in self.port_results_stacks.items():
            stack.setVisible(stack_type == scan_type)
        
        # Update table headers for current scan type
        current_table = self.get_current_port_table()
        if current_table:
            if scan_type == "Ping Sweep":
                current_table.setColumnCount(2)
                current_table.setHorizontalHeaderLabels(["IP Address", "Status"])
            elif scan_type == "Huggin Sweep":
                current_table.setColumnCount(3)
                current_table.setHorizontalHeaderLabels(["IP Address", "Open Ports", "Services"])
            elif scan_type == "Layer2 Sweep":
                current_table.setColumnCount(4)
                current_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor", "Protocol"])
            else:  # TCP/UDP Scan
                current_table.setColumnCount(4)
                current_table.setHorizontalHeaderLabels(["IP Address", "Port", "State", "Service"])
    
    def get_current_port_terminal(self):
        """Get current scan type terminal"""
        scan_type = getattr(self, 'current_port_scan_type', self.port_scan_type.currentText())
        if hasattr(self, 'port_terminals') and scan_type in self.port_terminals:
            return self.port_terminals[scan_type]
        return getattr(self, 'port_terminal', None)
    
    def get_current_port_table(self):
        """Get current scan type table"""
        scan_type = getattr(self, 'current_port_scan_type', self.port_scan_type.currentText())
        if hasattr(self, 'port_tables') and scan_type in self.port_tables:
            return self.port_tables[scan_type]
        return getattr(self, 'port_table', None)
    
    def update_port_table_for_type(self, table, results, scan_type):
        """Update specific table with scan results"""
        if not table:
            return
        
        from PyQt6.QtWidgets import QTableWidgetItem
        
        table.setRowCount(0)
        
        # Handle ping sweep results
        if scan_type == 'Ping Sweep' or 'alive_hosts' in results:
            table.setColumnCount(2)
            table.setHorizontalHeaderLabels(["IP Address", "Status"])
            alive_hosts = results.get('alive_hosts', [])
            for host in alive_hosts:
                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(host))
                table.setItem(row, 1, QTableWidgetItem("Up"))
        
        # Handle huggin sweep results
        elif scan_type == 'Huggin Sweep':
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels(["IP Address", "Open Ports", "Services"])
            # For now, show as alive hosts until proper huggin sweep is implemented
            alive_hosts = results.get('alive_hosts', [])
            for host in alive_hosts:
                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(host))
                table.setItem(row, 1, QTableWidgetItem("80,443"))
                table.setItem(row, 2, QTableWidgetItem("HTTP, HTTPS"))
        
        # Handle Layer2 sweep results
        elif scan_type == 'Layer2 Sweep' or 'layer2_hosts' in results:
            table.setColumnCount(4)
            table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Vendor", "Protocol"])
            layer2_hosts = results.get('layer2_hosts', [])
            for host in layer2_hosts:
                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(host.get('ip', 'N/A')))
                table.setItem(row, 1, QTableWidgetItem(host.get('mac', 'N/A')))
                table.setItem(row, 2, QTableWidgetItem(host.get('vendor', 'Unknown')))
                table.setItem(row, 3, QTableWidgetItem(host.get('protocol', 'Unknown')))
        
        # Handle targeted scan results
        else:
            table.setColumnCount(4)
            table.setHorizontalHeaderLabels(["IP Address", "Port", "State", "Service"])
            for host, data in results.items():
                if isinstance(data, dict) and 'open_ports' in data:
                    for port_info in data['open_ports']:
                        row = table.rowCount()
                        table.insertRow(row)
                        
                        table.setItem(row, 0, QTableWidgetItem(host))
                        table.setItem(row, 1, QTableWidgetItem(str(port_info['port'])))
                        table.setItem(row, 2, QTableWidgetItem('open'))
                        table.setItem(row, 3, QTableWidgetItem(port_info['service']))

        
        table.resizeColumnsToContents()
    
    def update_port_table(self, results):
        """Update port table with scan results - delegates to scan-type-specific method"""
        scan_type = self.port_scan_type.currentText()
        current_table = self.get_current_port_table()
        if current_table:
            self.update_port_table_for_type(current_table, results, scan_type)
    
    def set_port_view(self, view_type):
        """Set port scan results view type"""
        self.current_port_view = view_type
        
        self.port_text_view_btn.setChecked(view_type == "text")
        self.port_tree_view_btn.setChecked(view_type == "tree")
        self.port_table_view_btn.setChecked(view_type == "table")
        
        # Switch view for current scan type
        scan_type = getattr(self, 'current_port_scan_type', self.port_scan_type.currentText())
        if hasattr(self, 'port_results_stacks') and scan_type in self.port_results_stacks:
            if view_type == "text":
                self.port_results_stacks[scan_type].setCurrentIndex(0)
            elif view_type == "table":
                self.port_results_stacks[scan_type].setCurrentIndex(1)
            elif view_type == "tree":
                self.port_results_stacks[scan_type].setCurrentIndex(2)
                # Update tree view with current results
                self.update_port_tree_view()
    
    def append_port_output(self, text):
        """Append text to current scan type terminal output"""
        current_terminal = self.get_current_port_terminal()
        if current_terminal:
            # Apply theme-specific font
            current_theme = getattr(self.main_window, 'current_theme', 'dark_blue')
            font_family = 'Share Tech Mono' if current_theme == 'matrix' else 'Neuropol X'
            
            if not text.startswith('<div style="font-family:'):
                text = f'<div style="font-family: {font_family}, monospace;">{text}</div>'
            
            current_terminal.insertHtml(text)
            
            # Auto-scroll to bottom
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(10, lambda: current_terminal.verticalScrollBar().setValue(
                current_terminal.verticalScrollBar().maximum()
            ))
    
    def start_port_progress(self, total):
        """Start port scan progress"""
        if self.port_progress_widget:
            self.port_progress_widget.start_progress(total, "Scanning ports...")
    
    def update_port_progress(self, completed, found, message=""):
        """Update port scan progress"""
        if self.port_progress_widget:
            self.port_progress_widget.update_progress(completed, found, message)
    
    def update_port_tree_view(self):
        """Update tree view with current scan results"""
        scan_type = getattr(self, 'current_port_scan_type', self.port_scan_type.currentText())
        
        # Get current tree widget
        if not hasattr(self, 'port_trees') or scan_type not in self.port_trees:
            return
        
        tree = self.port_trees[scan_type]
        tree.clear()
        
        # Get results for current scan type
        results = None
        if hasattr(self, 'port_scan_results_by_type') and scan_type in self.port_scan_results_by_type:
            results = self.port_scan_results_by_type[scan_type]
        elif hasattr(self, 'port_scan_results'):
            results = self.port_scan_results
        
        if not results:
            return
        
        from PyQt6.QtWidgets import QTreeWidgetItem
        from PyQt6.QtCore import Qt
        
        # Handle different scan types
        if scan_type == 'Ping Sweep' or 'alive_hosts' in results:
            alive_hosts = results.get('alive_hosts', [])
            for host in alive_hosts:
                host_item = QTreeWidgetItem(tree, [host, "Host Status"])
                status_item = QTreeWidgetItem(host_item, ["Status", "Up"])
                host_item.setExpanded(True)
        
        elif scan_type == 'Huggin Sweep':
            alive_hosts = results.get('alive_hosts', [])
            for host in alive_hosts:
                host_item = QTreeWidgetItem(tree, [host, "Host Information"])
                ports_item = QTreeWidgetItem(host_item, ["Open Ports", "80, 443"])
                services_item = QTreeWidgetItem(host_item, ["Services", "HTTP, HTTPS"])
                host_item.setExpanded(True)
        
        elif scan_type == 'Layer2 Sweep' or 'layer2_hosts' in results:
            layer2_hosts = results.get('layer2_hosts', [])
            for host in layer2_hosts:
                host_item = QTreeWidgetItem(tree, [host.get('ip', 'N/A'), "Layer 2 Device"])
                mac_item = QTreeWidgetItem(host_item, ["MAC Address", host.get('mac', 'N/A')])
                vendor_item = QTreeWidgetItem(host_item, ["Vendor", host.get('vendor', 'Unknown')])
                protocol_item = QTreeWidgetItem(host_item, ["Discovery Protocol", host.get('protocol', 'Unknown')])
                host_item.setExpanded(True)
        
        else:  # TCP/UDP Scan
            for host, data in results.items():
                if isinstance(data, dict) and host != 'scan_type' and host != 'target':
                    host_item = QTreeWidgetItem(tree, [host, "Target Host"])
                    
                    # Add server type if available
                    if data.get('server_type'):
                        server_item = QTreeWidgetItem(host_item, ["Server Type", data['server_type']])
                    
                    # Add OS detection if available
                    if data.get('os_detection'):
                        os_info = data['os_detection']
                        os_item = QTreeWidgetItem(host_item, ["Operating System", os_info['os']])
                        confidence_item = QTreeWidgetItem(os_item, ["Confidence", os_info['confidence']])
                        
                        # Handle both 'reason' and 'evidence' fields
                        if os_info.get('reason'):
                            reason_item = QTreeWidgetItem(os_item, ["Detection Method", os_info['reason']])
                        elif os_info.get('evidence'):
                            evidence_text = ', '.join(os_info['evidence']) if isinstance(os_info['evidence'], list) else str(os_info['evidence'])
                            reason_item = QTreeWidgetItem(os_item, ["Evidence", evidence_text])
                        
                        # Add detection methods if available
                        if os_info.get('detection_methods'):
                            methods_text = ', '.join(os_info['detection_methods'])
                            methods_item = QTreeWidgetItem(os_item, ["Methods", methods_text])
                        
                        os_item.setExpanded(True)
                    
                    # Add open ports
                    if 'open_ports' in data and data['open_ports']:
                        ports_item = QTreeWidgetItem(host_item, ["Open Ports", f"{len(data['open_ports'])} ports found"])
                        
                        for port_info in data['open_ports']:
                            port_item = QTreeWidgetItem(ports_item, [f"Port {port_info['port']}", port_info['service']])
                            state_item = QTreeWidgetItem(port_item, ["State", "open"])
                            service_item = QTreeWidgetItem(port_item, ["Service", port_info['service']])
                            if port_info.get('confidence'):
                                conf_item = QTreeWidgetItem(port_item, ["Confidence", port_info['confidence']])
                            if port_info.get('version'):
                                version_item = QTreeWidgetItem(port_item, ["Version", port_info['version']])
                            if port_info.get('banner'):
                                banner_item = QTreeWidgetItem(port_item, ["Banner", port_info['banner'][:50]])
                            if port_info.get('tls_version'):
                                tls_item = QTreeWidgetItem(port_item, ["TLS Version", port_info['tls_version']])
                            port_item.setExpanded(True)
                        
                        ports_item.setExpanded(True)
                    
                    # Add service categories if available
                    if data.get('service_categories'):
                        categories_item = QTreeWidgetItem(host_item, ["Service Categories", f"{len(data['service_categories'])} categories"])
                        for category, ports in data['service_categories'].items():
                            cat_item = QTreeWidgetItem(categories_item, [category, ', '.join(map(str, ports))])
                        categories_item.setExpanded(True)
                    
                    host_item.setExpanded(True)
        
        tree.resizeColumnToContents(0)
        tree.resizeColumnToContents(1)
    
    def export_port_results(self):
        """Export port scan results"""
        scan_type = self.port_scan_type.currentText()
        results = None
        
        # Get results for current scan type
        if hasattr(self, 'port_scan_results_by_type') and scan_type in self.port_scan_results_by_type:
            results = self.port_scan_results_by_type[scan_type]
        elif hasattr(self, 'port_scan_results'):
            results = self.port_scan_results
        
        if not results:
            self.status_updated.emit(f"No {scan_type} results to export")
            return
        
        export_format = self.port_export_combo.currentText().lower()
        target = self.port_target_input.text().strip() or "port_scan_target"
        
        try:
            from app.core.exporter import exporter
            
            success, filepath, message = exporter.export_results(
                results,
                target,
                export_format,
                scan_type="port_scan"
            )
            
            if success:
                self.append_port_output(f"<p style='color: #00FF41;'>[EXPORT] Results exported to {filepath}</p><br>")
                self.status_updated.emit(f"Port scan results exported to {filepath}")
            else:
                self.append_port_output(f"<p style='color: #FF4500;'>[EXPORT ERROR] {message}</p><br>")
                self.status_updated.emit(f"Export failed: {message}")
                
        except Exception as e:
            self.append_port_output(f"<p style='color: #FF4500;'>[EXPORT ERROR] Export failed: {str(e)}</p>")
            self.status_updated.emit(f"Port scan export error: {str(e)}")