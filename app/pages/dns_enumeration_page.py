from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QCheckBox, QComboBox, QSpinBox, QPushButton, QStackedWidget, QTextEdit, QTableWidget, QTreeWidget, QToolButton, QSpacerItem, QSizePolicy
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon
import os

from app.widgets.progress_widget import ProgressWidget

class DNSEnumerationPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent.main_window if hasattr(parent, 'main_window') else parent
        self.setup_ui()

    def setup_ui(self):
        """Setup the UI components"""
        # Create main layout
        self.content_layout = QVBoxLayout(self)
        self.content_layout.setContentsMargins(15, 15, 15, 15)
        self.content_layout.setSpacing(10)
        # Target input field
        target_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        target_label.setFixedWidth(150)
        target_layout.addWidget(target_label)
        
        self.dns_target_input = QLineEdit()
        self.dns_target_input.setPlaceholderText("Enter target domain (e.g., example.com)")
        self.dns_target_input.textChanged.connect(self.check_dns_target_type)
        self.dns_target_input.returnPressed.connect(self.run_dns_scan)
        target_layout.addWidget(self.dns_target_input)
        self.content_layout.addLayout(target_layout)
        
        # Record Type Checkboxes
        record_row = QHBoxLayout()
        types_label = QLabel("Types:")
        types_label.setFixedWidth(150)
        record_row.addWidget(types_label)
        
        self.all_checkbox = QCheckBox("ALL")
        self.all_checkbox.stateChanged.connect(self.toggle_all_records)
        record_row.addWidget(self.all_checkbox)
        record_row.addSpacing(10)

        self.record_type_checkboxes = {}
        for rtype in ['A', 'CNAME', 'MX', 'TXT', 'NS', 'SRV']:
            cb = QCheckBox(rtype)
            cb.stateChanged.connect(self.update_all_checkbox)
            self.record_type_checkboxes[rtype] = cb
            record_row.addWidget(cb)
            record_row.addSpacing(10)

        self.ptr_checkbox = QCheckBox("PTR")
        self.ptr_checkbox.setEnabled(False)
        self.ptr_checkbox.stateChanged.connect(self.update_all_checkbox)
        record_row.addWidget(self.ptr_checkbox)
        
        record_row.addStretch()
        self.content_layout.addLayout(record_row)

        # Method & Wordlist/Bruteforce
        method_row = QHBoxLayout()
        method_label = QLabel("Method:")
        method_label.setFixedWidth(150)
        method_row.addWidget(method_label)
        
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Wordlist", "Bruteforce"])
        self.method_combo.setFixedWidth(150)
        self.method_combo.currentTextChanged.connect(self.toggle_method_options)
        method_row.addWidget(self.method_combo)

        self.wordlist_combo = QComboBox()
        self.populate_dns_wordlists()
        method_row.addWidget(self.wordlist_combo, 1)

        # Bruteforce options
        self.bruteforce_label = QLabel("Charset:")
        self.char_checkboxes = {}
        self.char_options = {'0-9': False, 'a-z': True, '-': True}
        self.length_label = QLabel("Length:")
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(1, 12)
        self.length_spinbox.setValue(3)
        self.length_spinbox.setFixedWidth(60)

        method_row.addWidget(self.bruteforce_label)
        for k, v in self.char_options.items():
            cb = QCheckBox(k)
            cb.setChecked(v)
            self.char_checkboxes[k] = cb
            method_row.addWidget(cb)
        method_row.addWidget(self.length_label)
        method_row.addWidget(self.length_spinbox)
        
        method_row.addStretch()
        self.method_row_layout = method_row
        self.content_layout.addLayout(method_row)
        
        # Set initial visibility - hide bruteforce options by default
        self.toggle_method_options("Wordlist")
        
        # Set default selections - only A record
        self.record_type_checkboxes['A'].setChecked(True)
        
        # Add run button and controls row
        controls_row = QHBoxLayout()
        
        # Run button
        try:
            from app.ui.animations.universal_run_button import UniversalRunButton
            self.dns_run_button = UniversalRunButton("Run")
        except ImportError:
            self.dns_run_button = QPushButton("Run")
        self.dns_run_button.setFixedWidth(80)
        self.dns_run_button.clicked.connect(self.toggle_dns_scan)
        controls_row.addWidget(self.dns_run_button)
        
        # Progress widget (inline, hidden by default)
        self.progress_widget = ProgressWidget(self)
        self.progress_widget.setVisible(False)
        
        # Add spacer to maintain consistent spacing when progress is hidden
        self.progress_spacer = QSpacerItem(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        controls_row.addItem(self.progress_spacer)
        controls_row.addWidget(self.progress_widget, 1)
        
        # View toggle buttons
        project_root = getattr(self.main_window, 'project_root', os.getcwd())
        text_icon_path = os.path.join(project_root, "resources", "icons", "text.png")
        table_icon_path = os.path.join(project_root, "resources", "icons", "table.png")
        graph_icon_path = os.path.join(project_root, "resources", "icons", "graph.png")
        
        self.text_view_btn = QToolButton()
        if os.path.exists(text_icon_path):
            self.text_view_btn.setIcon(QIcon(text_icon_path))
        else:
            self.text_view_btn.setText("Text")
        self.text_view_btn.setFixedWidth(40)
        self.text_view_btn.setCheckable(True)
        self.text_view_btn.setChecked(True)
        self.text_view_btn.clicked.connect(lambda: self.set_dns_view("text"))
        controls_row.addWidget(self.text_view_btn)
        
        self.table_view_btn = QToolButton()
        if os.path.exists(table_icon_path):
            self.table_view_btn.setIcon(QIcon(table_icon_path))
        else:
            self.table_view_btn.setText("Table")
        self.table_view_btn.setFixedWidth(40)
        self.table_view_btn.setCheckable(True)
        self.table_view_btn.clicked.connect(lambda: self.set_dns_view("table"))
        controls_row.addWidget(self.table_view_btn)
        
        self.graph_view_btn = QToolButton()
        if os.path.exists(graph_icon_path):
            self.graph_view_btn.setIcon(QIcon(graph_icon_path))
        else:
            self.graph_view_btn.setText("Graph")
        self.graph_view_btn.setFixedWidth(40)
        self.graph_view_btn.setCheckable(True)
        self.graph_view_btn.clicked.connect(lambda: self.set_dns_view("graph"))
        controls_row.addWidget(self.graph_view_btn)
        
        # Export button
        self.dns_export_combo = QComboBox()
        self.dns_export_combo.addItems(["JSON", "CSV", "XML", "HTML"])
        self.dns_export_combo.setFixedWidth(120)
        controls_row.addWidget(self.dns_export_combo)
        
        self.dns_export_button = QPushButton("Export")
        self.dns_export_button.setFixedWidth(85)
        self.dns_export_button.setEnabled(False)
        self.dns_export_button.clicked.connect(self.export_dns_results)
        controls_row.addWidget(self.dns_export_button)
        self.content_layout.addLayout(controls_row)
        
        # Add results stack with multiple views
        self.dns_results_stack = QStackedWidget()
        
        # Text view (terminal)
        self.dns_terminal = QTextEdit()
        self.dns_terminal.setReadOnly(True)
        self.apply_terminal_theme()
        self.dns_terminal.setPlaceholderText("DNS enumeration results will appear here...")
        self.dns_results_stack.addWidget(self.dns_terminal)
        
        # Table view
        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(3)
        self.dns_table.setHorizontalHeaderLabels(["Domain/Record", "Type", "Value"])
        self.dns_results_stack.addWidget(self.dns_table)
        
        # Graph view (tree)
        self.dns_tree = QTreeWidget()
        self.dns_tree.setHeaderLabels(["Domain", "Type", "Value"])
        self.dns_results_stack.addWidget(self.dns_tree)
        
        self.content_layout.addWidget(self.dns_results_stack, 1)
        
        # Initialize current view
        self.current_dns_view = "text"
        self.dns_scan_results = {}
        self.dns_scanning = False

    def populate_dns_wordlists(self):
        """Populate DNS wordlist dropdown"""
        self.wordlist_combo.addItem("Default subdomains", None)
        project_root = getattr(self.main_window, 'project_root', os.getcwd())
        wordlist_dir = os.path.join(project_root, "resources", "wordlists")
        if os.path.exists(wordlist_dir):
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    self.wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
        
        # Set default wordlist to subdomains-top1000.txt
        default_wordlist_path = os.path.join(wordlist_dir, "subdomains-top1000.txt")
        for i in range(self.wordlist_combo.count()):
            if self.wordlist_combo.itemData(i) == default_wordlist_path:
                self.wordlist_combo.setCurrentIndex(i)
                break

    def check_dns_target_type(self):
        """Check and validate DNS target type"""
        text = self.dns_target_input.text().strip()
        # Check if target looks like IP (3 octets with dots)
        import re
        ip_pattern = r'^(\d{1,3}\.){2,3}\d{1,3}'
        is_ip_like = bool(re.match(ip_pattern, text))
        
        if is_ip_like:
            # Enable PTR, disable and uncheck others
            self.ptr_checkbox.setEnabled(True)
            self.ptr_checkbox.setChecked(True)
            self.all_checkbox.setEnabled(False)
            self.all_checkbox.setChecked(False)
            for checkbox in self.record_type_checkboxes.values():
                checkbox.setEnabled(False)
                checkbox.setChecked(False)
            # Hide method row when PTR is active
            if hasattr(self, 'method_row_layout'):
                for i in range(self.method_row_layout.count()):
                    item = self.method_row_layout.itemAt(i)
                    if item and item.widget():
                        item.widget().setVisible(False)
        else:
            # Enable others, disable PTR
            self.ptr_checkbox.setEnabled(False)
            self.ptr_checkbox.setChecked(False)
            self.all_checkbox.setEnabled(True)
            for checkbox in self.record_type_checkboxes.values():
                checkbox.setEnabled(True)
            # Set A record as default when switching from IP
            if text and not any(cb.isChecked() for cb in self.record_type_checkboxes.values()):
                self.record_type_checkboxes['A'].setChecked(True)
            # Show method row when PTR is not active
            if hasattr(self, 'method_row_layout'):
                for i in range(self.method_row_layout.count()):
                    item = self.method_row_layout.itemAt(i)
                    if item and item.widget():
                        item.widget().setVisible(True)
                # Re-apply method visibility settings
                if hasattr(self, 'method_combo'):
                    self.toggle_method_options(self.method_combo.currentText())

    def toggle_all_records(self):
        """Toggle all DNS record types"""
        state = self.all_checkbox.isChecked()
        for checkbox in self.record_type_checkboxes.values():
            checkbox.setChecked(state)
        if self.ptr_checkbox.isEnabled():
            self.ptr_checkbox.setChecked(state)

    def update_all_checkbox(self):
        """Update all checkbox state"""
        all_checked = all(cb.isChecked() for cb in self.record_type_checkboxes.values())
        if self.ptr_checkbox.isEnabled():
            all_checked = all_checked and self.ptr_checkbox.isChecked()
        self.all_checkbox.setChecked(all_checked)

    def toggle_method_options(self, method):
        """Toggle DNS method options"""
        is_wordlist = (method == "Wordlist")
        
        self.wordlist_combo.setVisible(is_wordlist)
        
        # Toggle bruteforce options visibility
        self.bruteforce_label.setVisible(not is_wordlist)
        self.length_label.setVisible(not is_wordlist)
        self.length_spinbox.setVisible(not is_wordlist)
        for checkbox in self.char_checkboxes.values():
            checkbox.setVisible(not is_wordlist)

    def run_dns_scan(self):
        """Run DNS enumeration scan"""
        # Get target from input field
        target = self.dns_target_input.text().strip()
        if not target:
            if hasattr(self, 'show_status'):
                self.show_status("Please enter a target domain", "warning")
            return
        
        # Get selected record types
        selected_types = []
        if self.all_checkbox.isChecked():
            selected_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV']
        else:
            for rtype, checkbox in self.record_type_checkboxes.items():
                if checkbox.isChecked():
                    selected_types.append(rtype)
            if self.ptr_checkbox.isEnabled() and self.ptr_checkbox.isChecked():
                selected_types.append('PTR')
        
        if not selected_types:
            selected_types = ['A']  # Default
        
        method = self.method_combo.currentText()
        wordlist_path = self.wordlist_combo.currentData() if method == "Wordlist" else None
        
        if hasattr(self, 'show_status'):
            self.show_status(f"Starting DNS enumeration for {target} with types: {', '.join(selected_types)} using {method}", "info")
        
        # Clear terminal before starting new scan
        self.dns_terminal.clear()
        self.append_dns_output(f"<p style='color: #00BFFF;'>[DNS SCAN] Starting enumeration for {target}</p><br>")
        
        # Set button state
        if hasattr(self.dns_run_button, 'start_scan'):
            self.dns_run_button.start_scan()
        else:
            self.dns_run_button.setText("Stop")
        
        # Show progress widget and hide spacer
        self.progress_widget.setVisible(True)
        self.progress_spacer.changeSize(0, 0, QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)
        self.progress_widget.reset_progress()
        
        # Run the actual DNS enumeration using dns_utils
        try:
            from app.tools import dns_utils
            from app.core.dns_settings import dns_settings
            
            dns_server = dns_settings.get_current_dns()
            if dns_server == "Default DNS":
                dns_server = None
            
            # Check if PTR scan
            if self.ptr_checkbox.isEnabled() and self.ptr_checkbox.isChecked():
                tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
                self.current_worker = dns_utils.query_ptr_records(
                    ip_range=target,
                    dns_server=dns_server,
                    output_callback=self.append_dns_output,
                    results_callback=self.store_dns_results,
                    tenant_id=tenant_id
                )
                # Connect finished signal for PTR worker
                if self.current_worker and hasattr(self.current_worker, 'signals'):
                    self.current_worker.signals.finished.connect(self.on_dns_scan_finished)
                return
            
            # Get bruteforce parameters
            char_sets = []
            max_length = 3
            if method == "Bruteforce":
                char_sets = [k for k, checkbox in self.char_checkboxes.items() if checkbox.isChecked()]
                max_length = self.length_spinbox.value()
                # Debug output
                self.append_dns_output(f"<p style='color: #87CEEB;'>[DEBUG] Bruteforce char_sets: {char_sets}, max_length: {max_length}</p><br>")
            
            # Use DNS enumeration logic
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            self.current_worker = dns_utils.enumerate_hostnames(
                target,
                wordlist_path,
                self.append_dns_output,
                lambda x: None,  # status callback
                self.on_dns_scan_finished,
                record_types=selected_types,
                use_bruteforce=(method == "Bruteforce"),
                char_sets=char_sets,
                max_length=max_length,
                dns_server=dns_server,
                results_callback=self.store_dns_results,
                progress_callback=self.update_dns_progress,
                progress_start_callback=self.start_dns_progress,
                tenant_id=tenant_id
            )
            
        except Exception as e:
            self.append_dns_output(f"<p style='color: #FF6B6B;'>[ERROR] Failed to start DNS scan: {e}</p><br>")
            import traceback
            self.append_dns_output(f"<p style='color: #FF6B6B;'>[ERROR] Traceback: {traceback.format_exc()}</p><br>")
        
        # Set scanning state
        self.dns_scanning = True
        self.dns_scan_results = {}
        
        # Disable export button during scan
        self.dns_export_button.setEnabled(False)

    def append_dns_output(self, text):
        """Append text to DNS terminal output"""
        # Get current theme for font selection
        current_theme = getattr(self.main_window, 'current_theme', 'dark_blue')
        font_family = 'Share Tech Mono' if current_theme == 'matrix' else 'Neuropol X'
        
        # Apply formatting
        if not text.startswith('<div style="font-family:'):
            text = f'<div style="font-family: {font_family}, monospace;">{text}</div>'
        
        # Insert HTML directly
        self.dns_terminal.insertHtml(text)
        
        # Force scroll to bottom
        QTimer.singleShot(10, lambda: self.dns_terminal.verticalScrollBar().setValue(
            self.dns_terminal.verticalScrollBar().maximum()
        ))

    def apply_terminal_theme(self):
        """Apply theme-specific styling to terminal"""
        # Get current theme from main window
        current_theme = getattr(self.main_window, 'current_theme', 'dark_blue')
        
        if current_theme == 'matrix':
            # Matrix theme with ShareTechMono font
            self.dns_terminal.setStyleSheet("""
                QTextEdit {
                    background-color: #000000;
                    color: #00FF41;
                    font-family: 'Share Tech Mono', monospace;
                    font-size: 11pt;
                    border: 1px solid #00FF41;
                    border-radius: 5px;
                    selection-background-color: #003300;
                }
            """)
        else:
            # Dark Blue theme with Neuropol font (default)
            self.dns_terminal.setStyleSheet("""
                QTextEdit {
                    background-color: #1E1E1E;
                    color: #DCDCDC;
                    font-family: 'Neuropol X', monospace;
                    font-size: 10pt;
                    border: 1px solid rgba(100, 200, 255, 100);
                    border-radius: 5px;
                    selection-background-color: #2D4F7C;
                }
            """)

    def store_dns_results(self, results):
        """Store and display DNS scan results"""
        # Store results for view switching
        self.dns_scan_results = results
        
        # Update table and graph views
        self.populate_dns_table(results)
        self.populate_dns_tree(results)

    def populate_dns_table(self, results):
        """Populate DNS table view"""
        if not results:
            return
            
        # Clear existing data
        self.dns_table.setRowCount(0)
        
        # Collect all records
        all_records = []
        for domain, record_types in results.items():
            for record_type, values in record_types.items():
                for value in values:
                    all_records.append({
                        'domain': domain,
                        'type': record_type,
                        'value': value
                    })
        
        # Populate table
        self.dns_table.setRowCount(len(all_records))
        for row, record in enumerate(all_records):
            from PyQt6.QtWidgets import QTableWidgetItem
            from PyQt6.QtCore import Qt
            
            domain_item = QTableWidgetItem(record['domain'])
            domain_item.setFlags(domain_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.dns_table.setItem(row, 0, domain_item)
            
            type_item = QTableWidgetItem(record['type'])
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.dns_table.setItem(row, 1, type_item)
            
            value_item = QTableWidgetItem(str(record['value']))
            value_item.setFlags(value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.dns_table.setItem(row, 2, value_item)
        
        self.dns_table.resizeColumnsToContents()

    def populate_dns_tree(self, results):
        """Populate DNS tree view"""
        if not results:
            return
            
        self.dns_tree.clear()
        
        from PyQt6.QtWidgets import QTreeWidgetItem
        
        for domain, record_types in results.items():
            domain_item = QTreeWidgetItem(self.dns_tree)
            domain_item.setText(0, domain)
            domain_item.setText(1, "Domain")
            domain_item.setText(2, "")
            
            for record_type, values in record_types.items():
                type_item = QTreeWidgetItem(domain_item)
                type_item.setText(0, record_type)
                type_item.setText(1, "Record Type")
                type_item.setText(2, f"{len(values)} records")
                
                for value in values:
                    record_item = QTreeWidgetItem(type_item)
                    record_item.setText(0, "")
                    record_item.setText(1, record_type)
                    record_item.setText(2, str(value))
        
        self.dns_tree.expandAll()
        self.dns_tree.resizeColumnToContents(0)
        self.dns_tree.resizeColumnToContents(1)
        self.dns_tree.resizeColumnToContents(2)

    def set_dns_view(self, view_type):
        """Set DNS results view type"""
        self.current_dns_view = view_type
        
        # Update button states
        self.text_view_btn.setChecked(view_type == "text")
        self.table_view_btn.setChecked(view_type == "table")
        self.graph_view_btn.setChecked(view_type == "graph")
        
        # Switch view
        if view_type == "text":
            self.dns_results_stack.setCurrentIndex(0)
        elif view_type == "table":
            self.dns_results_stack.setCurrentIndex(1)
        elif view_type == "graph":
            self.dns_results_stack.setCurrentIndex(2)

    def on_dns_scan_finished(self):
        """Handle DNS scan completion"""
        self.append_dns_output(f"<p style='color: #00FF41;'>[SCAN] DNS enumeration completed</p><br>")
        if hasattr(self, 'show_status'):
            self.show_status("DNS enumeration completed", "success")
        
        # Reset button state
        if hasattr(self.dns_run_button, 'stop_scan'):
            self.dns_run_button.stop_scan()
        else:
            self.dns_run_button.setText("Run")
        
        # Keep progress widget visible with completed status
        self.progress_widget.finish_progress("DNS scan completed")
        
        # Hide progress after delay and restore spacer
        QTimer.singleShot(3000, lambda: (
            self.progress_widget.setVisible(False),
            self.progress_spacer.changeSize(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        ))
        
        self.dns_scanning = False
        
        # Enable export button if we have results
        if self.dns_scan_results:
            self.dns_export_button.setEnabled(True)

    def toggle_dns_scan(self):
        """Toggle DNS scan - start if not running, stop if running"""
        if self.dns_scanning:
            self.cancel_dns_scan()
        else:
            self.run_dns_scan()

    def cancel_dns_scan(self):
        """Cancel running DNS scan"""
        if hasattr(self, 'current_worker') and self.current_worker:
            self.current_worker.is_running = False
        
        self.dns_scanning = False
        
        # Reset button state
        if hasattr(self.dns_run_button, 'stop_scan'):
            self.dns_run_button.stop_scan()
        else:
            self.dns_run_button.setText("Run")
        
        # Hide progress widget and restore spacer
        self.progress_widget.setVisible(False)
        self.progress_spacer.changeSize(0, 0, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        
        self.append_dns_output(f"<p style='color: #FFAA00;'>[SCAN] DNS enumeration cancelled</p><br>")
        if hasattr(self, 'show_status'):
            self.show_status("DNS scan cancelled", "warning")

    def export_dns_results(self):
        """Export DNS scan results"""
        if not self.dns_scan_results:
            if hasattr(self, 'show_status'):
                self.show_status("No DNS results to export", "warning")
            return
        
        export_format = self.dns_export_combo.currentText().lower()
        target = self.dns_target_input.text().strip() or "unknown"
        
        try:
            from app.core.exporter import exporter
            
            success, filepath, message = exporter.export_results(
                self.dns_scan_results,
                target,
                export_format,
                scan_type="dns_enum"
            )
            
            if success:
                self.append_dns_output(f"<p style='color: #00FF41;'>[EXPORT] Results exported to {filepath}</p><br>")
                if hasattr(self, 'show_status'):
                    self.show_status(f"DNS results exported to {filepath}", "success")
            else:
                self.append_dns_output(f"<p style='color: #FF4500;'>[EXPORT ERROR] {message}</p><br>")
                if hasattr(self, 'show_status'):
                    self.show_status(f"Export failed: {message}", "error")
                
        except Exception as e:
            self.append_dns_output(f"<p style='color: #FF4500;'>[EXPORT ERROR] Export failed: {str(e)}</p>")
            if hasattr(self, 'show_status'):
                self.show_status(f"Export error: {str(e)}", "error")

    def start_dns_progress(self, total):
        """Start DNS scan progress tracking"""
        self.progress_widget.setVisible(True)
        self.progress_widget.start_progress(total, "DNS enumeration...")
        if hasattr(self, 'show_status'):
            self.show_status(f"Starting DNS scan with {total} items", "info")

    def update_dns_progress(self, completed, found, message=""):
        """Update DNS scan progress"""
        self.progress_widget.update_progress(completed, found)
        if hasattr(self, 'show_status'):
            self.show_status(f"Progress: {completed} completed, {found} found", "info")