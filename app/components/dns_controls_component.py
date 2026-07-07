import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                            QCheckBox, QComboBox, QSpinBox, QPushButton, QFrame)
from PyQt6.QtCore import pyqtSignal
from app.core.logger import logger

class DNSControlsComponent(QWidget):
    scan_started = pyqtSignal(dict)
    scan_stopped = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_scanning = False
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup DNS controls UI"""
        layout = QVBoxLayout(self)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("domain.com or IP address")
        self.target_input.textChanged.connect(self.check_target_type)
        target_layout.addWidget(self.target_input)
        
        layout.addLayout(target_layout)
        
        # Options frame
        options_frame = QFrame()
        options_layout = QVBoxLayout(options_frame)
        
        # Record types
        self.setup_record_types(options_layout)
        
        # Method selection
        self.setup_method_options(options_layout)
        
        layout.addWidget(options_frame)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Start DNS Scan")
        self.start_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)

    def setup_record_types(self, layout):
        """Setup DNS record type selection"""
        layout.addWidget(QLabel("Record Types:"))
        
        record_layout = QHBoxLayout()
        
        self.all_checkbox = QCheckBox("ALL")
        self.all_checkbox.stateChanged.connect(self.toggle_all_records)
        record_layout.addWidget(self.all_checkbox)
        
        self.record_type_checkboxes = {}
        for rtype in ['A', 'CNAME', 'MX', 'TXT', 'NS', 'SRV']:
            cb = QCheckBox(rtype)
            cb.stateChanged.connect(self.update_all_checkbox)
            self.record_type_checkboxes[rtype] = cb
            record_layout.addWidget(cb)
        
        # Set default A record
        self.record_type_checkboxes['A'].setChecked(True)
        
        layout.addLayout(record_layout)

    def setup_method_options(self, layout):
        """Setup DNS enumeration method options"""
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Method:"))
        
        self.method_combo = QComboBox()
        self.method_combo.addItems(["Wordlist", "Bruteforce"])
        self.method_combo.currentTextChanged.connect(self.toggle_method_options)
        method_layout.addWidget(self.method_combo)
        
        layout.addLayout(method_layout)
        
        # Wordlist selection
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(QLabel("Wordlist:"))
        
        self.wordlist_combo = QComboBox()
        self.populate_wordlists()
        wordlist_layout.addWidget(self.wordlist_combo)
        
        layout.addLayout(wordlist_layout)
        self.wordlist_layout = wordlist_layout
        
        # Bruteforce options
        self.bruteforce_layout = QVBoxLayout()
        
        char_layout = QHBoxLayout()
        char_layout.addWidget(QLabel("Charset:"))
        
        self.char_checkboxes = {}
        for charset in ['0-9', 'a-z', '-']:
            cb = QCheckBox(charset)
            cb.setChecked(charset != '0-9')  # Default a-z and - checked
            self.char_checkboxes[charset] = cb
            char_layout.addWidget(cb)
        
        self.bruteforce_layout.addLayout(char_layout)
        
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Max Length:"))
        
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(1, 12)
        self.length_spinbox.setValue(3)
        self.length_spinbox.setFixedWidth(60)
        length_layout.addWidget(self.length_spinbox)
        
        self.bruteforce_layout.addLayout(length_layout)
        layout.addLayout(self.bruteforce_layout)
        
        # Set initial visibility
        self.toggle_method_options("Wordlist")

    def populate_wordlists(self):
        """Populate DNS wordlist dropdown"""
        self.wordlist_combo.addItem("Default subdomains", None)
        
        try:
            if hasattr(self.parent(), 'main_window') and self.parent().main_window:
                wordlist_dir = os.path.join(self.parent().main_window.project_root, "resources", "wordlists")
                if os.path.exists(wordlist_dir):
                    for filename in os.listdir(wordlist_dir):
                        if filename.endswith(".txt"):
                            self.wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)

    def toggle_all_records(self):
        """Toggle all DNS record types"""
        state = self.all_checkbox.isChecked()
        for checkbox in self.record_type_checkboxes.values():
            checkbox.setChecked(state)

    def update_all_checkbox(self):
        """Update all checkbox state"""
        all_checked = all(cb.isChecked() for cb in self.record_type_checkboxes.values())
        self.all_checkbox.setChecked(all_checked)

    def toggle_method_options(self, method):
        """Toggle DNS method options"""
        is_wordlist = (method == "Wordlist")
        
        # Show/hide wordlist options
        for i in range(self.wordlist_layout.count()):
            widget = self.wordlist_layout.itemAt(i).widget()
            if widget:
                widget.setVisible(is_wordlist)
        
        # Show/hide bruteforce options
        for i in range(self.bruteforce_layout.count()):
            item = self.bruteforce_layout.itemAt(i)
            if item.layout():
                for j in range(item.layout().count()):
                    widget = item.layout().itemAt(j).widget()
                    if widget:
                        widget.setVisible(not is_wordlist)

    def check_target_type(self):
        """Check target type for PTR records"""
        text = self.target_input.text().strip()
        
        # Check if target looks like IP
        import re
        ip_pattern = r'^(\d{1,3}\.){2,3}\d{1,3}'
        is_ip_like = bool(re.match(ip_pattern, text))
        
        if is_ip_like:
            # Enable PTR, disable others
            for checkbox in self.record_type_checkboxes.values():
                checkbox.setEnabled(False)
                checkbox.setChecked(False)
            
            # Add PTR checkbox if not exists
            if not hasattr(self, 'ptr_checkbox'):
                self.ptr_checkbox = QCheckBox("PTR")
                # Add to record layout
            
            if hasattr(self, 'ptr_checkbox'):
                self.ptr_checkbox.setEnabled(True)
                self.ptr_checkbox.setChecked(True)
            
            # Hide method options for PTR
            self.method_combo.setVisible(False)
        else:
            # Enable others, disable PTR
            for checkbox in self.record_type_checkboxes.values():
                checkbox.setEnabled(True)
            
            # Set A record as default
            if text and not any(cb.isChecked() for cb in self.record_type_checkboxes.values()):
                self.record_type_checkboxes['A'].setChecked(True)
            
            if hasattr(self, 'ptr_checkbox'):
                self.ptr_checkbox.setEnabled(False)
                self.ptr_checkbox.setChecked(False)
            
            # Show method options
            self.method_combo.setVisible(True)
            self.toggle_method_options(self.method_combo.currentText())

    def start_scan(self):
        """Start DNS scan"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        # Get selected record types
        selected_types = []
        if self.all_checkbox.isChecked():
            selected_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV']
        else:
            for rtype, checkbox in self.record_type_checkboxes.items():
                if checkbox.isChecked():
                    selected_types.append(rtype)
        
        if hasattr(self, 'ptr_checkbox') and self.ptr_checkbox.isChecked():
            selected_types = ['PTR']
        
        if not selected_types:
            selected_types = ['A']
        
        params = {
            'target': target,
            'record_types': selected_types,
            'method': self.method_combo.currentText(),
            'wordlist_path': self.wordlist_combo.currentData() if self.method_combo.currentText() == "Wordlist" else None
        }
        
        # Add bruteforce options if selected
        if self.method_combo.currentText() == "Bruteforce":
            char_sets = [k for k, v in self.char_checkboxes.items() if v.isChecked()]
            params.update({
                'char_sets': char_sets,
                'max_length': self.length_spinbox.value()
            })
        
        self.set_scanning_state(True)
        self.scan_started.emit(params)

    def stop_scan(self):
        """Stop DNS scan"""
        self.set_scanning_state(False)
        self.scan_stopped.emit()

    def set_scanning_state(self, scanning):
        """Set scanning state"""
        self.is_scanning = scanning
        self.start_button.setEnabled(not scanning)
        self.stop_button.setEnabled(scanning)
        
        # Change button text
        if scanning:
            self.start_button.setText("Running...")
            self.stop_button.setText("End")
        else:
            self.start_button.setText("Start DNS Scan")
            self.stop_button.setText("Stop Scan")

    def get_target(self):
        """Get current target"""
        return self.target_input.text().strip()

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass