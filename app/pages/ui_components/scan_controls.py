# app/pages/ui_components/scan_controls.py
from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QComboBox, QCheckBox)
from PyQt6.QtCore import pyqtSignal, Qt
from app.ui.animations.button_animations import PulsingButton

class ScanControls(QWidget):
    """Reusable scan controls component with target input, options, and run button."""
    
    # Signals
    scan_started = pyqtSignal(dict)  # Emits scan parameters
    scan_stopped = pyqtSignal()
    
    def __init__(self, scan_type="Generic", parent=None):
        super().__init__(parent)
        self.scan_type = scan_type
        self.is_scanning = False
        self.setup_ui()
        self.apply_styles()
    
    def setup_ui(self):
        """Setup the scan controls UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Target input row
        target_layout = QHBoxLayout()
        target_label = QLabel("Target:")
        target_label.setFixedWidth(80)
        target_layout.addWidget(target_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText(f"Enter target for {self.scan_type} scan")
        self.target_input.returnPressed.connect(self.toggle_scan)
        target_layout.addWidget(self.target_input)
        
        layout.addLayout(target_layout)
        
        # Options row
        self.options_layout = QHBoxLayout()
        self.setup_scan_options()
        layout.addLayout(self.options_layout)
        
        # Controls row
        controls_layout = QHBoxLayout()
        
        # Run button
        self.run_button = PulsingButton("Run")
        self.run_button.setFixedWidth(80)
        self.run_button.clicked.connect(self.toggle_scan)
        controls_layout.addWidget(self.run_button)
        
        controls_layout.addStretch()
        layout.addLayout(controls_layout)
    
    def setup_scan_options(self):
        """Setup scan-specific options. Override in subclasses."""
        # Default options
        self.timeout_combo = QComboBox()
        self.timeout_combo.addItems(["5s", "10s", "30s", "60s"])
        self.timeout_combo.setCurrentText("10s")
        
        timeout_label = QLabel("Timeout:")
        self.options_layout.addWidget(timeout_label)
        self.options_layout.addWidget(self.timeout_combo)
        
        self.options_layout.addStretch()
    
    def apply_styles(self):
        """Apply component styles."""
        self.setStyleSheet("""
            QWidget {
                background-color: rgba(0, 0, 0, 50);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QLabel {
                color: #DCDCDC;
                font-weight: bold;
                background: transparent;
                border: none;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 5px;
            }
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 5px;
            }
            QCheckBox {
                color: #DCDCDC;
                background: transparent;
                border: none;
            }
        """)
    
    def toggle_scan(self):
        """Toggle scan state."""
        if self.is_scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start the scan."""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.is_scanning = True
        self.run_button.setText("Stop")
        if hasattr(self.run_button, 'start_pulse'):
            self.run_button.start_pulse("#FF0000")
        
        # Collect scan parameters
        params = {
            'target': target,
            'timeout': self.timeout_combo.currentText(),
            'scan_type': self.scan_type
        }
        
        # Add custom options
        params.update(self.get_custom_options())
        
        self.scan_started.emit(params)
    
    def stop_scan(self):
        """Stop the scan."""
        self.is_scanning = False
        self.run_button.setText("Run")
        if hasattr(self.run_button, 'stop_pulse'):
            self.run_button.stop_pulse()
        
        self.scan_stopped.emit()
    
    def get_custom_options(self):
        """Get custom scan options. Override in subclasses."""
        return {}
    
    def set_target(self, target):
        """Set the target input value."""
        self.target_input.setText(target)
    
    def get_target(self):
        """Get the current target value."""
        return self.target_input.text().strip()
    
    def set_scanning_state(self, scanning):
        """Set the scanning state externally."""
        if scanning != self.is_scanning:
            if scanning:
                self.start_scan()
            else:
                self.stop_scan()
    
    def add_custom_option(self, widget, label=None):
        """Add a custom option widget to the options layout."""
        if label:
            label_widget = QLabel(label)
            self.options_layout.insertWidget(self.options_layout.count() - 1, label_widget)
        self.options_layout.insertWidget(self.options_layout.count() - 1, widget)