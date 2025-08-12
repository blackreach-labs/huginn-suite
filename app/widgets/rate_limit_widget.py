# app/widgets/rate_limit_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QSpinBox, QPushButton, QCheckBox, QGroupBox, QSlider)
from PyQt6.QtCore import Qt
from app.core.rate_limiter import rate_limiter

class RateLimitWidget(QWidget):
    """Widget for rate limiting configuration"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.load_current_settings()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Rate limiting group
        rate_group = QGroupBox("⚡ Rate Limiting Configuration")
        rate_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        rate_layout = QVBoxLayout(rate_group)
        
        # Enable checkbox
        self.enable_checkbox = QCheckBox("Enable Rate Limiting")
        self.enable_checkbox.setStyleSheet("color: #DCDCDC; font-size: 11pt;")
        self.enable_checkbox.toggled.connect(self.toggle_rate_limiting)
        
        # Requests per second
        rps_layout = QHBoxLayout()
        rps_layout.addWidget(QLabel("Requests per second:"))
        
        self.rps_slider = QSlider(Qt.Orientation.Horizontal)
        self.rps_slider.setRange(1, 100)
        self.rps_slider.setValue(10)
        self.rps_slider.valueChanged.connect(self.update_rps_label)
        
        self.rps_label = QLabel("10")
        self.rps_label.setFixedWidth(30)
        self.rps_label.setStyleSheet("color: #00FF41; font-weight: bold;")
        
        rps_layout.addWidget(self.rps_slider)
        rps_layout.addWidget(self.rps_label)
        
        # Concurrent threads
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Max concurrent threads:"))
        
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 200)
        self.threads_spinbox.setValue(50)
        self.threads_spinbox.setFixedWidth(80)
        self.threads_spinbox.setStyleSheet("""
            QSpinBox {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px;
            }
        """)
        
        threads_layout.addWidget(self.threads_spinbox)
        threads_layout.addStretch()
        
        # Preset buttons
        preset_layout = QHBoxLayout()
        preset_layout.addWidget(QLabel("Presets:"))
        
        presets = [
            ("🐌 Stealth", 2, 10),
            ("🚶 Slow", 5, 20),
            ("🏃 Normal", 10, 50),
            ("🏎️ Fast", 25, 100),
            ("🚀 Aggressive", 50, 200)
        ]
        
        for name, rps, threads in presets:
            btn = QPushButton(name)
            btn.setFixedWidth(90)
            btn.clicked.connect(lambda checked, r=rps, t=threads: self.apply_preset(r, t))
            btn.setStyleSheet("""
                QPushButton {
                    background-color: rgba(100, 200, 255, 100);
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 6px;
                    font-size: 9pt;
                }
                QPushButton:hover {
                    background-color: rgba(100, 200, 255, 150);
                }
            """)
            preset_layout.addWidget(btn)
        
        preset_layout.addStretch()
        
        # Apply button
        apply_layout = QHBoxLayout()
        self.apply_button = QPushButton("✅ Apply Settings")
        self.apply_button.clicked.connect(self.apply_settings)
        self.apply_button.setEnabled(False)
        self.apply_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 100, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 11pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 100, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888;
            }
        """)
        
        # Status label
        self.status_label = QLabel("Rate limiting disabled")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        apply_layout.addWidget(self.apply_button)
        apply_layout.addStretch()
        
        # Add to rate layout
        rate_layout.addWidget(self.enable_checkbox)
        rate_layout.addLayout(rps_layout)
        rate_layout.addLayout(threads_layout)
        rate_layout.addLayout(preset_layout)
        rate_layout.addLayout(apply_layout)
        rate_layout.addWidget(self.status_label)
        
        layout.addWidget(rate_group)
        layout.addStretch()
        
    def load_current_settings(self):
        """Load current rate limiting settings"""
        limits = rate_limiter.get_current_limits()
        
        self.enable_checkbox.setChecked(limits['enabled'])
        self.rps_slider.setValue(limits['requests_per_second'])
        self.threads_spinbox.setValue(limits['concurrent_threads'])
        self.update_rps_label(limits['requests_per_second'])
        self.toggle_rate_limiting(limits['enabled'])
        
    def toggle_rate_limiting(self, enabled):
        """Toggle rate limiting controls"""
        self.rps_slider.setEnabled(enabled)
        self.threads_spinbox.setEnabled(enabled)
        self.apply_button.setEnabled(enabled)
        
        if not enabled:
            rate_limiter.disable()
            self.status_label.setText("Rate limiting disabled")
            self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        else:
            self.status_label.setText("Rate limiting enabled - click Apply to save")
            self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
    
    def update_rps_label(self, value):
        """Update requests per second label"""
        self.rps_label.setText(str(value))
        
        # Color code based on speed
        if value <= 5:
            color = "#00AA00"  # Green - safe
        elif value <= 15:
            color = "#FFAA00"  # Orange - moderate
        else:
            color = "#FF6600"  # Red - aggressive
            
        self.rps_label.setStyleSheet(f"color: {color}; font-weight: bold;")
    
    def apply_preset(self, rps, threads):
        """Apply a preset configuration"""
        self.rps_slider.setValue(rps)
        self.threads_spinbox.setValue(threads)
        self.update_rps_label(rps)
        
        if self.enable_checkbox.isChecked():
            self.apply_settings()
    
    def apply_settings(self):
        """Apply rate limiting settings"""
        if not self.enable_checkbox.isChecked():
            return
        
        rps = self.rps_slider.value()
        threads = self.threads_spinbox.value()
        
        rate_limiter.set_rate_limit(rps, threads, True)
        
        self.status_label.setText(f"✅ Applied: {rps} req/s, {threads} threads")
        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")