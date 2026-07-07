from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar, QPushButton
from PyQt6.QtCore import pyqtSignal

class ProgressComponent(QWidget):
    scan_cancelled = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()
        self.setVisible(False)  # Hidden by default

    def setup_ui(self):
        """Setup progress UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        
        # Progress info layout
        info_layout = QHBoxLayout()
        
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #64C8FF; font-weight: bold;")
        info_layout.addWidget(self.status_label)
        
        # Phase indicator
        self.phase_label = QLabel("")
        self.phase_label.setStyleSheet("color: #87CEEB; font-size: 10pt;")
        info_layout.addWidget(self.phase_label)
        
        info_layout.addStretch()
        
        # Time elapsed
        self.time_label = QLabel("00:00")
        self.time_label.setStyleSheet("color: #DCDCDC; font-size: 10pt;")
        info_layout.addWidget(self.time_label)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.cancel_scan)
        self.cancel_button.setFixedWidth(80)
        info_layout.addWidget(self.cancel_button)
        
        # Store references for hiding
        self.timer_cancel_widgets = [self.phase_label, self.time_label, self.cancel_button, self.status_label]
        
        layout.addLayout(info_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Detailed progress info
        details_layout = QHBoxLayout()
        
        self.vulnerabilities_found = QLabel("Vulnerabilities: 0")
        self.vulnerabilities_found.setStyleSheet("color: #FF6B6B; font-size: 9pt;")
        details_layout.addWidget(self.vulnerabilities_found)
        
        self.requests_sent = QLabel("Requests: 0")
        self.requests_sent.setStyleSheet("color: #4ECDC4; font-size: 9pt;")
        details_layout.addWidget(self.requests_sent)
        
        self.current_speed = QLabel("Speed: 0 req/s")
        self.current_speed.setStyleSheet("color: #45B7D1; font-size: 9pt;")
        details_layout.addWidget(self.current_speed)
        
        details_layout.addStretch()
        layout.addLayout(details_layout)
        
        # Initialize timer for elapsed time
        from PyQt6.QtCore import QTimer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_elapsed_time)
        self.start_time = None
        self.scan_stats = {'vulnerabilities': 0, 'requests': 0, 'speed': 0}

    def start_progress(self, message="Starting scan...", hide_timer_cancel=False):
        """Start progress tracking"""
        self.status_label.setText(message)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        self.setVisible(True)
        
        # Hide timer and cancel elements if requested
        if hide_timer_cancel:
            for widget in self.timer_cancel_widgets:
                widget.setVisible(False)
        else:
            for widget in self.timer_cancel_widgets:
                widget.setVisible(True)
        
        # Start timer for elapsed time
        import time
        self.start_time = time.time()
        self.timer.start(1000)  # Update every second
        
        # Reset stats
        self.scan_stats = {'vulnerabilities': 0, 'requests': 0, 'speed': 0}
        self.update_scan_stats()

    def set_total(self, total):
        """Set total items for progress tracking"""
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(0)

    def update_progress(self, completed, message="", phase="", stats=None):
        """Update progress with detailed information"""
        if message:
            self.status_label.setText(message)
        
        if phase:
            self.phase_label.setText(f"[{phase}]")
        
        if self.progress_bar.maximum() > 0:
            self.progress_bar.setValue(completed)
        
        # Update scan statistics
        if stats:
            self.scan_stats.update(stats)
            self.update_scan_stats()
    
    def update_scan_stats(self):
        """Update scan statistics display"""
        self.vulnerabilities_found.setText(f"Vulnerabilities: {self.scan_stats['vulnerabilities']}")
        self.requests_sent.setText(f"Requests: {self.scan_stats['requests']}")
        self.current_speed.setText(f"Speed: {self.scan_stats['speed']} req/s")
    
    def update_elapsed_time(self):
        """Update elapsed time display"""
        if self.start_time:
            import time
            elapsed = int(time.time() - self.start_time)
            minutes = elapsed // 60
            seconds = elapsed % 60
            self.time_label.setText(f"{minutes:02d}:{seconds:02d}")

    def finish_progress(self, message="Completed", final_stats=None):
        """Finish progress tracking"""
        self.status_label.setText(message)
        self.phase_label.setText("[Complete]")
        
        if self.progress_bar.maximum() > 0:
            self.progress_bar.setValue(self.progress_bar.maximum())
        else:
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
        
        # Stop timer
        self.timer.stop()
        
        # Update final stats
        if final_stats:
            self.scan_stats.update(final_stats)
            self.update_scan_stats()
        
        # Hide after a longer delay to show final results
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(5000, lambda: self.setVisible(False))

    def cancel_operation(self):
        """Cancel current operation"""
        self.status_label.setText("Cancelling...")
        self.phase_label.setText("[Cancelled]")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        # Stop timer
        if hasattr(self, 'timer'):
            self.timer.stop()
        
        self.setVisible(False)

    def cancel_scan(self):
        """Handle cancel button click"""
        self.scan_cancelled.emit()

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass