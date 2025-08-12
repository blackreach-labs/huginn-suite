# app/ui/animations/universal_run_button.py
from PyQt6.QtWidgets import QPushButton
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QColor

class UniversalRunButton(QPushButton):
    """Universal animated run button for all scans"""
    
    def __init__(self, text="Run", parent=None):
        super().__init__(text, parent)
        self.setup_animation()
        self.is_running = False
        
    def setup_animation(self):
        """Setup pulsing animation"""
        self.color_timer = QTimer()
        self.color_timer.timeout.connect(self.toggle_pulse_color)
        self.pulse_state = False
        
    def start_scan(self):
        """Start scan state - change to Stop and flash red"""
        if not self.is_running:
            self.is_running = True
            self.setText("Stop")
            self.color_timer.start(500)  # Flash every 500ms
            
    def stop_scan(self):
        """Stop scan state - change to Run and stop flashing"""
        if self.is_running:
            self.is_running = False
            self.setText("Run")
            self.color_timer.stop()
            self.setStyleSheet("")  # Reset to default
            
    def toggle_pulse_color(self):
        """Toggle between red pulse colors"""
        if self.pulse_state:
            # Bright red pulse
            self.setStyleSheet("""
                QPushButton {
                    background-color: #FF0000;
                    color: white;
                    border: 2px solid #FF0000;
                    font-weight: bold;
                }
            """)
        else:
            # Dim red pulse
            self.setStyleSheet("""
                QPushButton {
                    background-color: #990000;
                    color: white;
                    border: 2px solid #990000;
                    font-weight: bold;
                }
            """)
        self.pulse_state = not self.pulse_state