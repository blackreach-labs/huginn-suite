# app/ui/animations/button_animations.py
from PyQt6.QtWidgets import QPushButton, QGraphicsOpacityEffect
from PyQt6.QtCore import QPropertyAnimation, QTimer, QEasingCurve, pyqtSignal
from PyQt6.QtGui import QColor

class PulsingButton(QPushButton):
    """Button with pulsing animation for active scans"""
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setup_pulse_animation()
        self.is_pulsing = False
        
    def setup_pulse_animation(self):
        """Setup pulse animation properties"""
        self.opacity_effect = QGraphicsOpacityEffect()
        self.setGraphicsEffect(self.opacity_effect)
        
        self.pulse_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.pulse_animation.setDuration(1000)
        self.pulse_animation.setStartValue(1.0)
        self.pulse_animation.setEndValue(0.3)
        self.pulse_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.pulse_animation.setLoopCount(-1)  # Infinite loop
        
        # Color pulse timer for background color changes
        self.color_timer = QTimer()
        self.color_timer.timeout.connect(self.toggle_pulse_color)
        self.pulse_state = False
        
    def start_pulse(self, color="#FF0000"):
        """Start pulsing animation with specified color"""
        if not self.is_pulsing:
            self.is_pulsing = True
            self.pulse_color = color
            self.pulse_animation.start()
            self.color_timer.start(500)  # Toggle every 500ms
            
    def stop_pulse(self):
        """Stop pulsing animation"""
        if self.is_pulsing:
            self.is_pulsing = False
            self.pulse_animation.stop()
            self.color_timer.stop()
            self.opacity_effect.setOpacity(1.0)
            self.setStyleSheet("")  # Reset to default
            
    def toggle_pulse_color(self):
        """Toggle between pulse colors"""
        if self.pulse_state:
            # Bright pulse
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {self.pulse_color};
                    color: white;
                    border: 2px solid {self.pulse_color};
                    font-weight: bold;
                }}
            """)
        else:
            # Dim pulse
            dim_color = self.darken_color(self.pulse_color, 0.6)
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {dim_color};
                    color: white;
                    border: 2px solid {dim_color};
                    font-weight: bold;
                }}
            """)
        self.pulse_state = not self.pulse_state
        
    def darken_color(self, color_hex, factor):
        """Darken a hex color by factor (0.0 to 1.0)"""
        color = QColor(color_hex)
        r = int(color.red() * factor)
        g = int(color.green() * factor)
        b = int(color.blue() * factor)
        return f"#{r:02x}{g:02x}{b:02x}"

class HoverScaleButton(QPushButton):
    """Button with hover scale animation"""
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setup_hover_animation()
        
    def setup_hover_animation(self):
        """Setup hover scale animation"""
        self.scale_factor = 1.05
        self.animation_duration = 200
        
        # Store original stylesheet
        self.original_style = self.styleSheet()
        
    def enterEvent(self, event):
        """Handle mouse enter event"""
        self.animate_scale(self.scale_factor)
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        """Handle mouse leave event"""
        self.animate_scale(1.0)
        super().leaveEvent(event)
        
    def animate_scale(self, scale):
        """Animate button scale"""
        # Simple hover effect without unsupported CSS properties
        if scale > 1.0:
            scaled_style = f"""
                QPushButton {{
                    background-color: #4a90e2;
                    border: 2px solid #64C8FF;
                }}
            """
        else:
            scaled_style = ""
        self.setStyleSheet(self.original_style + scaled_style)

class GlowButton(QPushButton):
    """Button with glow effect on hover"""
    
    def __init__(self, text="", glow_color="#64C8FF", parent=None):
        super().__init__(text, parent)
        self.glow_color = glow_color
        self.setup_glow_effect()
        
    def setup_glow_effect(self):
        """Setup glow effect properties"""
        self.original_style = self.styleSheet()
        
    def enterEvent(self, event):
        """Apply glow effect on hover"""
        glow_style = f"""
            QPushButton {{
                border: 2px solid {self.glow_color};
                background-color: #2a2a2a;
            }}
        """
        self.setStyleSheet(self.original_style + glow_style)
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        """Remove glow effect"""
        self.setStyleSheet(self.original_style)
        super().leaveEvent(event)
        
    def hex_to_rgb(self, hex_color):
        """Convert hex color to RGB values"""
        color = QColor(hex_color)
        return f"{color.red()}, {color.green()}, {color.blue()}"

class StatusButton(QPushButton):
    """Button that changes appearance based on status"""
    
    status_changed = pyqtSignal(str)
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.current_status = "idle"
        self.status_colors = {
            "idle": "#555555",
            "running": "#FF6600", 
            "success": "#00AA00",
            "error": "#FF4444",
            "warning": "#FFAA00"
        }
        self.setup_status_animation()
        
    def setup_status_animation(self):
        """Setup status change animation"""
        self.status_animation = QPropertyAnimation(self, b"color")
        self.status_animation.setDuration(300)
        self.status_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        
    def set_status(self, status, animate=True):
        """Set button status with optional animation"""
        if status not in self.status_colors:
            return
            
        old_status = self.current_status
        self.current_status = status
        
        if animate and old_status != status:
            self.animate_status_change()
        else:
            self.apply_status_style()
            
        self.status_changed.emit(status)
        
    def animate_status_change(self):
        """Animate status change"""
        self.apply_status_style()
        
    def apply_status_style(self):
        """Apply current status styling"""
        color = self.status_colors[self.current_status]
        
        if self.current_status == "running":
            # Pulsing effect for running status
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: 2px solid {color};
                    font-weight: bold;
                }}
            """)
        else:
            # Solid color for other statuses
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    border: 2px solid {color};
                    font-weight: bold;
                }}
            """)

class AnimatedToggleButton(QPushButton):
    """Toggle button with smooth animation"""
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setCheckable(True)
        self.setup_toggle_animation()
        
    def setup_toggle_animation(self):
        """Setup toggle animation"""
        self.toggle_animation = QPropertyAnimation(self, b"color")
        self.toggle_animation.setDuration(250)
        self.toggle_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        
        self.toggled.connect(self.animate_toggle)
        
    def animate_toggle(self, checked):
        """Animate toggle state change"""
        if checked:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #64C8FF;
                    color: white;
                    border: 2px solid #64C8FF;
                    font-weight: bold;
                }
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background-color: #555555;
                    color: #DCDCDC;
                    border: 2px solid #555555;
                }
            """)