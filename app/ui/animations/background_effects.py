# app/ui/animations/background_effects.py
import random
import math
from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import QTimer, QPropertyAnimation, QRect, Qt, pyqtSignal
from PyQt6.QtGui import QPainter, QColor, QBrush, QPen, QFont

class MatrixRainEffect(QWidget):
    """Matrix-style falling characters background effect"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.drops = []
        self.setup_effect()
        
    def setup_effect(self):
        """Initialize matrix rain effect"""
        self.setStyleSheet("background: transparent;")
        
        # Animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_drops)
        self.timer.start(100)  # Update every 100ms
        
        # Initialize drops
        self.init_drops()
        
    def init_drops(self):
        """Initialize falling character drops"""
        if self.width() > 0:
            columns = self.width() // 20  # Character width
            self.drops = []
            
            for i in range(columns):
                drop = {
                    'x': i * 20,
                    'y': random.randint(-500, 0),
                    'speed': random.randint(2, 8),
                    'chars': [random.choice(self.characters) for _ in range(20)],
                    'alpha': random.randint(50, 255)
                }
                self.drops.append(drop)
    
    def update_drops(self):
        """Update drop positions and trigger repaint"""
        for drop in self.drops:
            drop['y'] += drop['speed']
            
            # Reset drop when it goes off screen
            if drop['y'] > self.height() + 100:
                drop['y'] = random.randint(-200, -50)
                drop['speed'] = random.randint(2, 8)
                drop['chars'] = [random.choice(self.characters) for _ in range(20)]
                drop['alpha'] = random.randint(50, 255)
        
        self.update()
    
    def paintEvent(self, event):
        """Paint matrix rain effect"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        font = QFont("Courier New", 12)
        painter.setFont(font)
        
        for drop in self.drops:
            for i, char in enumerate(drop['chars']):
                y_pos = drop['y'] + (i * 20)
                
                if 0 <= y_pos <= self.height():
                    # Fade effect - brighter at the head
                    alpha = max(0, drop['alpha'] - (i * 15))
                    color = QColor(0, 255, 65, alpha)
                    painter.setPen(color)
                    
                    painter.drawText(drop['x'], y_pos, char)
    
    def resizeEvent(self, event):
        """Handle resize events"""
        super().resizeEvent(event)
        self.init_drops()

class ParticleField(QWidget):
    """Floating particle background effect"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.particles = []
        self.setup_effect()
        
    def setup_effect(self):
        """Initialize particle field effect"""
        self.setStyleSheet("background: transparent;")
        
        # Animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_particles)
        self.timer.start(50)  # Update every 50ms
        
        # Initialize particles
        self.init_particles()
        
    def init_particles(self):
        """Initialize floating particles"""
        if self.width() > 0 and self.height() > 0:
            particle_count = min(50, (self.width() * self.height()) // 10000)
            self.particles = []
            
            for _ in range(particle_count):
                particle = {
                    'x': random.randint(0, self.width()),
                    'y': random.randint(0, self.height()),
                    'vx': random.uniform(-1, 1),
                    'vy': random.uniform(-1, 1),
                    'size': random.randint(2, 6),
                    'alpha': random.randint(50, 150),
                    'color': random.choice(['#64C8FF', '#00FF41', '#FFAA00'])
                }
                self.particles.append(particle)
    
    def update_particles(self):
        """Update particle positions"""
        for particle in self.particles:
            particle['x'] += particle['vx']
            particle['y'] += particle['vy']
            
            # Wrap around screen edges
            if particle['x'] < 0:
                particle['x'] = self.width()
            elif particle['x'] > self.width():
                particle['x'] = 0
                
            if particle['y'] < 0:
                particle['y'] = self.height()
            elif particle['y'] > self.height():
                particle['y'] = 0
        
        self.update()
    
    def paintEvent(self, event):
        """Paint particle field"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        for particle in self.particles:
            color = QColor(particle['color'])
            color.setAlpha(particle['alpha'])
            
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            
            painter.drawEllipse(
                int(particle['x'] - particle['size']/2),
                int(particle['y'] - particle['size']/2),
                particle['size'],
                particle['size']
            )
    
    def resizeEvent(self, event):
        """Handle resize events"""
        super().resizeEvent(event)
        self.init_particles()

class NeonGlowEffect(QWidget):
    """Neon glow lines background effect"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.lines = []
        self.setup_effect()
        
    def setup_effect(self):
        """Initialize neon glow effect"""
        self.setStyleSheet("background: transparent;")
        
        # Animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_lines)
        self.timer.start(100)
        
        # Initialize lines
        self.init_lines()
        
    def init_lines(self):
        """Initialize neon lines"""
        if self.width() > 0 and self.height() > 0:
            line_count = 8
            self.lines = []
            
            for _ in range(line_count):
                line = {
                    'x1': random.randint(0, self.width()),
                    'y1': random.randint(0, self.height()),
                    'x2': random.randint(0, self.width()),
                    'y2': random.randint(0, self.height()),
                    'color': random.choice(['#FF0080', '#00FFFF', '#FFFF00']),
                    'alpha': random.randint(100, 200),
                    'pulse_phase': random.uniform(0, 2 * math.pi)
                }
                self.lines.append(line)
    
    def update_lines(self):
        """Update line glow effect"""
        for line in self.lines:
            line['pulse_phase'] += 0.2
            line['alpha'] = int(150 + 50 * math.sin(line['pulse_phase']))
        
        self.update()
    
    def paintEvent(self, event):
        """Paint neon glow lines"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        for line in self.lines:
            color = QColor(line['color'])
            color.setAlpha(line['alpha'])
            
            # Draw multiple lines for glow effect
            for width in [8, 4, 2]:
                pen = QPen(color, width)
                painter.setPen(pen)
                painter.drawLine(line['x1'], line['y1'], line['x2'], line['y2'])
                
                # Reduce alpha for outer glow
                color.setAlpha(color.alpha() // 2)
    
    def resizeEvent(self, event):
        """Handle resize events"""
        super().resizeEvent(event)
        self.init_lines()

class WaveEffect(QWidget):
    """Ocean wave background effect"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.wave_offset = 0
        self.setup_effect()
        
    def setup_effect(self):
        """Initialize wave effect"""
        self.setStyleSheet("background: transparent;")
        
        # Animation timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_waves)
        self.timer.start(50)
        
    def update_waves(self):
        """Update wave animation"""
        self.wave_offset += 0.1
        self.update()
    
    def paintEvent(self, event):
        """Paint wave effect"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw multiple wave layers
        colors = ['#0077BE', '#00AAFF', '#00DDAA']
        
        for i, color in enumerate(colors):
            wave_color = QColor(color)
            wave_color.setAlpha(80)
            
            painter.setPen(QPen(wave_color, 3))
            
            # Calculate wave points
            points = []
            for x in range(0, self.width(), 10):
                y = self.height() // 2 + int(30 * math.sin((x / 50.0) + self.wave_offset + i))
                points.append((x, y))
            
            # Draw wave line
            for j in range(len(points) - 1):
                painter.drawLine(points[j][0], points[j][1], points[j+1][0], points[j+1][1])

class TerminalEffect(QWidget):
    """Terminal-style typing effect"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.text_lines = [
            "Initializing security protocols...",
            "Loading enumeration modules...",
            "Establishing secure connections...",
            "Ready for penetration testing.",
        ]
        self.current_line = 0
        self.current_char = 0
        self.displayed_text = []
        self.setup_effect()
        
    def setup_effect(self):
        """Initialize terminal effect"""
        self.setStyleSheet("background: transparent;")
        
        # Typing timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.type_character)
        self.timer.start(100)  # Type every 100ms
        
    def type_character(self):
        """Type next character"""
        if self.current_line < len(self.text_lines):
            line = self.text_lines[self.current_line]
            
            if self.current_char < len(line):
                # Add character to current line
                if len(self.displayed_text) <= self.current_line:
                    self.displayed_text.append("")
                
                self.displayed_text[self.current_line] += line[self.current_char]
                self.current_char += 1
            else:
                # Move to next line
                self.current_line += 1
                self.current_char = 0
                
                # Pause before next line
                self.timer.stop()
                QTimer.singleShot(500, lambda: self.timer.start(100))
        else:
            # Reset after all lines are typed
            QTimer.singleShot(3000, self.reset_effect)
        
        self.update()
    
    def reset_effect(self):
        """Reset typing effect"""
        self.current_line = 0
        self.current_char = 0
        self.displayed_text = []
        self.timer.start(100)
    
    def paintEvent(self, event):
        """Paint terminal text"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        font = QFont("Courier New", 12)
        painter.setFont(font)
        painter.setPen(QColor("#00FF00"))
        
        y_offset = 50
        for i, line in enumerate(self.displayed_text):
            painter.drawText(20, y_offset + (i * 25), line)
            
            # Draw cursor on current line
            if i == self.current_line and self.current_char < len(self.text_lines[i]):
                cursor_x = 20 + painter.fontMetrics().horizontalAdvance(line)
                painter.drawText(cursor_x, y_offset + (i * 25), "_")

class BackgroundEffectManager:
    """Manager for background effects based on theme"""
    
    def __init__(self, parent_widget):
        self.parent_widget = parent_widget
        self.current_effect = None
        
    def set_effect(self, effect_type, theme_config=None):
        """Set background effect based on type"""
        # Remove current effect
        if self.current_effect:
            self.current_effect.setParent(None)
            self.current_effect = None
        
        # Create new effect
        effect_map = {
            'matrix_rain': MatrixRainEffect,
            'particle_field': ParticleField,
            'neon_glow': NeonGlowEffect,
            'wave_effects': WaveEffect,
            'terminal_effects': TerminalEffect
        }
        
        if effect_type in effect_map:
            self.current_effect = effect_map[effect_type](self.parent_widget)
            self.current_effect.resize(self.parent_widget.size())
            self.current_effect.show()
            self.current_effect.lower()  # Send to back
    
    def resize_effect(self, size):
        """Resize current effect"""
        if self.current_effect:
            self.current_effect.resize(size)
    
    def remove_effect(self):
        """Remove current background effect"""
        if self.current_effect:
            self.current_effect.setParent(None)
            self.current_effect = None