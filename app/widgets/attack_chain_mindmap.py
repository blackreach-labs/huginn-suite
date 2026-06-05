#!/usr/bin/env python3
"""
Attack Chain Mindmap Widget
Interactive mindmap for visualizing attack chains and navigation
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFrame
from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QPainter, QPen, QBrush, QColor, QFont, QPolygon, QPixmap
from PyQt6.QtCore import QPoint, QRect
import math
import os

class AttackChainMindmap(QWidget):
    phase_selected = pyqtSignal(str, dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(800, 120)
        self.setMaximumHeight(150)
        self.phases = self._create_attack_phases_horizontal()
        self.selected_phase = None
        self.hover_phase = None
        
        # Load background image
        bg_path = os.path.join("resources", "icons", "attack_chain_bg.png")
        self._bg_pixmap = QPixmap(bg_path) if os.path.exists(bg_path) else None
        
        # Animation timer
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.update)
        self.animation_timer.start(50)  # 20 FPS
        
        self.setMouseTracking(True)
    
    def resizeEvent(self, event):
        """Handle widget resize to update phase positions"""
        super().resizeEvent(event)
        self.update()
    
    def _create_attack_phases_horizontal(self):
        """Create attack chain phases in horizontal layout for narrow bar"""
        return {
            "SETUP": {
                "pos": (100, 60),
                "color": QColor(100, 200, 255),
                "description": "Target profiling & scope definition",
                "tools": ["Payload Builder", "Listener Manager", "C2 Orchestrator"],
                "connections": ["RECON"]
            },
            "RECON": {
                "pos": (250, 60),
                "color": QColor(255, 200, 100),
                "description": "Information gathering & enumeration",
                "tools": ["AD Enumerator", "Kerberos Tools", "DNS/Port Scanning"],
                "connections": ["SCAN"]
            },
            "SCAN": {
                "pos": (400, 60),
                "color": QColor(255, 150, 150),
                "description": "Vulnerability identification & correlation",
                "tools": ["Vulnerability Correlator", "Attack Graph Engine"],
                "connections": ["EXPLOIT"]
            },
            "EXPLOIT": {
                "pos": (550, 60),
                "color": QColor(255, 100, 100),
                "description": "Active exploitation & initial access",
                "tools": ["RPC Exploits", "SMB Attacks", "Web Exploits"],
                "connections": ["ELEVATE"]
            },
            "ELEVATE": {
                "pos": (700, 60),
                "color": QColor(200, 100, 255),
                "description": "Privilege escalation & lateral movement",
                "tools": ["Windows Agent", "Evidence Collector", "Credential Harvesting"],
                "connections": ["REPORT"]
            },
            "REPORT": {
                "pos": (850, 60),
                "color": QColor(100, 255, 200),
                "description": "Reporting, remediation & analytics",
                "tools": ["Advanced Reporting", "Remediation", "Dashboard", "Analytics", "Evidence Management", "Playbook Export"],
                "connections": []
            }
        }
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw background
        if self._bg_pixmap and not self._bg_pixmap.isNull():
            scaled_bg = self._bg_pixmap.scaled(
                self.size(),
                Qt.AspectRatioMode.IgnoreAspectRatio,
                Qt.TransformationMode.SmoothTransformation)
            painter.drawPixmap(0, 0, scaled_bg)
        else:
            painter.fillRect(self.rect(), QColor(20, 30, 40))
        
        # Stretch phases across full width with no margins
        width = self.width()
        if width > 0:
            phase_names = list(self.phases.keys())
            for i, phase_name in enumerate(phase_names):
                # Position from edge to edge with equal spacing
                x_pos = int((width * (i + 0.5)) / len(phase_names))
                self.phases[phase_name]["pos"] = (x_pos, 60)
        
        # Draw connections first
        self._draw_connections(painter)
        
        # Draw phases
        self._draw_phases(painter)
    
    def _draw_connections(self, painter):
        """Draw connections between phases"""
        pen = QPen(QColor(100, 200, 255, 100), 2)
        painter.setPen(pen)
        
        for phase_name, phase_data in self.phases.items():
            start_pos = phase_data["pos"]
            for connection in phase_data["connections"]:
                if connection in self.phases:
                    end_pos = self.phases[connection]["pos"]
                    
                    # Draw arrow
                    self._draw_arrow(painter, start_pos, end_pos)
    
    def _draw_arrow(self, painter, start, end):
        """Draw arrow between two points"""
        # Calculate arrow direction
        dx = end[0] - start[0]
        dy = end[1] - start[1]
        length = math.sqrt(dx*dx + dy*dy)
        
        if length == 0:
            return
        
        # Normalize
        dx /= length
        dy /= length
        
        # Adjust start and end points to circle edges
        radius = 70
        start_x = start[0] + dx * radius
        start_y = start[1] + dy * radius
        end_x = end[0] - dx * radius
        end_y = end[1] - dy * radius
        
        # Draw line
        painter.drawLine(int(start_x), int(start_y), int(end_x), int(end_y))
        
        # Draw arrowhead
        arrow_length = 15
        arrow_angle = 0.5
        
        arrow_x1 = end_x - arrow_length * math.cos(math.atan2(dy, dx) - arrow_angle)
        arrow_y1 = end_y - arrow_length * math.sin(math.atan2(dy, dx) - arrow_angle)
        arrow_x2 = end_x - arrow_length * math.cos(math.atan2(dy, dx) + arrow_angle)
        arrow_y2 = end_y - arrow_length * math.sin(math.atan2(dy, dx) + arrow_angle)
        
        arrow = QPolygon([
            QPoint(int(end_x), int(end_y)),
            QPoint(int(arrow_x1), int(arrow_y1)),
            QPoint(int(arrow_x2), int(arrow_y2))
        ])
        
        painter.setBrush(QBrush(QColor(100, 200, 255, 100)))
        painter.drawPolygon(arrow)
    
    def _draw_phases(self, painter):
        """Draw phase circles with icons"""
        hovered_phase_data = None
        
        # Draw all phases first
        for phase_name, phase_data in self.phases.items():
            pos = phase_data["pos"]
            color = phase_data["color"]
            
            # Determine circle state
            is_selected = phase_name == self.selected_phase
            is_hovered = phase_name == self.hover_phase
            
            # Store hovered phase for tooltip drawing later
            if is_hovered:
                hovered_phase_data = (phase_name, phase_data, pos)
            
            # Use activated icon when hovered or selected, default otherwise
            base_radius = 70
            radius = base_radius
            
            if is_selected or is_hovered:
                icon_path = os.path.join("resources", "icons", f"{phase_name}_ACTIVATED.png")
            else:
                icon_path = os.path.join("resources", "icons", f"{phase_name}.png")
            
            # Fallback to default icon if activated version doesn't exist
            if not os.path.exists(icon_path):
                icon_path = os.path.join("resources", "icons", f"{phase_name}.png")
            
            if os.path.exists(icon_path):
                pixmap = QPixmap(icon_path)
                if not pixmap.isNull():
                    # Scale icon to fill entire oblong (consistent size, no grow on hover)
                    width = radius * 2.5
                    height = radius * 1.2
                    scaled_pixmap = pixmap.scaled(int(width), int(height), Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
                    icon_x = int(pos[0] - width / 2)
                    icon_y = int(pos[1] - height / 2)
                    painter.drawPixmap(icon_x, icon_y, scaled_pixmap)
            else:
                # Fallback to colored ellipse if no icon
                painter.setBrush(QBrush(color))
                painter.setPen(QPen(QColor(255, 255, 255), 2))
                width = radius * 2.5
                height = radius * 1.2
                painter.drawEllipse(int(pos[0] - width/2), int(pos[1] - height/2), int(width), int(height))

        # Tooltip drawing removed
    
    def _draw_phase_tooltip(self, painter, phase_name, phase_data, pos):
        """Draw tooltip with phase details"""
        tooltip_width = 200
        tooltip_height = 60
        
        # Position tooltip to avoid screen edges
        tooltip_x = pos[0] + 80
        tooltip_y = pos[1] - 30
        
        if tooltip_x + tooltip_width > self.width():
            tooltip_x = pos[0] - 80 - tooltip_width
        
        # Draw tooltip background
        painter.setBrush(QBrush(QColor(0, 0, 0, 200)))
        painter.setPen(QPen(QColor(100, 200, 255), 2))
        painter.drawRoundedRect(tooltip_x, tooltip_y, tooltip_width, tooltip_height, 10, 10)
        
        # Draw tooltip content
        painter.setPen(QPen(QColor(255, 255, 255)))
        painter.setFont(QFont("Arial", 9, QFont.Weight.Bold))
        
        # Phase name and description only
        text_rect = QRect(tooltip_x + 10, tooltip_y + 10, tooltip_width - 20, tooltip_height - 20)
        display_name = phase_data.get(phase_name)
        painter.drawText(text_rect, Qt.TextFlag.TextWordWrap, f"{display_name}: {phase_data['description']}")
    
    def mousePressEvent(self, event):
        """Handle mouse clicks on phases"""
        if event.button() == Qt.MouseButton.LeftButton:
            clicked_phase = self._get_phase_at_position(event.position().toPoint())
            if clicked_phase:
                self.selected_phase = clicked_phase
                self.phase_selected.emit(clicked_phase, self.phases[clicked_phase])
                self.update()
    
    def mouseMoveEvent(self, event):
        """Handle mouse hover over phases"""
        hovered_phase = self._get_phase_at_position(event.position().toPoint())
        if hovered_phase != self.hover_phase:
            self.hover_phase = hovered_phase
            self.setCursor(Qt.CursorShape.PointingHandCursor if hovered_phase else Qt.CursorShape.ArrowCursor)
            self.update()
    
    def _get_phase_at_position(self, pos):
        """Get phase at mouse position"""
        for phase_name, phase_data in self.phases.items():
            phase_pos = phase_data["pos"]
            dx = abs(pos.x() - phase_pos[0])
            dy = abs(pos.y() - phase_pos[1])
            # Use ellipse equation for proper hit detection
            if (dx*dx)/(87.5*87.5) + (dy*dy)/(42*42) <= 1:
                return phase_name
        return None