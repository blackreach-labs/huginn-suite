# app/widgets/mode_selection_dialog.py
import os
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QFrame, QApplication, QGraphicsDropShadowEffect,
                             QWidget, QSpacerItem, QSizePolicy)
from PyQt6.QtCore import Qt, pyqtSignal, QPropertyAnimation, QEasingCurve, QSize
from PyQt6.QtGui import QFont, QPixmap, QColor, QRadialGradient, QPalette, QPainter, QBrush


class ModeSelectionDialog(QDialog):
    """Dialog to select between Guided Workflow and Advanced Mode"""

    mode_selected = pyqtSignal(str)  # "guided" or "advanced"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Huginn - Select Mode")
        self.setModal(True)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setWindowOpacity(0.0)
        self._resources_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "resources", "icons"
        )
        self.setup_ui()

    def showEvent(self, event):
        """Ensure the dialog covers the full screen and fade in."""
        super().showEvent(event)
        screen = QApplication.primaryScreen().geometry()
        self.setGeometry(screen)
        # Fade-in animation
        self._fade_anim = QPropertyAnimation(self, b"windowOpacity")
        self._fade_anim.setDuration(300)
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        self._fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade_anim.start()

    def paintEvent(self, event):
        """Draw the welcome image as the full-page background."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect()
        bg_path = os.path.join(self._resources_path, "Welcome_to_Huginn.png")
        bg_pixmap = QPixmap(bg_path)
        if not bg_pixmap.isNull():
            scaled_bg = bg_pixmap.scaled(
                rect.size(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation)
            # Center the scaled pixmap
            x = (rect.width() - scaled_bg.width()) // 2
            y = (rect.height() - scaled_bg.height()) // 2
            painter.drawPixmap(x, y, scaled_bg)
        else:
            # Fallback gradient if image not found
            gradient = QRadialGradient(rect.center().x(), rect.center().y(),
                                       max(rect.width(), rect.height()) * 0.7)
            gradient.setColorAt(0.0, QColor(30, 40, 50))
            gradient.setColorAt(0.6, QColor(20, 25, 35))
            gradient.setColorAt(1.0, QColor(5, 5, 10))
            painter.fillRect(rect, QBrush(gradient))
        painter.end()

    def setup_ui(self):
        """Setup the dialog UI"""
        # Outer layout with stretch to vertically center content
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        outer_layout.addStretch(1)

        # Inner content container with max width
        content = QWidget()
        content.setStyleSheet("background: transparent;")
        content.setMaximumWidth(1200)
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(40, 20, 40, 20)
        content_layout.setSpacing(24)

        # Subtitle
        subtitle = QLabel("Choose your preferred mode to get started")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(QFont("Neuropol X", 13))
        subtitle.setStyleSheet("""
            font-size: 13pt;
            color: #B0C4DE;
            padding-bottom: 10px;
            background: transparent;
            border: none;
        """)
        content_layout.addWidget(subtitle)

        # Mode selection cards
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(40)
        buttons_layout.addStretch(1)

        # Guided Workflow card
        guided_frame = self.create_mode_button(
            "GUIDED WORKFLOW",
            "Step-by-step penetration testing\nmethodology. Perfect for beginners.",
            "#32CD32",
            os.path.join(self._resources_path, "guided_mode.png"),
            lambda: self.select_mode("guided")
        )
        buttons_layout.addWidget(guided_frame)

        # Advanced Mode card
        advanced_frame = self.create_mode_button(
            "ADVANCED MODE",
            "Full access to all tools and features.\nFor experienced penetration testers.",
            "#FF6347",
            os.path.join(self._resources_path, "advanced_mode.png"),
            lambda: self.select_mode("advanced")
        )
        buttons_layout.addWidget(advanced_frame)

        buttons_layout.addStretch(1)
        content_layout.addLayout(buttons_layout)

        # Footer with keyboard hints
        footer = QLabel("Press  G  for Guided  |  A  for Advanced  |  Esc  to skip")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("""
            font-size: 10pt;
            color: #666666;
            padding-top: 24px;
            background: transparent;
            border: none;
        """)
        content_layout.addWidget(footer)

        # Center the content widget horizontally
        h_center = QHBoxLayout()
        h_center.addStretch(1)
        h_center.addWidget(content)
        h_center.addStretch(1)

        outer_layout.addLayout(h_center)
        outer_layout.addStretch(1)

    def create_mode_button(self, title, description, color, icon_path, callback):
        """Create a mode selection button as a card with icon, title, and description."""
        frame = QFrame()
        frame.setObjectName("modeCard")
        frame.setStyleSheet(f"""
            QFrame#modeCard {{
                background-color: rgba(10, 15, 25, 200);
                border: 2px solid {color};
                border-radius: 14px;
            }}
            QFrame#modeCard:hover {{
                background-color: rgba(30, 40, 60, 220);
                border: 2px solid {color};
            }}
        """)
        frame.setFixedSize(500, 300)
        frame.setCursor(Qt.CursorShape.PointingHandCursor)

        # Glow shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(30)
        shadow.setColor(QColor(color))
        shadow.setOffset(0, 0)
        frame.setGraphicsEffect(shadow)

        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(30, 24, 30, 24)
        layout.setSpacing(14)

        # Icon
        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("background: transparent; border: none;")
        icon_pixmap = QPixmap(icon_path)
        if not icon_pixmap.isNull():
            icon_label.setPixmap(icon_pixmap.scaled(
                QSize(80, 80),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation))
        layout.addWidget(icon_label)

        # Title
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setFont(QFont("Neuropol X", 14, QFont.Weight.Bold))
        title_label.setStyleSheet(f"""
            font-size: 14pt;
            font-weight: bold;
            color: {color};
            background: transparent;
            border: none;
        """)
        layout.addWidget(title_label)

        # Description
        desc_label = QLabel(description)
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("""
            font-size: 11pt;
            color: #CCCCCC;
            background: transparent;
            border: none;
            line-height: 140%;
        """)
        layout.addWidget(desc_label)

        frame.mousePressEvent = lambda event: callback() if event.button() == Qt.MouseButton.LeftButton else None

        return frame

    def select_mode(self, mode):
        """Handle mode selection"""
        self.mode_selected.emit(mode)
        self.accept()

    def keyPressEvent(self, event):
        """Handle key press events with shortcuts."""
        key = event.key()
        if key == Qt.Key.Key_Escape:
            self.select_mode("advanced")
        elif key == Qt.Key.Key_G:
            self.select_mode("guided")
        elif key == Qt.Key.Key_A:
            self.select_mode("advanced")
        else:
            super().keyPressEvent(event)
