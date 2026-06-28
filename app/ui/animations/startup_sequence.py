# -*- coding: utf-8 -*-
# app/ui/animations/startup_sequence.py
"""
Startup splash sequence for Huginn.

Displays background.png fullscreen, fades in logo.png over it,
runs a progress bar, then signals completion.
"""
import os
import math
from PyQt6.QtWidgets import QWidget, QApplication
from PyQt6.QtCore import Qt, QTimer, QPointF, pyqtSignal
from PyQt6.QtGui import (
    QPainter, QColor, QFont, QPixmap, QRadialGradient,
    QLinearGradient, QPen, QBrush
)


class StartupSequenceWidget(QWidget):
    """Fullscreen splash: background image + logo fade-in + progress bar."""

    sequence_finished = pyqtSignal()

    PHASE_LABELS = ["RECON", "SCAN", "ENUMERATE", "EXPLOIT", "REPORT"]

    def __init__(self, resources_path=None):
        # No parent — this is a top-level fullscreen window
        super().__init__(None)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        self._resources_path = resources_path or ""

        # Animation state
        self._phase = 0  # 0=fade_in_logo, 1=progress, 2=hold
        self._elapsed_ms = 0

        # Phase 0: logo fade-in
        self._logo_opacity = 0.0
        self._fade_in_duration = 3000  # ms

        # Phase 1: progress bar
        self._progress = 0.0
        self._progress_duration = 2200  # ms
        self._progress_start_time = 0

        # Glow pulse
        self._glow_phase = 0.0

        # Load images
        self._bg_pixmap = None
        self._logo_pixmap = None
        self._load_images()

        # Main timer (~60fps)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    def _load_images(self):
        """Load background and logo images."""
        bg_path = os.path.join(self._resources_path, "background.png")
        if os.path.exists(bg_path):
            self._bg_pixmap = QPixmap(bg_path)

        logo_path = os.path.join(self._resources_path, "logo.png")
        if os.path.exists(logo_path):
            self._logo_pixmap = QPixmap(logo_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Show fullscreen and begin the animation."""
        self.showFullScreen()
        self.setFocus()
        self._phase = 0
        self._elapsed_ms = 0
        self._logo_opacity = 0.0
        self._progress = 0.0
        self._timer.start(16)

    # ------------------------------------------------------------------
    # Events (skipping disabled - intro must complete)
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Animation tick
    # ------------------------------------------------------------------

    def _tick(self):
        self._elapsed_ms += 16
        self._glow_phase += 0.05

        if self._phase == 0:
            self._logo_opacity = min(1.0, self._elapsed_ms / self._fade_in_duration)
            if self._logo_opacity >= 1.0:
                self._phase = 1
                self._progress_start_time = self._elapsed_ms

        elif self._phase == 1:
            elapsed_in_phase = self._elapsed_ms - self._progress_start_time
            self._progress = min(1.0, elapsed_in_phase / self._progress_duration)
            if self._progress >= 1.0:
                self._phase = 2
                QTimer.singleShot(400, self._finish)

        self.update()

    def _finish(self):
        self._timer.stop()
        self.sequence_finished.emit()

    # ------------------------------------------------------------------
    # Painting
    # ------------------------------------------------------------------

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect()
        w, h = rect.width(), rect.height()

        # Layer 1: Background image (always fully visible)
        self._draw_background(painter, w, h)

        # Layer 2: Logo fading in over the background
        self._draw_logo(painter, w, h)

        # Layer 3: Progress bar (appears once logo is mostly visible)
        if self._logo_opacity > 0.6:
            bar_opacity = min(1.0, (self._logo_opacity - 0.6) / 0.4)
            self._draw_progress_section(painter, w, h, bar_opacity)

        painter.end()

    def _draw_background(self, painter, w, h):
        """Draw background.png scaled to fill the entire screen."""
        if self._bg_pixmap and not self._bg_pixmap.isNull():
            scaled = self._bg_pixmap.scaled(
                w, h,
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation
            )
            # Center the scaled image
            x = (w - scaled.width()) // 2
            y = (h - scaled.height()) // 2
            painter.drawPixmap(x, y, scaled)
        else:
            # Fallback dark gradient
            gradient = QRadialGradient(w / 2, h / 2, max(w, h) * 0.7)
            gradient.setColorAt(0.0, QColor(8, 12, 20))
            gradient.setColorAt(1.0, QColor(0, 0, 0))
            painter.fillRect(self.rect(), QBrush(gradient))

    def _draw_logo(self, painter, w, h):
        """Draw logo.png centered, fading in."""
        if not self._logo_pixmap or self._logo_pixmap.isNull():
            self._draw_fallback_logo(painter, w, h)
            return

        # Scale logo to fit nicely — ~50% of screen width
        target_w = int(w * 0.50)
        target_h = int(target_w * self._logo_pixmap.height() / self._logo_pixmap.width())

        # Cap height
        max_h = int(h * 0.50)
        if target_h > max_h:
            target_h = max_h
            target_w = int(target_h * self._logo_pixmap.width() / self._logo_pixmap.height())

        scaled = self._logo_pixmap.scaled(
            target_w, target_h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation
        )

        x = (w - scaled.width()) // 2
        y = (h - scaled.height()) // 2 - int(h * 0.05)  # slightly above center

        painter.setOpacity(self._logo_opacity)
        painter.drawPixmap(x, y, scaled)
        painter.setOpacity(1.0)

    def _draw_fallback_logo(self, painter, w, h):
        """Text fallback if logo.png is missing."""
        painter.setOpacity(self._logo_opacity)
        font = QFont("Neuropol X", 52)
        font.setWeight(QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(QColor(80, 180, 255))
        title_rect = self.rect().adjusted(0, int(h * 0.25), 0, -int(h * 0.35))
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, "HUGINN")
        painter.setOpacity(1.0)

    def _draw_progress_section(self, painter, w, h, opacity):
        """Draw 'INITIALIZING...' text, progress bar, and phase labels."""
        painter.setOpacity(opacity)

        # Position below center
        center_y = int(h * 0.73)
        bar_w = int(w * 0.32)
        bar_h = 7
        bar_x = (w - bar_w) // 2

        # "INITIALIZING..." label
        label_font = QFont("Share Tech Mono", 11)
        label_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 3)
        painter.setFont(label_font)
        painter.setPen(QColor(160, 200, 240))
        label_y = center_y - 22
        painter.drawText(bar_x, label_y, bar_w, 20,
                         Qt.AlignmentFlag.AlignCenter, "INITIALIZING...")

        # Progress bar track
        track_y = center_y + 4
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(15, 25, 45, 180))
        painter.drawRoundedRect(bar_x, track_y, bar_w, bar_h, 3, 3)

        # Progress bar fill
        fill_w = int(bar_w * self._progress)
        if fill_w > 0:
            bar_gradient = QLinearGradient(bar_x, 0, bar_x + fill_w, 0)
            bar_gradient.setColorAt(0.0, QColor(20, 80, 180))
            bar_gradient.setColorAt(0.5, QColor(50, 140, 255))
            bar_gradient.setColorAt(1.0, QColor(90, 190, 255))
            painter.setBrush(QBrush(bar_gradient))
            painter.drawRoundedRect(bar_x, track_y, fill_w, bar_h, 3, 3)

            # Leading edge glow
            glow_x = bar_x + fill_w
            glow_pulse = 0.5 + 0.5 * math.sin(self._glow_phase * 3)
            glow_color = QColor(100, 200, 255, int(100 * glow_pulse))
            glow_grad = QRadialGradient(glow_x, track_y + bar_h / 2, 18)
            glow_grad.setColorAt(0.0, glow_color)
            glow_grad.setColorAt(1.0, QColor(0, 0, 0, 0))
            painter.setBrush(QBrush(glow_grad))
            painter.drawEllipse(QPointF(glow_x, track_y + bar_h / 2), 18, 10)

        # Phase labels
        labels_y = track_y + bar_h + 16
        phase_font = QFont("Share Tech Mono", 9)
        phase_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1)
        painter.setFont(phase_font)

        total_labels = len(self.PHASE_LABELS)
        label_section_w = bar_w / total_labels

        for i, label in enumerate(self.PHASE_LABELS):
            lx = bar_x + int(i * label_section_w)
            threshold = (i + 1) / total_labels

            if self._progress >= threshold:
                painter.setPen(QColor(100, 200, 255))
            elif self._progress >= (i / total_labels):
                pulse = 0.5 + 0.5 * math.sin(self._glow_phase * 4)
                painter.setPen(QColor(100, 200, 255, int(100 + 155 * pulse)))
            else:
                painter.setPen(QColor(50, 70, 100))

            painter.drawText(int(lx), labels_y, int(label_section_w), 20,
                             Qt.AlignmentFlag.AlignCenter, label)

            if i < total_labels - 1:
                sep_x = int(lx + label_section_w)
                painter.setPen(QColor(40, 60, 90))
                painter.drawText(sep_x - 6, labels_y, 12, 20,
                                 Qt.AlignmentFlag.AlignCenter, ">")

        painter.setOpacity(1.0)
