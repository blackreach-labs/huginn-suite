import time
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QFrame
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


class ScanDetailsComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup details UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Container frame
        self.details_frame = QFrame()
        self.details_frame.setObjectName("scanDetailsFrame")
        frame_layout = QVBoxLayout(self.details_frame)
        frame_layout.setContentsMargins(14, 12, 14, 12)
        frame_layout.setSpacing(8)

        # Title
        title = QLabel("Scan Details")
        title.setFont(QFont("Neuropol X", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #64C8FF; background: transparent; border: none;")
        frame_layout.addWidget(title)

        # Details output
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Neuropol X", 9))
        self.details_text.setPlaceholderText("Select a scan to view details...")
        frame_layout.addWidget(self.details_text)

        layout.addWidget(self.details_frame)

    def update_scan_details(self, scan_item):
        """Update scan details display with styled HTML"""
        started = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_item.start_time))
        duration = self.format_duration(time.time() - scan_item.start_time)

        # Status color
        status_color = "#00FF41"
        if scan_item.status == "Paused":
            status_color = "#FFD700"
        elif scan_item.status == "Completed":
            status_color = "#64C8FF"
        elif scan_item.status in ("Stopped", "Failed", "Cancelled"):
            status_color = "#FF5252"

        # Progress text
        if scan_item.total_items > 0:
            progress_pct = int((scan_item.completed_items / scan_item.total_items) * 100)
            progress_text = f"{progress_pct}% ({scan_item.completed_items}/{scan_item.total_items})"
        else:
            progress_text = "Indeterminate"

        html = f"""
        <div style="font-family: 'Neuropol X', monospace; color: #DCDCDC; line-height: 1.6;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Scan ID</td>
                    <td style="color: #E0E0E0; padding: 3px 0;">{scan_item.scan_id}</td>
                </tr>
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Type</td>
                    <td style="color: #64C8FF; font-weight: bold; padding: 3px 0;">{scan_item.scan_type}</td>
                </tr>
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Target</td>
                    <td style="color: #00FF41; padding: 3px 0;">{scan_item.target}</td>
                </tr>
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Status</td>
                    <td style="color: {status_color}; font-weight: bold; padding: 3px 0;">{scan_item.status}</td>
                </tr>
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Started</td>
                    <td style="color: #E0E0E0; padding: 3px 0;">{started}</td>
                </tr>
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Duration</td>
                    <td style="color: #E0E0E0; padding: 3px 0;">{duration}</td>
                </tr>
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Progress</td>
                    <td style="color: #E0E0E0; padding: 3px 0;">{progress_text}</td>
                </tr>
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Details</td>
                    <td style="color: #B0B0B0; padding: 3px 0;">{scan_item.details}</td>
                </tr>
                <tr>
                    <td style="color: #808080; padding: 3px 12px 3px 0; white-space: nowrap;">Thread</td>
                    <td style="color: #B0B0B0; padding: 3px 0;">{scan_item.thread_id or 'N/A'}</td>
                </tr>
            </table>
        </div>
        """
        self.details_text.setHtml(html)

    def format_duration(self, seconds):
        """Format duration in human readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h {minutes}m"

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass
