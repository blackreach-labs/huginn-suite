# app/widgets/help_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QGroupBox, QTabWidget)
from PyQt6.QtCore import Qt

class HelpWidget(QWidget):
    """Widget displaying keyboard shortcuts and help information"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Help header
        header = QLabel("❓ Help & Keyboard Shortcuts")
        header.setStyleSheet("color: #64C8FF; font-size: 14pt; font-weight: bold;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Tabbed help content
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: rgba(0, 0, 0, 100);
            }
            QTabBar::tab {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                padding: 8px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(100, 200, 255, 150);
                color: #000;
            }
        """)
        
        # Shortcuts tab
        shortcuts_widget = QWidget()
        shortcuts_layout = QVBoxLayout(shortcuts_widget)
        
        shortcuts_text = QTextEdit()
        shortcuts_text.setReadOnly(True)
        shortcuts_text.setStyleSheet(self._get_text_style())
        
        shortcuts_html = """
        <h3 style='color: #64C8FF;'>Keyboard Shortcuts</h3>
        <table style='width: 100%; color: #DCDCDC;'>
        <tr><td style='padding: 5px; font-weight: bold;'>Ctrl+N</td><td style='padding: 5px;'>Start New Scan</td></tr>
        <tr><td style='padding: 5px; font-weight: bold;'>Ctrl+E</td><td style='padding: 5px;'>Export Results</td></tr>
        <tr><td style='padding: 5px; font-weight: bold;'>Ctrl+T</td><td style='padding: 5px;'>Toggle Theme</td></tr>
        <tr><td style='padding: 5px; font-weight: bold;'>Ctrl+M</td><td style='padding: 5px;'>Multi-Target Scan</td></tr>
        <tr><td style='padding: 5px; font-weight: bold;'>Ctrl+P</td><td style='padding: 5px;'>Pause/Resume Scan</td></tr>
        <tr><td style='padding: 5px; font-weight: bold;'>Ctrl+S</td><td style='padding: 5px;'>Stop Scan</td></tr>
        <tr><td style='padding: 5px; font-weight: bold;'>Ctrl+Q</td><td style='padding: 5px;'>Quit Application</td></tr>
        <tr><td style='padding: 5px; font-weight: bold;'>F1</td><td style='padding: 5px;'>Show Help</td></tr>
        <tr><td style='padding: 5px; font-weight: bold;'>Escape</td><td style='padding: 5px;'>Stop Current Operation</td></tr>
        </table>
        """
        
        shortcuts_text.setHtml(shortcuts_html)
        shortcuts_layout.addWidget(shortcuts_text)
        
        # Usage tab
        usage_widget = QWidget()
        usage_layout = QVBoxLayout(usage_widget)
        
        usage_text = QTextEdit()
        usage_text.setReadOnly(True)
        usage_text.setStyleSheet(self._get_text_style())
        
        usage_html = """
        <h3 style='color: #64C8FF;'>Quick Start Guide</h3>
        <h4 style='color: #00FF41;'>Basic Scanning:</h4>
        <ol style='color: #DCDCDC;'>
        <li>Enter target domain or IP address</li>
        <li>Select scan type (DNS, Port, HTTP, etc.)</li>
        <li>Configure options (wordlists, record types)</li>
        <li>Click scan button or press <strong>Ctrl+N</strong></li>
        <li>Export results with <strong>Ctrl+E</strong></li>
        </ol>
        
        <h4 style='color: #00FF41;'>Advanced Features:</h4>
        <ul style='color: #DCDCDC;'>
        <li><strong>Multi-Target:</strong> Press <strong>Ctrl+M</strong> for bulk scanning</li>
        <li><strong>Templates:</strong> Save and load scan configurations</li>
        <li><strong>Scheduling:</strong> Automate scans for specific times</li>
        <li><strong>Rate Limiting:</strong> Control scan speed and threads</li>
        <li><strong>Proxy Support:</strong> Route scans through proxy servers</li>
        </ul>
        
        <h4 style='color: #00FF41;'>Export Options:</h4>
        <ul style='color: #DCDCDC;'>
        <li><strong>JSON/CSV/XML:</strong> Raw data formats</li>
        <li><strong>PDF:</strong> Professional reports</li>
        <li><strong>Summary:</strong> Executive summaries</li>
        <li><strong>Correlate:</strong> Vulnerability analysis</li>
        <li><strong>Compare:</strong> Change detection</li>
        </ul>
        """
        
        usage_text.setHtml(usage_html)
        usage_layout.addWidget(usage_text)
        
        # About tab
        about_widget = QWidget()
        about_layout = QVBoxLayout(about_widget)
        
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setStyleSheet(self._get_text_style())
        
        about_html = """
        <h3 style='color: #64C8FF;'>About Huginn</h3>
        <p style='color: #DCDCDC;'>
        Huginn is a comprehensive penetration testing toolkit built with PyQt6, 
        featuring a complete enumeration suite with modern GUI interface and advanced 
        security analysis capabilities.
        </p>
        
        <h4 style='color: #00FF41;'>Features:</h4>
        <ul style='color: #DCDCDC;'>
        <li>8 enumeration tools (DNS, Port, SMB, SMTP, SNMP, HTTP, API, Database)</li>
        <li>Multi-target scanning capabilities</li>
        <li>Professional reporting (PDF, Executive summaries)</li>
        <li>Vulnerability correlation analysis</li>
        <li>Scan scheduling and automation</li>
        <li>Proxy support and rate limiting</li>
        <li>Custom templates and themes</li>
        </ul>
        
        <h4 style='color: #00FF41;'>Disclaimer:</h4>
        <p style='color: #FFAA00;'>
        This tool is intended for authorized security testing and educational purposes only. 
        Users are responsible for complying with applicable laws and regulations.
        </p>
        """
        
        about_text.setHtml(about_html)
        about_layout.addWidget(about_text)
        
        # Add tabs
        self.tabs.addTab(shortcuts_widget, "⌨️ Shortcuts")
        self.tabs.addTab(usage_widget, "📖 Usage")
        self.tabs.addTab(about_widget, "ℹ️ About")
        
        # Close button
        close_layout = QHBoxLayout()
        close_button = QPushButton("✖️ Close")
        close_button.clicked.connect(self.hide)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(255, 100, 100, 200);
            }
        """)
        
        close_layout.addStretch()
        close_layout.addWidget(close_button)
        
        layout.addWidget(header)
        layout.addWidget(self.tabs)
        layout.addLayout(close_layout)
        
    def _get_text_style(self):
        return """
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 8px;
            }
        """