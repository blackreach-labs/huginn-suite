# app/pages/session_info_page_new.py
from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, QTextEdit
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont, QShortcut, QKeySequence

from app.pages.components.base_page import BasePage
from app.components.session_info.session_overview_component import SessionOverviewComponent
from app.components.session_info.session_management_component import SessionManagementComponent
from app.components.session_info.session_data_tables_component import SessionDataTablesComponent

class SessionInfoPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(parent)

    def setup_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(10, 10, 10, 10)

        self.create_header()
        self.create_content_tabs()
        self.create_status_bar()
        self.setup_shortcuts()
        self.apply_theme()

    def create_header(self):
        """Create header with title and session management"""
        header_layout = QHBoxLayout()
        
        title_label = QLabel("📊 Session Information")
        title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #64C8FF; margin-bottom: 10px;")
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        # Session management component
        self.session_management = SessionManagementComponent()
        header_layout.addWidget(self.session_management)
        
        self.main_layout.addLayout(header_layout)

    def create_content_tabs(self):
        """Create main content tabs"""
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
        
        # Current Session Overview Tab
        self.overview_component = SessionOverviewComponent()
        self.tabs.addTab(self.overview_component, "📋 Current Session")
        
        # Data Tables Tab
        self.data_tables_component = SessionDataTablesComponent()
        self.tabs.addTab(self.data_tables_component.get_exports_table(), "📤 Exports")
        self.tabs.addTab(self.data_tables_component.get_scans_table(), "🔍 Scans")
        
        # Statistics Tab
        self.stats_widget = self.create_stats_tab()
        self.tabs.addTab(self.stats_widget, "📊 Statistics")
        
        self.main_layout.addWidget(self.tabs)

    def create_stats_tab(self):
        """Create statistics tab"""
        from PyQt6.QtWidgets import QWidget
        
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                color: #DCDCDC;
                font-family: 'Courier New', monospace;
                padding: 8px;
            }
        """)
        
        layout.addWidget(self.stats_text)
        return widget

    def create_status_bar(self):
        """Create status bar"""
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        self.main_layout.addWidget(self.status_label)

    def connect_signals(self):
        """Connect component signals"""
        # Connect session management signals
        self.session_management.session_changed.connect(self.on_session_changed)
        self.session_management.status_updated.connect(self.update_status)
        
        # Connect data tables signals
        self.data_tables_component.status_updated.connect(self.update_status)

    def on_session_changed(self, session_id):
        """Handle session change"""
        try:
            from app.core.session_manager import session_manager
            
            session = session_manager.get_session(session_id)
            if session:
                # Update overview
                self.overview_component.update_session_info(session)
                
                # Update statistics
                stats = session_manager.get_session_statistics(session_id)
                self.overview_component.update_statistics(stats)
                
                # Update data tables
                self.data_tables_component.update_exports_table(session_id)
                self.data_tables_component.update_scans_table(session_id)
                
                # Update statistics tab
                self.update_statistics_display(session_id, stats)
                
                self.update_status(f"Loaded session: {session['name']}")
        except Exception as e:
            self.update_status(f"Error loading session: {str(e)}")

    def update_statistics_display(self, session_id, stats):
        """Update statistics display"""
        stats_text = f"Session Statistics\n"
        stats_text += "=" * 30 + "\n\n"
        
        stats_text += f"Total Scans: {stats.get('total_scans', 0)}\n"
        stats_text += f"Total Exports: {stats.get('total_exports', 0)}\n"
        stats_text += f"Unique Targets: {stats.get('targets_scanned', 0)}\n"
        stats_text += f"Total Results: {stats.get('total_results', 0)}\n\n"
        
        # Scan types
        scan_types = stats.get('scan_types', {})
        if scan_types:
            stats_text += "Scan Types:\n"
            stats_text += "-" * 15 + "\n"
            for scan_type, count in scan_types.items():
                stats_text += f"  {scan_type}: {count}\n"
            stats_text += "\n"
        
        # Export types
        export_types = stats.get('export_types', {})
        if export_types:
            stats_text += "Export Formats:\n"
            stats_text += "-" * 15 + "\n"
            for export_type, count in export_types.items():
                stats_text += f"  {export_type}: {count}\n"
            stats_text += "\n"
        
        # Date range
        date_range = stats.get('date_range', {})
        if date_range.get('start') and date_range.get('end'):
            stats_text += f"Date Range:\n"
            stats_text += f"  Start: {date_range['start'][:19]}\n"
            stats_text += f"  End: {date_range['end'][:19]}\n"
        
        self.stats_text.setPlainText(stats_text)

    def update_status(self, message):
        """Update status message"""
        self.status_label.setText(message)
        if "error" in message.lower():
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
        else:
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
        
        # Emit status signal for main window
        self.status_updated.emit(message)

    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        self.back_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.back_shortcut.activated.connect(lambda: self.navigate_signal.emit("home"))

    def apply_theme(self):
        """Apply theme styling"""
        self.setStyleSheet("""
            QWidget {
                background-color: #1E1E1E;
                color: #DCDCDC;
            }
        """)

    def cleanup(self):
        """Cleanup resources when page is destroyed"""
        if hasattr(self.session_management, 'cleanup'):
            self.session_management.cleanup()

    def get_page_title(self):
        return "Session Information"

    def get_page_icon(self):
        return "session_icon.png"