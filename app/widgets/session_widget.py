# app/widgets/session_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QGroupBox, QTabWidget, QComboBox,
                            QDialog, QDialogButtonBox, QFormLayout)
from PyQt6.QtCore import Qt, pyqtSignal
from app.core.session_manager import session_manager
import json
from datetime import datetime

class SessionDialog(QDialog):
    """Dialog for creating/editing sessions"""
    
    def __init__(self, session_data=None, parent=None):
        super().__init__(parent)
        self.session_data = session_data
        self.setup_ui()
        
        if session_data:
            self.load_session_data()
    
    def setup_ui(self):
        self.setWindowTitle("Session Details")
        self.setFixedSize(400, 300)
        
        layout = QVBoxLayout(self)
        
        # Form layout
        form_layout = QFormLayout()
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter session name...")
        
        self.description_input = QTextEdit()
        self.description_input.setFixedHeight(80)
        self.description_input.setPlaceholderText("Enter session description...")
        
        self.targets_input = QTextEdit()
        self.targets_input.setFixedHeight(60)
        self.targets_input.setPlaceholderText("Enter targets (one per line)...")
        
        form_layout.addRow("Name:", self.name_input)
        form_layout.addRow("Description:", self.description_input)
        form_layout.addRow("Targets:", self.targets_input)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | 
                                 QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addLayout(form_layout)
        layout.addWidget(buttons)
    
    def load_session_data(self):
        """Load existing session data"""
        if self.session_data:
            self.name_input.setText(self.session_data.get('name', ''))
            self.description_input.setPlainText(self.session_data.get('description', ''))
            targets = self.session_data.get('targets', [])
            self.targets_input.setPlainText('\n'.join(targets))
    
    def get_session_data(self):
        """Get session data from form"""
        targets_text = self.targets_input.toPlainText().strip()
        targets = [t.strip() for t in targets_text.split('\n') if t.strip()]
        
        return {
            'name': self.name_input.text().strip(),
            'description': self.description_input.toPlainText().strip(),
            'targets': targets
        }

class SessionWidget(QWidget):
    """Widget for session management"""
    
    session_changed = pyqtSignal(str)  # Signal when session changes
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.refresh_sessions()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main group
        main_group = QGroupBox("📁 Session Management")
        main_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        main_layout = QVBoxLayout(main_group)
        
        # Current session display
        current_layout = QHBoxLayout()
        current_layout.addWidget(QLabel("Current Session:"))
        
        self.current_session_label = QLabel("None")
        self.current_session_label.setStyleSheet("color: #FFAA00; font-weight: bold;")
        
        self.set_current_button = QPushButton("Set Current")
        self.set_current_button.clicked.connect(self.set_current_session)
        
        current_layout.addWidget(self.current_session_label)
        current_layout.addWidget(self.set_current_button)
        current_layout.addStretch()
        
        # Session controls
        controls_layout = QHBoxLayout()
        
        self.new_session_button = QPushButton("📁 New Session")
        self.new_session_button.clicked.connect(self.create_new_session)
        
        self.edit_session_button = QPushButton("✏️ Edit")
        self.edit_session_button.clicked.connect(self.edit_selected_session)
        
        self.delete_session_button = QPushButton("🗑️ Delete")
        self.delete_session_button.clicked.connect(self.delete_selected_session)
        
        self.refresh_button = QPushButton("🔄 Refresh")
        self.refresh_button.clicked.connect(self.refresh_sessions)
        
        button_style = """
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """
        
        self.new_session_button.setStyleSheet(button_style.replace("100, 200, 255", "100, 255, 100"))
        self.edit_session_button.setStyleSheet(button_style)
        self.delete_session_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 100, 100"))
        self.refresh_button.setStyleSheet(button_style)
        self.set_current_button.setStyleSheet(button_style)
        
        controls_layout.addWidget(self.new_session_button)
        controls_layout.addWidget(self.edit_session_button)
        controls_layout.addWidget(self.delete_session_button)
        controls_layout.addWidget(self.refresh_button)
        controls_layout.addStretch()
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
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
        
        # Sessions table tab
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(6)
        self.sessions_table.setHorizontalHeaderLabels([
            "ID", "Name", "Description", "Created", "Scans", "Status"
        ])
        self.sessions_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                gridline-color: #555;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                padding: 4px;
                border: none;
                font-weight: bold;
            }
        """)
        self.sessions_table.cellDoubleClicked.connect(self.view_session_details)
        self.results_tabs.addTab(self.sessions_table, "📋 Sessions")
        
        # Session details tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
        """)
        self.results_tabs.addTab(self.details_text, "📄 Details")
        
        # Statistics tab
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
        """)
        self.results_tabs.addTab(self.stats_text, "📊 Statistics")
        
        # Credential Management tab
        from app.widgets.secure_credential_widget import SecureCredentialWidget
        self.credential_widget = SecureCredentialWidget()
        self.results_tabs.addTab(self.credential_widget, "🔑 Credential Management")
        
        # Status label
        self.status_label = QLabel("Session management ready")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        # Add to main layout
        main_layout.addLayout(current_layout)
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.results_tabs)
        main_layout.addWidget(self.status_label)
        
        layout.addWidget(main_group)
        
    def refresh_sessions(self):
        """Refresh sessions display"""
        try:
            sessions = session_manager.get_all_sessions()
            
            # Update table
            self.sessions_table.setRowCount(len(sessions))
            
            for row, session in enumerate(sessions):
                # ID
                id_item = QTableWidgetItem(session['id'])
                self.sessions_table.setItem(row, 0, id_item)
                
                # Name
                name_item = QTableWidgetItem(session['name'])
                self.sessions_table.setItem(row, 1, name_item)
                
                # Description
                desc = session.get('description', '')
                if len(desc) > 30:
                    desc = desc[:27] + "..."
                desc_item = QTableWidgetItem(desc)
                self.sessions_table.setItem(row, 2, desc_item)
                
                # Created date
                created = session.get('created_date', '')
                if created:
                    try:
                        dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        date_str = dt.strftime('%Y-%m-%d')
                    except:
                        date_str = created[:10]
                else:
                    date_str = 'N/A'
                
                date_item = QTableWidgetItem(date_str)
                self.sessions_table.setItem(row, 3, date_item)
                
                # Scan count
                scan_count = len(session.get('scan_ids', []))
                scan_item = QTableWidgetItem(str(scan_count))
                self.sessions_table.setItem(row, 4, scan_item)
                
                # Status
                status = session.get('status', 'active')
                status_item = QTableWidgetItem(status)
                if status == 'active':
                    status_item.setForeground(Qt.GlobalColor.green)
                else:
                    status_item.setForeground(Qt.GlobalColor.yellow)
                self.sessions_table.setItem(row, 5, status_item)
            
            self.sessions_table.resizeColumnsToContents()
            
            # Update current session display
            current_session = session_manager.get_current_session()
            if current_session:
                self.current_session_label.setText(current_session['name'])
                self.current_session_label.setStyleSheet("color: #00FF41; font-weight: bold;")
            else:
                self.current_session_label.setText("None")
                self.current_session_label.setStyleSheet("color: #FFAA00; font-weight: bold;")
            
            self.status_label.setText(f"Loaded {len(sessions)} sessions")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            
        except Exception as e:
            self.status_label.setText(f"Error loading sessions: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def create_new_session(self):
        """Create new session"""
        dialog = SessionDialog(parent=self)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            session_data = dialog.get_session_data()
            
            if not session_data['name']:
                self.status_label.setText("❌ Session name is required")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
                return
            
            try:
                session = session_manager.create_session(
                    name=session_data['name'],
                    description=session_data['description'],
                    targets=session_data['targets']
                )
                
                self.refresh_sessions()
                self.status_label.setText(f"✅ Created session: {session['name']}")
                self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
                
            except Exception as e:
                self.status_label.setText(f"Error creating session: {str(e)}")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def edit_selected_session(self):
        """Edit selected session"""
        current_row = self.sessions_table.currentRow()
        if current_row < 0:
            self.status_label.setText("❌ Please select a session to edit")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        try:
            session_id_item = self.sessions_table.item(current_row, 0)
            if session_id_item:
                session_id = session_id_item.text()
                session = session_manager.get_session(session_id)
                
                if session:
                    dialog = SessionDialog(session_data=session, parent=self)
                    
                    if dialog.exec() == QDialog.DialogCode.Accepted:
                        session_data = dialog.get_session_data()
                        
                        if session_manager.update_session(session_id, session_data):
                            self.refresh_sessions()
                            self.status_label.setText(f"✅ Updated session: {session_data['name']}")
                            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
                        else:
                            self.status_label.setText("❌ Failed to update session")
                            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
                
        except Exception as e:
            self.status_label.setText(f"Error editing session: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def delete_selected_session(self):
        """Delete selected session"""
        current_row = self.sessions_table.currentRow()
        if current_row < 0:
            self.status_label.setText("❌ Please select a session to delete")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        try:
            session_id_item = self.sessions_table.item(current_row, 0)
            if session_id_item:
                session_id = session_id_item.text()
                
                if session_manager.delete_session(session_id):
                    self.refresh_sessions()
                    self.status_label.setText(f"🗑️ Deleted session {session_id}")
                    self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
                else:
                    self.status_label.setText("❌ Failed to delete session")
                    self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
                
        except Exception as e:
            self.status_label.setText(f"Error deleting session: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def set_current_session(self):
        """Set current active session"""
        current_row = self.sessions_table.currentRow()
        if current_row < 0:
            self.status_label.setText("❌ Please select a session to set as current")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        try:
            session_id_item = self.sessions_table.item(current_row, 0)
            if session_id_item:
                session_id = session_id_item.text()
                
                if session_manager.set_current_session(session_id):
                    self.refresh_sessions()
                    session = session_manager.get_session(session_id)
                    self.status_label.setText(f"✅ Set current session: {session['name']}")
                    self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
                    
                    self.session_changed.emit(session_id)
                else:
                    self.status_label.setText("❌ Failed to set current session")
                    self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
                
        except Exception as e:
            self.status_label.setText(f"Error setting current session: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def view_session_details(self, row, column):
        """View session details when double-clicked"""
        try:
            session_id_item = self.sessions_table.item(row, 0)
            if session_id_item:
                session_id = session_id_item.text()
                session = session_manager.get_session(session_id)
                
                if session:
                    # Display session details
                    details_text = f"Session Details (ID: {session_id})\n"
                    details_text += "=" * 40 + "\n\n"
                    details_text += f"Name: {session['name']}\n"
                    details_text += f"Description: {session.get('description', 'N/A')}\n"
                    details_text += f"Created: {session.get('created_date', 'N/A')}\n"
                    details_text += f"Status: {session.get('status', 'active')}\n"
                    details_text += f"Scan Count: {len(session.get('scan_ids', []))}\n\n"
                    
                    # Targets
                    targets = session.get('targets', [])
                    if targets:
                        details_text += f"Targets ({len(targets)}):\n"
                        details_text += "-" * 15 + "\n"
                        for target in targets:
                            details_text += f"• {target}\n"
                        details_text += "\n"
                    
                    # Statistics
                    stats = session_manager.get_session_statistics(session_id)
                    if stats:
                        details_text += "Statistics:\n"
                        details_text += "-" * 10 + "\n"
                        details_text += f"Total Scans: {stats.get('total_scans', 0)}\n"
                        details_text += f"Targets Scanned: {stats.get('targets_scanned', 0)}\n"
                        details_text += f"Total Results: {stats.get('total_results', 0)}\n"
                        
                        scan_types = stats.get('scan_types', {})
                        if scan_types:
                            details_text += "\nScan Types:\n"
                            for scan_type, count in scan_types.items():
                                details_text += f"  {scan_type}: {count}\n"
                    
                    self.details_text.setPlainText(details_text)
                    self.results_tabs.setCurrentIndex(1)  # Switch to details tab
                    
                    # Update statistics tab
                    self.update_statistics_display(stats)
                    
        except Exception as e:
            self.status_label.setText(f"Error loading session details: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def update_statistics_display(self, stats):
        """Update statistics display"""
        if not stats:
            self.stats_text.setPlainText("No statistics available")
            return
        
        stats_text = "Session Statistics\n"
        stats_text += "=" * 20 + "\n\n"
        
        stats_text += f"Total Scans: {stats.get('total_scans', 0)}\n"
        stats_text += f"Unique Targets: {stats.get('targets_scanned', 0)}\n"
        stats_text += f"Total Results: {stats.get('total_results', 0)}\n\n"
        
        # Scan types
        scan_types = stats.get('scan_types', {})
        if scan_types:
            stats_text += "Scan Types Distribution:\n"
            stats_text += "-" * 25 + "\n"
            for scan_type, count in scan_types.items():
                percentage = (count / stats.get('total_scans', 1)) * 100
                stats_text += f"{scan_type}: {count} ({percentage:.1f}%)\n"
            stats_text += "\n"
        
        # Date range
        date_range = stats.get('date_range', {})
        if date_range.get('start') and date_range.get('end'):
            stats_text += f"Date Range:\n"
            stats_text += f"Start: {date_range['start'][:10]}\n"
            stats_text += f"End: {date_range['end'][:10]}\n"
        
        self.stats_text.setPlainText(stats_text)