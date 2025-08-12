# app/widgets/scan_history_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QGroupBox, QTabWidget, QComboBox)
from PyQt6.QtCore import Qt, pyqtSignal
# from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository
import json
from datetime import datetime

class ScanHistoryWidget(QWidget):
    """Widget for managing scan history and database"""
    
    scan_loaded = pyqtSignal(dict)  # Signal when scan is loaded
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.refresh_history()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main group
        main_group = QGroupBox("📚 Scan History Database")
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
        
        # Search and filter controls
        controls_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search scans...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
        """)
        
        self.search_button = QPushButton("🔍 Search")
        self.search_button.clicked.connect(self.search_scans)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Types", "DNS Enum", "Port Scan", "HTTP Enum", 
                                   "Vuln Scan", "OSINT", "Cert Transparency"])
        self.filter_combo.currentTextChanged.connect(self.filter_changed)
        
        self.refresh_button = QPushButton("🔄 Refresh")
        self.refresh_button.clicked.connect(self.refresh_history)
        
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
        
        self.search_button.setStyleSheet(button_style)
        self.refresh_button.setStyleSheet(button_style)
        
        controls_layout.addWidget(QLabel("Search:"))
        controls_layout.addWidget(self.search_input)
        controls_layout.addWidget(self.search_button)
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.filter_combo)
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
        
        # History table tab
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "ID", "Target", "Type", "Date", "Results", "Duration", "Status"
        ])
        self.history_table.setStyleSheet("""
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
        self.history_table.cellDoubleClicked.connect(self.load_scan)
        self.results_tabs.addTab(self.history_table, "📋 History")
        
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
        
        # Scan details tab
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
        
        # Action buttons
        actions_layout = QHBoxLayout()
        
        self.load_button = QPushButton("📥 Load Selected")
        self.load_button.clicked.connect(self.load_selected_scan)
        self.load_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 255, 100, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 10pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 255, 100, 200);
            }
        """)
        
        self.delete_button = QPushButton("🗑️ Delete Selected")
        self.delete_button.clicked.connect(self.delete_selected_scan)
        self.delete_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 10pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 100, 100, 200);
            }
        """)
        
        actions_layout.addWidget(self.load_button)
        actions_layout.addWidget(self.delete_button)
        actions_layout.addStretch()
        
        # Status label
        self.status_label = QLabel("Scan history loaded")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        # Add to main layout
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.results_tabs)
        main_layout.addLayout(actions_layout)
        main_layout.addWidget(self.status_label)
        
        layout.addWidget(main_group)
        
    def refresh_history(self):
        """Refresh scan history display"""
        try:
            # Get scan history
            scans = scan_db.get_scan_history(limit=100)
            
            # Update table
            self.history_table.setRowCount(len(scans))
            
            for row, scan in enumerate(scans):
                # ID
                id_item = QTableWidgetItem(str(scan['id']))
                self.history_table.setItem(row, 0, id_item)
                
                # Target
                target_item = QTableWidgetItem(scan['target'])
                self.history_table.setItem(row, 1, target_item)
                
                # Type
                type_item = QTableWidgetItem(scan['scan_type'])
                self.history_table.setItem(row, 2, type_item)
                
                # Date
                timestamp = scan['timestamp']
                if isinstance(timestamp, str):
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        date_str = dt.strftime('%Y-%m-%d %H:%M')
                    except:
                        date_str = timestamp[:16]
                else:
                    date_str = str(timestamp)[:16]
                
                date_item = QTableWidgetItem(date_str)
                self.history_table.setItem(row, 3, date_item)
                
                # Results count
                results_item = QTableWidgetItem(str(scan.get('results_count', 0)))
                self.history_table.setItem(row, 4, results_item)
                
                # Duration
                duration = scan.get('duration', 0)
                duration_str = f"{duration}s" if duration else "N/A"
                duration_item = QTableWidgetItem(duration_str)
                self.history_table.setItem(row, 5, duration_item)
                
                # Status
                status_item = QTableWidgetItem(scan.get('status', 'completed'))
                if scan.get('status') == 'completed':
                    status_item.setForeground(Qt.GlobalColor.green)
                else:
                    status_item.setForeground(Qt.GlobalColor.yellow)
                self.history_table.setItem(row, 6, status_item)
            
            self.history_table.resizeColumnsToContents()
            
            # Update statistics
            self.update_statistics()
            
            self.status_label.setText(f"Loaded {len(scans)} scan records")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            
        except Exception as e:
            self.status_label.setText(f"Error loading history: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def search_scans(self):
        """Search scans based on query"""
        query = self.search_input.text().strip()
        if not query:
            self.refresh_history()
            return
        
        try:
            scans = scan_db.search_scans(query)
            
            # Update table with search results
            self.history_table.setRowCount(len(scans))
            
            for row, scan in enumerate(scans):
                self.history_table.setItem(row, 0, QTableWidgetItem(str(scan['id'])))
                self.history_table.setItem(row, 1, QTableWidgetItem(scan['target']))
                self.history_table.setItem(row, 2, QTableWidgetItem(scan['scan_type']))
                
                timestamp = scan['timestamp'][:16] if scan['timestamp'] else 'N/A'
                self.history_table.setItem(row, 3, QTableWidgetItem(timestamp))
                
                self.history_table.setItem(row, 4, QTableWidgetItem(str(scan.get('results_count', 0))))
                
                duration = scan.get('duration', 0)
                duration_str = f"{duration}s" if duration else "N/A"
                self.history_table.setItem(row, 5, QTableWidgetItem(duration_str))
                
                self.history_table.setItem(row, 6, QTableWidgetItem(scan.get('status', 'completed')))
            
            self.history_table.resizeColumnsToContents()
            
            self.status_label.setText(f"Found {len(scans)} matching scans")
            self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
            
        except Exception as e:
            self.status_label.setText(f"Search error: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def filter_changed(self):
        """Handle filter change"""
        filter_type = self.filter_combo.currentText()
        
        if filter_type == "All Types":
            self.refresh_history()
        else:
            # Map display names to database values
            type_map = {
                "DNS Enum": "dns_enum",
                "Port Scan": "port_scan", 
                "HTTP Enum": "http_enum",
                "Vuln Scan": "vuln_scan",
                "OSINT": "osint",
                "Cert Transparency": "cert_transparency"
            }
            
            scan_type = type_map.get(filter_type)
            if scan_type:
                try:
                    scans = scan_db.get_scan_history(limit=100, scan_type=scan_type)
                    
                    # Update table with filtered results
                    self.history_table.setRowCount(len(scans))
                    
                    for row, scan in enumerate(scans):
                        self.history_table.setItem(row, 0, QTableWidgetItem(str(scan['id'])))
                        self.history_table.setItem(row, 1, QTableWidgetItem(scan['target']))
                        self.history_table.setItem(row, 2, QTableWidgetItem(scan['scan_type']))
                        
                        timestamp = scan['timestamp'][:16] if scan['timestamp'] else 'N/A'
                        self.history_table.setItem(row, 3, QTableWidgetItem(timestamp))
                        
                        self.history_table.setItem(row, 4, QTableWidgetItem(str(scan.get('results_count', 0))))
                        
                        duration = scan.get('duration', 0)
                        duration_str = f"{duration}s" if duration else "N/A"
                        self.history_table.setItem(row, 5, QTableWidgetItem(duration_str))
                        
                        self.history_table.setItem(row, 6, QTableWidgetItem(scan.get('status', 'completed')))
                    
                    self.history_table.resizeColumnsToContents()
                    
                    self.status_label.setText(f"Filtered to {len(scans)} {filter_type} scans")
                    self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
                    
                except Exception as e:
                    self.status_label.setText(f"Filter error: {str(e)}")
                    self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def update_statistics(self):
        """Update statistics display"""
        try:
            stats = scan_db.get_scan_statistics()
            
            stats_text = "Scan Database Statistics\n"
            stats_text += "=" * 25 + "\n\n"
            
            stats_text += f"Total Scans: {stats.get('total_scans', 0)}\n"
            stats_text += f"Unique Targets: {stats.get('unique_targets', 0)}\n\n"
            
            # Scan types breakdown
            scan_types = stats.get('scan_types', {})
            if scan_types:
                stats_text += "Scans by Type:\n"
                stats_text += "-" * 15 + "\n"
                for scan_type, count in scan_types.items():
                    stats_text += f"{scan_type}: {count}\n"
                stats_text += "\n"
            
            # Recent activity
            recent = stats.get('recent_activity', {})
            if recent:
                stats_text += "Recent Activity (Last 7 Days):\n"
                stats_text += "-" * 30 + "\n"
                for date, count in recent.items():
                    stats_text += f"{date}: {count} scans\n"
            
            self.stats_text.setPlainText(stats_text)
            
        except Exception as e:
            self.stats_text.setPlainText(f"Error loading statistics: {str(e)}")
    
    def load_scan(self, row, column):
        """Load scan details when double-clicked"""
        try:
            scan_id_item = self.history_table.item(row, 0)
            if scan_id_item:
                scan_id = int(scan_id_item.text())
                scan = scan_db.get_scan_by_id(scan_id)
                
                if scan:
                    # Display scan details
                    details_text = f"Scan Details (ID: {scan_id})\n"
                    details_text += "=" * 30 + "\n\n"
                    details_text += f"Target: {scan['target']}\n"
                    details_text += f"Type: {scan['scan_type']}\n"
                    details_text += f"Date: {scan['timestamp']}\n"
                    details_text += f"Duration: {scan.get('duration', 0)}s\n"
                    details_text += f"Results Count: {scan.get('results_count', 0)}\n"
                    details_text += f"Status: {scan.get('status', 'completed')}\n\n"
                    
                    if scan.get('summary'):
                        details_text += f"Summary: {scan['summary']}\n\n"
                    
                    # Show results preview
                    results = scan.get('results', {})
                    if results:
                        details_text += "Results Preview:\n"
                        details_text += "-" * 15 + "\n"
                        details_text += json.dumps(results, indent=2, default=str)[:1000]
                        if len(json.dumps(results, default=str)) > 1000:
                            details_text += "\n... (truncated)"
                    
                    self.details_text.setPlainText(details_text)
                    self.results_tabs.setCurrentIndex(2)  # Switch to details tab
                    
        except Exception as e:
            self.status_label.setText(f"Error loading scan details: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def load_selected_scan(self):
        """Load selected scan for analysis"""
        current_row = self.history_table.currentRow()
        if current_row < 0:
            self.status_label.setText("❌ Please select a scan to load")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        try:
            scan_id_item = self.history_table.item(current_row, 0)
            if scan_id_item:
                scan_id = int(scan_id_item.text())
                scan = scan_db.get_scan_by_id(scan_id)
                
                if scan:
                    self.scan_loaded.emit(scan)
                    self.status_label.setText(f"✅ Loaded scan {scan_id}")
                    self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
                
        except Exception as e:
            self.status_label.setText(f"Error loading scan: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def delete_selected_scan(self):
        """Delete selected scan"""
        current_row = self.history_table.currentRow()
        if current_row < 0:
            self.status_label.setText("❌ Please select a scan to delete")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        try:
            scan_id_item = self.history_table.item(current_row, 0)
            if scan_id_item:
                scan_id = int(scan_id_item.text())
                
                if scan_db.delete_scan(scan_id):
                    self.refresh_history()
                    self.status_label.setText(f"🗑️ Deleted scan {scan_id}")
                    self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
                else:
                    self.status_label.setText("❌ Failed to delete scan")
                    self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
                
        except Exception as e:
            self.status_label.setText(f"Error deleting scan: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")