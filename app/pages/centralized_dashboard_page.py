# app/pages/centralized_dashboard_page.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QTableWidget, QTableWidgetItem, QLabel, QPushButton,
                            QGroupBox, QGridLayout, QTextEdit, QSplitter,
                            QHeaderView, QFrame)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor
from ..core.unified_ui_integration import create_unified_integration
from ..core.centralized_scan_data import centralized_scan_data
import json
from app.core.logger import logger

class CentralizedDashboardPage(QWidget):
    """Unified dashboard showing all scan types with real-time updates"""
    
    def __init__(self, tenant_id: str = "default"):
        super().__init__()
        self.tenant_id = tenant_id
        self.ui_integration = create_unified_integration(tenant_id)
        self.tables = {}
        self.summary_labels = {}
        self.setup_ui()
        self.setup_real_time_updates()
    
    def setup_ui(self):
        """Setup the dashboard UI"""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🔬 Centralized Security Dashboard")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #00BFFF; margin: 10px;")
        layout.addWidget(title)
        
        # Create splitter for main content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # Left side - Summary statistics
        self.setup_summary_panel(splitter)
        
        # Right side - Detailed data tables
        self.setup_data_tables(splitter)
        
        # Bottom - Export controls
        self.setup_export_controls(layout)
        
        # Set splitter proportions
        splitter.setSizes([300, 700])
    
    def setup_summary_panel(self, parent):
        """Setup summary statistics panel"""
        summary_widget = QWidget()
        summary_layout = QVBoxLayout(summary_widget)
        
        # Summary title
        summary_title = QLabel("📊 Scan Summary")
        summary_title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        summary_title.setStyleSheet("color: #FFD700; margin-bottom: 10px;")
        summary_layout.addWidget(summary_title)
        
        # Create summary groups for each scan type
        scan_types = [
            ("RPC", "rpc_endpoints", "#FF6B6B"),
            ("DNS", "dns_subdomains", "#4ECDC4"), 
            ("Ports", "port_open_ports", "#45B7D1"),
            ("SMB", "smb_shares", "#96CEB4"),
            ("HTTP", "http_directories", "#FFEAA7"),
            ("LDAP", "ldap_users", "#DDA0DD"),
            ("SNMP", "snmp_communities", "#F0E68C")
        ]
        
        for name, scan_type, color in scan_types:
            group = self.create_summary_group(name, scan_type, color)
            summary_layout.addWidget(group)
        
        summary_layout.addStretch()
        parent.addWidget(summary_widget)
    
    def create_summary_group(self, name: str, scan_type: str, color: str) -> QGroupBox:
        """Create a summary group for a scan type"""
        group = QGroupBox(f"{name} Scans")
        group.setStyleSheet(f"""
            QGroupBox {{
                font-weight: bold;
                border: 2px solid {color};
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: {color};
            }}
        """)
        
        layout = QGridLayout(group)
        
        # Total results
        total_label = QLabel("Total Results:")
        total_value = QLabel("0")
        total_value.setStyleSheet(f"color: {color}; font-weight: bold;")
        layout.addWidget(total_label, 0, 0)
        layout.addWidget(total_value, 0, 1)
        
        # Unique targets
        targets_label = QLabel("Targets:")
        targets_value = QLabel("0")
        targets_value.setStyleSheet(f"color: {color}; font-weight: bold;")
        layout.addWidget(targets_label, 1, 0)
        layout.addWidget(targets_value, 1, 1)
        
        # Last scan
        last_label = QLabel("Last Scan:")
        last_value = QLabel("Never")
        last_value.setStyleSheet("color: #888888; font-size: 10px;")
        layout.addWidget(last_label, 2, 0)
        layout.addWidget(last_value, 2, 1)
        
        # Store references for updates
        self.summary_labels[scan_type] = {
            'total': total_value,
            'targets': targets_value,
            'last_scan': last_value
        }
        
        return group
    
    def setup_data_tables(self, parent):
        """Setup data tables for each scan type"""
        tab_widget = QTabWidget()
        tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #555555;
                color: #00BFFF;
            }
        """)
        
        # Create tabs for each scan type
        scan_types = [
            ("🔧 RPC", "rpc_endpoints", ["Protocol", "UUID", "Port", "First Seen", "Count"]),
            ("🌐 DNS", "dns_subdomains", ["Subdomain", "Domain", "First Seen", "Count"]),
            ("🔌 Ports", "port_open_ports", ["Port", "Service", "Protocol", "First Seen", "Count"]),
            ("📁 SMB", "smb_shares", ["Share", "Type", "Access", "First Seen", "Count"]),
            ("🌍 HTTP", "http_directories", ["Directory", "Status", "Size", "First Seen", "Count"]),
            ("👥 LDAP", "ldap_users", ["Username", "Display Name", "UPN", "First Seen", "Count"]),
            ("📡 SNMP", "snmp_communities", ["Community", "Access Level", "First Seen", "Count"])
        ]
        
        for tab_name, scan_type, columns in scan_types:
            table = self.create_data_table(columns)
            tab_widget.addTab(table, tab_name)
            self.tables[scan_type] = table
            
            # Register table with UI integration
            self.ui_integration.register_component(scan_type, "table", table)
        
        parent.addWidget(tab_widget)
    
    def create_data_table(self, columns: list) -> QTableWidget:
        """Create a data table with specified columns"""
        table = QTableWidget()
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        
        # Style the table
        table.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                color: white;
                gridline-color: #555555;
                selection-background-color: #4a4a4a;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #00BFFF;
                padding: 8px;
                border: 1px solid #555555;
                font-weight: bold;
            }
        """)
        
        # Configure table properties
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        
        return table
    
    def setup_export_controls(self, layout):
        """Setup export and control buttons"""
        controls_frame = QFrame()
        controls_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        controls_frame.setStyleSheet("background-color: #3c3c3c; border-radius: 5px; margin: 5px;")
        
        controls_layout = QHBoxLayout(controls_frame)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh Data")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        refresh_btn.clicked.connect(self.refresh_data)
        controls_layout.addWidget(refresh_btn)
        
        # Export buttons
        export_json_btn = QPushButton("📄 Export JSON")
        export_json_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        export_json_btn.clicked.connect(self.export_json)
        controls_layout.addWidget(export_json_btn)
        
        export_csv_btn = QPushButton("📊 Export CSV")
        export_csv_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        export_csv_btn.clicked.connect(self.export_csv)
        controls_layout.addWidget(export_csv_btn)
        
        # Export PDF button
        export_pdf_btn = QPushButton("📋 Export PDF")
        export_pdf_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        export_pdf_btn.clicked.connect(self.export_pdf)
        controls_layout.addWidget(export_pdf_btn)
        
        controls_layout.addStretch()
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #00FF41; font-weight: bold;")
        controls_layout.addWidget(self.status_label)
        
        layout.addWidget(controls_frame)
    
    def setup_real_time_updates(self):
        """Setup real-time data updates"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(1000)  # Update every 1 second
        
        # Start UI integration updates
        self.ui_integration.start_real_time_updates()
        
        # Initial data load
        self.update_dashboard()
    
    def update_dashboard(self):
        """Update dashboard with latest data"""
        try:
            # Update summary statistics
            self.update_summary_stats()
            
            # Update status
            self.status_label.setText(f"Last updated: {self.get_current_time()}")
            
        except Exception as e:
            self.status_label.setText(f"Update error: {str(e)}")
    
    def update_summary_stats(self):
        """Update summary statistics for all scan types"""
        for scan_type, labels in self.summary_labels.items():
            try:
                summary = centralized_scan_data.get_scan_summary(
                    tenant_id=self.tenant_id,
                    scan_type=scan_type
                )
                
                labels['total'].setText(str(summary.get('total_results', 0)))
                labels['targets'].setText(str(summary.get('unique_targets', 0)))
                
                last_scan = summary.get('last_scan_time', 'Never')
                if last_scan != 'Never':
                    # Format timestamp
                    from datetime import datetime
                    try:
                        dt = datetime.fromisoformat(last_scan.replace('Z', '+00:00'))
                        last_scan = dt.strftime('%H:%M:%S')
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
                
                labels['last_scan'].setText(last_scan)
                
            except Exception as e:
                labels['total'].setText("Error")
                labels['targets'].setText("Error")
                labels['last_scan'].setText("Error")
    
    def refresh_data(self):
        """Manually refresh all data"""
        self.status_label.setText("Refreshing...")
        self.update_dashboard()
        
        # Force refresh UI components
        for scan_type, table in self.tables.items():
            self.ui_integration.update_component(scan_type, table)
    
    def export_json(self):
        """Export all data to JSON"""
        try:
            from PyQt6.QtWidgets import QFileDialog
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Dashboard Data", "dashboard_data.json", "JSON Files (*.json)"
            )
            
            if filename:
                # Collect all data
                export_data = {
                    'tenant_id': self.tenant_id,
                    'export_time': self.get_current_time(),
                    'scan_data': {}
                }
                
                for scan_type in self.tables.keys():
                    export_data['scan_data'][scan_type] = centralized_scan_data.get_scan_data(
                        tenant_id=self.tenant_id,
                        scan_type=scan_type
                    )
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
                
                self.status_label.setText(f"Exported to {filename}")
                
        except Exception as e:
            self.status_label.setText(f"Export error: {str(e)}")
    
    def export_csv(self):
        """Export current table data to CSV"""
        try:
            from PyQt6.QtWidgets import QFileDialog
            import csv
            
            # Get current tab
            current_tab = self.sender().parent().parent().findChild(QTabWidget)
            if not current_tab:
                return
                
            current_index = current_tab.currentIndex()
            scan_types = list(self.tables.keys())
            
            if current_index < len(scan_types):
                scan_type = scan_types[current_index]
                table = self.tables[scan_type]
                
                filename, _ = QFileDialog.getSaveFileName(
                    self, f"Export {scan_type} Data", f"{scan_type}_data.csv", "CSV Files (*.csv)"
                )
                
                if filename:
                    with open(filename, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        
                        # Write headers
                        headers = []
                        for col in range(table.columnCount()):
                            headers.append(table.horizontalHeaderItem(col).text())
                        writer.writerow(headers)
                        
                        # Write data
                        for row in range(table.rowCount()):
                            row_data = []
                            for col in range(table.columnCount()):
                                item = table.item(row, col)
                                row_data.append(item.text() if item else "")
                            writer.writerow(row_data)
                    
                    self.status_label.setText(f"Exported {scan_type} to {filename}")
                    
        except Exception as e:
            self.status_label.setText(f"CSV export error: {str(e)}")
    
    def export_pdf(self):
        """Export data to PDF report"""
        try:
            from PyQt6.QtWidgets import QFileDialog, QMessageBox, QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel
            from app.core.pdf_report_generator import create_pdf_generator
            
            # Create dialog for report type selection
            dialog = QDialog(self)
            dialog.setWindowTitle("PDF Export Options")
            dialog.setModal(True)
            dialog.resize(400, 200)
            
            layout = QVBoxLayout(dialog)
            
            layout.addWidget(QLabel("Select report type:"))
            
            btn_layout = QHBoxLayout()
            
            exec_btn = QPushButton("Executive Summary")
            exec_btn.clicked.connect(lambda: self._export_pdf_type("executive", dialog))
            btn_layout.addWidget(exec_btn)
            
            tech_btn = QPushButton("Technical Report")
            tech_btn.clicked.connect(lambda: self._export_pdf_type("technical", dialog))
            btn_layout.addWidget(tech_btn)
            
            comp_btn = QPushButton("Compliance Report")
            comp_btn.clicked.connect(lambda: self._export_pdf_type("compliance", dialog))
            btn_layout.addWidget(comp_btn)
            
            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(dialog.reject)
            btn_layout.addWidget(cancel_btn)
            
            layout.addLayout(btn_layout)
            
            dialog.exec()
            
        except Exception as e:
            self.status_label.setText(f"PDF export error: {str(e)}")
    
    def _export_pdf_type(self, report_type: str, dialog):
        """Export specific PDF report type"""
        try:
            from PyQt6.QtWidgets import QFileDialog
            from app.core.pdf_report_generator import create_pdf_generator
            
            dialog.accept()
            
            filename, _ = QFileDialog.getSaveFileName(
                self, f"Export {report_type.title()} PDF Report", 
                f"{report_type}_report_{self.get_current_time().replace(':', '-').replace(' ', '_')}.pdf", 
                "PDF Files (*.pdf)"
            )
            
            if filename:
                generator = create_pdf_generator(self.tenant_id)
                
                if report_type == "executive":
                    success = generator.generate_executive_report(filename)
                elif report_type == "technical":
                    success = generator.generate_technical_report(filename)
                else:  # compliance
                    success = generator.generate_compliance_report(filename, 'OWASP_TOP_10')
                
                if success:
                    self.status_label.setText(f"PDF report exported to {filename}")
                else:
                    self.status_label.setText("PDF export failed")
                    
        except Exception as e:
            self.status_label.setText(f"PDF export error: {str(e)}")
    
    def get_current_time(self) -> str:
        """Get current time as formatted string"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def closeEvent(self, event):
        """Clean up when closing"""
        if hasattr(self, 'update_timer'):
            self.update_timer.stop()
        
        if hasattr(self, 'ui_integration'):
            self.ui_integration.stop_real_time_updates()
        
        event.accept()

def create_centralized_dashboard(tenant_id: str = "default") -> CentralizedDashboardPage:
    """Create centralized dashboard for specific tenant"""
    return CentralizedDashboardPage(tenant_id=tenant_id)