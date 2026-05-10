# app/components/session_info/session_data_tables_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, QMessageBox
from PyQt6.QtCore import pyqtSignal
from datetime import datetime
import os
from app.core.logger import logger

class SessionDataTablesComponent(QWidget):
    status_updated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Controls for exports
        controls_layout = QHBoxLayout()
        
        self.open_export_button = QPushButton("📂 Open Export")
        self.open_export_button.clicked.connect(self.open_selected_export)
        
        self.export_location_button = QPushButton("📁 Show in Explorer")
        self.export_location_button.clicked.connect(self.show_export_location)
        
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
        
        self.open_export_button.setStyleSheet(button_style)
        self.export_location_button.setStyleSheet(button_style)
        
        controls_layout.addWidget(self.open_export_button)
        controls_layout.addWidget(self.export_location_button)
        controls_layout.addStretch()
        
        # Exports table
        self.exports_table = QTableWidget()
        self.exports_table.setColumnCount(6)
        self.exports_table.setHorizontalHeaderLabels([
            "Timestamp", "Target", "Format", "File Path", "Size", "Scan Type"
        ])
        
        # Scans table
        self.scans_table = QTableWidget()
        self.scans_table.setColumnCount(6)
        self.scans_table.setHorizontalHeaderLabels([
            "ID", "Target", "Scan Type", "Timestamp", "Duration", "Results"
        ])
        
        table_style = """
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
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
        """
        
        self.exports_table.setStyleSheet(table_style)
        self.scans_table.setStyleSheet(table_style)
        
        layout.addLayout(controls_layout)
        layout.addWidget(self.exports_table)

    def get_exports_table(self):
        """Get exports table widget"""
        return self.exports_table

    def get_scans_table(self):
        """Get scans table widget"""
        return self.scans_table

    def update_exports_table(self, session_id):
        """Update exports table"""
        try:
            # Mock data for now - replace with actual session manager call
            exports = []  # session_manager.get_session_exports(session_id)
            
            self.exports_table.setRowCount(len(exports))
            
            for row, export in enumerate(exports):
                # Timestamp
                timestamp = export.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
                
                self.exports_table.setItem(row, 0, QTableWidgetItem(timestamp))
                self.exports_table.setItem(row, 1, QTableWidgetItem(export.get('target', 'N/A')))
                self.exports_table.setItem(row, 2, QTableWidgetItem(export.get('format', 'N/A')))
                self.exports_table.setItem(row, 3, QTableWidgetItem(export.get('file_path', 'N/A')))
                
                # File size
                size = export.get('file_size', 0)
                size_str = f"{size:,} bytes" if size else "N/A"
                self.exports_table.setItem(row, 4, QTableWidgetItem(size_str))
                
                self.exports_table.setItem(row, 5, QTableWidgetItem(export.get('scan_type', 'N/A')))
            
            self.exports_table.resizeColumnsToContents()
            
        except Exception as e:
            self.status_updated.emit(f"Error updating exports table: {str(e)}")

    def update_scans_table(self, session_id):
        """Update scans table"""
        try:
            # Mock data for now - replace with actual session manager call
            scans = []  # session_manager.get_session_scans(session_id)
            
            self.scans_table.setRowCount(len(scans))
            
            for row, scan in enumerate(scans):
                self.scans_table.setItem(row, 0, QTableWidgetItem(str(scan.get('id', 'N/A'))))
                self.scans_table.setItem(row, 1, QTableWidgetItem(scan.get('target', 'N/A')))
                self.scans_table.setItem(row, 2, QTableWidgetItem(scan.get('scan_type', 'N/A')))
                
                # Timestamp
                timestamp = scan.get('timestamp', '')
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
                
                self.scans_table.setItem(row, 3, QTableWidgetItem(timestamp))
                
                # Duration
                duration = scan.get('duration', 0)
                duration_str = f"{duration}s" if duration else "N/A"
                self.scans_table.setItem(row, 4, QTableWidgetItem(duration_str))
                
                self.scans_table.setItem(row, 5, QTableWidgetItem(str(scan.get('results_count', 0))))
            
            self.scans_table.resizeColumnsToContents()
            
        except Exception as e:
            self.status_updated.emit(f"Error updating scans table: {str(e)}")

    def open_selected_export(self):
        """Open selected export file"""
        current_row = self.exports_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select an export to open")
            return
        
        file_path_item = self.exports_table.item(current_row, 3)
        if file_path_item:
            file_path = file_path_item.text()
            if os.path.exists(file_path):
                os.startfile(file_path)
                self.status_updated.emit(f"Opened export: {file_path}")
            else:
                QMessageBox.warning(self, "Warning", f"File not found: {file_path}")
                self.status_updated.emit(f"File not found: {file_path}")

    def show_export_location(self):
        """Show export location in file explorer"""
        current_row = self.exports_table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select an export")
            return
        
        file_path_item = self.exports_table.item(current_row, 3)
        if file_path_item:
            file_path = file_path_item.text()
            if os.path.exists(file_path):
                os.system(f'explorer /select,"{file_path}"')
                self.status_updated.emit(f"Showed location: {file_path}")
            else:
                QMessageBox.warning(self, "Warning", f"File not found: {file_path}")
                self.status_updated.emit(f"File not found: {file_path}")