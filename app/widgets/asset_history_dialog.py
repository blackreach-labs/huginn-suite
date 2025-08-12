# app/widgets/asset_history_dialog.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                             QTableWidget, QTableWidgetItem, QHeaderView, 
                             QPushButton, QTextEdit, QSplitter)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from app.core.asset_manager import asset_manager

class AssetHistoryDialog(QDialog):
    """Dialog for viewing asset change history"""
    
    def __init__(self, tenant_id, ip_address, parent=None):
        super().__init__(parent)
        self.tenant_id = tenant_id
        self.ip_address = ip_address
        self.setup_ui()
        self.load_history()
        
    def setup_ui(self):
        """Setup the dialog UI"""
        self.setWindowTitle(f"Asset History - {self.ip_address}")
        self.setModal(True)
        self.resize(800, 600)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Title
        title = QLabel(f"Change History for Asset: {self.ip_address}")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF; margin-bottom: 10px;")
        layout.addWidget(title)
        
        # Splitter for table and details
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # History table
        self.history_table = self.create_history_table()
        splitter.addWidget(self.history_table)
        
        # Details area
        details_label = QLabel("Change Details:")
        details_label.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 10px;")
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        self.details_text.setPlaceholderText("Select a history entry to view details")
        
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.addWidget(details_label)
        details_layout.addWidget(self.details_text)
        
        splitter.addWidget(details_widget)
        splitter.setSizes([400, 200])
        
        layout.addWidget(splitter)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_history)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(150, 150, 150, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(150, 150, 150, 200);
            }
        """)
        
        button_layout.addWidget(refresh_btn)
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        # Apply dark theme styling
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QTableWidget {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                gridline-color: rgba(100, 200, 255, 50);
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid rgba(100, 200, 255, 30);
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                font-weight: bold;
                padding: 8px;
                border: none;
            }
            QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                padding: 5px;
            }
            QLabel {
                color: #DCDCDC;
            }
        """)
    
    def create_history_table(self):
        """Create the history table"""
        table = QTableWidget()
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels([
            "Timestamp", "Change Type", "Old Value", "New Value"
        ])
        
        # Set column widths
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        table.setColumnWidth(0, 150)  # Timestamp
        table.setColumnWidth(1, 120)  # Change Type
        
        # Connect selection change
        table.itemSelectionChanged.connect(self.on_selection_changed)
        
        return table
    
    def load_history(self):
        """Load asset history from database"""
        try:
            history = asset_manager.get_asset_history(self.tenant_id, self.ip_address)
            
            self.history_table.setRowCount(len(history))
            
            for row, entry in enumerate(history):
                # Timestamp
                timestamp_item = QTableWidgetItem(entry.get('timestamp', ''))
                timestamp_item.setFlags(timestamp_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.history_table.setItem(row, 0, timestamp_item)
                
                # Change Type
                change_type = entry.get('change_type', '')
                change_item = QTableWidgetItem(change_type)
                change_item.setFlags(change_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                
                # Color code change types
                if change_type == 'CREATED':
                    change_item.setBackground(Qt.GlobalColor.green)
                    change_item.setForeground(Qt.GlobalColor.white)
                elif change_type == 'DELETED':
                    change_item.setBackground(Qt.GlobalColor.red)
                    change_item.setForeground(Qt.GlobalColor.white)
                elif change_type in ['OS_IDENTIFIED', 'STATUS_CHANGE']:
                    change_item.setBackground(Qt.GlobalColor.blue)
                    change_item.setForeground(Qt.GlobalColor.white)
                elif change_type in ['SERVICES_ADDED', 'VULNERABILITIES_ADDED']:
                    change_item.setBackground(Qt.GlobalColor.darkYellow)
                    change_item.setForeground(Qt.GlobalColor.white)
                
                self.history_table.setItem(row, 1, change_item)
                
                # Old Value
                old_value_item = QTableWidgetItem(entry.get('old_value', ''))
                old_value_item.setFlags(old_value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.history_table.setItem(row, 2, old_value_item)
                
                # New Value
                new_value_item = QTableWidgetItem(entry.get('new_value', ''))
                new_value_item.setFlags(new_value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.history_table.setItem(row, 3, new_value_item)
            
            if not history:
                # Show message if no history
                self.details_text.setPlainText("No change history found for this asset.")
            else:
                self.details_text.setPlainText(f"Found {len(history)} history entries. Select an entry to view details.")
                
        except Exception as e:
            self.details_text.setPlainText(f"Error loading history: {e}")
    
    def on_selection_changed(self):
        """Handle selection change in history table"""
        current_row = self.history_table.currentRow()
        if current_row >= 0:
            # Get all data for the selected row
            timestamp = self.history_table.item(current_row, 0).text() if self.history_table.item(current_row, 0) else ""
            change_type = self.history_table.item(current_row, 1).text() if self.history_table.item(current_row, 1) else ""
            old_value = self.history_table.item(current_row, 2).text() if self.history_table.item(current_row, 2) else ""
            new_value = self.history_table.item(current_row, 3).text() if self.history_table.item(current_row, 3) else ""
            
            # Format details
            details = f"""Change Details:

Timestamp: {timestamp}
Change Type: {change_type}

Old Value: {old_value if old_value else '(empty)'}

New Value: {new_value if new_value else '(empty)'}

Description: {self.get_change_description(change_type, old_value, new_value)}"""
            
            self.details_text.setPlainText(details)
    
    def get_change_description(self, change_type, old_value, new_value):
        """Get a human-readable description of the change"""
        descriptions = {
            'CREATED': 'Asset was initially discovered and added to the inventory.',
            'DELETED': 'Asset was removed from the inventory.',
            'OS_IDENTIFIED': f'Operating system was identified as {new_value}.',
            'STATUS_CHANGE': f'Asset status changed from {old_value} to {new_value}.',
            'SERVICES_ADDED': f'New services were discovered: {new_value}.',
            'VULNERABILITIES_ADDED': f'New vulnerabilities were found: {new_value}.',
            'FIELD_UPDATE': f'Asset fields were updated: {new_value}.'
        }
        
        return descriptions.get(change_type, 'Asset information was modified.')