from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView)
from PyQt6.QtCore import pyqtSignal, Qt

class AssetTableComponent(QWidget):
    asset_selected = pyqtSignal(str)
    filters_changed = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_assets = []
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup table UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header with filters
        header_layout = QHBoxLayout()
        
        title = QLabel("Asset List")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Filters
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("color: #DCDCDC; font-weight: bold;")
        header_layout.addWidget(filter_label)
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "DISCOVERED", "IDENTIFIED", "KNOWN"])
        self.status_filter.currentTextChanged.connect(self.on_filters_changed)
        header_layout.addWidget(self.status_filter)
        
        self.os_filter = QComboBox()
        self.os_filter.addItem("All OS")
        self.os_filter.currentTextChanged.connect(self.on_filters_changed)
        header_layout.addWidget(self.os_filter)
        
        layout.addLayout(header_layout)
        
        # Asset table
        self.asset_table = self.create_table()
        layout.addWidget(self.asset_table)

    def create_table(self):
        """Create asset table"""
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "IP Address", "Hostname", "OS Type", "Status", 
            "Ports", "Services", "Shares/Web", "Vulnerabilities"
        ])
        
        # Set column widths
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)
        
        table.setColumnWidth(0, 120)
        table.setColumnWidth(2, 100)
        table.setColumnWidth(3, 100)
        table.setColumnWidth(4, 60)
        table.setColumnWidth(5, 80)
        table.setColumnWidth(6, 100)
        table.setColumnWidth(7, 100)
        
        # Connect selection
        table.itemSelectionChanged.connect(self.on_selection_changed)
        
        # Context menu
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self.show_context_menu)
        
        return table

    def update_assets(self, assets):
        """Update assets and refresh filters"""
        self.current_assets = assets
        self.update_os_filter()
        self.populate_table(assets)

    def populate_table(self, assets):
        """Populate table with assets"""
        self.asset_table.setRowCount(len(assets))
        
        for row, asset in enumerate(assets):
            # IP Address
            ip_item = QTableWidgetItem(asset['ip_address'])
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.asset_table.setItem(row, 0, ip_item)
            
            # Hostname
            hostname = asset.get('hostname', '')
            hostname_item = QTableWidgetItem(hostname)
            hostname_item.setFlags(hostname_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.asset_table.setItem(row, 1, hostname_item)
            
            # OS Type
            os_item = QTableWidgetItem(asset.get('os_type', 'Unknown'))
            os_item.setFlags(os_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.asset_table.setItem(row, 2, os_item)
            
            # Status
            status_item = QTableWidgetItem(asset.get('status', 'DISCOVERED'))
            status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            
            # Color code status
            status = asset.get('status', 'DISCOVERED')
            if status == 'DISCOVERED':
                status_item.setBackground(Qt.GlobalColor.yellow)
                status_item.setForeground(Qt.GlobalColor.black)
            elif status == 'IDENTIFIED':
                status_item.setBackground(Qt.GlobalColor.darkYellow)
                status_item.setForeground(Qt.GlobalColor.white)
            elif status == 'KNOWN':
                status_item.setBackground(Qt.GlobalColor.green)
                status_item.setForeground(Qt.GlobalColor.white)
            
            self.asset_table.setItem(row, 3, status_item)
            
            # Ports, Services, Shares/Web, Vulnerabilities
            ports_item = QTableWidgetItem(str(len(asset.get('open_ports', []))))
            services_item = QTableWidgetItem(str(len(asset.get('services', []))))
            shares_item = QTableWidgetItem("")  # Placeholder
            vulns_item = QTableWidgetItem(str(len(asset.get('vulnerabilities', []))))
            
            if len(asset.get('vulnerabilities', [])) > 0:
                vulns_item.setBackground(Qt.GlobalColor.red)
                vulns_item.setForeground(Qt.GlobalColor.white)
            
            self.asset_table.setItem(row, 4, ports_item)
            self.asset_table.setItem(row, 5, services_item)
            self.asset_table.setItem(row, 6, shares_item)
            self.asset_table.setItem(row, 7, vulns_item)

    def update_os_filter(self):
        """Update OS filter options"""
        os_types = set()
        for asset in self.current_assets:
            os_type = asset.get('os_type', 'Unknown')
            if os_type != 'Unknown':
                os_types.add(os_type)
        
        current_selection = self.os_filter.currentText()
        self.os_filter.clear()
        self.os_filter.addItem("All OS")
        
        for os_type in sorted(os_types):
            self.os_filter.addItem(os_type)
        
        index = self.os_filter.findText(current_selection)
        if index >= 0:
            self.os_filter.setCurrentIndex(index)

    def on_filters_changed(self):
        """Handle filter changes"""
        status_filter = self.status_filter.currentText()
        os_filter = self.os_filter.currentText()
        self.filters_changed.emit(status_filter, os_filter)

    def on_selection_changed(self):
        """Handle table selection"""
        current_row = self.asset_table.currentRow()
        if current_row >= 0:
            ip_item = self.asset_table.item(current_row, 0)
            if ip_item:
                ip_address = ip_item.text()
                # Find asset by IP
                for asset in self.current_assets:
                    if asset['ip_address'] == ip_address:
                        self.asset_selected.emit(asset['asset_id'])
                        break

    def show_context_menu(self, position):
        """Show table context menu"""
        item = self.asset_table.itemAt(position)
        if item:
            row = item.row()
            ip_item = self.asset_table.item(row, 0)
            if ip_item:
                ip_address = ip_item.text()
                for asset in self.current_assets:
                    if asset['ip_address'] == ip_address:
                        global_pos = self.asset_table.mapToGlobal(position)
                        from app.components.asset_context_menu import AssetContextMenu
                        menu = AssetContextMenu(asset, self)
                        menu.exec(global_pos)
                        break

    def clear_selection(self):
        """Clear table selection"""
        self.asset_table.clearSelection()

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                padding: 5px;
                min-width: 160px;
            }
            QTableWidget {
                background-color: rgba(0, 0, 0, 100);
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
        """)