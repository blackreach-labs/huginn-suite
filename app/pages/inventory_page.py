from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QSplitter, QLabel, QFrame, 
                             QPushButton, QComboBox, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QMenu, QMessageBox, QGroupBox, QGridLayout, QWidget,
                             QTextEdit, QScrollArea, QDialog)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QFont
from app.widgets.asset_graphics_widget import AssetGraphicsWidget, AssetDetailsWidget
from app.core.asset_manager import asset_manager

class InventoryPage(QWidget):
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.current_assets = []
        self.tenant_id = self.get_current_tenant()
        self.last_tenant = self.tenant_id
        self.setObjectName("InventoryPage")
        self.setup_ui()
        self.setup_timers()
        self.load_assets()
    
    def showEvent(self, event):
        """Called when the page becomes visible - refresh assets"""
        super().showEvent(event)
        self.load_assets()

    def setup_ui(self):
        """Setup the UI components"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        
        self.setup_page(main_layout)

    def get_current_tenant(self):
        """Get current tenant from profile system"""
        try:
            if hasattr(self.main_window, 'current_profile_name') and self.main_window.current_profile_name:
                return self.main_window.current_profile_name
            return 'default'
        except:
            return 'default'

    def setup_page(self, main_layout):
        """Setup page layout and components"""
        # Title and controls header
        header_layout = QHBoxLayout()
        
        title = QLabel("Asset Inventory")
        title.setStyleSheet("""
            font-size: 24pt;
            font-weight: bold;
            color: #64C8FF;
        """)
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Filter controls
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("color: #DCDCDC; font-weight: bold;")
        header_layout.addWidget(filter_label)
        
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "DISCOVERED", "IDENTIFIED", "KNOWN"])
        self.status_filter.currentTextChanged.connect(self.apply_filters)
        self.status_filter.setFixedWidth(120)
        header_layout.addWidget(self.status_filter)
        
        self.os_filter = QComboBox()
        self.os_filter.addItem("All OS")
        self.os_filter.currentTextChanged.connect(self.apply_filters)
        self.os_filter.setFixedWidth(120)
        header_layout.addWidget(self.os_filter)
        
        # Credentials button
        credentials_btn = QPushButton("🔐 Credentials")
        credentials_btn.clicked.connect(self.open_credentials_manager)
        credentials_btn.setFixedWidth(120)
        credentials_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 165, 0, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 165, 0, 200);
            }
        """)
        header_layout.addWidget(credentials_btn)
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_assets)
        refresh_btn.setFixedWidth(100)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """)
        header_layout.addWidget(refresh_btn)
        
        main_layout.addLayout(header_layout)
        
        # Statistics panel
        stats_frame = self.create_statistics_panel()
        main_layout.addWidget(stats_frame)
        
        # Main content area with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side - Asset graphics
        left_frame = QFrame()
        left_frame.setFrameStyle(QFrame.Shape.Box)
        left_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
        """)
        
        left_layout = QVBoxLayout(left_frame)
        left_layout.setContentsMargins(10, 10, 10, 10)
        
        graphics_title = QLabel("Asset Overview")
        graphics_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF; margin-bottom: 10px;")
        left_layout.addWidget(graphics_title)
        
        self.asset_graphics = AssetGraphicsWidget()
        self.asset_graphics.asset_selected.connect(self.on_asset_selected)
        self.asset_graphics.asset_context_menu.connect(self.show_asset_context_menu)
        left_layout.addWidget(self.asset_graphics)
        
        splitter.addWidget(left_frame)
        
        # Right side - Asset details and table
        right_frame = QFrame()
        right_frame.setFrameStyle(QFrame.Shape.Box)
        right_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
        """)
        
        right_layout = QVBoxLayout(right_frame)
        right_layout.setContentsMargins(10, 10, 10, 10)
        
        # Asset details (hidden by default)
        self.asset_details = AssetDetailsWidget()
        self.asset_details.setVisible(False)
        self.asset_details.back_to_list.connect(self.show_asset_list)
        right_layout.addWidget(self.asset_details)
        
        # Asset table section
        self.table_section = QWidget()
        table_section_layout = QVBoxLayout(self.table_section)
        table_section_layout.setContentsMargins(0, 0, 0, 0)
        
        self.table_title = QLabel("Asset List")
        self.table_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF; margin: 10px 0 5px 0;")
        table_section_layout.addWidget(self.table_title)
        
        self.asset_table = self.create_asset_table()
        table_section_layout.addWidget(self.asset_table)
        
        right_layout.addWidget(self.table_section)
        
        splitter.addWidget(right_frame)
        
        # Set splitter proportions
        splitter.setSizes([600, 400])
        main_layout.addWidget(splitter)
        
        # Apply global styling
        self.setStyleSheet("""
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #64C8FF;
            }
        """)

    def create_statistics_panel(self):
        """Create the statistics panel"""
        stats_frame = QFrame()
        stats_frame.setFrameStyle(QFrame.Shape.Box)
        stats_frame.setFixedHeight(100)
        stats_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(20, 30, 40, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
        """)
        
        stats_layout = QGridLayout(stats_frame)
        stats_layout.setContentsMargins(20, 10, 20, 10)
        
        # Statistics labels
        self.total_assets_label = self.create_stat_label("0", "Total Assets")
        self.discovered_label = self.create_stat_label("0", "Discovered")
        self.identified_label = self.create_stat_label("0", "Identified")
        self.known_label = self.create_stat_label("0", "Known")
        self.recent_activity_label = self.create_stat_label("0", "Recent Activity")
        
        stats_layout.addWidget(self.total_assets_label, 0, 0)
        stats_layout.addWidget(self.discovered_label, 0, 1)
        stats_layout.addWidget(self.identified_label, 0, 2)
        stats_layout.addWidget(self.known_label, 0, 3)
        stats_layout.addWidget(self.recent_activity_label, 0, 4)
        
        return stats_frame
    
    def create_stat_label(self, value, description):
        """Create a statistics label widget"""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        
        desc_label = QLabel(description)
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setStyleSheet("font-size: 10pt; color: #87CEEB;")
        desc_label.setWordWrap(True)
        
        layout.addWidget(value_label)
        layout.addWidget(desc_label)
        
        # Store reference to value label for updates
        container.value_label = value_label
        
        return container

    def create_asset_table(self):
        """Create the asset table"""
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "IP Address", "Hostname", "OS Type", "Status", "Ports", "Services", "Shares/Web", "Vulnerabilities"
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
        
        table.setColumnWidth(0, 120)  # IP Address
        table.setColumnWidth(2, 100)  # OS Type
        table.setColumnWidth(3, 100)  # Status
        table.setColumnWidth(4, 60)   # Ports
        table.setColumnWidth(5, 80)   # Services
        table.setColumnWidth(6, 100)  # Shares/Web
        table.setColumnWidth(7, 100)  # Vulnerabilities
        
        # Styling
        table.setStyleSheet("""
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
        
        # Connect selection change
        table.itemSelectionChanged.connect(self.on_table_selection_changed)
        
        # Enable context menu
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self.show_table_context_menu)
        
        return table

    def setup_timers(self):
        """Setup automatic refresh timer"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.load_assets)
        self.refresh_timer.start(30000)  # Refresh every 30 seconds
        
        # Listen for profile changes by checking periodically
        self.profile_check_timer = QTimer()
        self.profile_check_timer.timeout.connect(self.check_profile_change)
        self.profile_check_timer.start(1000)  # Check every 1 second
        self.last_known_tenant = self.tenant_id

    def check_profile_change(self):
        """Check if profile has changed and reload if needed"""
        current_tenant = self.get_current_tenant()
        if current_tenant != self.last_known_tenant:
            print(f"Profile changed from {self.last_known_tenant} to {current_tenant}")
            self.last_known_tenant = current_tenant
            self.tenant_id = current_tenant
            # Force clear and reload
            self.current_assets = []
            self.asset_graphics.update_assets([])
            self.populate_asset_table([])
            self.load_assets()

    def load_assets(self):
        """Load assets from the asset manager"""
        try:
            # Update tenant ID in case session changed
            old_tenant = self.tenant_id
            self.tenant_id = self.get_current_tenant()
            
            # Clear current data if tenant changed
            if old_tenant != self.tenant_id:
                self.current_assets = []
                self.asset_graphics.update_assets([])
                self.populate_asset_table([])
            
            # Get assets from asset manager
            assets = asset_manager.get_assets(self.tenant_id)
            self.current_assets = assets
            
            # Update graphics display
            self.asset_graphics.update_assets(assets)
            
            # Update table
            self.populate_asset_table(assets)
            
            # Update statistics
            self.update_statistics()
            
            # Update OS filter options
            self.update_os_filter()
            
            self.status_updated.emit(f"Loaded {len(assets)} assets for profile {self.tenant_id}")
            
        except Exception as e:
            self.status_updated.emit(f"Error loading assets: {e}")

    def update_statistics(self):
        """Update the statistics display"""
        try:
            stats = asset_manager.get_asset_statistics(self.tenant_id)
            
            # Update total assets
            self.total_assets_label.value_label.setText(str(stats.get('total_assets', 0)))
            
            # Update status breakdown
            status_breakdown = stats.get('status_breakdown', {})
            self.discovered_label.value_label.setText(str(status_breakdown.get('DISCOVERED', 0)))
            self.identified_label.value_label.setText(str(status_breakdown.get('IDENTIFIED', 0)))
            self.known_label.value_label.setText(str(status_breakdown.get('KNOWN', 0)))
            
            # Update recent activity
            self.recent_activity_label.value_label.setText(str(stats.get('recent_activity', 0)))
            
        except Exception as e:
            self.status_updated.emit(f"Error updating statistics: {e}")
    
    def apply_filters(self):
        """Apply current filters to the asset display"""
        status_filter = self.status_filter.currentText()
        os_filter = self.os_filter.currentText()
        
        filtered_assets = []
        
        for asset in self.current_assets:
            # Apply status filter
            if status_filter != "All" and asset.get('status') != status_filter:
                continue
            
            # Apply OS filter
            if os_filter != "All OS" and asset.get('os_type') != os_filter:
                continue
            
            filtered_assets.append(asset)
        
        # Update displays with filtered assets
        self.asset_graphics.update_assets(filtered_assets)
        self.populate_asset_table(filtered_assets)
        
        self.status_updated.emit(f"Showing {len(filtered_assets)} of {len(self.current_assets)} assets")
    
    def show_asset_list(self):
        """Show asset list and hide asset details"""
        self.asset_details.setVisible(False)
        self.table_section.setVisible(True)
        self.asset_table.clearSelection()
        self.status_updated.emit("Returned to asset list")
    
    def on_asset_selected(self, asset_id):
        """Handle asset selection from graphics"""
        # Find the asset by ID
        selected_asset = None
        for asset in self.current_assets:
            if asset['asset_id'] == asset_id:
                selected_asset = asset
                break
        
        if selected_asset:
            # Show asset details, hide asset list
            self.asset_details.update_asset(selected_asset)
            self.asset_details.setVisible(True)
            self.table_section.setVisible(False)
            
            self.status_updated.emit(f"Selected asset: {selected_asset['ip_address']}")
    
    def on_table_selection_changed(self):
        """Handle table selection changes"""
        current_row = self.asset_table.currentRow()
        if current_row >= 0 and current_row < len(self.current_assets):
            # Get the asset for this row (considering filters)
            ip_item = self.asset_table.item(current_row, 0)
            if ip_item:
                ip_address = ip_item.text()
                
                # Find the asset by IP
                selected_asset = None
                for asset in self.current_assets:
                    if asset['ip_address'] == ip_address:
                        selected_asset = asset
                        break
                
                if selected_asset:
                    # Show asset details, hide asset list
                    self.asset_details.update_asset(selected_asset)
                    self.asset_details.setVisible(True)
                    self.table_section.setVisible(False)

    def show_asset_details_dialog(self, asset):
        """Show detailed asset information dialog with notes editing"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Asset Details - {asset['ip_address']}")
        dialog.setModal(True)
        dialog.resize(700, 700)
        
        layout = QVBoxLayout(dialog)
        
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        
        # Format asset details
        details = f"""
Asset Information:
IP Address: {asset['ip_address']}
Hostname: {asset.get('hostname', 'N/A')}
OS Type: {asset.get('os_type', 'Unknown')}
OS Version: {asset.get('os_version', 'N/A')}
Status: {asset.get('status', 'DISCOVERED')}
Confidence: {asset.get('confidence', 0)}%
First Seen: {asset.get('first_seen', 'N/A')}
Last Seen: {asset.get('last_seen', 'N/A')}

Open Ports ({len(asset.get('open_ports', []))}):
"""
        
        for port in asset.get('open_ports', []):
            details += f"  - {port.get('port')}/{port.get('protocol', 'tcp')}\n"
        
        details += f"\nServices ({len(asset.get('services', []))}):\n"
        for service in asset.get('services', []):
            details += f"  - {service.get('port')}: {service.get('service')}"
            if service.get('version'):
                details += f" ({service['version']})"
            details += "\n"
        
        details += f"\nVulnerabilities ({len(asset.get('vulnerabilities', []))}):\n"
        for vuln in asset.get('vulnerabilities', []):
            details += f"  - {vuln.get('name', vuln.get('id', 'Unknown'))} ({vuln.get('severity', 'Unknown')})\n"
        
        # SMB Share Information
        metadata = asset.get('metadata', {})
        
        if metadata.get('shares_found'):
            details += f"\nSMB Shares ({metadata['shares_found']}):\n"
            share_list = metadata.get('share_list', [])
            for share in share_list:
                details += f"  - \\\\{asset['ip_address']}\\{share}\n"
        
        # HTTP Web Application Data
        if metadata.get('server_type') == 'web_server':
            details += f"\nWeb Application Information:\n"
            
            if metadata.get('server_header'):
                details += f"  - Server: {metadata['server_header']}\n"
            
            if metadata.get('directories_found'):
                details += f"  - Directories Found: {metadata['directories_found']}\n"
                directory_list = metadata.get('directory_list', [])
                for directory in directory_list[:10]:
                    details += f"    • /{directory}\n"
                if len(directory_list) > 10:
                    details += f"    • ... and {len(directory_list) - 10} more\n"
            
            if metadata.get('files_found'):
                details += f"  - Accessible Files: {metadata['files_found']}\n"
                file_list = metadata.get('file_list', [])
                for file in file_list[:10]:
                    details += f"    • {file}\n"
                if len(file_list) > 10:
                    details += f"    • ... and {len(file_list) - 10} more\n"
        
        # Discovery Methods
        discovery_methods = metadata.get('discovery_methods', [])
        if discovery_methods:
            details += f"\nDiscovery Methods:\n"
            for method in discovery_methods:
                details += f"  - {method.replace('_', ' ').title()}\n"
        elif metadata.get('discovery_method'):
            details += f"\nDiscovery Method: {metadata['discovery_method'].replace('_', ' ').title()}\n"
        
        # Notes section
        notes = asset.get('notes', '')
        details += f"\nNotes:\n{notes if notes else 'No notes available.'}"
        
        details_text.setPlainText(details)
        layout.addWidget(details_text)
        
        # Add notes editing section
        notes_section = QGroupBox("Edit Notes")
        notes_layout = QVBoxLayout(notes_section)
        
        notes_edit = QTextEdit()
        notes_edit.setPlainText(notes)
        notes_edit.setMaximumHeight(100)
        notes_layout.addWidget(notes_edit)
        
        notes_buttons = QHBoxLayout()
        save_notes_btn = QPushButton("💾 Save Notes")
        save_notes_btn.clicked.connect(lambda: self.save_asset_notes(asset, notes_edit.toPlainText(), dialog))
        save_notes_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """)
        notes_buttons.addWidget(save_notes_btn)
        notes_buttons.addStretch()
        notes_layout.addLayout(notes_buttons)
        
        layout.addWidget(notes_section)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
        
        dialog.exec()
    
    def save_asset_notes(self, asset, notes_text, dialog):
        """Save notes for the asset"""
        try:
            success = asset_manager.update_asset_notes(self.tenant_id, asset['ip_address'], notes_text)
            if success:
                self.status_updated.emit(f"Notes saved for {asset['ip_address']}")
                # Refresh the asset data
                self.load_assets()
                dialog.accept()
            else:
                self.status_updated.emit(f"Failed to save notes for {asset['ip_address']}")
        except Exception as e:
            self.status_updated.emit(f"Error saving notes: {e}")

    def populate_asset_table(self, assets):
        """Populate the asset table with data"""
        self.asset_table.setRowCount(len(assets))
        
        for row, asset in enumerate(assets):
            # IP Address
            ip_item = QTableWidgetItem(asset['ip_address'])
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.asset_table.setItem(row, 0, ip_item)
            
            # Hostname - show both IP and hostname if different
            hostname = asset.get('hostname', '')
            ip = asset['ip_address']
            if hostname and hostname != ip:
                display_text = f"{ip} ({hostname})"
            else:
                display_text = hostname
            hostname_item = QTableWidgetItem(display_text)
            hostname_item.setFlags(hostname_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.asset_table.setItem(row, 1, hostname_item)
            
            # OS Type / Server Type
            os_type = asset.get('os_type', 'Unknown')
            metadata = asset.get('metadata', {})
            server_type = metadata.get('server_type', '')
            
            # Display server type if available, otherwise OS type
            display_text = server_type if server_type else os_type
            
            os_item = QTableWidgetItem(display_text)
            os_item.setFlags(os_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            
            # Color code based on server type
            if 'Domain Controller' in display_text:
                os_item.setBackground(Qt.GlobalColor.darkBlue)
                os_item.setForeground(Qt.GlobalColor.yellow)
            elif 'Windows Server' in display_text:
                os_item.setBackground(Qt.GlobalColor.blue)
                os_item.setForeground(Qt.GlobalColor.white)
            
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
            
            # Ports count
            ports_count = len(asset.get('open_ports', []))
            ports_item = QTableWidgetItem(str(ports_count))
            ports_item.setFlags(ports_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.asset_table.setItem(row, 4, ports_item)
            
            # Services count
            services_count = len(asset.get('services', []))
            services_item = QTableWidgetItem(str(services_count))
            services_item.setFlags(services_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.asset_table.setItem(row, 5, services_item)
            
            # SMB Shares / Web Data
            metadata = asset.get('metadata', {})
            shares_web_text = ""
            
            if metadata.get('shares_found'):
                shares_web_text = f"{metadata['shares_found']} shares"
            elif metadata.get('server_type') == 'web_server':
                web_info = []
                if metadata.get('directories_found'):
                    web_info.append(f"{metadata['directories_found']} dirs")
                if metadata.get('files_found'):
                    web_info.append(f"{metadata['files_found']} files")
                if metadata.get('vulnerabilities_found'):
                    web_info.append(f"{metadata['vulnerabilities_found']} vulns")
                shares_web_text = ", ".join(web_info) if web_info else "Web server"
            
            shares_web_item = QTableWidgetItem(shares_web_text)
            shares_web_item.setFlags(shares_web_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.asset_table.setItem(row, 6, shares_web_item)
            
            # Vulnerabilities count
            vulns_count = len(asset.get('vulnerabilities', []))
            vulns_item = QTableWidgetItem(str(vulns_count))
            vulns_item.setFlags(vulns_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            
            # Color code vulnerabilities
            if vulns_count > 0:
                vulns_item.setBackground(Qt.GlobalColor.red)
                vulns_item.setForeground(Qt.GlobalColor.white)
            
            self.asset_table.setItem(row, 7, vulns_item)
    
    def update_os_filter(self):
        """Update OS filter options based on current assets"""
        current_os_types = set()
        for asset in self.current_assets:
            os_type = asset.get('os_type', 'Unknown')
            if os_type != 'Unknown':
                current_os_types.add(os_type)
        
        # Clear and repopulate OS filter
        current_selection = self.os_filter.currentText()
        self.os_filter.clear()
        self.os_filter.addItem("All OS")
        
        for os_type in sorted(current_os_types):
            self.os_filter.addItem(os_type)
        
        # Restore selection if still valid
        index = self.os_filter.findText(current_selection)
        if index >= 0:
            self.os_filter.setCurrentIndex(index)
    
    def show_table_context_menu(self, position):
        """Show context menu for table"""
        item = self.asset_table.itemAt(position)
        if not item:
            return
        
        row = item.row()
        ip_item = self.asset_table.item(row, 0)
        if not ip_item:
            return
        
        ip_address = ip_item.text()
        
        # Find the asset
        selected_asset = None
        for asset in self.current_assets:
            if asset['ip_address'] == ip_address:
                selected_asset = asset
                break
        
        if selected_asset:
            # Convert table position to global position
            global_pos = self.asset_table.mapToGlobal(position)
            self.show_asset_context_menu(selected_asset['asset_id'], global_pos)
    
    def show_asset_context_menu(self, asset_id, position):
        """Show context menu for asset"""
        # Find the asset
        selected_asset = None
        for asset in self.current_assets:
            if asset['asset_id'] == asset_id:
                selected_asset = asset
                break
        
        if not selected_asset:
            return
        
        menu = QMenu(self)
        
        # Scan actions
        scan_menu = menu.addMenu("🔍 Scan")
        
        port_scan_action = QAction("Port Scan", self)
        port_scan_action.triggered.connect(lambda: self.initiate_port_scan(selected_asset))
        scan_menu.addAction(port_scan_action)
        
        service_scan_action = QAction("Service Detection", self)
        service_scan_action.triggered.connect(lambda: self.initiate_service_scan(selected_asset))
        scan_menu.addAction(service_scan_action)
        
        vuln_scan_action = QAction("Vulnerability Scan", self)
        vuln_scan_action.triggered.connect(lambda: self.initiate_vuln_scan(selected_asset))
        scan_menu.addAction(vuln_scan_action)
        
        menu.addSeparator()
        
        # Information actions
        details_action = QAction("📋 View Details", self)
        details_action.triggered.connect(lambda: self.show_asset_details_dialog(selected_asset))
        menu.addAction(details_action)
        
        menu.addSeparator()
        
        # Management actions
        delete_action = QAction("🗑️ Remove Asset", self)
        delete_action.triggered.connect(lambda: self.remove_asset(selected_asset))
        menu.addAction(delete_action)
        
        menu.exec(position)
    
    def initiate_port_scan(self, asset):
        """Initiate port scan for asset"""
        self.status_updated.emit(f"Initiating port scan for {asset['ip_address']}")
        self.navigate_signal.emit("recon_enumeration")
        QTimer.singleShot(500, lambda: self.set_port_scan_target(asset['ip_address']))
    
    def initiate_service_scan(self, asset):
        """Initiate service detection for asset"""
        self.status_updated.emit(f"Initiating service scan for {asset['ip_address']}")
        self.navigate_signal.emit("recon_enumeration")
    
    def initiate_vuln_scan(self, asset):
        """Initiate vulnerability scan for asset"""
        self.status_updated.emit(f"Initiating vulnerability scan for {asset['ip_address']}")
        self.navigate_signal.emit("vuln_scanning")
    
    def set_port_scan_target(self, ip_address):
        """Set target in port scanning tab"""
        try:
            if hasattr(self.main_window, 'recon_enumeration_page'):
                recon_page = self.main_window.recon_enumeration_page
                if hasattr(recon_page, 'port_target_input'):
                    recon_page.port_target_input.setText(ip_address)
        except Exception as e:
            print(f"Error setting port scan target: {e}")
    
    def remove_asset(self, asset):
        """Remove asset from inventory"""
        reply = QMessageBox.question(
            self, 
            "Remove Asset", 
            f"Are you sure you want to remove asset {asset['ip_address']} from the inventory?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                success = asset_manager.remove_asset(self.tenant_id, asset['ip_address'])
                if success:
                    self.load_assets()  # Refresh the display
                    self.status_updated.emit(f"Asset {asset['ip_address']} removed from inventory")
                else:
                    self.status_updated.emit(f"Failed to remove asset {asset['ip_address']}")
            except Exception as e:
                self.status_updated.emit(f"Error removing asset: {e}")
    
    def open_credentials_manager(self):
        """Open the credentials management dialog"""
        from app.widgets.secure_credential_widget import SecureCredentialWidget
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Credential Management")
        dialog.setModal(True)
        dialog.resize(1000, 700)
        
        # Apply dark theme styling to dialog
        dialog.setStyleSheet("""
            QDialog {
                background-color: #1a1a1a;
                color: #DCDCDC;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(10, 10, 10, 10)
        
        credentials_widget = SecureCredentialWidget()
        layout.addWidget(credentials_widget)
        
        self.status_updated.emit("Credentials Management opened")
        dialog.exec()