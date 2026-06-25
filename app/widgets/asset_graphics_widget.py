# app/widgets/asset_graphics_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,QTableWidget, QTableWidgetItem,
                             QFrame, QScrollArea, QGridLayout, QPushButton, QMenu, QTabWidget)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve, QRect
from PyQt6.QtGui import QPainter, QColor, QFont, QPixmap, QPen, QBrush, QAction
import json

class AssetGraphicsWidget(QWidget):
    """Graphics widget for displaying assets visually"""
    
    asset_selected = pyqtSignal(str)  # asset_id
    asset_context_menu = pyqtSignal(str, object)  # asset_id, QPoint
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.assets = []
        self.selected_asset = None
        self.setup_ui()
        
        # Animation timer for status indicators
        self.animation_timer = QTimer()
        self.animation_timer.timeout.connect(self.update_animations)
        self.animation_timer.start(100)  # 10 FPS
        self.animation_frame = 0
    
    def setup_ui(self):
        """Setup the UI components"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Scroll area for assets
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Container widget for assets
        self.assets_container = QWidget()
        self.assets_layout = QGridLayout(self.assets_container)
        self.assets_layout.setSpacing(20)
        
        scroll_area.setWidget(self.assets_container)
        layout.addWidget(scroll_area)
        
        # Apply styling
        self.setStyleSheet("""
            QScrollArea {
                background-color: rgba(0, 0, 0, 50);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
            QWidget {
                background-color: transparent;
            }
        """)
    
    def update_assets(self, assets_data):
        """Update the displayed assets"""
        self.assets = assets_data
        self.refresh_display()
    
    def refresh_display(self):
        """Refresh the asset display"""
        # Clear existing widgets
        for i in reversed(range(self.assets_layout.count())):
            child = self.assets_layout.itemAt(i).widget()
            if child:
                child.setParent(None)
        
        # Add asset widgets
        row, col = 0, 0
        max_cols = 6  # Assets per row
        
        for asset in self.assets:
            asset_widget = AssetWidget(asset)
            asset_widget.clicked.connect(lambda aid=asset['asset_id']: self.asset_selected.emit(aid))
            asset_widget.context_menu_requested.connect(
                lambda aid, pos: self.asset_context_menu.emit(aid, pos)
            )
            
            self.assets_layout.addWidget(asset_widget, row, col)
            
            col += 1
            if col >= max_cols:
                col = 0
                row += 1
        
        # Add stretch to push assets to top-left
        self.assets_layout.setRowStretch(row + 1, 1)
        self.assets_layout.setColumnStretch(max_cols, 1)
    
    def update_animations(self):
        """Update animation frame"""
        self.animation_frame = (self.animation_frame + 1) % 100
        
        # Update all asset widgets
        for i in range(self.assets_layout.count()):
            widget = self.assets_layout.itemAt(i).widget()
            if isinstance(widget, AssetWidget):
                widget.animation_frame = self.animation_frame
                widget.update()

class AssetWidget(QFrame):
    """Individual asset display widget"""
    
    clicked = pyqtSignal()
    context_menu_requested = pyqtSignal(str, object)  # asset_id, QPoint
    
    def __init__(self, asset_data, parent=None):
        super().__init__(parent)
        self.asset_data = asset_data
        self.animation_frame = 0
        self.setup_ui()
        self.setup_styling()
    
    def setup_ui(self):
        """Setup the asset widget UI"""
        self.setFixedSize(180, 200)
        self.setFrameStyle(QFrame.Shape.Box)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)
        
        # Asset icon/type indicator
        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setFixedHeight(60)
        layout.addWidget(self.icon_label)
        
        # IP Address
        ip_label = QLabel(self.asset_data['ip_address'])
        ip_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ip_label.setStyleSheet("font-weight: bold; font-size: 12pt; color: #64C8FF;")
        layout.addWidget(ip_label)
        
        # Hostname (if available)
        if self.asset_data.get('hostname'):
            hostname_label = QLabel(self.asset_data['hostname'])
            hostname_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hostname_label.setStyleSheet("font-size: 10pt; color: #DCDCDC;")
            hostname_label.setWordWrap(True)
            layout.addWidget(hostname_label)
        
        # OS Type and Server Type
        os_type = self.asset_data.get('os_type', 'Unknown')
        metadata = self.asset_data.get('metadata', {})
        server_type = metadata.get('server_type', '')
        
        # Display server type if available, otherwise OS type
        if server_type:
            display_text = server_type
            if 'Domain Controller' in server_type:
                text_color = "#FFD700"  # Gold for DC
            elif 'Windows Server' in server_type:
                text_color = "#0078D4"  # Blue for Windows Server
            else:
                text_color = "#87CEEB"
        else:
            display_text = os_type
            text_color = "#87CEEB"
        
        os_label = QLabel(display_text)
        os_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        os_label.setStyleSheet(f"font-size: 10pt; color: {text_color}; font-weight: bold;")
        os_label.setWordWrap(True)
        layout.addWidget(os_label)
        
        # Status indicator
        self.status_label = QLabel(self.asset_data.get('status', 'DISCOVERED'))
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("font-size: 9pt; font-weight: bold;")
        layout.addWidget(self.status_label)
        
        # Services count
        services_count = len(self.asset_data.get('services', []))
        if services_count > 0:
            services_label = QLabel(f"{services_count} services")
            services_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            services_label.setStyleSheet("font-size: 8pt; color: #90EE90;")
            layout.addWidget(services_label)
        
        # Vulnerabilities count
        vulns_count = len(self.asset_data.get('vulnerabilities', []))
        if vulns_count > 0:
            vulns_label = QLabel(f"{vulns_count} vulnerabilities")
            vulns_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            vulns_label.setStyleSheet("font-size: 8pt; color: #FF6B6B;")
            layout.addWidget(vulns_label)
        
        layout.addStretch()
    
    def setup_styling(self):
        """Setup widget styling based on asset status"""
        status = self.asset_data.get('status', 'DISCOVERED')
        os_type = self.asset_data.get('os_type', 'Unknown')
        
        # Base styling
        base_style = """
            AssetWidget {
                background-color: rgba(20, 30, 40, 200);
                border-radius: 10px;
                margin: 2px;
            }
            AssetWidget:hover {
                background-color: rgba(40, 60, 80, 220);
            }
        """
        
        # Status-based border colors
        if status == 'DISCOVERED':
            border_color = "#FFD700"  # Gold
            self.status_label.setStyleSheet("font-size: 9pt; font-weight: bold; color: #FFD700;")
        elif status == 'IDENTIFIED':
            border_color = "#FFA500"  # Orange
            self.status_label.setStyleSheet("font-size: 9pt; font-weight: bold; color: #FFA500;")
        elif status == 'KNOWN':
            border_color = "#00FF41"  # Green
            self.status_label.setStyleSheet("font-size: 9pt; font-weight: bold; color: #00FF41;")
        else:
            border_color = "#64C8FF"  # Blue
        
        # Add border styling
        style = base_style + f"""
            AssetWidget {{
                border: 2px solid {border_color};
            }}
        """
        
        self.setStyleSheet(style)
        
        # Set icon based on OS type
        self.update_icon()
    
    def update_icon(self):
        """Update the asset icon based on OS type and server type"""
        os_type = self.asset_data.get('os_type', 'Unknown').lower()
        metadata = self.asset_data.get('metadata', {})
        server_type = metadata.get('server_type', '').lower()
        os_icon = metadata.get('os_icon', '')
        
        # Determine icon and color based on server type and OS
        icon_text = "?"
        icon_color = "#64C8FF"
        
        # Prioritize server type for icon selection
        if 'domain controller' in server_type:
            icon_text = "🏛️"  # Domain Controller
            icon_color = "#0078D4"
        elif 'windows server' in server_type:
            icon_text = "🖥️"  # Windows Server
            icon_color = "#0078D4"
        elif 'windows' in server_type or 'windows' in os_type:
            icon_text = "💻"  # Windows Workstation
            icon_color = "#0078D4"
        elif 'linux server' in server_type or ('linux' in os_type and 'server' in server_type):
            icon_text = "🐧"  # Linux Server
            icon_color = "#FCC624"
        elif 'linux' in os_type:
            icon_text = "🐧"  # Linux
            icon_color = "#FCC624"
        elif 'mac' in os_type or 'darwin' in os_type:
            icon_text = "🍎"
            icon_color = "#A2AAAD"
        elif 'router' in os_type or 'cisco' in os_type:
            icon_text = "🌐"
            icon_color = "#1BA0D7"
        elif 'printer' in os_type:
            icon_text = "🖨️"
            icon_color = "#4CAF50"
        elif os_type == 'unknown':
            icon_text = "❓"
            icon_color = "#FFD700"
        
        # Create pixmap with icon
        pixmap = QPixmap(60, 60)
        pixmap.fill(Qt.GlobalColor.transparent)
        
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw background circle
        painter.setBrush(QBrush(QColor(icon_color)))
        painter.setPen(QPen(QColor(icon_color), 2))
        painter.drawEllipse(5, 5, 50, 50)
        
        # Draw icon text
        painter.setPen(QPen(QColor("white")))
        font = QFont()
        font.setPointSize(20)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, icon_text)
        
        # Add server type indicator for Domain Controllers
        if 'domain controller' in server_type:
            painter.setPen(QPen(QColor("#FFD700"), 2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(2, 2, 56, 56)  # Golden ring for DC
        
        painter.end()
        
        self.icon_label.setPixmap(pixmap)
    
    def paintEvent(self, event):
        """Custom paint event for animations"""
        super().paintEvent(event)
        
        # Add pulsing effect for DISCOVERED status
        if self.asset_data.get('status') == 'DISCOVERED':
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            # Calculate pulse alpha
            pulse_alpha = int(50 + 30 * abs(50 - self.animation_frame) / 50)
            
            # Draw pulsing border
            pen = QPen(QColor(255, 215, 0, pulse_alpha))
            pen.setWidth(3)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 10, 10)
    
    def mousePressEvent(self, event):
        """Handle mouse press events"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        elif event.button() == Qt.MouseButton.RightButton:
            self.context_menu_requested.emit(self.asset_data['asset_id'], event.globalPosition().toPoint())
    
    def enterEvent(self, event):
        """Handle mouse enter event"""
        self.setStyleSheet(self.styleSheet() + """
            AssetWidget {
                background-color: rgba(60, 90, 120, 240);
            }
        """)
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        """Handle mouse leave event"""
        self.setup_styling()  # Reset to original styling
        super().leaveEvent(event)

class AssetDetailsWidget(QFrame):
    """Detailed view of a selected asset"""
    
    back_to_list = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_asset = None
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the details widget UI"""
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            AssetDetailsWidget {
                background-color: rgba(20, 30, 40, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
            QTabWidget::pane {
                border: 1px solid rgba(100, 200, 255, 100);
                background-color: rgba(0, 0, 0, 50);
            }
            QTabBar::tab {
                background-color: rgba(40, 60, 80, 150);
                color: #DCDCDC;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: rgba(80, 120, 160, 150);
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header with back button and title
        header_layout = QHBoxLayout()
        
        self.back_button = QPushButton("← Back to List")
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                border: none;
                border-radius: 5px;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """)
        self.back_button.setFixedWidth(120)
        header_layout.addWidget(self.back_button)
        
        self.title_label = QLabel("Asset Details")
        self.title_label.setStyleSheet("font-size: 12pt; font-weight: bold; color: #64C8FF; margin-bottom: 0px;")
        header_layout.addWidget(self.title_label)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # Tab widget for organized display
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.overview_tab = QScrollArea()
        self.overview_widget = QWidget()
        self.overview_layout = QVBoxLayout(self.overview_widget)
        self.overview_tab.setWidget(self.overview_widget)
        self.overview_tab.setWidgetResizable(True)
        
        self.services_tab = QScrollArea()
        self.services_widget = QWidget()
        self.services_layout = QVBoxLayout(self.services_widget)
        self.services_tab.setWidget(self.services_widget)
        self.services_tab.setWidgetResizable(True)
        
        self.security_tab = QScrollArea()
        self.security_widget = QWidget()
        self.security_layout = QVBoxLayout(self.security_widget)
        self.security_tab.setWidget(self.security_widget)
        self.security_tab.setWidgetResizable(True)
        
        self.tab_widget.addTab(self.overview_tab, "📋 Overview")
        self.tab_widget.addTab(self.services_tab, "🔧 Services")
        self.tab_widget.addTab(self.security_tab, "🛡️ Security")
        
        # Connect back button
        self.back_button.clicked.connect(self.back_to_list.emit)
    
    def update_asset(self, asset_data):
        """Update the displayed asset details"""
        try:
            self.current_asset = asset_data
            
            # Clear existing details from all tabs
            self.clear_tab_contents()
            
            if not asset_data:
                no_selection = QLabel("No asset selected")
                no_selection.setAlignment(Qt.AlignmentFlag.AlignCenter)
                no_selection.setStyleSheet(
                    "color: #87CEEB; font-style: italic; padding: 20px;"
                )
                self.overview_layout.addWidget(no_selection)
                return
            
            # Update title with asset IP
            self.title_label.setText(f"Asset Details - {asset_data['ip_address']}")
            
            # Populate tabs with error handling
            self.populate_overview_tab(asset_data)
            self.populate_services_tab(asset_data)
            self.populate_security_tab(asset_data)
            
        except Exception as e:
            print(f"Error updating asset details: {e}")
            error_label = QLabel(f"Error loading asset details: {str(e)}")
            error_label.setStyleSheet("color: #FF6B6B; font-style: italic;")
            self.overview_layout.addWidget(error_label)
    
    def clear_tab_contents(self):
        """Clear all tab contents"""
        for layout in [self.overview_layout, self.services_layout, self.security_layout]:
            for i in reversed(range(layout.count())):
                item = layout.itemAt(i)
                if item:
                    widget = item.widget()
                    if widget:
                        widget.deleteLater()
                    layout.removeItem(item)
    
    def populate_overview_tab(self, asset_data):
        """Populate the overview tab"""
        # Basic information card

        summary_card = self.create_info_card("Asset Summary")
        ports = len(asset_data.get('open_ports', []))
        services = len(asset_data.get('services', []))
        vulns = len(asset_data.get('vulnerabilities', []))
        summary_text = QLabel(
            f"""
        <b>{asset_data['ip_address']}</b><br>
        {asset_data.get('os_type', 'Unknown')}<br>
        Status: {asset_data.get('status', 'DISCOVERED')} |
        Ports: {ports} |
        Services: {services} |
        Vulnerabilities: {vulns}
        """
        )
        summary_text.setStyleSheet("""
            color: #DCDCDC;
            border: none;
            background: transparent;
        """)
        summary_card.layout().addWidget(summary_text)
        self.overview_layout.addWidget(summary_card)


        basic_card = self.create_info_card("Basic Information")
        self.add_card_row(basic_card, "IP Address", asset_data['ip_address'])
        
        if asset_data.get('hostname'):
            self.add_card_row(basic_card, "Hostname", asset_data['hostname'])
        
        self.add_card_row(basic_card, "OS Type", asset_data.get('os_type', 'Unknown'))
        
        if asset_data.get('os_version'):
            self.add_card_row(basic_card, "OS Version", asset_data['os_version'])
        
        status = asset_data.get('status', 'DISCOVERED')
        status_color = {'DISCOVERED': '#FFD700', 'IDENTIFIED': '#FFA500', 'KNOWN': '#00FF41'}.get(status, '#64C8FF')
        self.add_card_row(basic_card, "Status", status, status_color)
        self.add_card_row(basic_card, "Confidence", f"{asset_data.get('confidence', 0)}%")
        
        self.overview_layout.addWidget(basic_card)
        
        # Discovery information card removed from main view
        
        self.overview_layout.addStretch()
    
    def populate_services_tab(self, asset_data):
        """Populate the services tab"""
        # Open ports card
        open_ports = asset_data.get('open_ports', [])
        if open_ports:
            ports_card = self.create_info_card(f"Open Ports ({len(open_ports)})")
            for port in open_ports[:15]:
                port_text = f"{port.get('port')}/{port.get('protocol', 'tcp')}"
                self.add_card_item(ports_card, port_text)
            if len(open_ports) > 15:
                self.add_card_item(ports_card, f"... and {len(open_ports) - 15} more", "#87CEEB")
            self.services_layout.addWidget(ports_card)
        
        # Services card with detailed information (limit to prevent memory issues)
        services = asset_data.get('services', [])
        if services:
            table = QTableWidget()
            table.setColumnCount(3)
            table.setHorizontalHeaderLabels([
                "Port",
                "Service",
                "Version"
            ])
            table.setRowCount(len(services))
            table.horizontalHeader().setStretchLastSection(True)
            for row, service in enumerate(services):
                table.setItem(
                    row,
                    0,
                    QTableWidgetItem(str(service.get('port', '')))
                )
                table.setItem(
                    row,
                    1,
                    QTableWidgetItem(service.get('service', ''))
                )
                table.setItem(
                    row,
                    2,
                    QTableWidgetItem(service.get('version', ''))
                )
            table.setStyleSheet("""
                QTableWidget {
                    background: rgba(26,34,46,220);
                    color: #DCDCDC;
                    border: none;
                }
                QHeaderView::section {
                    background-color: rgba(20,30,50,200);
                    color: #64C8FF;
                    font-weight: bold;
                }
            """)
            self.services_layout.addWidget(table)
        
        # SSH detailed information card (simplified to reduce memory usage)
        ssh_services = [s for s in services if s.get('service') == 'ssh']
        if ssh_services:
            ssh_service = ssh_services[0]  # Take first SSH service
            ssh_card = self.create_info_card("SSH Service Details")
            
            if ssh_service.get('banner'):
                self.add_card_row(ssh_card, "Banner", ssh_service['banner'][:100])
            if ssh_service.get('ssh_version'):
                self.add_card_row(ssh_card, "Version", ssh_service['ssh_version'])
            if ssh_service.get('os_detection'):
                self.add_card_row(ssh_card, "OS", ssh_service['os_detection'])
            
            # Simplified algorithm display to prevent memory issues
            if ssh_service.get('kex_algorithms'):
                self.add_card_row(ssh_card, "KEX Algorithms", f"{len(ssh_service['kex_algorithms'])} found")
            
            if ssh_service.get('host_key_algorithms'):
                self.add_card_row(ssh_card, "Host Keys", f"{len(ssh_service['host_key_algorithms'])} found")
            
            if ssh_service.get('encryption_ciphers'):
                self.add_card_row(ssh_card, "Encryption", f"{len(ssh_service['encryption_ciphers'])} ciphers")
            
            if ssh_service.get('mac_ciphers'):
                self.add_card_row(ssh_card, "MAC", f"{len(ssh_service['mac_ciphers'])} algorithms")
            
            # Authentication Results
            if ssh_service.get('auth_results'):
                successful = [auth for auth in ssh_service['auth_results'] if auth.get('success')]
                if successful:
                    self.add_card_row(ssh_card, "Authentication", f"{len(successful)} successful")
            
            self.services_layout.addWidget(ssh_card)
        
        # SMB shares card
        metadata = asset_data.get('metadata', {})
        if metadata.get('shares_found'):
            shares_card = self.create_info_card(f"SMB Shares ({metadata['shares_found']})")
            share_list = metadata.get('share_list', [])
            for share in share_list:
                self.add_card_item(shares_card, f"\\\\{asset_data['ip_address']}\\{share}")
            self.services_layout.addWidget(shares_card)
        
        # Web application card
        if metadata.get('server_type') == 'web_server':
            web_card = self.create_info_card("Web Application")
            
            if metadata.get('server_header'):
                self.add_card_row(web_card, "Server", metadata['server_header'])
            
            if metadata.get('directories_found'):
                self.add_card_row(web_card, "Directories", f"{metadata['directories_found']} found")
            
            if metadata.get('files_found'):
                self.add_card_row(web_card, "Files", f"{metadata['files_found']} accessible")
            
            if metadata.get('tech_stack'):
                tech_text = ', '.join(metadata['tech_stack'][:5])
                if len(metadata['tech_stack']) > 5:
                    tech_text += f" (+{len(metadata['tech_stack']) - 5} more)"
                self.add_card_row(web_card, "Technologies", tech_text)
            
            self.services_layout.addWidget(web_card)
        
        self.services_layout.addStretch()
    
    def populate_security_tab(self, asset_data):
        """Populate the security tab"""
        # Vulnerabilities card
        vulnerabilities = asset_data.get('vulnerabilities', [])

        if vulnerabilities:
            table = QTableWidget()
            table.setColumnCount(2)
            table.setHorizontalHeaderLabels([
                "Severity",
                "Vulnerability"
            ])
            table.setRowCount(len(vulnerabilities))
            table.horizontalHeader().setStretchLastSection(True)

            for row, vuln in enumerate(vulnerabilities):
                table.setItem(
                    row,
                    0,
                    QTableWidgetItem(
                        vuln.get('severity', 'unknown').upper()
                    )
                )
                table.setItem(
                    row,
                    1,
                    QTableWidgetItem(
                        vuln.get('name', vuln.get('id', 'Unknown'))
                    )
                )
            self.security_layout.addWidget(table)
        
        # Security assessment card
        metadata = asset_data.get('metadata', {})
        if metadata.get('security_score') or metadata.get('vulnerabilities_found'):
            security_card = self.create_info_card("Security Assessment")
            
            if metadata.get('security_score'):
                score = int(metadata['security_score']) if isinstance(metadata['security_score'], str) else metadata['security_score']
                score_color = '#90EE90' if score >= 80 else '#FFAA00' if score >= 60 else '#FF8800'
                self.add_card_row(security_card, "Security Score", f"{score}/100", score_color)
            
            if metadata.get('vulnerabilities_found'):
                self.add_card_row(security_card, "Web Vulnerabilities", f"{metadata['vulnerabilities_found']} found", "#FF8800")
            
            self.security_layout.addWidget(security_card)
        
        # If no security data
        if not vulnerabilities and not metadata.get('security_score') and not metadata.get('vulnerabilities_found'):
            no_security = QLabel("No security information available")
            no_security.setStyleSheet("color: #87CEEB; font-style: italic; text-align: center; padding: 20px;")
            self.security_layout.addWidget(no_security)
        
        self.security_layout.addStretch()
    
    def create_info_card(self, title):
        """Create an information card widget"""
        card = QFrame()
        card.setFrameStyle(QFrame.Shape.Box)
        card.setStyleSheet("""
            QFrame {
                background-color: rgba(40, 60, 80, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                margin: 5px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(3)
        
        # Card title
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 12pt; font-weight: bold; color: #64C8FF; margin-bottom: 5px;")
        layout.addWidget(title_label)
        
        return card
    

    def add_card_row(self, card, label, value, color="#DCDCDC"):
        """Compact property-grid style row"""

        row_layout = QHBoxLayout()
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(10)

        label_widget = QLabel(label)

        label_widget.setFixedWidth(140)

        label_widget.setStyleSheet("""
            color: #87CEEB;
            font-weight: bold;
            border: none;
            background: transparent;
        """)

        value_widget = QLabel(str(value))

        value_widget.setWordWrap(True)

        value_widget.setStyleSheet(f"""
            color: {color};
            border: none;
            background: transparent;
        """)

        row_layout.addWidget(label_widget)
        row_layout.addWidget(value_widget, 1)

        card.layout().addLayout(row_layout)

    def add_card_item(self, card, text, color="#DCDCDC"):
        """Add a simple item to a card"""
        item = QLabel(f"• {text}")
        item.setStyleSheet(f"color: {color}; margin-left: 10px;")
        item.setWordWrap(True)
        card.layout().addWidget(item)
