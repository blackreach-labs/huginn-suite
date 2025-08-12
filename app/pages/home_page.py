# app/pages/home_page.py
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
                             QPushButton, QTextEdit, QSizePolicy, QSplitter)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPixmap, QIcon, QFont
import os
import logging

from app.pages.components.base_page import BasePage
from app.widgets.attack_chain_mindmap import AttackChainMindmap
from app.widgets.security_dashboard_widget import SecurityDashboardWidget

class HoverButton(QPushButton):
    """Custom hover button with description display."""
    
    def __init__(self, title, description_lines, parent=None):
        super().__init__(parent)
        self.title = title
        self.description_lines = description_lines
        self.home_page = parent
        
    def enterEvent(self, event):
        super().enterEvent(event)
        if self.home_page and hasattr(self.home_page, 'update_info_panel'):
            self.home_page.update_info_panel(self.title, self.description_lines)
        
    def leaveEvent(self, event):
        super().leaveEvent(event)
        if self.home_page and hasattr(self.home_page, 'clear_info_panel'):
            self.home_page.clear_info_panel()

class HomePage(BasePage):
    """Refactored home page using component-based architecture."""
    
    def __init__(self, parent=None):
        self.navigation_buttons = []
        super().__init__(parent)
    
    def setup_ui(self):
        """Setup the home page UI components."""
        # Create main layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Create navigation panel (left side)
        nav_panel = self.create_navigation_panel()
        
        # Create info panel (right side)
        info_panel = self.create_info_panel()
        
        # Add panels to main layout with stretch factors
        main_layout.addWidget(nav_panel, 0)  # Fixed width
        main_layout.addWidget(info_panel, 1)  # Expandable
        
        self.apply_theme()
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    
    def create_navigation_panel(self):
        """Create the left navigation panel with tool buttons."""
        nav_frame = QFrame()
        nav_frame.setObjectName("NavigationPanel")
        nav_frame.setFixedWidth(280)
        nav_frame.setStyleSheet("""
            QFrame#NavigationPanel {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 15px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        
        nav_layout = QVBoxLayout(nav_frame)
        nav_layout.setContentsMargins(15, 15, 15, 15)
        nav_layout.setSpacing(10)
        
        # Title
        title = QLabel("HUGGIN")
        title.setObjectName("TitleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            font-size: 18pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 10px;
        """)
        nav_layout.addWidget(title)
        
        # Dashboard navigation buttons
        button_configs = self.get_dashboard_button_configs()
        
        for config in button_configs:
            button = self.create_navigation_button(config)
            nav_layout.addWidget(button)
            self.navigation_buttons.append(button)
        
        # Add stretch to push buttons to top
        nav_layout.addStretch()
        
        return nav_frame
    
    def get_dashboard_button_configs(self):
        """Get dashboard navigation button configurations."""
        return [
            {
                "name": "target_profiles", 
                "title": "🎯 TARGET PROFILES", 
                "desc": ["Manage target profiles, scope definitions, and engagement parameters for penetration testing assessments."], 
                "icon": "resources/icons/1.png"
            },
            {
                "name": "credential_manager", 
                "title": "🔑 CREDENTIAL MANAGER", 
                "desc": ["Secure credential storage and management for authentication during security assessments."], 
                "icon": "resources/icons/2.png"
            },
            {
                "name": "centralized_dashboard", 
                "title": "📊 REALTIME DASHBOARD", 
                "desc": ["Real-time unified dashboard showing all scan results, metrics, and security status across all tools and services."], 
                "icon": "resources/icons/3.png"
            },
            {
                "name": "security_dashboard", 
                "title": "🛡️ SECURITY DASHBOARD", 
                "desc": ["Live security metrics, threat levels, remediation actions, and system health monitoring."], 
                "icon": "resources/icons/4.png"
            }
        ]
    
    def create_navigation_button(self, config):
        """Create a navigation button with icon and text."""
        button = HoverButton(config["title"], config["desc"], self)
        
        # Set button properties
        button.setMinimumHeight(60)
        button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        # Load icon
        if self.main_window:
            icon_path = os.path.join(self.main_window.project_root, config["icon"])
            icon = QIcon(icon_path)
            if icon.isNull():
                logging.warning(f"Could not load icon at {icon_path}")
            
            button.setIcon(icon)
            button.setIconSize(QSize(32, 32))
        
        button.setText(config["title"])
        
        # Apply button styling
        self.apply_button_style(button)
        
        # Connect navigation signal
        button.clicked.connect(lambda checked, n=config["name"]: self.navigate_signal.emit(n))
        
        return button
    
    def apply_button_style(self, button):
        """Apply consistent styling to navigation buttons."""
        button.setStyleSheet("""
            QPushButton {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 10px;
                color: #DCDCDC;
                font-size: 12pt;
                font-weight: bold;
                text-align: left;
                padding: 8px 12px;
            }
            QPushButton:hover {
                background-color: rgba(40, 60, 80, 200);
                border: 2px solid #64C8FF;
                color: #FFFFFF;
            }
            QPushButton:pressed {
                background-color: rgba(60, 100, 140, 220);
                border: 2px solid #88DFFF;
            }
        """)
    
    def create_info_panel(self):
        """Create the right dashboard panel."""
        # Create splitter for dashboard components
        dashboard_splitter = QSplitter(Qt.Orientation.Vertical)
        dashboard_splitter.setStyleSheet("""
            QSplitter {
                background-color: rgba(0, 0, 0, 150);
                border-radius: 15px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
        """)
        
        # Add attack chain mindmap at top
        mindmap_frame = QFrame()
        mindmap_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 30);
                margin: 10px;
            }
        """)
        mindmap_layout = QVBoxLayout(mindmap_frame)
        mindmap_layout.setContentsMargins(10, 10, 10, 10)
        
        # Mindmap title
        mindmap_title = QLabel("🧠 Attack Chain Workflow")
        mindmap_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mindmap_title.setStyleSheet("""
            font-size: 16pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 5px;
        """)
        mindmap_layout.addWidget(mindmap_title)
        
        # Add mindmap widget
        try:
            self.mindmap_widget = AttackChainMindmap()
            self.mindmap_widget.phase_selected.connect(self.on_phase_selected)
            mindmap_layout.addWidget(self.mindmap_widget)
        except Exception as e:
            logging.warning(f"Could not load mindmap widget: {e}")
            placeholder = QLabel("🧠 Interactive Attack Chain Mindmap\n(Click phases to navigate)")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #DCDCDC; padding: 20px;")
            mindmap_layout.addWidget(placeholder)
        
        dashboard_splitter.addWidget(mindmap_frame)
        
        # Add security dashboard at bottom
        dashboard_frame = QFrame()
        dashboard_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 30);
                margin: 10px;
            }
        """)
        dashboard_layout = QVBoxLayout(dashboard_frame)
        dashboard_layout.setContentsMargins(10, 10, 10, 10)
        
        # Dashboard title
        dashboard_title = QLabel("🛡️ Security Overview")
        dashboard_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dashboard_title.setStyleSheet("""
            font-size: 16pt;
            font-weight: bold;
            color: #64C8FF;
            padding: 5px;
        """)
        dashboard_layout.addWidget(dashboard_title)
        
        # Add security dashboard widget
        try:
            self.security_dashboard = SecurityDashboardWidget()
            dashboard_layout.addWidget(self.security_dashboard)
        except Exception as e:
            logging.warning(f"Could not load security dashboard: {e}")
            placeholder = QLabel("🛡️ Real-time Security Metrics\n(Live threat monitoring and system status)")
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("color: #DCDCDC; padding: 20px;")
            dashboard_layout.addWidget(placeholder)
        
        dashboard_splitter.addWidget(dashboard_frame)
        
        # Set splitter proportions (mindmap smaller, dashboard larger)
        dashboard_splitter.setSizes([200, 400])
        
        return dashboard_splitter
    
    def on_phase_selected(self, phase_name, phase_data):
        """Handle attack chain phase selection."""
        # Map phase names to navigation targets
        phase_mapping = {
            "SETUP": "scripts",
            "RECON": "recon_enumeration",
            "VULN": "vuln_scanning", 
            "EXPLOIT": "os_exploits",
            "POST-EX": "post_exploitation",
            "REPORT": "scripts"
        }
        
        target = phase_mapping.get(phase_name)
        if target:
            self.navigate_signal.emit(target)
        else:
            logging.warning(f"Unknown phase selected: {phase_name}")
    
    def update_info_panel(self, title, description_lines):
        """Update the info panel with dashboard information."""
        # For dashboard buttons, we can show additional info or animate components
        if hasattr(self, 'mindmap_widget') and "MINDMAP" in title:
            # Could animate the mindmap or highlight specific phases
            pass
        elif hasattr(self, 'security_dashboard') and "SECURITY" in title:
            # Could refresh the security dashboard
            if hasattr(self.security_dashboard, 'refresh_dashboard'):
                self.security_dashboard.refresh_dashboard()
    
    def clear_info_panel(self):
        """Reset info panel to default state."""
        # Reset any animations or highlights
        pass
    
    def apply_theme(self):
        """Apply theme to the home page."""
        if self.main_window and hasattr(self.main_window, 'theme_manager'):
            colors = self.main_window.theme_manager.get_theme_colors()
            self.setStyleSheet(f"""
                HomePage {{
                    background-color: {colors.get('background', '#1E1E1E')};
                }}
            """)
    
    def get_page_title(self):
        """Get the display title for this page."""
        return "Home"
    
    def get_page_icon(self):
        """Get the icon path for this page."""
        if self.main_window:
            return os.path.join(self.main_window.project_root, "resources/icons/1.png")
        return None
    
    def cleanup(self):
        """Cleanup resources when page is destroyed."""
        self.navigation_buttons.clear()