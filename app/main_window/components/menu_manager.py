"""Menu management for the main window."""
from PyQt6.QtWidgets import QMenuBar, QMenu
from PyQt6.QtGui import QAction, QKeySequence


class MenuManager:
    """Manages the main window menu bar."""
    
    def __init__(self, main_window):
        self.main_window = main_window
        self.menubar = None
        
    def create_menu_bar(self):
        """Create and configure the menu bar."""
        self.menubar = self.main_window.menuBar()
        self._apply_menu_styling()
        
        # Create menus
        self._create_file_menu()
        self._create_view_menu()
        self._create_help_menu()
        
        return self.menubar
    
    def _apply_menu_styling(self):
        """Apply styling to the menu bar."""
        self.menubar.setStyleSheet("""
            QMenuBar {
                background-color: rgba(20, 30, 40, 200);
                color: #DCDCDC;
                border-bottom: 1px solid rgba(100, 200, 255, 100);
                font-size: 11pt;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 4px 8px;
            }
            QMenuBar::item:selected {
                background-color: rgba(100, 200, 255, 100);
                border-radius: 4px;
            }
            QMenu {
                background-color: rgba(30, 40, 50, 240);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
            }
            QMenu::item {
                padding: 6px 12px;
            }
            QMenu::item:selected {
                background-color: rgba(100, 200, 255, 150);
            }
        """)
    
    def _create_file_menu(self):
        """Create the File menu."""
        file_menu = self.menubar.addMenu('&File')
        
        # Profiles submenu
        profiles_menu = file_menu.addMenu('&Profiles')
        self._add_action(profiles_menu, '&New Profile', 'Ctrl+N', 'Create a new engagement profile', self.main_window.new_profile)
        self._add_action(profiles_menu, '&Load Profile...', 'Ctrl+O', 'Load an existing engagement profile', self.main_window.load_profile)
        self._add_action(profiles_menu, '&Delete Profile...', None, 'Delete an engagement profile', self.main_window.delete_profile)
        
        file_menu.addSeparator()
        self._add_action(file_menu, '&Export Results', 'Ctrl+E', 'Export scan results', self.main_window.export_current_results)
        
        file_menu.addSeparator()
        self._add_action(file_menu, '&Databases', 'Ctrl+D', 'Database management and SQL queries', self.main_window.open_database_management)
        self._add_action(file_menu, '&Global Settings', 'Ctrl+,', 'Configure API keys and global settings', self.main_window.open_global_settings)
        self._add_action(file_menu, '&License Manager', None, 'Manage professional license', self.main_window.open_license_manager)
        
        file_menu.addSeparator()
        self._add_action(file_menu, 'E&xit', 'Ctrl+Q', 'Exit application', self.main_window.close)
    
    def _create_view_menu(self):
        """Create the View menu."""
        view_menu = self.menubar.addMenu('&View')
        
        # Navigation Style submenu
        nav_menu = view_menu.addMenu('&Navigation Style')
        self._add_action(nav_menu, '&Advanced Mode', None, 'Switch to advanced methodology navigation', lambda: self.main_window.set_home_style('attack_chain'))
        self._add_action(nav_menu, '&Guided Mode', None, 'Step-by-step penetration testing methodology', lambda: self.main_window.navigate_to('guided_workflow'))
        

        
        # Theme submenu
        self._create_theme_menu(view_menu)
        
        view_menu.addSeparator()
        
        # Navigation actions
        self._add_action(view_menu, '&Running Scans...', 'Ctrl+Shift+R', 'Monitor and control active scans', self.main_window.show_running_scans)
        self._add_action(view_menu, '&Sessions', 'Ctrl+Shift+S', 'Manage scanning sessions', self.main_window.open_sessions_dialog)
        self._add_action(view_menu, 'Session &Info', 'Ctrl+I', 'View current session information and exports', self.main_window.show_session_info)
        self._add_action(view_menu, '&Reports', 'Ctrl+R', 'Advanced reporting and compliance', self.main_window.open_reports_dialog)
        self._add_action(view_menu, '&Inventory', 'Ctrl+Shift+I', 'View and manage discovered assets', lambda: self.main_window.navigate_to('inventory'))
        
        view_menu.addSeparator()
        
        # Utility actions
        self._add_action(view_menu, '&Minimize to Tray', 'Ctrl+M', 'Minimize application to system tray', self.main_window.minimize_to_tray)
        self._add_action(view_menu, '&Clear Output', 'Ctrl+L', 'Clear terminal output', self.main_window.clear_current_output)
        
        view_menu.addSeparator()
        
        # Professional Features submenu
        self._create_professional_menu(view_menu)
    
    def _create_theme_menu(self, parent_menu):
        """Create the Theme submenu."""
        theme_menu = parent_menu.addMenu('&Themes')
        
        self._add_action(theme_menu, '&Theme Selector...', 'Ctrl+T', 'Open enhanced theme selector', self.main_window.open_theme_selector)
        theme_menu.addSeparator()
        
        # Quick theme actions
        for theme_key, theme_name in self.main_window.theme_manager.get_available_themes():
            action = QAction(f'&{theme_name}', self.main_window)
            action.triggered.connect(lambda checked, key=theme_key: self.main_window.theme_manager.set_theme(key))
            theme_menu.addAction(action)
    
    def _create_professional_menu(self, parent_menu):
        """Create the Professional Features submenu."""
        pro_menu = parent_menu.addMenu('&Professional Features')
        
        self._add_action(pro_menu, '&Stealth Mode', None, 'Configure stealth and evasion settings', self.main_window.open_stealth_config)
        pro_menu.addSeparator()
        
        self._add_action(pro_menu, '&AD Enumeration', None, 'Active Directory enumeration and attacks', self.main_window.open_ad_enumeration)
        pro_menu.addSeparator()
        
        self._add_action(pro_menu, '&Enhanced Reporting', None, 'Executive dashboards and compliance reports', self.main_window.open_enhanced_reporting)
        self._add_action(pro_menu, '&Advanced Analytics', None, 'Trend analysis, anomaly detection, and predictive insights', self.main_window.open_advanced_analytics)
        self._add_action(pro_menu, '&Wireless Security', None, 'WiFi and Bluetooth security testing', self.main_window.open_wireless_security)
        
        pro_menu.addSeparator()
        
        self._add_action(pro_menu, '&Social Engineering', None, 'Phishing campaigns and credential harvesting', self.main_window.open_social_engineering)
        self._add_action(pro_menu, '&Anti-Forensics', None, 'Log clearing and evasion techniques', self.main_window.open_anti_forensics)
        self._add_action(pro_menu, '&VPN Connection', None, 'Manage VPN connections', self.main_window.open_vpn_manager)
    
    def _create_help_menu(self):
        """Create the Help menu."""
        help_menu = self.menubar.addMenu('&Help')
        
        self._add_action(help_menu, '&Tool Help', 'F1', 'Show detailed tool help and documentation', self.main_window.show_enhanced_help)
        help_menu.addSeparator()
        self._add_action(help_menu, '&About', None, 'About Huggin', self.main_window.show_about)
    
    def _add_action(self, menu, text, shortcut, status_tip, callback):
        """Helper method to add an action to a menu."""
        action = QAction(text, self.main_window)
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        if status_tip:
            action.setStatusTip(status_tip)
        action.triggered.connect(callback)
        menu.addAction(action)
        return action