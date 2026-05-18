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
        self._create_navigate_menu()
        self._create_tools_menu()
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
        """Create the File menu — file operations only."""
        file_menu = self.menubar.addMenu('&File')
        
        # Profiles submenu
        profiles_menu = file_menu.addMenu('&Profiles')
        self._add_action(profiles_menu, '&New Profile', 'Ctrl+N', 'Create a new engagement profile', self.main_window.new_profile)
        self._add_action(profiles_menu, '&Load Profile...', 'Ctrl+O', 'Load an existing engagement profile', self.main_window.load_profile)
        self._add_action(profiles_menu, '&Delete Profile...', None, 'Delete an engagement profile', self.main_window.delete_profile)
        
        file_menu.addSeparator()
        self._add_action(file_menu, '&Export Results', 'Ctrl+E', 'Export scan results', self.main_window.export_current_results)
        
        file_menu.addSeparator()
        self._add_action(file_menu, 'E&xit', 'Ctrl+Q', 'Exit application', self.main_window.close)

    def _create_navigate_menu(self):
        """Create the Navigate menu — all page navigation."""
        nav_menu = self.menubar.addMenu('&Navigate')
        
        # Mindmap phases
        self._add_action(nav_menu, '&Engagement Setup', None, 'Target profiling and scope definition', lambda: self.main_window.navigate_to('attack_chain_home'))
        self._add_action(nav_menu, '&Recon && Enumeration', None, 'Information gathering and enumeration', lambda: self.main_window.navigate_to('recon_enumeration'))
        self._add_action(nav_menu, '&Vulnerability Analysis', None, 'Vulnerability identification and correlation', lambda: self.main_window.navigate_to('vuln_scanning'))
        self._add_action(nav_menu, 'E&xploitation', None, 'Active exploitation and initial access', lambda: self.main_window.navigate_to('web_exploits'))
        self._add_action(nav_menu, '&Post-Exploitation', None, 'Privilege escalation and lateral movement', lambda: self.main_window.navigate_to('post_exploitation'))
        self._add_action(nav_menu, 'Re&porting', None, 'Reporting, remediation and analytics', lambda: self.main_window.navigate_to('findings'))
        
        nav_menu.addSeparator()
        
        # Standalone pages
        self._add_action(nav_menu, '&Inventory', 'Ctrl+Shift+I', 'View and manage discovered assets', lambda: self.main_window.navigate_to('inventory'))
        self._add_action(nav_menu, 'V&PN Connection', None, 'Manage VPN connections', self.main_window.navigate_to_vpn)
        self._add_action(nav_menu, '&Running Scans', 'Ctrl+Shift+R', 'Monitor and control active scans', self.main_window.show_running_scans)
        self._add_action(nav_menu, '&Sessions', 'Ctrl+Shift+S', 'Session management and information', self.main_window.show_session_info)

    def _create_tools_menu(self):
        """Create the Tools menu — configuration and utility tools."""
        tools_menu = self.menubar.addMenu('&Tools')
        
        self._add_action(tools_menu, '&Stealth Mode', None, 'Configure stealth and evasion settings', self.main_window.open_stealth_config)
        
        tools_menu.addSeparator()
        
        self._add_action(tools_menu, '&Databases', 'Ctrl+D', 'Database management and SQL queries', self.main_window.open_database_management)
        self._add_action(tools_menu, '&Global Settings', 'Ctrl+,', 'Configure API keys and global settings', self.main_window.open_global_settings)
        self._add_action(tools_menu, '&License Manager', None, 'Manage professional license', self.main_window.open_license_manager)
    
    def _create_view_menu(self):
        """Create the View menu — visual/UI preferences only."""
        view_menu = self.menubar.addMenu('&View')
        
        # Navigation Style submenu
        nav_menu = view_menu.addMenu('&Navigation Style')
        self._add_action(nav_menu, '&Advanced Mode', None, 'Switch to advanced methodology navigation', lambda: self.main_window.set_home_style('attack_chain'))
        self._add_action(nav_menu, '&Guided Mode', None, 'Step-by-step penetration testing methodology', lambda: self.main_window.navigate_to('guided_workflow'))
        
        # Theme submenu
        self._create_theme_menu(view_menu)
        
        view_menu.addSeparator()
        
        self._add_action(view_menu, '&Minimize to Tray', 'Ctrl+M', 'Minimize application to system tray', self.main_window.minimize_to_tray)
        self._add_action(view_menu, '&Clear Output', 'Ctrl+L', 'Clear terminal output', self.main_window.clear_current_output)
    
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
    
    def _create_help_menu(self):
        """Create the Help menu."""
        help_menu = self.menubar.addMenu('&Help')
        
        self._add_action(help_menu, '&Tool Help', 'F1', 'Show detailed tool help and documentation', self.main_window.show_enhanced_help)
        help_menu.addSeparator()
        self._add_action(help_menu, '&About', None, 'About Huginn', self.main_window.show_about)
    
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
