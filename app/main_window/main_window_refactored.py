"""Refactored main window using component-based architecture."""
import os
from PyQt6.QtWidgets import QMainWindow, QStatusBar, QWidget, QVBoxLayout, QSizePolicy
from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QFontDatabase
from PyQt6.QtWidgets import QApplication

from app.ui.animations.background_effects import BackgroundEffectManager
from app.widgets.animated_stacked_widget import AnimatedStackedWidget
from app.widgets.attack_chain_mindmap import AttackChainMindmap
from app.core.logger import logger

# Import component managers
from .components.menu_manager import MenuManager
from .components.navigation_manager import NavigationManager
from .components.theme_manager import MainWindowThemeManager
from .components.tray_manager import MainWindowTrayManager

# Import pages
# Lazy imports - pages loaded on demand
from app.core.lazy_initialization import LazyPageManager
from app.core.startup_optimizer import StartupOptimizer


class MainWindow(QMainWindow):
    """Refactored main window with component-based architecture."""
    
    # Phase mapping for mindmap navigation
    PHASE_MAP = {
        "SETUP": "attack_chain_home",
        "RECON": "recon_enumeration",
        "VULN": "vuln_scanning",
        "SCAN": "vuln_scanning",
        "EXPLOIT": "web_exploits",
        "POST-EX": "post_exploitation",
        "ELEVATE": "post_exploitation",
        "REPORT": "findings"
    }
    
    def __init__(self, project_root):
        super().__init__()
        self._initialize_attributes(project_root)
        self._initialize_components()
    
    def _initialize_attributes(self, project_root):
        """Initialize instance attributes."""
        self.project_root = project_root
        self.current_profile_name = None
        self.current_engagement_id = None
        self.session_info_window = None
        self._current_home_style = 'attack_chain'
        self.startup_optimizer = StartupOptimizer()
    
    def _initialize_components(self):
        """Initialize all UI components and managers."""
        self._configure_thread_pool()
        self._setup_window()
        self._setup_managers()
        self._setup_ui()
        self._setup_lazy_pages()
        self._apply_styling()
        self._optimized_final_setup()

    def _configure_thread_pool(self):
        """Configure the global QThreadPool with sensible limits."""
        from PyQt6.QtCore import QThreadPool
        pool = QThreadPool.globalInstance()
        # Cap at 2× CPU count, minimum 4, maximum 32.
        # Prevents runaway thread creation during aggressive scans.
        import os
        cpu_count = os.cpu_count() or 4
        max_threads = max(4, min(cpu_count * 2, 32))
        pool.setMaxThreadCount(max_threads)
        logger.info(f"QThreadPool max threads set to {max_threads} (CPUs: {cpu_count})")
    
    def _setup_window(self):
        """Set up basic window properties."""
        self.setWindowTitle("Huginn (PyQt6 Edition) - Layout Version")
        
        # Dynamic sizing based on screen
        from PyQt6.QtGui import QGuiApplication
        screen = QGuiApplication.primaryScreen().availableGeometry()
        window_size = QSize(min(1600, int(screen.width() * 0.8)), min(1000, int(screen.height() * 0.8)))
        
        self.setMinimumSize(QSize(1200, 800))
        self.resize(window_size)
        self.setWindowFlags(Qt.WindowType.Window)
        
        # Load custom font
        self._load_custom_font()
    
    def _setup_managers(self):
        """Initialize component managers."""
        self.menu_manager = MenuManager(self)
        self.navigation_manager = NavigationManager(self)
        self.theme_manager = MainWindowThemeManager(self, self.project_root)
        self.tray_manager = MainWindowTrayManager(self, self.project_root)
    
    def _setup_ui(self):
        """Set up the user interface."""
        # Create menu bar
        self.menu_manager.create_menu_bar()
        
        # Create status bar
        self._create_status_bar()
        
        # Initialize background effects
        self.background_effects = BackgroundEffectManager(self)
        
        # Create main widget with mindmap
        self._create_main_widget()
        
        # Setup system tray
        self.tray_manager.setup_system_tray()
    
    def _create_status_bar(self):
        """Create and configure the status bar."""
        self.status_bar = QStatusBar()
        self._apply_status_bar_styling()
        self._add_status_bar_widgets()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Huginn Layout Version")
    
    def _apply_status_bar_styling(self):
        """Apply styling to status bar."""
        self.status_bar.setStyleSheet("""
            QStatusBar {
                background-color: rgba(20, 30, 40, 200);
                color: #64C8FF;
                border-top: 1px solid rgba(100, 200, 255, 100);
                font-size: 11pt;
                padding: 2px;
            }
        """)
    
    def _add_status_bar_widgets(self):
        """Add widgets to status bar."""
        try:
            from app.widgets.memory_widget import MemoryWidget
            memory_widget = MemoryWidget()
            self.status_bar.addPermanentWidget(memory_widget)
        except ImportError as e:
            logger.warning(f"Memory widget not available: {e}")
    
    def _create_main_widget(self):
        """Create the main widget with mindmap and stack."""
        main_widget = self._create_main_layout()
        self._setup_mindmap(main_widget.layout())
        self._setup_stack_widget(main_widget.layout())
        self.setCentralWidget(main_widget)
    
    def _create_main_layout(self):
        """Create main widget with layout."""
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(5, 0, 5, 5)
        main_layout.setSpacing(0)
        return main_widget
    
    def _setup_mindmap(self, layout):
        """Setup mindmap component."""
        self.mindmap = AttackChainMindmap()
        self.mindmap.phase_selected.connect(self.on_mindmap_phase_selected)
        self.mindmap.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        layout.addWidget(self.mindmap, 0)
    
    def _setup_stack_widget(self, layout):
        """Setup stacked widget for pages."""
        self.stack = AnimatedStackedWidget(self)
        layout.addWidget(self.stack)
    
    def _setup_lazy_pages(self):
        """Setup lazy page loading system."""
        self.page_manager = LazyPageManager(self)
        
        # Register page factories (imported only when needed)

        self.page_manager.register_page('attack_chain_home', lambda: self._create_attack_chain_home())
        self.page_manager.register_page('guided_workflow', lambda: self._create_guided_workflow())
        self.page_manager.register_page('recon_enumeration', lambda: self._create_recon_enumeration())
        self.page_manager.register_page('vuln_scanning', lambda: self._create_vuln_scanning())
        self.page_manager.register_page('inventory', lambda: self._create_inventory())
        self.page_manager.register_page('session_info', lambda: self._create_session_info())
        self.page_manager.register_page('running_scans', lambda: self._create_running_scans())
        self.page_manager.register_page('web_exploits', lambda: self._create_web_exploits())
        self.page_manager.register_page('post_exploitation', lambda: self._create_post_exploitation())
        self.page_manager.register_page('findings', lambda: self._create_findings())
        self.page_manager.register_page('global_settings', lambda: self._create_global_settings())
        self.page_manager.register_page('database_management', lambda: self._create_database_management())
        self.page_manager.register_page('vpn', lambda: self._create_vpn())
        self.page_manager.register_page('script_editor', lambda: self._create_script_editor())
        self.page_manager.register_page('cracking', lambda: self._create_cracking())
        # Add other pages as needed
        

        
    def _create_attack_chain_home(self):
        try:
            from app.pages.attack_chain_home import AttackChainHomePage
            page = AttackChainHomePage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create attack chain home page: {e}")
            return None
        
    def _create_guided_workflow(self):
        try:
            from app.pages.guided_workflow_page import GuidedWorkflowPage
            page = GuidedWorkflowPage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create guided workflow page: {e}")
            return None
        
    def _create_recon_enumeration(self):
        try:
            from app.pages.recon_enumeration_page import ReconEnumerationPage
            return ReconEnumerationPage(self)
        except Exception as e:
            logger.error(f"Failed to create recon enumeration page: {e}")
            return None
        
    def _create_vuln_scanning(self):
        try:
            from app.pages.vuln_scanning_page import VulnScanningPage
            return VulnScanningPage(self)
        except Exception as e:
            logger.error(f"Failed to create vuln scanning page: {e}")
            return None
    
    def _create_inventory(self):
        from app.pages.inventory_page import InventoryPage
        page = InventoryPage(self)
        self._connect_page_signals(page)
        return page

    def _create_vpn(self):
        from app.widgets.vpn_widget import VPNWidget
        page = VPNWidget(self)
        return page
    
    def _create_session_info(self):
        from app.pages.session_info_page import SessionInfoPage
        page = SessionInfoPage(self)
        self._connect_page_signals(page)
        return page
    
    def _create_running_scans(self):
        try:
            from app.pages.running_scans_page import RunningScansPage
            page = RunningScansPage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create running scans page: {e}")
            return None
    
    def _create_web_exploits(self):
        try:
            from app.pages.web_exploits_page import WebExploitsPage
            page = WebExploitsPage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create web exploits page: {e}")
            return None
    
    def _create_post_exploitation(self):
        try:
            from app.pages.post_exploitation_page import PostExploitationPage
            page = PostExploitationPage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create post exploitation page: {e}")
            return None
    
    def _create_findings(self):
        try:
            from app.pages.findings_page import FindingsPage
            page = FindingsPage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create findings page: {e}")
            return None
    
    def _create_global_settings(self):
        try:
            from app.pages.global_settings_page import GlobalSettingsPage
            page = GlobalSettingsPage()
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create global settings page: {e}")
            return None
    
    def _create_database_management(self):
        try:
            from app.pages.database_management_page import DatabaseManagementPage
            page = DatabaseManagementPage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create database management page: {e}")
            return None
    
    def _create_script_editor(self):
        try:
            from app.pages.script_editor_page import ScriptEditorPage
            page = ScriptEditorPage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create script editor page: {e}")
            return None

    def _create_cracking(self):
        try:
            from app.pages.cracking_page import CrackingPage
            page = CrackingPage(self)
            self._connect_page_signals(page)
            return page
        except Exception as e:
            logger.error(f"Failed to create cracking page: {e}")
            return None
    
    def _connect_page_signals(self, page):
        """Connect signals for a specific page when it's created."""
        if hasattr(page, 'navigate_signal'):
            page.navigate_signal.connect(self.navigate_to)
        if hasattr(page, 'status_updated'):
            page.status_updated.connect(self.update_status_bar)
    
    def _apply_styling(self):
        """Apply global styling and theme."""
        self._apply_global_styling()
        self.theme_manager.apply_initial_theme()
    
    def _optimized_final_setup(self):
        """Optimized final setup based on user preferences."""
        # Initialize license manager
        from app.core.license_manager import license_manager
        license_manager.check_license_expiry()
        
        # Always show mode selection dialog for now
        self.show_mode_selection()
    
    def _load_custom_font(self):
        """Load custom font for the application."""
        try:
            font_path = os.path.join(self.project_root, "resources", "fonts", "neuropol.otf")
            font_id = QFontDatabase.addApplicationFont(font_path)
            if font_id == -1:
                logger.warning(f"Font loading failed - file not found or invalid: {font_path}")
                self.neuropol_family = None
            else:
                self.neuropol_family = QFontDatabase.applicationFontFamilies(font_id)[0]
                logger.info(f"Custom font '{self.neuropol_family}' loaded from {font_path}")
                
                # Set as application default font
                from PyQt6.QtGui import QFont
                app_font = QFont(self.neuropol_family, 12)
                QApplication.instance().setFont(app_font)
        except (FileNotFoundError, OSError) as e:
            logger.error(f"Font file access error in _load_custom_font: {e}")
            self.neuropol_family = None
        except Exception as e:
            logger.error(f"Unexpected error in _load_custom_font: {e}")
            self.neuropol_family = None
    
    def _apply_global_styling(self):
        """Apply global application styling."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0A0A0A;
            }
            
            /* Scrollbars */
            QScrollBar:vertical {
                background-color: rgba(50, 50, 50, 100);
                width: 12px;
                border-radius: 6px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: rgba(100, 200, 255, 150);
                border-radius: 6px;
                min-height: 20px;
                margin: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            
            QScrollBar:horizontal {
                background-color: rgba(50, 50, 50, 100);
                height: 12px;
                border-radius: 6px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background-color: rgba(100, 200, 255, 150);
                border-radius: 6px;
                min-width: 20px;
                margin: 2px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
        """)
    
    # Delegate methods to managers
    def navigate_to(self, page_name):
        """Navigate to a specific page (lazy loaded)."""
        page = self.page_manager.get_page(page_name)
        if page:
            self.stack.setCurrentWidget(page)
            self.status_bar.showMessage(f"Navigated to {page_name}")
            # Update mindmap icon to activated state
            if hasattr(self, 'mindmap'):
                phase = self._page_to_phase(page_name)
                if phase:
                    self.mindmap.selected_phase = phase
                    self.mindmap.update()

    def _page_to_phase(self, page_name):
        """Reverse lookup: map a page name back to its mindmap phase."""
        # Preferred phase for each page (avoids duplicates like SCAN/VULN)
        page_to_phase_map = {
            "attack_chain_home": "SETUP",
            "recon_enumeration": "RECON",
            "vuln_scanning": "SCAN",
            "web_exploits": "EXPLOIT",
            "post_exploitation": "ELEVATE",
            "findings": "REPORT",
        }
        return page_to_phase_map.get(page_name)
    
    def on_mindmap_phase_selected(self, phase_name, phase_data):
        """Handle mindmap phase selection."""
        try:
            page = self.PHASE_MAP.get(phase_name)
            if page:
                self.navigate_to(page)
        except Exception as e:
            logger.error(f"Error handling mindmap selection: {e}")
            self.status_bar.showMessage("Navigation error occurred")
    
    def set_home_style(self, style):
        """Set the home page navigation style."""
        self.theme_manager.set_home_style(style)
    
    def open_theme_selector(self):
        """Open enhanced theme selector dialog."""
        self.theme_manager.open_theme_selector()
    
    def minimize_to_tray(self):
        """Minimize application to system tray."""
        self.tray_manager.minimize_to_tray()
    
    def update_status_bar(self, message):
        """Update status bar with message from child widgets."""
        self.status_bar.showMessage(message)
    
    # Event handlers
    def resizeEvent(self, event):
        """Handle window resize events."""
        super().resizeEvent(event)
        if event and hasattr(self, 'background_effects'):
            self.background_effects.resize_effect(event.size())
    
    def changeEvent(self, event):
        """Handle window state changes."""
        if hasattr(self, 'tray_manager') and self.tray_manager is not None:
            if self.tray_manager.handle_window_state_change(event):
                return
        super().changeEvent(event)
    
    def closeEvent(self, event):
        """Handle application close event."""
        try:
            if hasattr(self, 'tray_manager') and self.tray_manager and self.tray_manager.handle_close_event(event):
                return
            
            self.status_bar.showMessage("Closing application...")
            self._cleanup_services()
            
            # Stop memory monitoring
            from app.core.memory_manager import memory_manager
            memory_manager.stop_monitoring()

            # Close all HTTP sessions
            from app.core.connection_pool import connection_pool
            connection_pool.close_all()

            # Wait for queued scan workers to finish (max 5 s)
            from PyQt6.QtCore import QThreadPool
            QThreadPool.globalInstance().waitForDone(5000)
            
            # Cleanup tray
            if hasattr(self, 'tray_manager') and self.tray_manager:
                self.tray_manager.cleanup()
            
            event.accept()
        except Exception as e:
            logger.error(f"Error during application close: {e}")
            event.accept()
    
    def _cleanup_services(self):
        """Cleanup running services before application exit."""
        # Stop local DNS server if running
        try:
            from app.core.local_dns_server import local_dns_server
            if hasattr(local_dns_server, 'running') and local_dns_server.running:
                local_dns_server.stop_server()
                logger.info("local_dns_server stopped")
        except ImportError:
            pass  # Module not available — nothing to stop
        except Exception as e:
            logger.error(f"Error stopping local_dns_server: {e}")

        # Disconnect VPN if connected
        try:
            from app.core.vpn_manager import vpn_manager
            if hasattr(vpn_manager, 'is_connected') and vpn_manager.is_connected:
                vpn_manager.disconnect()
                logger.info("vpn_manager disconnected")
        except ImportError:
            pass  # Module not available — nothing to stop
        except Exception as e:
            logger.error(f"Error stopping vpn_manager: {e}")
    
    # Legacy methods for compatibility
    def export_current_results(self):
        """Export results from current page."""
        current_widget = self.stack.currentWidget()
        if hasattr(current_widget, 'export_results'):
            current_widget.export_results()
        else:
            self.status_bar.showMessage("No exportable results on current page")
    
    def clear_current_output(self):
        """Clear output on current page."""
        current_widget = self.stack.currentWidget()
        clear_methods = ['clear_terminal', 'clear_current_terminal']
        
        for method in clear_methods:
            if hasattr(current_widget, method):
                getattr(current_widget, method)()
                return
                
        terminal = getattr(current_widget, 'terminal_output', None)
        if terminal and hasattr(terminal, 'clear'):
            terminal.clear()
        else:
            self.status_bar.showMessage("No output to clear on current page")
    
    def toggle_fullscreen(self):
        """Toggle fullscreen mode."""
        if self.isFullScreen():
            self.showNormal()
            self.status_bar.showMessage("Exited fullscreen mode")
        else:
            self.showFullScreen()
            self.status_bar.showMessage("Entered fullscreen mode - Press F11 to exit")
    
    def show_about(self):
        """Show about dialog."""
        try:
            from app.widgets.about_dialog import AboutDialog
            dialog = AboutDialog(self)
            dialog.exec()
        except Exception as e:
            logger.error(f"Error showing about dialog: {e}")
            self.status_bar.showMessage("About dialog not available")
    
    def show_running_scans(self):
        """Show the Running Scans page."""
        self.navigate_to("running_scans")
    
    def show_session_info(self):
        """Show the Session Info page."""
        self.navigate_to("session_info")
    
    def show_enhanced_help(self):
        """Show enhanced help panel."""
        if not hasattr(self, 'enhanced_help_panel') or self.enhanced_help_panel is None:
            from app.widgets.enhanced_help_panel import EnhancedHelpPanel
            self.enhanced_help_panel = EnhancedHelpPanel(self)
        self.enhanced_help_panel.show()
        self.enhanced_help_panel.raise_()
        self.enhanced_help_panel.activateWindow()
        self.status_bar.showMessage("Enhanced help panel opened - F1 to close")
    
    def show_mode_selection(self):
        """Show animated startup sequence, then mode selection dialog."""
        try:
            from app.ui.animations.startup_sequence import StartupSequenceWidget

            resources_path = os.path.join(self.project_root, "resources", "icons")
            self._startup_sequence = StartupSequenceWidget(resources_path=resources_path)
            self._startup_sequence.sequence_finished.connect(self._on_startup_sequence_done)
            self._startup_sequence.start()
        except Exception as e:
            logger.error(f"Error showing startup sequence: {e}")
            self._show_mode_selection_dialog()

    def _on_startup_sequence_done(self):
        """Called when the startup sequence finishes."""
        try:
            if hasattr(self, '_startup_sequence') and self._startup_sequence:
                self._startup_sequence.close()
                self._startup_sequence = None
        except Exception as e:
            logger.warning(f"Error cleaning up startup sequence: {e}")
        self._show_mode_selection_dialog()

    def _show_mode_selection_dialog(self):
        """Show the mode selection dialog (original behavior)."""
        try:
            from app.widgets.mode_selection_dialog import ModeSelectionDialog
            
            dialog = ModeSelectionDialog(self)
            dialog.mode_selected.connect(self.on_mode_selected)
            dialog.exec()
        except Exception as e:
            logger.error(f"Error showing mode selection dialog: {e}")
            # Fallback to advanced mode
            self.on_mode_selected("advanced")
    
    def on_mode_selected(self, mode):
        """Handle mode selection"""
        try:
            # Save preference for next startup
            try:
                self.startup_optimizer.set_preferred_mode(mode)
            except Exception as e:
                logger.warning(f"Failed to save mode preference: {e}")
            
            if mode == "guided":
                page = self.page_manager.get_page('guided_workflow')
                if page:
                    self.stack.setCurrentWidget(page)
                    if hasattr(page, 'start_questionnaire_directly'):
                        page.start_questionnaire_directly()
                    self.status_bar.showMessage("Guided Workflow Mode - Follow the step-by-step methodology")
                else:
                    logger.error("Failed to load guided workflow page")
                    self.status_bar.showMessage("Guided workflow page not available")
            else:
                page = self.page_manager.get_page('attack_chain_home')
                if page:
                    self.stack.setCurrentWidget(page)
                    self.status_bar.showMessage("Advanced Mode - Full access to all tools and features")
                else:
                    logger.error("Failed to load attack chain home page")
                    self.status_bar.showMessage("Attack chain home page not available")
            
            # Enter fullscreen mode after mode selection
            self.showFullScreen()
        except Exception as e:
            logger.error(f"Error in mode selection: {e}")
            self.status_bar.showMessage(f"Mode selection failed: {str(e)}")
            # Fallback - try to show attack chain home page
            try:
                attack_chain_page = self.page_manager.get_page('attack_chain_home')
                if attack_chain_page:
                    self.stack.setCurrentWidget(attack_chain_page)
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
    
    def _create_dialog(self, title, widget_class, size=(800, 600), *args):
        """Create a standard dialog with widget."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout
        
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setModal(True)
        dialog.resize(*size)
        
        layout = QVBoxLayout(dialog)
        widget = widget_class(dialog, *args)
        layout.addWidget(widget)
        
        return dialog
    
    # Professional feature methods (simplified for brevity)
    def open_license_manager(self):
        """Open license management dialog."""
        try:
            from app.widgets.license_widget import LicenseWidget
            dialog = self._create_dialog("License Manager", LicenseWidget, (1200, 1100))
            self.status_bar.showMessage("License Manager opened")
            dialog.exec()
        except ImportError as e:
            logger.error(f"License widget import failed in open_license_manager: {e}")
            self.status_bar.showMessage("License Manager not available")
        except Exception as e:
            logger.error(f"Unexpected error in open_license_manager: {e}")
            self.status_bar.showMessage("Failed to open License Manager")
    
    def open_reports_dialog(self):
        """Navigate to the Findings page and switch to the Advanced Reporting tab."""
        try:
            self.navigate_to('findings')
            # Switch to the Advanced Reporting tab (index 1) once the page is loaded
            page = self.page_manager.get_page('findings')
            if page and hasattr(page, 'tab_widget'):
                page.tab_widget.setCurrentIndex(1)
            self.status_bar.showMessage("Advanced Reporting & Compliance opened")
        except Exception as e:
            logger.error(f"Unexpected error in open_reports_dialog: {e}")
            self.status_bar.showMessage("Failed to open Advanced Reporting")
    
    def open_sessions_dialog(self):
        """Open session management dialog."""
        try:
            from app.widgets.session_widget import SessionWidget
            dialog = self._create_dialog("Session Management", SessionWidget, (900, 700))
            self.status_bar.showMessage("Session Management opened")
            dialog.exec()
        except ImportError as e:
            logger.error(f"Session widget import failed in open_sessions_dialog: {e}")
            self.status_bar.showMessage("Session Management not available")
        except Exception as e:
            logger.error(f"Unexpected error in open_sessions_dialog: {e}")
            self.status_bar.showMessage("Failed to open Session Management")
    
    # Professional feature methods (fully implemented)
    def open_stealth_config(self):
        """Open stealth mode configuration"""
        try:
            from app.widgets.stealth_widget_improved import ImprovedStealthWidget
            dialog = self._create_dialog("Stealth Mode Configuration", ImprovedStealthWidget, (1000, 800))
            self.status_bar.showMessage("Stealth Mode configuration opened")
            dialog.exec()
        except ImportError as e:
            logger.error(f"Stealth widget import failed in open_stealth_config: {e}")
            self.status_bar.showMessage("Stealth Mode not available")
        except Exception as e:
            logger.error(f"Unexpected error in open_stealth_config: {e}")
            self.status_bar.showMessage("Failed to open Stealth Mode")
    
    def open_ad_enumeration(self):
        """Navigate to RECON > Active Directory tab."""
        try:
            from app.core.license_manager import license_manager
            from PyQt6.QtWidgets import QMessageBox

            if not license_manager.validate_feature_access('ad_enumeration', server_side=True):
                QMessageBox.warning(self, "Enterprise Feature",
                                    "AD Enumeration requires Enterprise license.\n\n"
                                    "Visit License Manager to upgrade.")
                return

            self.navigate_to('recon_enumeration')
            page = self.page_manager.get_page('recon_enumeration')
            if page and hasattr(page, 'tab_widget'):
                # Find the Active Directory tab by its label (robust against
                # optional tabs that may shift the index at runtime).
                tab_widget = page.tab_widget
                for i in range(tab_widget.count()):
                    if 'Active Directory' in tab_widget.tabText(i):
                        tab_widget.setCurrentIndex(i)
                        break

            self.status_bar.showMessage("RECON — Active Directory")
        except Exception as e:
            logger.error(f"Error navigating to AD enumeration: {e}")
            self.status_bar.showMessage("Failed to open AD Enumeration")
    
    def open_enhanced_reporting(self):
        """Open enhanced reporting engine"""
        try:
            from app.core.license_manager import license_manager
            from PyQt6.QtWidgets import QMessageBox
            
            # Server-side license validation
            if not license_manager.validate_feature_access('enhanced_reporting', server_side=True):
                QMessageBox.warning(self, "Enterprise Feature", 
                                  "Enhanced Reporting requires Enterprise license.\n\n"
                                  "Visit License Manager to upgrade.")
                return
            
            from app.widgets.enhanced_reporting_widget import EnhancedReportingWidget
            from PyQt6.QtWidgets import QDialog, QVBoxLayout
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Enhanced Reporting Engine")
            dialog.setModal(True)
            dialog.resize(1200, 800)
            
            layout = QVBoxLayout(dialog)
            reporting_widget = EnhancedReportingWidget(dialog)
            layout.addWidget(reporting_widget)
            
            self.status_bar.showMessage("Enhanced Reporting opened")
            dialog.exec()
        except ImportError as e:
            logger.error(f"Enhanced reporting widget import failed in open_enhanced_reporting: {e}")
            self.status_bar.showMessage("Enhanced Reporting not available")
        except Exception as e:
            logger.error(f"Unexpected error in open_enhanced_reporting: {e}")
            self.status_bar.showMessage("Failed to open Enhanced Reporting")
    
    def open_advanced_analytics(self):
        """Navigate to Findings > Analytics tab."""
        try:
            self.navigate_to('findings')
            page = self.page_manager.get_page('findings')
            if page and hasattr(page, 'tab_widget'):
                tab_widget = page.tab_widget
                for i in range(tab_widget.count()):
                    if 'Analytics' in tab_widget.tabText(i):
                        tab_widget.setCurrentIndex(i)
                        break

            self.status_bar.showMessage("Findings — Advanced Analytics")
        except Exception as e:
            logger.error(f"Unexpected error in open_advanced_analytics: {e}")
            self.status_bar.showMessage("Failed to open Advanced Analytics")
    
    def open_wireless_security(self):
        """Navigate to RECON > Wireless tab."""
        try:
            from app.core.license_manager import license_manager
            from PyQt6.QtWidgets import QMessageBox

            if not license_manager.validate_feature_access('wireless_security', server_side=True):
                QMessageBox.warning(self, "Enterprise Feature",
                                    "Wireless Security requires Enterprise license.\n\n"
                                    "Visit License Manager to upgrade.")
                return

            self.navigate_to('recon_enumeration')
            page = self.page_manager.get_page('recon_enumeration')
            if page and hasattr(page, 'tab_widget'):
                tab_widget = page.tab_widget
                for i in range(tab_widget.count()):
                    if 'Wireless' in tab_widget.tabText(i):
                        tab_widget.setCurrentIndex(i)
                        break

            self.status_bar.showMessage("RECON — Wireless Security")
        except Exception as e:
            logger.error(f"Unexpected error in open_wireless_security: {e}")
            self.status_bar.showMessage("Failed to open Wireless Security")
    
    def open_social_engineering(self):
        """Open social engineering toolkit"""
        try:
            from app.core.license_manager import license_manager
            from PyQt6.QtWidgets import QMessageBox
            
            if not license_manager.validate_feature_access('social_engineering', server_side=True):
                QMessageBox.warning(self, "Enterprise Feature", 
                                  "Social Engineering requires Enterprise license.\n\n"
                                  "Visit License Manager to upgrade.")
                return
                
            from app.widgets.social_engineering_widget import SocialEngineeringWidget
            dialog = self._create_dialog("Social Engineering Toolkit", SocialEngineeringWidget, (1200, 800))
            self.status_bar.showMessage("Social Engineering opened")
            dialog.exec()
        except ImportError as e:
            logger.error(f"Social engineering widget import failed in open_social_engineering: {e}")
            self.status_bar.showMessage("Social Engineering not available")
        except Exception as e:
            logger.error(f"Unexpected error in open_social_engineering: {e}")
            self.status_bar.showMessage("Failed to open Social Engineering")

    def navigate_to_social_engineering(self):
        """Navigate to the Social Engineering tab under RECON."""
        # Use the factory to get/create the recon page
        from app.pages.components.page_factory import PageFactory
        try:
            recon_page = PageFactory.get_page_instance("enumeration")
            if not recon_page:
                recon_page = PageFactory.create_page("enumeration", self)
            if recon_page:
                # Add to stack if needed
                if recon_page not in [self.stack.widget(i) for i in range(self.stack.count())]:
                    self.stack.addWidget(recon_page)
                self.stack.animate_to_widget(recon_page)
                # Select the Social Engineering tab
                if hasattr(recon_page, 'tab_widget'):
                    for i in range(recon_page.tab_widget.count()):
                        if "Social Engineering" in recon_page.tab_widget.tabText(i):
                            recon_page.tab_widget.setCurrentIndex(i)
                            break
                self.status_bar.showMessage("Social Engineering")
            else:
                self.status_bar.showMessage("Recon page not available")
        except Exception as e:
            logger.error(f"Failed to navigate to Social Engineering: {e}")
            self.status_bar.showMessage("Social Engineering not available")
    
    def open_anti_forensics(self):
        """Open anti-forensics toolkit"""
        try:
            from app.core.license_manager import license_manager
            from PyQt6.QtWidgets import QMessageBox
            
            if not license_manager.validate_feature_access('anti_forensics', server_side=True):
                QMessageBox.warning(self, "Enterprise Feature", 
                                  "Anti-Forensics requires Enterprise license.\n\n"
                                  "Visit License Manager to upgrade.")
                return
                
            from app.widgets.anti_forensics_widget import AntiForensicsWidget
            dialog = self._create_dialog("Anti-Forensics & Evasion Techniques", AntiForensicsWidget, (1100, 700))
            self.status_bar.showMessage("Anti-Forensics opened")
            dialog.exec()
        except ImportError as e:
            logger.error(f"Anti-forensics widget import failed in open_anti_forensics: {e}")
            self.status_bar.showMessage("Anti-Forensics not available")
        except Exception as e:
            logger.error(f"Unexpected error in open_anti_forensics: {e}")
            self.status_bar.showMessage("Failed to open Anti-Forensics")

    def navigate_to_anti_forensics(self):
        """Navigate to the Anti-Forensics tab under ELEVATE (Post-Exploitation)."""
        from app.pages.post_exploitation_page import PostExploitationPage
        # Find or create the post-exploitation page in the stack
        page = None
        for i in range(self.stack.count()):
            widget = self.stack.widget(i)
            if isinstance(widget, PostExploitationPage):
                page = widget
                break
        if not page:
            page = PostExploitationPage(self)
            self.stack.addWidget(page)
        self.stack.animate_to_widget(page)
        # Select the Anti-Forensics tab
        if hasattr(page, 'tab_widget'):
            for i in range(page.tab_widget.count()):
                if "Anti-Forensics" in page.tab_widget.tabText(i):
                    page.tab_widget.setCurrentIndex(i)
                    break
        self.status_bar.showMessage("Anti-Forensics")

    def navigate_to_cracking(self):
        """Navigate to the Cracking tab under Post-Exploitation."""
        from app.pages.post_exploitation_page import PostExploitationPage
        page = None
        for i in range(self.stack.count()):
            widget = self.stack.widget(i)
            if isinstance(widget, PostExploitationPage):
                page = widget
                break
        if not page:
            page = PostExploitationPage(self)
            self.stack.addWidget(page)
        self.stack.animate_to_widget(page)
        # Select the Cracking tab
        if hasattr(page, 'tab_widget'):
            for i in range(page.tab_widget.count()):
                if "Cracking" in page.tab_widget.tabText(i):
                    page.tab_widget.setCurrentIndex(i)
                    break
        self.status_bar.showMessage("Cracking Tools")
    
    def open_vpn_manager(self):
        """Open VPN connection manager"""
        try:
            from app.core.license_manager import license_manager
            from PyQt6.QtWidgets import QMessageBox, QDialog, QVBoxLayout
            
            # Check if VPN feature is enabled
            if not license_manager.is_feature_enabled('vpn_connection'):
                QMessageBox.warning(self, "Professional Feature", 
                                  "VPN Connection Manager requires Professional or Enterprise license.\n\n"
                                  "Visit License Manager to upgrade.")
                return
            

            from app.widgets.vpn_widget import VPNWidget
            dialog = self._create_dialog("VPN Connection Manager", VPNWidget, (1280, 800))
            self.status_bar.showMessage("VPN Manager opened")
            dialog.exec()
        except ImportError as e:
            logger.error(f"VPN widget import failed in open_vpn_manager: {e}")
            self.status_bar.showMessage("VPN Manager not available")
        except Exception as e:
            logger.error(f"Unexpected error in open_vpn_manager: {e}")
            self.status_bar.showMessage("Failed to open VPN Manager")

    def navigate_to_vpn(self):
        """Navigate to the VPN Connection Manager page."""
        page = self.page_manager.get_page('vpn')
        if page:
            if page not in [self.stack.widget(i) for i in range(self.stack.count())]:
                self.stack.addWidget(page)
            self.stack.animate_to_widget(page)
            self.status_bar.showMessage("VPN Connection Manager")
        else:
            self.status_bar.showMessage("VPN Manager not available")
    

    
    def _get_attack_chain_home(self):
        """Retrieve (and lazily create) the attack chain home page."""
        return self.page_manager.get_page('attack_chain_home')

    def new_profile(self):
        """Navigate to Engagement Setup and create a new engagement."""
        try:
            self.navigate_to("attack_chain_home")
            page = self._get_attack_chain_home()
            if page:
                page.new_profile()
            else:
                self.status_bar.showMessage("Engagement management not available")
        except Exception as e:
            logger.error(f"Unexpected error in new_profile: {e}")
            self.status_bar.showMessage("Failed to create new engagement")

    def load_profile(self):
        """Navigate to Engagement Setup and show the load-engagement dialog."""
        try:
            self.navigate_to("attack_chain_home")
            page = self._get_attack_chain_home()
            if page:
                page.load_profile()
            else:
                self.status_bar.showMessage("Engagement management not available")
        except Exception as e:
            logger.error(f"Unexpected error in load_profile: {e}")
            self.status_bar.showMessage("Failed to load engagement")

    def delete_profile(self):
        """Show a list of engagements and delete the selected one."""
        try:
            page = self._get_attack_chain_home()
            if page:
                page.delete_profile_dialog()
            else:
                self.status_bar.showMessage("Engagement management not available")
        except Exception as e:
            logger.error(f"Unexpected error in delete_profile: {e}")
            self.status_bar.showMessage("Failed to delete engagement")
    
    def open_database_management(self):
        """Open database management page"""
        self.navigate_to("database_management")

    def open_import_export(self):
        """Open Import/Export dialog for findings."""
        try:
            from app.core.feature_gap_integration import FeatureGapIntegration
            FeatureGapIntegration._open_import_export()
        except Exception as e:
            logger.error(f"Failed to open Import/Export: {e}")
            self.status_bar.showMessage("Import/Export not available")

    def open_team_collaboration(self):
        """Open Team Collaboration dialog."""
        try:
            from app.core.feature_gap_integration import FeatureGapIntegration
            FeatureGapIntegration._open_collaboration()
        except Exception as e:
            logger.error(f"Failed to open Team Collaboration: {e}")
            self.status_bar.showMessage("Team Collaboration not available")
    
    def open_global_settings(self):
        """Open global settings page"""
        self.navigate_to("global_settings")
    
    def open_script_editor(self):
        """Open script editor page"""
        self.navigate_to("script_editor")