"""Navigation management for the main window."""
from typing import Dict, Any
from PyQt6.QtCore import Qt
from app.pages.components.page_factory import PageFactory
from app.pages.page_registry import register_all_pages, get_registered_page_info


class NavigationManager:
    """Manages page navigation and routing with factory pattern."""
    
    def __init__(self, main_window):
        self.main_window = main_window
        self.page_registry = {}
        self.page_instances = {}
        
        # Register all pages with factory
        register_all_pages()
        
        # Setup navigation registry
        self._setup_page_registry()
        self._setup_factory_navigation()
    
    def _setup_page_registry(self):
        """Set up the page registry with navigation mappings."""
        self.page_registry = {
            "home": self._navigate_home,
            "attack_chain_home": self._navigate_attack_chain_home,
            "enumeration": self._navigate_recon_enumeration,
            "http": self._navigate_recon_enumeration,
            "http_enum": self._navigate_recon_enumeration,
            "vuln_scanning": self._navigate_vuln_scanning,
            "web_exploits": self._navigate_web_exploits,
            "databases": self._navigate_databases,
            "os_exploits": self._navigate_os_exploits,
            "cracking": self._navigate_cracking,
            "osint": self._navigate_osint,
            "osint_recon": self._navigate_osint,
            "findings": self._navigate_findings,
            "owasp_api": self._navigate_owasp_api,
            "scripts": self._navigate_scripts,
            "running_scans": self._navigate_running_scans,
            "session_info": self._navigate_session_info,
            "network_discovery": self._navigate_network_discovery,
            "recon_enumeration": self._navigate_recon_enumeration,
            "shell_management": self._navigate_shell_management,
            "interactive_shell": self._navigate_interactive_shell,
            "post_exploitation": self._navigate_post_exploitation,
            "huginn_scanner": self._navigate_huginn_scanner,
            "inventory": self._navigate_inventory,
            "guided_workflow": self._navigate_guided_workflow,
            # New dashboard navigation
            "centralized_dashboard": self._navigate_centralized_dashboard,
            "security_dashboard": self._navigate_security_dashboard,
            "attack_chain_mindmap": self._navigate_attack_chain_mindmap,
        }
    
    def navigate_to(self, page_name: str) -> None:
        """Navigate to a specific page using factory pattern."""
        self.main_window.status_bar.showMessage(f"Navigating to {page_name}...")
        
        # Try factory-based navigation first
        if self._navigate_with_factory(page_name):
            return
        
        # Fallback to legacy navigation
        if page_name in self.page_registry:
            self.page_registry[page_name]()
        else:
            print(f"Navigation request to unknown page: {page_name}")
            self.main_window.status_bar.showMessage(f"Unknown page: {page_name}")
    
    def _navigate_with_factory(self, page_name: str) -> bool:
        """Navigate using the page factory pattern."""
        try:
            # Check if page is registered with factory
            registered_pages = PageFactory.get_registered_pages()
            if page_name not in registered_pages:
                return False
            
            # Get or create page instance
            page_instance = PageFactory.get_page_instance(page_name)
            if not page_instance:
                page_instance = PageFactory.create_page(page_name, self.main_window)
            
            if not page_instance:
                return False
            
            # Check if page is ready
            if hasattr(page_instance, 'is_page_ready') and not page_instance.is_page_ready():
                self.main_window.status_bar.showMessage(f"Page {page_name} is not ready")
                return False
            
            # Add page to stack if not already added
            if page_instance not in [self.main_window.stack.widget(i) for i in range(self.main_window.stack.count())]:
                self.main_window.stack.addWidget(page_instance)
            
            # Activate page
            if hasattr(page_instance, 'on_page_activated'):
                page_instance.on_page_activated()
            
            # Navigate to page
            self.main_window.stack.animate_to_widget(page_instance)
            
            # Update status
            page_title = page_instance.get_page_title() if hasattr(page_instance, 'get_page_title') else page_name
            self.main_window.status_bar.showMessage(f"{page_title} - Ready")
            
            return True
            
        except Exception as e:
            print(f"Factory navigation failed for {page_name}: {e}")
            return False
    
    def _setup_factory_navigation(self):
        """Setup navigation mappings for factory-created pages."""
        page_info = get_registered_page_info()
        
        for page_name, info in page_info.items():
            # Add factory navigation to registry
            self.page_registry[page_name] = lambda pn=page_name: self._navigate_with_factory(pn)
    
    def _navigate_home(self):
        """Navigate to home page."""
        # Try factory-based home page first
        if self._navigate_with_factory("home"):
            return
        
        # Fallback to legacy home page
        current_home = getattr(self.main_window, '_current_home_style', 'attack_chain')
        if current_home == 'attack_chain':
            self.main_window.stack.animate_to_widget(self.main_window.attack_chain_home)
            self.main_window.status_bar.showMessage("Advanced Mode - Follow the penetration testing methodology")
        else:
            self.main_window.stack.animate_to_widget(self.main_window.home_page)
            self.main_window.status_bar.showMessage("Classic Home - Select a tool to get started")
    
    def _navigate_attack_chain_home(self):
        """Navigate to attack chain home page."""
        self.main_window.stack.animate_to_widget(self.main_window.attack_chain_home)
        self.main_window.status_bar.showMessage("Advanced Mode - Target Profiles & Credential Management")
    
    def _navigate_enumeration(self):
        """Navigate to enumeration page."""
        # Try factory-based enumeration page first
        if self._navigate_with_factory("enumeration"):
            return
        
        # Navigate to recon enumeration page
        self.main_window.stack.animate_to_widget(self.main_window.recon_enumeration_page)
        self.main_window.status_bar.showMessage("Reconnaissance & Enumeration - Network scanning, DNS, and service enumeration")
    
    def _navigate_http(self):
        """Navigate to HTTP enumeration."""
        print(f"DEBUG: NAVIGATION INTERCEPTED - Attempted navigation to HTTP")
        print(f"DEBUG: Redirecting to enumeration page instead")
        self.main_window.stack.animate_to_widget(self.main_window.recon_enumeration_page)
        self.main_window.status_bar.showMessage("HTTP Enumeration - Use Run button to start scan")
    
    def _navigate_vuln_scanning(self):
        """Navigate to vulnerability scanning page."""
        self.main_window.stack.animate_to_widget(self.main_window.vuln_page)
        self.main_window.status_bar.showMessage("Vulnerability Scanning Tools")
    
    def _navigate_web_exploits(self):
        """Navigate to web exploits page."""
        self.main_window.stack.animate_to_widget(self.main_window.web_exploits_page)
        self.main_window.status_bar.showMessage("Web Application Exploits")
    
    def _navigate_databases(self):
        """Navigate to database attacks page."""
        self.main_window.stack.animate_to_widget(self.main_window.db_attacks_page)
        self.main_window.status_bar.showMessage("Database Attack Tools")
    
    def _navigate_os_exploits(self):
        """Navigate to OS exploits page."""
        self.main_window.stack.animate_to_widget(self.main_window.os_exploits_page)
        self.main_window.status_bar.showMessage("Operating System Exploits")
    
    def _navigate_cracking(self):
        """Navigate to cracking page."""
        if self._navigate_with_factory("cracking"):
            return
        # Fallback: create and cache the page
        if not hasattr(self.main_window, 'cracking_page'):
            from app.pages.cracking_page import CrackingPage
            self.main_window.cracking_page = CrackingPage(self.main_window)
            self.main_window.stack.addWidget(self.main_window.cracking_page)
        self.main_window.stack.animate_to_widget(self.main_window.cracking_page)
        self.main_window.status_bar.showMessage("Cracking Tools")
    
    def _navigate_osint(self):
        """Navigate to OSINT page."""
        self.main_window.stack.animate_to_widget(self.main_window.osint_page)
        self.main_window.status_bar.showMessage("OSINT & Reconnaissance Tools")
    
    def _navigate_findings(self):
        """Navigate to findings page."""
        self.main_window.stack.animate_to_widget(self.main_window.findings_page)
        self.main_window.status_bar.showMessage("Common Pentest Findings")
    
    def _navigate_owasp_api(self):
        """Navigate to OWASP API page."""
        self.main_window.stack.animate_to_widget(self.main_window.owasp_api_page)
        self.main_window.status_bar.showMessage("OWASP API Security Top 10")
    
    def _navigate_scripts(self):
        """Navigate to scripts page."""
        self.main_window.stack.animate_to_widget(self.main_window.scripts_page)
        self.main_window.status_bar.showMessage("Scripts & Tools")
    
    def _navigate_running_scans(self):
        """Navigate to running scans page."""
        self.main_window.stack.animate_to_widget(self.main_window.running_scans_page)
        self.main_window.status_bar.showMessage("Running Scans Monitor - Control active enumeration scans")
    
    def _navigate_session_info(self):
        """Navigate to session info."""
        self.main_window.show_session_info()
    
    def _navigate_network_discovery(self):
        """Navigate to network discovery page."""
        self.main_window.stack.animate_to_widget(self.main_window.network_discovery_page)
        self.main_window.status_bar.showMessage("Network Discovery & Host Enumeration")
    
    def _navigate_recon_enumeration(self):
        """Navigate to recon enumeration page."""
        self.main_window.stack.animate_to_widget(self.main_window.recon_enumeration_page)
        self.main_window.status_bar.showMessage("Reconnaissance & Enumeration - Network scanning, DNS, and service enumeration")
        # Animate the mindmap phase
        if hasattr(self.main_window, 'mindmap'):
            self.main_window.mindmap.stop_animation()
            self.main_window.mindmap.animate_phase("recon_enum")
    
    def _navigate_shell_management(self):
        """Navigate to shell management page."""
        self.main_window.stack.animate_to_widget(self.main_window.shell_management_page)
        self.main_window.status_bar.showMessage("Shell Management & Interactive Sessions")
    
    def _navigate_interactive_shell(self):
        """Navigate to interactive shell page."""
        self.main_window.stack.animate_to_widget(self.main_window.web_exploits_page)
        # Switch to Interactive Shell tab
        if hasattr(self.main_window.web_exploits_page, 'tab_widget'):
            for i in range(self.main_window.web_exploits_page.tab_widget.count()):
                if "Interactive Shell" in self.main_window.web_exploits_page.tab_widget.tabText(i):
                    self.main_window.web_exploits_page.tab_widget.setCurrentIndex(i)
                    break
        self.main_window.status_bar.showMessage("Interactive Shell - Establish and manage shell connections")
        # Animate the mindmap phase
        if hasattr(self.main_window, 'mindmap'):
            self.main_window.mindmap.stop_animation()
            self.main_window.mindmap.animate_phase("exploitation")
    
    def _navigate_post_exploitation(self):
        """Navigate to post exploitation page."""
        self.main_window.stack.animate_to_widget(self.main_window.post_exploitation_page)
        self.main_window.status_bar.showMessage("Post-Exploitation Tools & Techniques")
    
    def _navigate_huginn_scanner(self):
        """Navigate to Huginn scanner page."""
        if hasattr(self.main_window, 'huginn_scanner_page'):
            self.main_window.stack.animate_to_widget(self.main_window.huginn_scanner_page)
            self.main_window.status_bar.showMessage("Huginn Advanced Security Scanner")
        else:
            self.main_window.status_bar.showMessage("Error: Huginn scanner page not found")
    
    def _navigate_inventory(self):
        """Navigate to inventory page."""
        self.main_window.stack.animate_to_widget(self.main_window.inventory_page)
        self.main_window.status_bar.showMessage("Asset Inventory - Manage discovered targets")
    
    def _navigate_guided_workflow(self):
        """Navigate to guided workflow page."""
        self.main_window.stack.animate_to_widget(self.main_window.guided_workflow_page)
        self.main_window.status_bar.showMessage("Guided Penetration Testing Workflow")
    
    def _navigate_centralized_dashboard(self):
        """Navigate to centralized dashboard."""
        try:
            from app.pages.centralized_dashboard_page import create_centralized_dashboard
            
            # Create or get existing dashboard
            if not hasattr(self.main_window, 'centralized_dashboard_page'):
                self.main_window.centralized_dashboard_page = create_centralized_dashboard()
                self.main_window.stack.addWidget(self.main_window.centralized_dashboard_page)
            
            self.main_window.stack.animate_to_widget(self.main_window.centralized_dashboard_page)
            self.main_window.status_bar.showMessage("Centralized Dashboard - Real-time scan results and metrics")
            
        except Exception as e:
            print(f"Error navigating to centralized dashboard: {e}")
            self.main_window.status_bar.showMessage("Error loading centralized dashboard")
    
    def _navigate_security_dashboard(self):
        """Navigate to security dashboard."""
        try:
            from app.widgets.security_dashboard_widget import SecurityDashboardWidget
            from PyQt6.QtWidgets import QWidget, QVBoxLayout
            
            # Create or get existing security dashboard page
            if not hasattr(self.main_window, 'security_dashboard_page'):
                page = QWidget()
                layout = QVBoxLayout(page)
                layout.setContentsMargins(0, 0, 0, 0)
                
                dashboard_widget = SecurityDashboardWidget()
                layout.addWidget(dashboard_widget)
                
                self.main_window.security_dashboard_page = page
                self.main_window.stack.addWidget(page)
            
            self.main_window.stack.animate_to_widget(self.main_window.security_dashboard_page)
            self.main_window.status_bar.showMessage("Security Dashboard - Live threat monitoring and system health")
            
        except Exception as e:
            print(f"Error navigating to security dashboard: {e}")
            self.main_window.status_bar.showMessage("Error loading security dashboard")
    
    def _navigate_attack_chain_mindmap(self):
        """Navigate to attack chain mindmap."""
        try:
            from app.widgets.attack_chain_mindmap import AttackChainMindmap
            from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
            
            # Create or get existing mindmap page
            if not hasattr(self.main_window, 'attack_chain_mindmap_page'):
                page = QWidget()
                layout = QVBoxLayout(page)
                layout.setContentsMargins(20, 20, 20, 20)
                
                # Title
                title = QLabel("🧠 Interactive Attack Chain Mindmap")
                title.setStyleSheet("font-size: 20pt; font-weight: bold; color: #64C8FF; padding: 10px;")
                title.setAlignment(Qt.AlignmentFlag.AlignCenter)
                layout.addWidget(title)
                
                # Mindmap widget
                mindmap_widget = AttackChainMindmap()
                mindmap_widget.phase_selected.connect(lambda phase, data: self.navigate_to(self._map_phase_to_page(phase)))
                layout.addWidget(mindmap_widget)
                
                self.main_window.attack_chain_mindmap_page = page
                self.main_window.stack.addWidget(page)
            
            self.main_window.stack.animate_to_widget(self.main_window.attack_chain_mindmap_page)
            self.main_window.status_bar.showMessage("Advanced Mode Mindmap - Interactive workflow visualization")
            
        except Exception as e:
            print(f"Error navigating to attack chain mindmap: {e}")
            self.main_window.status_bar.showMessage("Error loading attack chain mindmap")
    
    def _map_phase_to_page(self, phase_name):
        """Map attack chain phase to navigation page."""
        phase_mapping = {
            "ENGAGEMENT SETUP": "attack_chain_home",
            "RECON & ENUMERATION": "recon_enumeration",
            "VULNERABILITY ANALYSIS": "vuln_scanning", 
            "EXPLOITATION": "web_exploits",
            "Interactive Shell": "interactive_shell",
            "POST-EXPLOITATION": "post_exploitation",
            "REPORTING & TOOLS": "scripts"
        }
        return phase_mapping.get(phase_name, "attack_chain_home")
    
    def get_page_info(self, page_name: str) -> Dict[str, Any]:
        """Get information about a registered page."""
        page_info = get_registered_page_info()
        return page_info.get(page_name, {})
    
    def get_all_pages(self) -> Dict[str, Any]:
        """Get information about all registered pages."""
        return get_registered_page_info()
    
    def cleanup(self):
        """Cleanup navigation manager resources."""
        # Cleanup factory instances
        PageFactory.clear_instances()
        
        # Clear local references
        self.page_instances.clear()
        self.page_registry.clear()