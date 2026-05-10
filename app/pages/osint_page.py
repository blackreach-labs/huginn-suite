from PyQt6.QtWidgets import QVBoxLayout, QTabWidget

from app.pages.components.base_page import BasePage
from app.components.infrastructure_osint_component import InfrastructureOSINTComponent
from app.components.breach_analysis_component import BreachAnalysisComponent
from app.components.people_search_component import PeopleSearchComponent
from app.components.social_media_component import SocialMediaComponent
from app.components.threat_intelligence_component import ThreatIntelligenceComponent
from app.components.automation_component import AutomationComponent
from app.components.compliance_component import ComplianceComponent
from app.core.logger import logger

class OSINTPage(BasePage):
    def __init__(self, parent=None):
        super().__init__(parent)


    def setup_ui(self):
        """Setup the UI - required by BasePage"""
        try:
            self.setup_page()
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        try:
            self.connect_events()
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)

    def setup_page(self):
        """Setup page layout and components"""
        # Create main layout
        self.content_layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Infrastructure reconnaissance tab
        self.infrastructure_component = InfrastructureOSINTComponent(self)
        self.tab_widget.addTab(self.infrastructure_component, "🌐 Infrastructure")
        
        # Breach analysis tab
        self.breach_component = BreachAnalysisComponent(self)
        self.tab_widget.addTab(self.breach_component, "🔓 Breach Analysis")
        
        # People search tab
        self.people_component = PeopleSearchComponent(self)
        self.tab_widget.addTab(self.people_component, "👥 People & Entities")
        
        # Social media tab
        self.social_component = SocialMediaComponent(self)
        self.tab_widget.addTab(self.social_component, "📱 Social Media")
        
        # Threat intelligence tab
        self.threat_component = ThreatIntelligenceComponent(self)
        self.tab_widget.addTab(self.threat_component, "⚠️ Threat Intel")
        
        # Automation tab
        self.automation_component = AutomationComponent(self)
        self.tab_widget.addTab(self.automation_component, "🤖 Automation")
        
        # Compliance tab
        self.compliance_component = ComplianceComponent(self)
        self.tab_widget.addTab(self.compliance_component, "⚖️ Compliance")
        
        self.content_layout.addWidget(self.tab_widget)

    def connect_events(self):
        """Connect component events"""
        # Infrastructure component events
        self.infrastructure_component.osint_started.connect(self.on_osint_started)
        self.infrastructure_component.osint_completed.connect(self.on_osint_completed)
        
        # Breach analysis events
        self.breach_component.analysis_started.connect(self.on_analysis_started)
        self.breach_component.analysis_completed.connect(self.on_analysis_completed)
        
        # People search events
        self.people_component.search_started.connect(self.on_search_started)
        self.people_component.search_completed.connect(self.on_search_completed)
        
        # Social media events
        self.social_component.analysis_started.connect(self.on_social_analysis_started)
        self.social_component.analysis_completed.connect(self.on_social_analysis_completed)
        
        # Threat intelligence events
        self.threat_component.intel_started.connect(self.on_intel_started)
        self.threat_component.intel_completed.connect(self.on_intel_completed)
        
        # Automation events
        self.automation_component.automation_started.connect(self.on_automation_started)
        self.automation_component.automation_completed.connect(self.on_automation_completed)
        
        # Compliance events
        self.compliance_component.compliance_checked.connect(self.on_compliance_checked)
        self.compliance_component.compliance_completed.connect(self.on_compliance_completed)
        
        # Event bus — subscribe using the callback API (EventBus uses
        # subscribe/publish, not Qt signals).
        try:
            from shared.events.event_bus import get_event_bus
            bus = get_event_bus()
            bus.subscribe("scan_started", lambda e: self.on_scan_started(
                getattr(e, 'scan_id', ''), getattr(e, 'scanner_type', '')
            ))
            bus.subscribe("scan_completed", lambda e: self.on_scan_completed(
                getattr(e, 'scan_id', ''), getattr(e, 'results', {})
            ))
        except Exception as _exc:
            logger.debug("EventBus subscription skipped", exc_info=True)

    def on_osint_started(self, target, osint_type):
        """Handle OSINT operation started"""
        self.show_status(f"Starting {osint_type} for {target}", "info")

    def on_osint_completed(self, results):
        """Handle OSINT operation completed"""
        self.show_status("OSINT operation completed", "success")

    def on_analysis_started(self, target, analysis_type):
        """Handle analysis started"""
        self.show_status(f"Starting {analysis_type} for {target}", "info")

    def on_analysis_completed(self, results):
        """Handle analysis completed"""
        self.show_status("Analysis completed", "success")

    def on_scan_started(self, scan_id, scan_type):
        """Handle scan started event"""
        if scan_type.startswith("osint"):
            self.show_status(f"OSINT scan {scan_id} started", "info")

    def on_scan_completed(self, scan_id, results):
        """Handle scan completed event"""
        self.show_status(f"Scan {scan_id} completed", "success")

    def on_search_started(self, target, search_type):
        """Handle people search started"""
        self.show_status(f"Starting {search_type} for {target}", "info")

    def on_search_completed(self, results):
        """Handle people search completed"""
        self.show_status("People search completed", "success")

    def on_social_analysis_started(self, target, analysis_type):
        """Handle social media analysis started"""
        self.show_status(f"Starting {analysis_type} for {target}", "info")

    def on_social_analysis_completed(self, results):
        """Handle social media analysis completed"""
        self.show_status("Social media analysis completed", "success")

    def on_intel_started(self, target, intel_type):
        """Handle threat intelligence started"""
        self.show_status(f"Starting {intel_type} for {target}", "info")

    def on_intel_completed(self, results):
        """Handle threat intelligence completed"""
        self.show_status("Threat intelligence completed", "success")

    def on_automation_started(self, target, automation_type):
        """Handle automation started"""
        self.show_status(f"Starting {automation_type}", "info")

    def on_automation_completed(self, results):
        """Handle automation completed"""
        self.show_status("Automation task completed", "success")

    def on_compliance_checked(self, target, compliance_type):
        """Handle compliance check"""
        self.show_status(f"Viewing {compliance_type}", "info")

    def on_compliance_completed(self, results):
        """Handle compliance completed"""
        self.show_status("Compliance information loaded", "success")