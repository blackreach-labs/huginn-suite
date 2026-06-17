# app/pages/page_registry.py
"""
Page registry for registering all application pages with the factory.
"""

from app.pages.components.page_factory import PageFactory
from app.core.logger import logger

def register_all_pages():
    """Register all application pages with the factory."""
    
    # Import pages
    from app.pages.home_page import HomePage
    from app.pages.dns_enumeration_page import DNSEnumerationPage
    from app.pages.huginn_scanner_page import HuginnScannerPage
    
    # Register core pages
    PageFactory.register_page("home", HomePage)
    PageFactory.register_page("dns_enumeration", DNSEnumerationPage)
    PageFactory.register_page("huginn_scanner", HuginnScannerPage)
    
    # Register legacy pages (for backward compatibility)
    try:
        from app.pages.recon_enumeration_page import ReconEnumerationPage
        PageFactory.register_page("enumeration", ReconEnumerationPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.vuln_scanning_page import VulnScanningPage
        PageFactory.register_page("vuln_scanning", VulnScanningPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.web_exploits_page import WebExploitsPage
        PageFactory.register_page("web_exploits", WebExploitsPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.db_attacks_page import DbAttacksPage
        PageFactory.register_page("databases", DbAttacksPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.os_exploits_page import OSExploitsPage
        PageFactory.register_page("os_exploits", OSExploitsPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.cracking_page import CrackingPage
        PageFactory.register_page("cracking", CrackingPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.osint_page import OSINTPage
        PageFactory.register_page("osint", OSINTPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.findings_page import FindingsPage
        PageFactory.register_page("findings", FindingsPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.owasp_api_page import OWASPAPIPage
        PageFactory.register_page("owasp_api", OWASPAPIPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)
    
    try:
        from app.pages.scripts_page import ScriptsPage
        PageFactory.register_page("scripts", ScriptsPage)
    except ImportError as _exc:
        pass
        logger.debug("Suppressed exception", exc_info=True)

def get_registered_page_info():
    """Get information about all registered pages.

    Returns class-level metadata only — does NOT instantiate any pages.
    Instantiating pages at registry time caused silent crashes because
    pages require a real parent widget and a fully initialised application.
    """
    pages = PageFactory.get_registered_pages()
    page_info = {}

    for page_name, page_class in pages.items():
        # Read metadata from class attributes if available; never instantiate.
        page_info[page_name] = {
            'class': page_class,
            'title': getattr(page_class, 'PAGE_TITLE', page_name.replace('_', ' ').title()),
            'icon': getattr(page_class, 'PAGE_ICON', None),
            'ready': True,
        }

    return page_info