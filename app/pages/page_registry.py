# app/pages/page_registry.py
"""
Page registry for registering all application pages with the factory.
"""

from app.pages.components.page_factory import PageFactory

def register_all_pages():
    """Register all application pages with the factory."""
    
    # Import pages
    from app.pages.home_page import HomePage
    from app.pages.dns_enumeration_page import DNSEnumerationPage
    from app.pages.huggin_scanner_page import HugginScannerPage
    
    # Register core pages
    PageFactory.register_page("home", HomePage)
    PageFactory.register_page("dns_enumeration", DNSEnumerationPage)
    PageFactory.register_page("huggin_scanner", HugginScannerPage)
    
    # Register legacy pages (for backward compatibility)
    try:
        from app.pages.recon_enumeration_page import ReconEnumerationPage
        PageFactory.register_page("enumeration", ReconEnumerationPage)
    except ImportError:
        pass
    
    try:
        from app.pages.vuln_scanning_page import VulnScanningPage
        PageFactory.register_page("vuln_scanning", VulnScanningPage)
    except ImportError:
        pass
    
    try:
        from app.pages.web_exploits_page import WebExploitsPage
        PageFactory.register_page("web_exploits", WebExploitsPage)
    except ImportError:
        pass
    
    try:
        from app.pages.db_attacks_page import DBAttacksPage
        PageFactory.register_page("databases", DBAttacksPage)
    except ImportError:
        pass
    
    try:
        from app.pages.os_exploits_page import OSExploitsPage
        PageFactory.register_page("os_exploits", OSExploitsPage)
    except ImportError:
        pass
    
    try:
        from app.pages.cracking_page import CrackingPage
        PageFactory.register_page("cracking", CrackingPage)
    except ImportError:
        pass
    
    try:
        from app.pages.osint_page import OSINTPage
        PageFactory.register_page("osint", OSINTPage)
    except ImportError:
        pass
    
    try:
        from app.pages.findings_page import FindingsPage
        PageFactory.register_page("findings", FindingsPage)
    except ImportError:
        pass
    
    try:
        from app.pages.owasp_api_page import OWASPAPIPage
        PageFactory.register_page("owasp_api", OWASPAPIPage)
    except ImportError:
        pass
    
    try:
        from app.pages.scripts_page import ScriptsPage
        PageFactory.register_page("scripts", ScriptsPage)
    except ImportError:
        pass

def get_registered_page_info():
    """Get information about all registered pages."""
    pages = PageFactory.get_registered_pages()
    page_info = {}
    
    for page_name, page_class in pages.items():
        # Try to get page metadata
        try:
            # Create temporary instance to get metadata
            temp_instance = page_class(None)
            page_info[page_name] = {
                'class': page_class,
                'title': temp_instance.get_page_title() if hasattr(temp_instance, 'get_page_title') else page_name,
                'icon': temp_instance.get_page_icon() if hasattr(temp_instance, 'get_page_icon') else None,
                'ready': temp_instance.is_page_ready() if hasattr(temp_instance, 'is_page_ready') else True
            }
            # Cleanup temporary instance
            if hasattr(temp_instance, 'cleanup'):
                temp_instance.cleanup()
        except Exception:
            # Fallback for pages that can't be instantiated without parent
            page_info[page_name] = {
                'class': page_class,
                'title': page_name.replace('_', ' ').title(),
                'icon': None,
                'ready': True
            }
    
    return page_info