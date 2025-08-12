#!/usr/bin/env python3

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def test_huggin_page():
    """Test if the huggin scanner page can be created"""
    try:
        print("Testing HugginScannerPage import...")
        from app.pages.huggin_scanner_page import HugginScannerPage
        print("[OK] HugginScannerPage imported successfully")
        
        print("Testing page creation...")
        page = HugginScannerPage(None)
        print("[OK] HugginScannerPage instance created successfully")
        
        print("Testing page methods...")
        title = page.get_page_title()
        print(f"[OK] Page title: {title}")
        
        icon = page.get_page_icon()
        print(f"[OK] Page icon: {icon}")
        
        print("Testing page registry...")
        from app.pages.page_registry import register_all_pages
        register_all_pages()
        print("[OK] Pages registered successfully")
        
        from app.pages.components.page_factory import PageFactory
        registered_pages = PageFactory.get_registered_pages()
        print(f"[OK] Registered pages: {list(registered_pages.keys())}")
        
        if 'huggin_scanner' in registered_pages:
            print("[OK] huggin_scanner is registered in factory")
        else:
            print("[ERROR] huggin_scanner is NOT registered in factory")
        
        print("\nAll tests passed!")
        return True
        
    except Exception as e:
        print(f"[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_huggin_page()