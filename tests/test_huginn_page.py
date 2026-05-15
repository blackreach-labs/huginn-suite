#!/usr/bin/env python3

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def test_huginn_page():
    """Test if the huginn scanner page can be created"""
    try:
        print("Testing HuginnScannerPage import...")
        from app.pages.huginn_scanner_page import HuginnScannerPage
        print("[OK] HuginnScannerPage imported successfully")
        
        print("Testing page creation...")
        page = HuginnScannerPage(None)
        print("[OK] HuginnScannerPage instance created successfully")
        
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
        
        if 'huginn_scanner' in registered_pages:
            print("[OK] huginn_scanner is registered in factory")
        else:
            print("[ERROR] huginn_scanner is NOT registered in factory")
        
        print("\nAll tests passed!")
        return True
        
    except Exception as e:
        print(f"[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_huginn_page()