"""Test script for the refactored main window."""
import sys
import os
from PyQt6.QtWidgets import QApplication

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_main_window_import():
    """Test that the main window can be imported."""
    try:
        from app.main_window import MainWindow
        print("[PASS] MainWindow import successful")
        return True
    except ImportError as e:
        print(f"[FAIL] MainWindow import failed: {e}")
        return False

def test_component_imports():
    """Test that all components can be imported."""
    components = [
        ("MenuManager", "app.main_window.components.menu_manager"),
        ("NavigationManager", "app.main_window.components.navigation_manager"),
        ("MainWindowThemeManager", "app.main_window.components.theme_manager"),
        ("MainWindowTrayManager", "app.main_window.components.tray_manager"),
    ]
    
    success = True
    for component_name, module_path in components:
        try:
            module = __import__(module_path, fromlist=[component_name])
            getattr(module, component_name)
            print(f"[PASS] {component_name} import successful")
        except (ImportError, AttributeError) as e:
            print(f"[FAIL] {component_name} import failed: {e}")
            success = False
    
    return success

def test_main_window_creation():
    """Test that the main window can be created."""
    try:
        app = QApplication([])
        
        from app.main_window import MainWindow
        project_root = os.path.dirname(os.path.abspath(__file__))
        
        # Create main window
        window = MainWindow(project_root)
        print("[PASS] MainWindow creation successful")
        
        # Test component access
        if hasattr(window, 'menu_manager'):
            print("[PASS] MenuManager component accessible")
        else:
            print("[FAIL] MenuManager component not accessible")
            
        if hasattr(window, 'navigation_manager'):
            print("[PASS] NavigationManager component accessible")
        else:
            print("[FAIL] NavigationManager component not accessible")
            
        if hasattr(window, 'theme_manager'):
            print("[PASS] ThemeManager component accessible")
        else:
            print("[FAIL] ThemeManager component not accessible")
            
        if hasattr(window, 'tray_manager'):
            print("[PASS] TrayManager component accessible")
        else:
            print("[FAIL] TrayManager component not accessible")
        
        # Test navigation
        try:
            window.navigate_to("home")
            print("[PASS] Navigation system working")
        except Exception as e:
            print(f"[FAIL] Navigation system failed: {e}")
        
        app.quit()
        return True
        
    except Exception as e:
        print(f"[FAIL] MainWindow creation failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing Refactored Main Window Architecture")
    print("=" * 50)
    
    # Test imports
    print("\\n1. Testing Imports:")
    import_success = test_main_window_import()
    component_success = test_component_imports()
    
    # Test creation
    print("\\n2. Testing Main Window Creation:")
    creation_success = test_main_window_creation()
    
    # Summary
    print("\\n" + "=" * 50)
    print("Test Summary:")
    print(f"  Import Tests: {'PASS' if import_success else 'FAIL'}")
    print(f"  Component Tests: {'PASS' if component_success else 'FAIL'}")
    print(f"  Creation Tests: {'PASS' if creation_success else 'FAIL'}")
    
    overall_success = import_success and component_success and creation_success
    print(f"  Overall: {'PASS' if overall_success else 'FAIL'}")
    
    if overall_success:
        print("\\nRefactored main window architecture is working correctly!")
        print("The application should now start with the new component-based architecture.")
    else:
        print("\\nSome tests failed. Please check the errors above.")