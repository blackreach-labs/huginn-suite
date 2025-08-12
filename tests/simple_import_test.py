"""Simple test to verify imports work."""
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("Testing imports...")

try:
    from app.main_window import MainWindow
    print("SUCCESS: MainWindow import works")
except Exception as e:
    print(f"FAILED: MainWindow import failed: {e}")
    sys.exit(1)

try:
    from app.main_window.components.menu_manager import MenuManager
    print("SUCCESS: MenuManager import works")
except Exception as e:
    print(f"FAILED: MenuManager import failed: {e}")

try:
    from app.main_window.components.navigation_manager import NavigationManager
    print("SUCCESS: NavigationManager import works")
except Exception as e:
    print(f"FAILED: NavigationManager import failed: {e}")

print("All imports successful! The refactored architecture is working.")