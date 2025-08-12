from sys import argv, exit
from os.path import dirname, abspath, join, exists
import atexit
from signal import signal, SIGINT, SIGTERM
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFontDatabase
from app.main_window import MainWindow
from app.core.logger import logger
from app.core.error_handler import setup_global_error_handling
from app.core.local_dns_server import local_dns_server
from app.core.vpn_manager import vpn_manager
from app.core.update_manager import update_manager

def _load_font(project_root):
    """Load application font with error handling"""
    try:
        font_path = join(project_root, "resources", "fonts", "neuropol.otf")
        if exists(font_path):
            QFontDatabase.addApplicationFont(font_path)
            logger.info("Font loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load font: {e}")

def _load_stylesheet(project_root, app):
    """Load application stylesheet with error handling"""
    try:
        theme_path = join(project_root, "resources", "themes", "default", "style.qss")
        if exists(theme_path):
            with open(theme_path, 'r') as f:
                app.setStyleSheet(f.read())
            logger.info("Stylesheet loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load stylesheet: {e}")

def _cleanup_dns_server():
    """Stop DNS server if running"""
    try:
        if hasattr(local_dns_server, 'running') and local_dns_server.running:
            local_dns_server.stop_server()
            logger.info("Local DNS server stopped during cleanup")
    except Exception as e:
        logger.error(f"Error stopping DNS server: {e}")

def _cleanup_vpn():
    """Disconnect VPN if connected"""
    try:
        if hasattr(vpn_manager, 'is_connected') and vpn_manager.is_connected:
            vpn_manager.disconnect()
            logger.info("VPN disconnected during cleanup")
    except Exception as e:
        logger.error(f"Error disconnecting VPN: {e}")

def _cleanup_update_manager():
    """Stop update manager"""
    try:
        update_manager.stop_auto_check()
        logger.info("Update manager stopped during cleanup")
    except Exception as e:
        logger.error(f"Error stopping update manager: {e}")

def cleanup_on_exit():
    """Cleanup function called when application exits"""
    _cleanup_dns_server()
    _cleanup_vpn()
    _cleanup_update_manager()

def signal_handler(signum, frame):
    """Handle system signals for graceful shutdown"""
    logger.info("Received shutdown signal, initiating cleanup...")
    cleanup_on_exit()
    exit(0)

def main():
    """
    The main entry point for the Huggin application.
    """
    # Register cleanup function
    atexit.register(cleanup_on_exit)
    
    # Register signal handlers for graceful shutdown
    signal(SIGINT, signal_handler)
    signal(SIGTERM, signal_handler)
    
    # --- Application Setup ---
    # This MUST be the first thing that happens.
    app = QApplication(argv)
    
    # Setup global error handling
    setup_global_error_handling()

    # --- Configuration and Logging ---
    project_root = dirname(abspath(__file__))
    
    logger.info("Application starting...")
    
    # Load resources with error handling
    _load_font(project_root)
    _load_stylesheet(project_root, app)
    
    # Create main window
    logger.info("Creating main window...")
    window = MainWindow(project_root=project_root)
    

    
    window.show()

    # --- Start Event Loop ---
    exit(app.exec())

if __name__ == "__main__":
    main()