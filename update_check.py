#!/usr/bin/env python3
"""Standalone update checker for Huginn"""

from app.core.auto_updater import SecureUpdater
from app.ui.update_dialog import UpdateDialog
from PyQt5.QtWidgets import QApplication
import sys

def main():
    app = QApplication(sys.argv)
    
    updater = SecureUpdater()
    manifest = updater.check_for_updates()
    
    if manifest:
        dialog = UpdateDialog(manifest)
        if dialog.exec_() == dialog.Accepted:
            updater.restart_application()
    else:
        print("No updates available")
    
    sys.exit(0)

if __name__ == "__main__":
    main()