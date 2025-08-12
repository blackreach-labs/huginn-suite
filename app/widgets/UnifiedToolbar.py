from PyQt6.QtWidgets import QToolBar, QWidget, QSizePolicy
from PyQt6.QtGui import QAction
# We've removed the problematic import for icons for now

class UnifiedToolbar(QToolBar):
    """
    A unified toolbar for the main window.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMovable(False)
        self.setStyleSheet("QToolBar { border: 0px; }")

        # --- Actions ---
        # Using text instead of icons to avoid the import error
        self.new_scan_action = QAction("New Scan", self)
        self.export_action = QAction("Export", self)
        self.settings_action = QAction("Settings", self)

        self.addAction(self.new_scan_action)
        self.addAction(self.export_action)

        # Add a spacer to push the settings icon to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.addWidget(spacer)

        self.addAction(self.settings_action)