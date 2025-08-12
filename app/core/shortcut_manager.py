from PyQt6.QtCore import QObject, pyqtSignal

class ShortcutManager(QObject):
    new_scan = pyqtSignal()
    export_results = pyqtSignal()
    toggle_theme = pyqtSignal()
    show_help = pyqtSignal()
    pause_scan = pyqtSignal()
    stop_scan = pyqtSignal()
    multi_target = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)