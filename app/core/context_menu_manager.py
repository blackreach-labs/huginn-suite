from PyQt6.QtWidgets import QMenu
from PyQt6.QtCore import QObject, pyqtSignal

class ContextMenuManager(QObject):
    copy_text = pyqtSignal(str)
    clear_output = pyqtSignal()
    export_results = pyqtSignal()
    save_to_file = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
    
    def create_terminal_menu(self, widget, selected_text):
        return QMenu()
    
    def create_input_menu(self, widget):
        return QMenu()