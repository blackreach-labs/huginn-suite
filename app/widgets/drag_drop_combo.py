from PyQt6.QtWidgets import QComboBox
from PyQt6.QtCore import pyqtSignal
from app.core.drag_drop_handler import DragDropMixin

class DragDropComboBox(QComboBox, DragDropMixin):
    file_dropped = pyqtSignal(str)

    def __init__(self, parent=None):
        QComboBox.__init__(self, parent)
        DragDropMixin.__init__(self)
        self.set_drop_callback(self.handle_file_drop)

    def handle_file_drop(self, file_paths):
        if file_paths:
            self.file_dropped.emit(file_paths[0])