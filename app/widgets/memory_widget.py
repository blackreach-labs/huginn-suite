from PyQt6.QtWidgets import QWidget, QLabel, QHBoxLayout

class MemoryWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        self.memory_label = QLabel("Memory: OK")
        layout.addWidget(self.memory_label)
        self.setVisible(False)