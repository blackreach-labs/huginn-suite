from PyQt6.QtWidgets import QWidget, QLabel, QHBoxLayout

class CacheStatusWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        self.status_label = QLabel("Cache: Ready")
        layout.addWidget(self.status_label)
        self.setVisible(False)
    
    def update_status(self, status):
        self.status_label.setText(f"Cache: {status}")