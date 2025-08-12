from PyQt6.QtWidgets import QWidget, QVBoxLayout
from PyQt6.QtCore import QSize

class CollapsibleWidget(QWidget):
    def __init__(self, child_widget):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(child_widget)
        self._child = child_widget

    def setVisible(self, visible: bool):
        super().setVisible(visible)
        self.updateGeometry()

    def sizeHint(self) -> QSize:
        if not self.isVisible():
            return QSize(0, 0)
        return super().sizeHint()
    
    def minimumSizeHint(self) -> QSize:
        if not self.isVisible():
            return QSize(0, 0)
        return super().minimumSizeHint()