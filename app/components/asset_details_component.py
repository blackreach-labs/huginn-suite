from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import pyqtSignal

class AssetDetailsComponent(QWidget):
    back_to_list = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup details UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Back button
        self.back_button = QPushButton("← Back to List")
        self.back_button.clicked.connect(self.back_to_list.emit)
        self.back_button.setFixedWidth(150)
        layout.addWidget(self.back_button)
        
        # Details content
        try:
            from app.widgets.asset_details_widget import AssetDetailsWidget
            self.details_widget = AssetDetailsWidget()
            layout.addWidget(self.details_widget)
        except ImportError:
            placeholder = QLabel("Asset details widget not available")
            placeholder.setStyleSheet("color: #FF6B6B; padding: 20px;")
            layout.addWidget(placeholder)
            self.details_widget = None

    def update_asset(self, asset):
        """Update asset details"""
        if self.details_widget:
            self.details_widget.update_asset(asset)

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
        """)