from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame
from PyQt6.QtCore import pyqtSignal

class AssetGraphicsComponent(QWidget):
    asset_selected = pyqtSignal(str)
    asset_context_menu = pyqtSignal(str, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup graphics UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        title = QLabel("Asset Overview")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF; margin-bottom: 10px;")
        layout.addWidget(title)
        
        try:
            from app.widgets.asset_graphics_widget import AssetGraphicsWidget
            self.graphics_widget = AssetGraphicsWidget()
            self.graphics_widget.asset_selected.connect(self.asset_selected.emit)
            self.graphics_widget.asset_context_menu.connect(self.asset_context_menu.emit)
            layout.addWidget(self.graphics_widget)
        except ImportError:
            placeholder = QLabel("Asset graphics not available")
            placeholder.setStyleSheet("color: #FF6B6B; padding: 20px;")
            layout.addWidget(placeholder)
            self.graphics_widget = None

    def update_assets(self, assets):
        """Update asset graphics"""
        if self.graphics_widget:
            self.graphics_widget.update_assets(assets)

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass