# app/widgets/advanced_theme_widget.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QFrame
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QPixmap, QPainter, QColor

class AdvancedThemeWidget(QWidget):
    """Widget for advanced theme selection and preview"""
    
    theme_selected = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the theme selection UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        title = QLabel("Advanced Theme Selection")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(title)
        
        # Theme selector
        selector_layout = QHBoxLayout()
        
        selector_layout.addWidget(QLabel("Theme:"))
        
        self.theme_combo = QComboBox()
        self.theme_combo.setMinimumWidth(200)
        selector_layout.addWidget(self.theme_combo)
        
        self.apply_button = QPushButton("Apply Theme")
        self.apply_button.clicked.connect(self.apply_selected_theme)
        selector_layout.addWidget(self.apply_button)
        
        selector_layout.addStretch()
        layout.addLayout(selector_layout)
        
        # Preview area
        preview_label = QLabel("Theme Preview:")
        preview_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(preview_label)
        
        self.preview_frame = QFrame()
        self.preview_frame.setFixedHeight(100)
        self.preview_frame.setStyleSheet("""
            QFrame {
                border: 1px solid #64C8FF;
                border-radius: 8px;
                background-color: rgba(20, 30, 40, 100);
            }
        """)
        layout.addWidget(self.preview_frame)
        
        # Preview content
        preview_layout = QHBoxLayout(self.preview_frame)
        self.preview_elements = []
        
        # Sample button
        sample_btn = QPushButton("Sample Button")
        sample_btn.setEnabled(False)
        preview_layout.addWidget(sample_btn)
        self.preview_elements.append(sample_btn)
        
        # Sample label
        sample_label = QLabel("Sample Text")
        preview_layout.addWidget(sample_label)
        self.preview_elements.append(sample_label)
        
        preview_layout.addStretch()
        
        layout.addStretch()
        
    def load_themes(self, theme_manager):
        """Load available themes into combo box"""
        self.theme_manager = theme_manager
        self.theme_combo.clear()
        
        for theme_id, theme_name in theme_manager.get_available_themes():
            self.theme_combo.addItem(theme_name, theme_id)
            
        # Set current theme
        current = theme_manager.get_current_theme()
        for i in range(self.theme_combo.count()):
            if self.theme_combo.itemData(i) == current:
                self.theme_combo.setCurrentIndex(i)
                break
                
        # Connect preview update
        self.theme_combo.currentTextChanged.connect(self.update_preview)
        self.update_preview()
        
    def update_preview(self):
        """Update theme preview"""
        if not hasattr(self, 'theme_manager'):
            return
            
        theme_id = self.theme_combo.currentData()
        if theme_id in self.theme_manager.available_themes:
            theme = self.theme_manager.available_themes[theme_id]
            
            # Update preview frame colors
            preview_style = f"""
                QFrame {{
                    border: 2px solid {theme['primary']};
                    border-radius: 8px;
                    background-color: {theme['surface']};
                }}
            """
            self.preview_frame.setStyleSheet(preview_style)
            
            # Update preview elements
            for element in self.preview_elements:
                if isinstance(element, QPushButton):
                    element.setStyleSheet(f"""
                        QPushButton {{
                            background-color: {theme['surface']};
                            border: 1px solid {theme['primary']};
                            color: {theme['text']};
                            padding: 4px 8px;
                            border-radius: 4px;
                        }}
                    """)
                elif isinstance(element, QLabel):
                    element.setStyleSheet(f"color: {theme['text']};")
                    
    def apply_selected_theme(self):
        """Apply the selected theme"""
        theme_id = self.theme_combo.currentData()
        if theme_id:
            self.theme_selected.emit(theme_id)