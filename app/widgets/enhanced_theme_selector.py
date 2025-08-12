# app/widgets/enhanced_theme_selector.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, 
                             QPushButton, QLabel, QScrollArea, QWidget, QFrame,
                             QMessageBox, QProgressBar)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QPixmap, QPainter, QColor, QLinearGradient

class ThemePreviewWidget(QFrame):
    """Widget to show theme preview"""
    
    def __init__(self, theme_name, theme_data, parent=None):
        super().__init__(parent)
        self.theme_name = theme_name
        self.theme_data = theme_data
        self.setFixedSize(200, 150)
        self.setFrameStyle(QFrame.Shape.Box)
        self.setLineWidth(2)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Theme name
        name_label = QLabel(theme_data.get('name', theme_name))
        name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name_label.setStyleSheet("font-weight: bold; font-size: 12pt;")
        layout.addWidget(name_label)
        
        # Preview area
        preview_area = QFrame()
        preview_area.setFixedHeight(80)
        preview_area.setStyleSheet(f"""
            QFrame {{
                background: {theme_data.get('colors', {}).get('background', '#1a1a1a')};
                border: 1px solid {theme_data.get('colors', {}).get('accent', '#64C8FF')};
                border-radius: 4px;
            }}
        """)
        layout.addWidget(preview_area)
        
        # Description
        desc_label = QLabel(theme_data.get('description', 'No description'))
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("font-size: 9pt; color: #888;")
        layout.addWidget(desc_label)
        
        # Apply theme colors to this widget
        self.setStyleSheet(f"""
            ThemePreviewWidget {{
                background-color: {theme_data.get('colors', {}).get('surface', '#2a2a2a')};
                border: 2px solid {theme_data.get('colors', {}).get('accent', '#64C8FF')};
                border-radius: 8px;
            }}
            QLabel {{
                color: {theme_data.get('colors', {}).get('text', '#FFFFFF')};
            }}
        """)

class ThemeSelectionDialog(QDialog):
    """Enhanced theme selection dialog"""
    
    theme_selected = pyqtSignal(str)
    
    def __init__(self, theme_manager, parent=None):
        super().__init__(parent)
        self.theme_manager = theme_manager
        self.setWindowTitle("Theme Selector")
        self.setModal(True)
        self.resize(800, 600)
        
        self.setup_ui()
        self.load_themes()
        
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header_label = QLabel("Select Theme")
        header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_label.setStyleSheet("font-size: 18pt; font-weight: bold; margin: 10px;")
        layout.addWidget(header_label)
        
        # Scroll area for themes
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        self.themes_widget = QWidget()
        self.themes_layout = QGridLayout(self.themes_widget)
        self.themes_layout.setSpacing(15)
        
        scroll_area.setWidget(self.themes_widget)
        layout.addWidget(scroll_area)
        
        # Progress bar for theme loading
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.apply_button = QPushButton("Apply Theme")
        self.apply_button.setEnabled(False)
        self.apply_button.clicked.connect(self.apply_selected_theme)
        button_layout.addWidget(self.apply_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        
        self.selected_theme = None
        
    def load_themes(self):
        """Load and display available themes"""
        themes = self.theme_manager.get_all_themes()
        
        # Handle both dict and list formats
        if isinstance(themes, list):
            themes_dict = {}
            for theme in themes:
                if isinstance(theme, tuple) and len(theme) == 2:
                    themes_dict[theme[0]] = {'name': theme[1]}
                else:
                    themes_dict[str(theme)] = {'name': str(theme)}
            themes = themes_dict
        
        row = 0
        col = 0
        max_cols = 3
        
        for theme_key, theme_data in themes.items():
            preview = ThemePreviewWidget(theme_key, theme_data, self)
            
            # Make clickable
            preview.mousePressEvent = lambda event, key=theme_key: self.select_theme(key)
            
            # Add locked indicator for premium themes
            if not self.theme_manager.is_theme_available(theme_key):
                lock_label = QLabel("🔒")
                lock_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                lock_label.setStyleSheet("font-size: 24pt; color: #FFD700;")
                lock_label.setParent(preview)
                lock_label.move(preview.width() - 30, 5)
                
                # Dim the preview
                preview.setStyleSheet(preview.styleSheet() + "opacity: 0.6;")
            
            self.themes_layout.addWidget(preview, row, col)
            
            col += 1
            if col >= max_cols:
                col = 0
                row += 1
    
    def select_theme(self, theme_key):
        """Select a theme"""
        if not self.theme_manager.is_theme_available(theme_key):
            # Show upgrade dialog
            theme_data = self.theme_manager.get_theme_colors(theme_key)
            QMessageBox.information(
                self,
                "Professional Theme",
                f"Theme '{theme_data.get('name', theme_key)}' requires a Professional license.\n\n"
                "Upgrade to Professional license to unlock all premium themes."
            )
            return
        
        # Clear previous selection
        for i in range(self.themes_layout.count()):
            widget = self.themes_layout.itemAt(i).widget()
            if isinstance(widget, ThemePreviewWidget):
                widget.setFrameStyle(QFrame.Shape.Box)
                widget.setLineWidth(2)
        
        # Highlight selected theme
        for i in range(self.themes_layout.count()):
            widget = self.themes_layout.itemAt(i).widget()
            if isinstance(widget, ThemePreviewWidget) and widget.theme_name == theme_key:
                widget.setFrameStyle(QFrame.Shape.Box)
                widget.setLineWidth(4)
                widget.setStyleSheet(widget.styleSheet() + "border-color: #FFD700;")
                break
        
        self.selected_theme = theme_key
        self.apply_button.setEnabled(True)
    
    def apply_selected_theme(self):
        """Apply the selected theme"""
        if not self.selected_theme:
            return
        
        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        # Apply theme with delay for visual feedback
        QTimer.singleShot(500, self._apply_theme)
    
    def _apply_theme(self):
        """Actually apply the theme"""
        try:
            self.theme_manager.set_theme(self.selected_theme)
            self.theme_selected.emit(self.selected_theme)
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to apply theme: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)