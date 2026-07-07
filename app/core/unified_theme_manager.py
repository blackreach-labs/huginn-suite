# app/core/unified_theme_manager.py
import json
import os
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication
from app.core.logger import logger

class UnifiedThemeManager(QObject):
    """Unified theme manager combining all theme management functionality.
    
    Provides comprehensive theme management including:
    - Multiple predefined themes (Dark, Light, Cyberpunk, Matrix, Ocean)
    - Theme persistence and loading
    - Dynamic stylesheet generation
    - Resource path resolution
    - Signal-based theme change notifications
    """
    
    theme_changed = pyqtSignal(str)
    
    def __init__(self, project_root):
        super().__init__()
        self.project_root = Path(project_root)
        self.themes_dir = self.project_root / "resources" / "themes"
        self.settings_file = self.project_root / "resources" / "config" / "theme_settings.json"
        self.current_theme = "dark"
        
        # Load predefined themes
        self.themes = self._load_predefined_themes()
        
        # Load user preference
        self._load_theme_preference()
    
    def _load_predefined_themes(self):
        """Load predefined theme configurations"""
        return {
            "dark": {
                "name": "Dark Theme",
                "primary": "#64C8FF",
                "secondary": "#00FF41", 
                "accent": "#FFAA00",
                "background": "#0A0A0A",
                "surface": "#1e1e1e",
                "surface_variant": "#2d2d2d",
                "text": "#DCDCDC",
                "text_secondary": "#888888",
                "border": "#555555",
                "success": "#00AA00",
                "warning": "#FF6600",
                "error": "#FF4444"
            },
            "light": {
                "name": "Light Theme",
                "primary": "#2196F3",
                "secondary": "#4CAF50",
                "accent": "#FF9800", 
                "background": "#FFFFFF",
                "surface": "#f5f5f5",
                "surface_variant": "#e0e0e0",
                "text": "#212121",
                "text_secondary": "#757575",
                "border": "#e0e0e0",
                "success": "#4CAF50",
                "warning": "#FF9800",
                "error": "#F44336"
            },
            "cyberpunk": {
                "name": "Cyberpunk",
                "primary": "#00FFFF",
                "secondary": "#FF00FF",
                "accent": "#FFFF00",
                "background": "#000000",
                "surface": "#0A0A0A",
                "surface_variant": "#1A0A1A",
                "text": "#00FF00",
                "text_secondary": "#00AA00",
                "border": "#FF00FF",
                "success": "#00FF00",
                "warning": "#FFFF00",
                "error": "#FF0040"
            },
            "matrix": {
                "name": "Matrix",
                "primary": "#00FF41",
                "secondary": "#00AA00",
                "accent": "#AAFF00",
                "background": "#000000",
                "surface": "#001100",
                "surface_variant": "#002200",
                "text": "#00FF41",
                "text_secondary": "#00AA00",
                "border": "#00FF41",
                "success": "#00FF41",
                "warning": "#AAFF00",
                "error": "#FF4400"
            },
            "ocean": {
                "name": "Ocean Blue",
                "primary": "#0077BE",
                "secondary": "#00AAFF",
                "accent": "#00DDAA",
                "background": "#001122",
                "surface": "#001A33",
                "surface_variant": "#002244",
                "text": "#E0F6FF",
                "text_secondary": "#B0D6E6",
                "border": "#0077BE",
                "success": "#00DDAA",
                "warning": "#FFAA00",
                "error": "#FF6B6B"
            }
        }
    
    def get_available_themes(self):
        """Get list of available themes"""
        return [(key, theme["name"]) for key, theme in self.themes.items()]
    
    def get_current_theme(self):
        """Get current theme name"""
        return self.current_theme
    
    def get_theme_colors(self, theme_name=None):
        """Get theme color palette"""
        theme_name = theme_name or self.current_theme
        return self.themes.get(theme_name, self.themes["dark"])
    
    def get_theme_animations(self, theme_name=None):
        """Get theme animation settings"""
        theme_name = theme_name or self.current_theme
        
        # Define animation settings for each theme
        animations = {
            "dark": {"neon_glow": True},
            "light": {},
            "cyberpunk": {"neon_glow": True, "particle_field": True},
            "matrix": {"matrix_rain": True, "terminal_effects": True},
            "ocean": {"wave_effects": True}
        }
        
        return animations.get(theme_name, {})
    
    def set_theme(self, theme_name):
        """Set and apply theme"""
        if theme_name in self.themes:
            self.current_theme = theme_name
            self._save_theme_preference()
            self.apply_theme()
            self.theme_changed.emit(theme_name)
            return True
        return False
    
    def toggle_theme(self):
        """Toggle between dark and light themes"""
        new_theme = "light" if self.current_theme == "dark" else "dark"
        self.set_theme(new_theme)
    
    def apply_theme(self, theme_name=None):
        """Apply theme to application"""
        theme_name = theme_name or self.current_theme
        if theme_name not in self.themes:
            return False
            
        colors = self.themes[theme_name]
        stylesheet = self._generate_stylesheet(colors)
        
        app = QApplication.instance()
        if app:
            app.setStyleSheet(stylesheet)
        return True
    
    def _generate_stylesheet(self, colors):
        """Generate comprehensive QSS stylesheet covering all widget types."""
        return f"""
        /* ================================================================
           GLOBAL BASE
           ================================================================ */
        QMainWindow {{
            background-color: {colors['background']};
            color: {colors['text']};
        }}

        QWidget {{
            background-color: {colors['background']};
            color: {colors['text']};
            font-size: 10pt;
        }}

        /* ================================================================
           FRAMES & CONTAINERS
           ================================================================ */
        QFrame {{
            background-color: {colors['surface']};
            border: 1px solid {colors['primary']}40;
            border-radius: 8px;
        }}

        QGroupBox {{
            color: {colors['primary']};
            border: 2px solid {colors['border']};
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
            font-weight: bold;
        }}

        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }}

        QSplitter {{
            background-color: {colors['background']};
            border: none;
        }}

        QSplitter::handle {{
            background-color: {colors['primary']}60;
            margin: 2px;
        }}

        QSplitter::handle:horizontal {{
            width: 4px;
        }}

        QSplitter::handle:vertical {{
            height: 4px;
        }}

        QSplitter::handle:hover {{
            background-color: {colors['primary']};
        }}

        /* ================================================================
           DIALOGS & DOCK WIDGETS
           ================================================================ */
        QDialog {{
            background-color: {colors['surface']};
            color: {colors['text']};
            border: 1px solid {colors['primary']}60;
            border-radius: 8px;
        }}

        QMessageBox {{
            background-color: {colors['surface']};
            color: {colors['text']};
        }}

        QMessageBox QLabel {{
            color: {colors['text']};
        }}

        QMessageBox QPushButton {{
            min-width: 80px;
        }}

        QDockWidget {{
            background-color: {colors['surface']};
            color: {colors['primary']};
            border: 1px solid {colors['primary']}40;
            titlebar-close-icon: none;
            titlebar-normal-icon: none;
        }}

        QDockWidget::title {{
            background-color: {colors['surface_variant']};
            color: {colors['primary']};
            padding: 6px;
            border-bottom: 1px solid {colors['primary']}60;
        }}

        QDockWidget::close-button, QDockWidget::float-button {{
            background-color: transparent;
            border: none;
            padding: 2px;
        }}

        QDockWidget::close-button:hover, QDockWidget::float-button:hover {{
            background-color: {colors['primary']}40;
            border-radius: 3px;
        }}

        /* ================================================================
           INPUT CONTROLS
           ================================================================ */
        QLineEdit {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            padding: 4px 8px;
            font-size: 10pt;
        }}

        QLineEdit:focus {{
            border: 2px solid {colors['primary']};
        }}

        QLineEdit:disabled {{
            background-color: {colors['surface_variant']};
            color: {colors['text_secondary']};
            border: 1px solid {colors['border']}80;
        }}

        QTextEdit {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            font-size: 10pt;
            padding: 8px;
        }}

        QTextEdit:focus {{
            border: 2px solid {colors['primary']};
        }}

        QPlainTextEdit {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            font-size: 10pt;
            padding: 8px;
        }}

        QPlainTextEdit:focus {{
            border: 2px solid {colors['primary']};
        }}

        QComboBox {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            padding: 4px 8px;
        }}

        QComboBox:focus {{
            border: 2px solid {colors['primary']};
        }}

        QComboBox:disabled {{
            background-color: {colors['surface_variant']};
            color: {colors['text_secondary']};
        }}

        QComboBox::drop-down {{
            border: none;
            padding-right: 4px;
        }}

        QComboBox::down-arrow {{
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid {colors['text']};
        }}

        QComboBox QAbstractItemView {{
            background-color: {colors['surface']};
            border: 1px solid {colors['primary']}60;
            color: {colors['text']};
            selection-background-color: {colors['primary']}80;
            selection-color: white;
        }}

        QSpinBox, QDoubleSpinBox {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            padding: 4px 8px;
        }}

        QSpinBox:focus, QDoubleSpinBox:focus {{
            border: 2px solid {colors['primary']};
        }}

        QSpinBox:disabled, QDoubleSpinBox:disabled {{
            background-color: {colors['surface_variant']};
            color: {colors['text_secondary']};
        }}

        QSpinBox::up-button, QDoubleSpinBox::up-button {{
            background-color: {colors['surface_variant']};
            border: none;
            border-left: 1px solid {colors['border']};
            border-top-right-radius: 4px;
        }}

        QSpinBox::down-button, QDoubleSpinBox::down-button {{
            background-color: {colors['surface_variant']};
            border: none;
            border-left: 1px solid {colors['border']};
            border-bottom-right-radius: 4px;
        }}

        QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
        QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {{
            background-color: {colors['primary']}40;
        }}

        QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {{
            image: none;
            border-left: 4px solid transparent;
            border-right: 4px solid transparent;
            border-bottom: 4px solid {colors['text']};
            width: 0px;
            height: 0px;
        }}

        QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {{
            image: none;
            border-left: 4px solid transparent;
            border-right: 4px solid transparent;
            border-top: 4px solid {colors['text']};
            width: 0px;
            height: 0px;
        }}

        /* ================================================================
           BUTTONS
           ================================================================ */
        QPushButton {{
            background-color: {colors['primary']};
            color: white;
            border: none;
            border-radius: 4px;
            padding: 6px 12px;
            font-size: 10pt;
            font-weight: bold;
        }}

        QPushButton:hover {{
            background-color: {colors['accent']};
        }}

        QPushButton:pressed {{
            background-color: {colors['primary']}CC;
        }}

        QPushButton:disabled {{
            background-color: {colors['surface_variant']};
            color: {colors['text_secondary']};
            border: 1px solid {colors['border']}80;
        }}

        QToolButton {{
            background-color: {colors['surface']};
            color: {colors['text']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            padding: 4px;
        }}

        QToolButton:hover {{
            background-color: {colors['primary']}40;
            border: 1px solid {colors['primary']};
        }}

        QToolButton:pressed {{
            background-color: {colors['primary']}80;
        }}

        QToolButton:checked {{
            background-color: {colors['primary']};
            color: white;
        }}

        QToolButton:disabled {{
            background-color: {colors['surface_variant']};
            color: {colors['text_secondary']};
        }}

        /* ================================================================
           TABLES
           ================================================================ */
        QTableWidget, QTableView {{
            background-color: {colors['surface']};
            alternate-background-color: {colors['surface_variant']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            gridline-color: {colors['border']}80;
            selection-background-color: {colors['primary']}80;
            selection-color: white;
        }}

        QTableWidget::item, QTableView::item {{
            padding: 4px 8px;
            border-bottom: 1px solid {colors['border']}40;
        }}

        QTableWidget::item:selected, QTableView::item:selected {{
            background-color: {colors['primary']}80;
            color: white;
        }}

        QTableWidget::item:hover, QTableView::item:hover {{
            background-color: {colors['primary']}30;
        }}

        QHeaderView::section {{
            background-color: {colors['primary']};
            color: white;
            padding: 6px 8px;
            border: none;
            border-right: 1px solid {colors['primary']}CC;
            font-weight: bold;
        }}

        QHeaderView::section:hover {{
            background-color: {colors['accent']};
        }}

        /* ================================================================
           TREE & LIST VIEWS
           ================================================================ */
        QTreeWidget, QTreeView {{
            background-color: {colors['surface']};
            alternate-background-color: {colors['surface_variant']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            selection-background-color: {colors['primary']}80;
            selection-color: white;
        }}

        QTreeWidget::item, QTreeView::item {{
            padding: 4px 2px;
            border: none;
        }}

        QTreeWidget::item:selected, QTreeView::item:selected {{
            background-color: {colors['primary']}80;
            color: white;
        }}

        QTreeWidget::item:hover, QTreeView::item:hover {{
            background-color: {colors['primary']}30;
        }}

        QTreeWidget::branch {{
            background-color: transparent;
        }}

        QListWidget, QListView {{
            background-color: {colors['surface']};
            alternate-background-color: {colors['surface_variant']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            selection-background-color: {colors['primary']}80;
            selection-color: white;
        }}

        QListWidget::item, QListView::item {{
            padding: 4px 8px;
            border: none;
        }}

        QListWidget::item:selected, QListView::item:selected {{
            background-color: {colors['primary']}80;
            color: white;
        }}

        QListWidget::item:hover, QListView::item:hover {{
            background-color: {colors['primary']}30;
        }}

        /* ================================================================
           PROGRESS BARS
           ================================================================ */
        QProgressBar {{
            border: 1px solid {colors['border']};
            border-radius: 4px;
            text-align: center;
            color: {colors['text']};
            font-weight: bold;
            background-color: {colors['surface']};
        }}

        QProgressBar::chunk {{
            background-color: {colors['primary']};
            border-radius: 3px;
        }}

        /* ================================================================
           CHECKBOXES & RADIO BUTTONS
           ================================================================ */
        QCheckBox {{
            color: {colors['text']};
            spacing: 8px;
        }}

        QCheckBox::indicator {{
            width: 16px;
            height: 16px;
            border-radius: 3px;
        }}

        QCheckBox::indicator:checked {{
            background-color: {colors['primary']};
            border: 1px solid {colors['primary']};
        }}

        QCheckBox::indicator:unchecked {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
        }}

        QCheckBox::indicator:unchecked:hover {{
            border: 1px solid {colors['primary']};
        }}

        QCheckBox:disabled {{
            color: {colors['text_secondary']};
        }}

        QCheckBox::indicator:disabled {{
            background-color: {colors['surface_variant']};
            border: 1px solid {colors['border']}80;
        }}

        QRadioButton {{
            color: {colors['text']};
            spacing: 8px;
        }}

        QRadioButton::indicator {{
            width: 16px;
            height: 16px;
            border-radius: 8px;
        }}

        QRadioButton::indicator:checked {{
            background-color: {colors['primary']};
            border: 2px solid {colors['primary']};
        }}

        QRadioButton::indicator:unchecked {{
            background-color: {colors['surface']};
            border: 2px solid {colors['border']};
        }}

        QRadioButton::indicator:unchecked:hover {{
            border: 2px solid {colors['primary']};
        }}

        QRadioButton:disabled {{
            color: {colors['text_secondary']};
        }}

        /* ================================================================
           LABELS
           ================================================================ */
        QLabel {{
            color: {colors['text']};
            border: none;
            background-color: transparent;
        }}

        /* ================================================================
           TABS
           ================================================================ */
        QTabWidget::pane {{
            border: 1px solid {colors['border']};
            background-color: {colors['surface']};
            border-radius: 0px 0px 4px 4px;
        }}

        QTabBar::tab {{
            background-color: {colors['surface_variant']};
            color: {colors['text_secondary']};
            padding: 8px 16px;
            margin-right: 2px;
            border-radius: 4px 4px 0px 0px;
            border: 1px solid {colors['border']}60;
            border-bottom: none;
        }}

        QTabBar::tab:selected {{
            background-color: {colors['primary']};
            color: white;
            border: 1px solid {colors['primary']};
            border-bottom: none;
        }}

        QTabBar::tab:hover:!selected {{
            background-color: {colors['primary']}30;
            color: {colors['text']};
        }}

        /* ================================================================
           MENUS
           ================================================================ */
        QMenuBar {{
            background-color: {colors['surface']};
            color: {colors['text']};
            border-bottom: 1px solid {colors['primary']}60;
            padding: 2px;
        }}

        QMenuBar::item {{
            background-color: transparent;
            padding: 4px 8px;
            border-radius: 4px;
        }}

        QMenuBar::item:selected {{
            background-color: {colors['primary']}60;
        }}

        QMenu {{
            background-color: {colors['surface']};
            color: {colors['text']};
            border: 1px solid {colors['primary']}60;
            border-radius: 4px;
            padding: 4px;
        }}

        QMenu::item {{
            padding: 6px 24px 6px 12px;
            border-radius: 3px;
        }}

        QMenu::item:selected {{
            background-color: {colors['primary']}60;
        }}

        QMenu::separator {{
            height: 1px;
            background-color: {colors['border']}60;
            margin: 4px 8px;
        }}

        /* ================================================================
           TOOLBAR
           ================================================================ */
        QToolBar {{
            background-color: {colors['surface']};
            border: none;
            border-bottom: 1px solid {colors['primary']}40;
            padding: 2px;
            spacing: 4px;
        }}

        QToolBar::separator {{
            width: 1px;
            background-color: {colors['border']}60;
            margin: 4px 2px;
        }}

        /* ================================================================
           STATUS BAR
           ================================================================ */
        QStatusBar {{
            background-color: {colors['surface']};
            color: {colors['primary']};
            border-top: 1px solid {colors['primary']}60;
        }}

        QStatusBar::item {{
            border: none;
        }}

        /* ================================================================
           SCROLLBARS
           ================================================================ */
        QScrollBar:vertical {{
            background-color: {colors['surface_variant']};
            width: 12px;
            border-radius: 6px;
            margin: 0px;
        }}

        QScrollBar::handle:vertical {{
            background-color: {colors['primary']};
            border-radius: 6px;
            min-height: 20px;
            margin: 2px;
        }}

        QScrollBar::handle:vertical:hover {{
            background-color: {colors['accent']};
        }}

        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}

        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
            background-color: transparent;
        }}

        QScrollBar:horizontal {{
            background-color: {colors['surface_variant']};
            height: 12px;
            border-radius: 6px;
            margin: 0px;
        }}

        QScrollBar::handle:horizontal {{
            background-color: {colors['primary']};
            border-radius: 6px;
            min-width: 20px;
            margin: 2px;
        }}

        QScrollBar::handle:horizontal:hover {{
            background-color: {colors['accent']};
        }}

        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}

        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{
            background-color: transparent;
        }}

        /* ================================================================
           SLIDERS
           ================================================================ */
        QSlider::groove:horizontal {{
            border: none;
            height: 4px;
            background-color: {colors['surface_variant']};
            border-radius: 2px;
        }}

        QSlider::handle:horizontal {{
            background-color: {colors['primary']};
            border: none;
            width: 16px;
            height: 16px;
            margin: -6px 0;
            border-radius: 8px;
        }}

        QSlider::handle:horizontal:hover {{
            background-color: {colors['accent']};
        }}

        QSlider::sub-page:horizontal {{
            background-color: {colors['primary']};
            border-radius: 2px;
        }}

        QSlider::groove:vertical {{
            border: none;
            width: 4px;
            background-color: {colors['surface_variant']};
            border-radius: 2px;
        }}

        QSlider::handle:vertical {{
            background-color: {colors['primary']};
            border: none;
            width: 16px;
            height: 16px;
            margin: 0 -6px;
            border-radius: 8px;
        }}

        QSlider::handle:vertical:hover {{
            background-color: {colors['accent']};
        }}

        /* ================================================================
           TOOLTIPS
           ================================================================ */
        QToolTip {{
            background-color: {colors['surface']};
            color: {colors['text']};
            border: 1px solid {colors['primary']}80;
            border-radius: 4px;
            padding: 4px 8px;
        }}
        """
    
    def load_custom_theme(self, theme_file_path):
        """Load custom theme from JSON file"""
        try:
            with open(theme_file_path, 'r') as f:
                theme_data = json.load(f)
            
            # Convert relative paths to absolute
            for category in theme_data.values():
                if isinstance(category, dict):
                    for key, value in category.items():
                        if isinstance(value, str) and value.endswith('.png'):
                            absolute_path = self.project_root / value
                            category[key] = str(absolute_path).replace('\\', '/')
            
            return theme_data
        except Exception as e:
            print(f"Error loading custom theme: {e}")
            return None
    
    def get_resource_path(self, relative_path):
        """Get absolute path for theme resource"""
        absolute_path = self.project_root / relative_path
        return str(absolute_path).replace('\\', '/')
    
    def _save_theme_preference(self):
        """Save current theme preference"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump({"theme": self.current_theme}, f)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _load_theme_preference(self):
        """Load saved theme preference"""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r') as f:
                    data = json.load(f)
                    theme = data.get("theme", "dark")
                    if theme in self.themes:
                        self.current_theme = theme
        except Exception:
            self.current_theme = "dark"

# Global instance
unified_theme_manager = None

def get_theme_manager(project_root=None):
    """Get global theme manager instance"""
    global unified_theme_manager
    if unified_theme_manager is None and project_root:
        unified_theme_manager = UnifiedThemeManager(project_root)
    return unified_theme_manager