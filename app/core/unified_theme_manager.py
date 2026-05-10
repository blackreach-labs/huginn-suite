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
        """Generate comprehensive QSS stylesheet"""
        return f"""
        /* Main Window */
        QMainWindow {{
            background-color: {colors['background']};
            color: {colors['text']};
        }}
        
        QWidget {{
            background-color: {colors['background']};
            color: {colors['text']};
        }}
        
        /* Frames and Containers */
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
        
        /* Input Controls */
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
        
        QTextEdit {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            font-size: 10pt;
            padding: 8px;
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
        
        QComboBox::drop-down {{
            border: none;
        }}
        
        QComboBox::down-arrow {{
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid {colors['text']};
        }}
        
        /* Buttons */
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
            background-color: {colors['text_secondary']};
            color: {colors['border']};
        }}
        
        /* Tables */
        QTableWidget {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
            border-radius: 4px;
            color: {colors['text']};
            gridline-color: {colors['border']};
        }}
        
        QHeaderView::section {{
            background-color: {colors['primary']};
            color: white;
            padding: 4px;
            border: none;
            font-weight: bold;
        }}
        
        /* Progress Bars */
        QProgressBar {{
            border: 1px solid {colors['border']};
            border-radius: 4px;
            text-align: center;
            color: {colors['text']};
            font-weight: bold;
        }}
        
        QProgressBar::chunk {{
            background-color: {colors['primary']};
            border-radius: 3px;
        }}
        
        /* Checkboxes */
        QCheckBox {{
            color: {colors['text']};
        }}
        
        QCheckBox::indicator:checked {{
            background-color: {colors['primary']};
            border: 1px solid {colors['primary']};
        }}
        
        QCheckBox::indicator:unchecked {{
            background-color: {colors['surface']};
            border: 1px solid {colors['border']};
        }}
        
        /* Labels */
        QLabel {{
            color: {colors['text']};
        }}
        
        /* Tabs */
        QTabWidget::pane {{
            border: 1px solid {colors['border']};
            background-color: {colors['surface']};
        }}
        
        QTabBar::tab {{
            background-color: {colors['surface']};
            color: {colors['text']};
            padding: 8px 12px;
            margin-right: 2px;
            border-radius: 4px 4px 0px 0px;
        }}
        
        QTabBar::tab:selected {{
            background-color: {colors['primary']};
            color: white;
        }}
        
        /* Menus */
        QMenuBar {{
            background-color: {colors['surface']};
            color: {colors['text']};
            border-bottom: 1px solid {colors['primary']}60;
        }}
        
        QMenuBar::item:selected {{
            background-color: {colors['primary']}60;
        }}
        
        QMenu {{
            background-color: {colors['surface']};
            color: {colors['text']};
            border: 1px solid {colors['primary']}60;
        }}
        
        QMenu::item:selected {{
            background-color: {colors['primary']}60;
        }}
        
        /* Status Bar */
        QStatusBar {{
            background-color: {colors['surface']};
            color: {colors['primary']};
            border-top: 1px solid {colors['primary']}60;
        }}
        
        /* Scrollbars */
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