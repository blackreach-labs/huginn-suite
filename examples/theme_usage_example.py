# examples/theme_usage_example.py
"""
Example usage of the Unified Theme Manager

This example demonstrates how to use the consolidated theme manager
in your application components.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton, QLabel
from PyQt6.QtCore import Qt
from app.core.unified_theme_manager import get_theme_manager

class ThemeExampleWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unified Theme Manager Example")
        self.setGeometry(100, 100, 600, 400)
        
        # Get theme manager instance
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.theme_manager = get_theme_manager(project_root)
        
        # Connect to theme change signal
        self.theme_manager.theme_changed.connect(self.on_theme_changed)
        
        self.setup_ui()
        
        # Apply initial theme
        self.theme_manager.apply_theme()
    
    def setup_ui(self):
        """Setup the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Title
        title = QLabel("Unified Theme Manager Demo")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 18pt; font-weight: bold; margin: 20px;")
        layout.addWidget(title)
        
        # Current theme display
        self.current_theme_label = QLabel()
        self.update_current_theme_display()
        self.current_theme_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.current_theme_label)
        
        # Theme buttons
        for theme_key, theme_name in self.theme_manager.get_available_themes():
            btn = QPushButton(f"Apply {theme_name}")
            btn.clicked.connect(lambda checked, key=theme_key: self.apply_theme(key))
            layout.addWidget(btn)
        
        # Toggle button
        toggle_btn = QPushButton("Toggle Dark/Light")
        toggle_btn.clicked.connect(self.theme_manager.toggle_theme)
        layout.addWidget(toggle_btn)
        
        # Color info
        self.color_info = QLabel()
        self.update_color_info()
        layout.addWidget(self.color_info)
    
    def apply_theme(self, theme_key):
        """Apply selected theme"""
        success = self.theme_manager.set_theme(theme_key)
        if success:
            print(f"Applied theme: {theme_key}")
        else:
            print(f"Failed to apply theme: {theme_key}")
    
    def on_theme_changed(self, theme_name):
        """Handle theme change event"""
        print(f"Theme changed to: {theme_name}")
        self.update_current_theme_display()
        self.update_color_info()
    
    def update_current_theme_display(self):
        """Update current theme display"""
        current = self.theme_manager.get_current_theme()
        colors = self.theme_manager.get_theme_colors()
        self.current_theme_label.setText(f"Current Theme: {colors['name']}")
    
    def update_color_info(self):
        """Update color information display"""
        colors = self.theme_manager.get_theme_colors()
        info_text = f"""
        Primary: {colors['primary']}
        Background: {colors['background']}
        Text: {colors['text']}
        Accent: {colors['accent']}
        """
        self.color_info.setText(info_text)

def main():
    """Run the theme example"""
    app = QApplication(sys.argv)
    
    window = ThemeExampleWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()