# app/widgets/theme_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QGroupBox, QButtonGroup, QRadioButton)
from PyQt6.QtCore import Qt
from app.core.theme_manager import theme_manager

class ThemeWidget(QWidget):
    """Widget for theme selection and management"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.load_current_theme()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Theme selection group
        theme_group = QGroupBox("🎨 Theme Selection")
        theme_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        theme_layout = QVBoxLayout(theme_group)
        
        # Theme radio buttons
        self.theme_group = QButtonGroup()
        
        self.dark_radio = QRadioButton("🌙 Dark Theme")
        self.dark_radio.setStyleSheet("color: #DCDCDC; font-size: 11pt; padding: 5px;")
        self.dark_radio.toggled.connect(lambda checked: self.on_theme_selected("dark") if checked else None)
        
        self.light_radio = QRadioButton("☀️ Light Theme")
        self.light_radio.setStyleSheet("color: #DCDCDC; font-size: 11pt; padding: 5px;")
        self.light_radio.toggled.connect(lambda checked: self.on_theme_selected("light") if checked else None)
        
        self.theme_group.addButton(self.dark_radio)
        self.theme_group.addButton(self.light_radio)
        
        # Quick toggle button
        toggle_layout = QHBoxLayout()
        
        self.toggle_button = QPushButton("🔄 Toggle Theme")
        self.toggle_button.clicked.connect(self.toggle_theme)
        self.toggle_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 11pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """)
        
        toggle_layout.addWidget(self.toggle_button)
        toggle_layout.addStretch()
        
        # Theme preview
        preview_layout = QVBoxLayout()
        preview_layout.addWidget(QLabel("Preview:"))
        
        self.preview_label = QLabel("Current theme colors will be applied to the entire application")
        self.preview_label.setStyleSheet("""
            QLabel {
                background-color: rgba(100, 200, 255, 50);
                border: 1px solid #555;
                border-radius: 4px;
                padding: 10px;
                font-size: 10pt;
            }
        """)
        self.preview_label.setWordWrap(True)
        
        preview_layout.addWidget(self.preview_label)
        
        # Status label
        self.status_label = QLabel("Theme settings will be saved automatically")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        # Add to theme layout
        theme_layout.addWidget(self.dark_radio)
        theme_layout.addWidget(self.light_radio)
        theme_layout.addLayout(toggle_layout)
        theme_layout.addLayout(preview_layout)
        theme_layout.addWidget(self.status_label)
        
        layout.addWidget(theme_group)
        layout.addStretch()
        
        # Connect to theme manager signals
        theme_manager.theme_changed.connect(self.on_theme_changed)
        
    def load_current_theme(self):
        """Load and display current theme"""
        current_theme = theme_manager.get_current_theme()
        
        if current_theme == "dark":
            self.dark_radio.setChecked(True)
        else:
            self.light_radio.setChecked(True)
        
        self.update_preview(current_theme)
    
    def on_theme_selected(self, theme_name):
        """Handle theme selection"""
        theme_manager.set_theme(theme_name)
        self.update_preview(theme_name)
        
        self.status_label.setText(f"✅ {theme_name.title()} theme applied")
        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
    
    def toggle_theme(self):
        """Toggle between themes"""
        theme_manager.toggle_theme()
        
        # Update radio buttons
        current_theme = theme_manager.get_current_theme()
        if current_theme == "dark":
            self.dark_radio.setChecked(True)
        else:
            self.light_radio.setChecked(True)
        
        self.status_label.setText(f"🔄 Switched to {current_theme} theme")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
    
    def on_theme_changed(self, theme_name):
        """Handle theme change signal"""
        self.update_preview(theme_name)
    
    def update_preview(self, theme_name):
        """Update theme preview"""
        colors = theme_manager.get_theme_colors(theme_name)
        
        preview_text = f"""
        {colors['name']} Preview:
        • Background: {colors['background']}
        • Primary: {colors['primary']}
        • Text: {colors['text']}
        • Accent: {colors['accent']}
        """
        
        self.preview_label.setText(preview_text.strip())
        
        # Update preview styling based on theme
        if theme_name == "light":
            self.preview_label.setStyleSheet(f"""
                QLabel {{
                    background-color: {colors['surface']};
                    border: 1px solid {colors['border']};
                    border-radius: 4px;
                    padding: 10px;
                    font-size: 10pt;
                    color: {colors['text']};
                }}
            """)
        else:
            self.preview_label.setStyleSheet(f"""
                QLabel {{
                    background-color: {colors['surface']};
                    border: 1px solid {colors['border']};
                    border-radius: 4px;
                    padding: 10px;
                    font-size: 10pt;
                    color: {colors['text']};
                }}
            """)