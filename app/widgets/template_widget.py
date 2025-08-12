# app/widgets/template_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QComboBox, QLineEdit, QTextEdit, QGroupBox)
from PyQt6.QtCore import Qt, pyqtSignal
from app.core.template_manager import template_manager

class TemplateWidget(QWidget):
    """Widget for managing scan templates"""
    
    template_loaded = pyqtSignal(dict)  # Signal when template is loaded
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.refresh_template_list()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Template management group
        template_group = QGroupBox("📋 Scan Templates")
        template_group.setStyleSheet("""
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
        
        template_layout = QVBoxLayout(template_group)
        
        # Template selection
        select_layout = QHBoxLayout()
        select_layout.addWidget(QLabel("Template:"))
        
        self.template_combo = QComboBox()
        self.template_combo.setFixedWidth(200)
        self.template_combo.currentTextChanged.connect(self.on_template_selected)
        select_layout.addWidget(self.template_combo)
        
        self.load_button = QPushButton("📥 Load")
        self.load_button.clicked.connect(self.load_template)
        self.load_button.setFixedWidth(60)
        
        self.delete_button = QPushButton("🗑️ Delete")
        self.delete_button.clicked.connect(self.delete_template)
        self.delete_button.setFixedWidth(70)
        
        select_layout.addWidget(self.load_button)
        select_layout.addWidget(self.delete_button)
        select_layout.addStretch()
        
        # Template description
        self.description_text = QTextEdit()
        self.description_text.setFixedHeight(60)
        self.description_text.setReadOnly(True)
        self.description_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 5px;
            }
        """)
        
        # Create new template
        create_layout = QHBoxLayout()
        create_layout.addWidget(QLabel("New Template:"))
        
        self.new_name_input = QLineEdit()
        self.new_name_input.setPlaceholderText("Template name")
        self.new_name_input.setFixedWidth(150)
        self.new_name_input.setStyleSheet(self._get_input_style())
        
        self.new_desc_input = QLineEdit()
        self.new_desc_input.setPlaceholderText("Description")
        self.new_desc_input.setStyleSheet(self._get_input_style())
        
        self.save_button = QPushButton("💾 Save Current")
        self.save_button.clicked.connect(self.save_current_as_template)
        self.save_button.setFixedWidth(100)
        
        create_layout.addWidget(self.new_name_input)
        create_layout.addWidget(self.new_desc_input)
        create_layout.addWidget(self.save_button)
        
        # Button styling
        button_style = """
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """
        
        self.load_button.setStyleSheet(button_style)
        self.delete_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 100, 100"))
        self.save_button.setStyleSheet(button_style.replace("100, 200, 255", "100, 255, 100"))
        
        # Status label
        self.status_label = QLabel("Select a template to load")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        # Add to template layout
        template_layout.addLayout(select_layout)
        template_layout.addWidget(QLabel("Description:"))
        template_layout.addWidget(self.description_text)
        template_layout.addLayout(create_layout)
        template_layout.addWidget(self.status_label)
        
        layout.addWidget(template_group)
        layout.addStretch()
        
    def _get_input_style(self):
        return """
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
        """
    
    def refresh_template_list(self):
        """Refresh the template dropdown list"""
        self.template_combo.clear()
        templates = template_manager.get_template_list()
        self.template_combo.addItems(templates)
        
        if templates:
            self.on_template_selected(templates[0])
    
    def on_template_selected(self, template_name):
        """Handle template selection"""
        if not template_name:
            return
        
        template = template_manager.load_template(template_name)
        if template:
            description = template.get('description', 'No description available')
            tools = ', '.join(template.get('tools', []))
            
            display_text = f"{description}\n\nTools: {tools}"
            self.description_text.setPlainText(display_text)
            
            self.status_label.setText(f"Template: {template_name}")
            self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
    
    def load_template(self):
        """Load selected template"""
        template_name = self.template_combo.currentText()
        if not template_name:
            return
        
        template = template_manager.load_template(template_name)
        if template:
            self.template_loaded.emit(template)
            self.status_label.setText(f"✅ Loaded: {template_name}")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
        else:
            self.status_label.setText(f"❌ Failed to load: {template_name}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def delete_template(self):
        """Delete selected template"""
        template_name = self.template_combo.currentText()
        if not template_name:
            return
        
        # Don't delete default templates
        if template_name in ["Quick Web Scan", "Stealth Recon", "Full Assessment"]:
            self.status_label.setText("❌ Cannot delete default templates")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        if template_manager.delete_template(template_name):
            self.refresh_template_list()
            self.status_label.setText(f"🗑️ Deleted: {template_name}")
            self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
        else:
            self.status_label.setText(f"❌ Failed to delete: {template_name}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def save_current_as_template(self):
        """Save current settings as new template"""
        name = self.new_name_input.text().strip()
        description = self.new_desc_input.text().strip()
        
        if not name:
            self.status_label.setText("❌ Please enter template name")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        if not description:
            description = f"Custom template: {name}"
        
        # Create basic template structure (would be populated by parent)
        current_settings = {
            "tools": ["dns_enum"],  # Default
            "settings": {
                "rate_limit": {"enabled": False},
                "proxy": {"enabled": False},
                "export_formats": ["JSON"]
            },
            "parameters": {}
        }
        
        if template_manager.create_template_from_current(name, description, current_settings):
            self.refresh_template_list()
            self.template_combo.setCurrentText(name)
            self.new_name_input.clear()
            self.new_desc_input.clear()
            
            self.status_label.setText(f"💾 Saved: {name}")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
        else:
            self.status_label.setText(f"❌ Failed to save: {name}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")