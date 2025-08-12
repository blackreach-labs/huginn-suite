# app/widgets/plugin_widget.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QTextEdit
from PyQt6.QtCore import pyqtSignal
from app.core.plugin_manager import plugin_manager

class PluginWidget(QWidget):
    """Widget for plugin management and execution."""
    
    plugin_executed = pyqtSignal(str, dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.load_plugins()
        
    def setup_ui(self):
        """Setup plugin widget UI."""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Plugin Manager")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(title)
        
        # Plugin selection
        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("Plugin:"))
        
        self.plugin_combo = QComboBox()
        self.plugin_combo.setMinimumWidth(200)
        selector_layout.addWidget(self.plugin_combo)
        
        self.execute_button = QPushButton("Execute Plugin")
        self.execute_button.clicked.connect(self.execute_selected_plugin)
        selector_layout.addWidget(self.execute_button)
        
        selector_layout.addStretch()
        layout.addLayout(selector_layout)
        
        # Results area
        results_label = QLabel("Plugin Results:")
        results_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(results_label)
        
        self.results_output = QTextEdit()
        self.results_output.setMaximumHeight(200)
        self.results_output.setPlaceholderText("Plugin results will appear here...")
        layout.addWidget(self.results_output)
        
        layout.addStretch()
        
    def load_plugins(self):
        """Load available plugins into combo box."""
        plugin_manager.load_plugins()
        plugin_manager.plugin_loaded.connect(self.on_plugin_loaded)
        plugin_manager.plugin_executed.connect(self.on_plugin_executed)
        
        # Populate combo box
        self.plugin_combo.clear()
        for plugin_name in plugin_manager.get_plugins():
            self.plugin_combo.addItem(plugin_name)
            
    def on_plugin_loaded(self, plugin_name):
        """Handle plugin loaded event."""
        self.plugin_combo.addItem(plugin_name)
        
    def execute_selected_plugin(self):
        """Execute the selected plugin."""
        plugin_name = self.plugin_combo.currentText()
        if not plugin_name:
            return
            
        # Get target from parent if available
        target = "example.com"  # Default target
        if hasattr(self.parent(), 'target_input'):
            target = self.parent().target_input.text().strip() or target
            
        self.results_output.append(f"Executing {plugin_name} on {target}...")
        result = plugin_manager.execute_plugin(plugin_name, target)
        
    def on_plugin_executed(self, plugin_name, result):
        """Handle plugin execution completion."""
        self.results_output.append(f"Plugin: {plugin_name}")
        self.results_output.append(f"Result: {result.get('result', 'No result')}")
        if 'error' in result:
            self.results_output.append(f"Error: {result['error']}")
        self.results_output.append("---")
        
        self.plugin_executed.emit(plugin_name, result)