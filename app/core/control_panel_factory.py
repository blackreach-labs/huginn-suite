from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QComboBox, QCheckBox, QPushButton, QSpinBox, QSizePolicy)
from PyQt6.QtCore import Qt

class ControlPanelFactory:
    """Factory for creating enumeration tool control panels from configuration data"""
    
    @staticmethod
    def create_panel(config, parent=None):
        """Create a control panel widget from configuration dictionary"""
        widget = QWidget(parent)
        widget.setMaximumHeight(200)  # Hard limit
        
        layout = QVBoxLayout(widget)
        layout.setSpacing(1)
        layout.setContentsMargins(0, 0, 0, 0)
        
        controls = {}
        row_widgets = {}
        
        for i, row_config in enumerate(config.get('rows', [])):
            # Create row widget even if initially hidden
            row_widget = QWidget(widget)  # Ensure proper parent
            row_widget.setFixedHeight(26)
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(5)
            
            # Set initial visibility
            if 'visible' in row_config and not row_config['visible']:
                row_widget.setVisible(False)
                row_widget.setMaximumHeight(0)
                row_widget.setMinimumHeight(0)
            
            # Add label
            if 'label' in row_config:
                label = QLabel(row_config['label'])
                label.setFixedWidth(150)
                row_layout.addWidget(label)
            
            # Add controls
            for control_config in row_config.get('controls', []):
                control = ControlPanelFactory._create_control(control_config, parent)
                controls[control_config['name']] = control
                
                if control_config.get('stretch'):
                    row_layout.addWidget(control, 1)
                else:
                    row_layout.addWidget(control)
                    if 'width' in control_config:
                        control.setFixedWidth(control_config['width'])
            
            # Add buttons if specified
            for button_config in row_config.get('buttons', []):
                button = QPushButton(button_config['text'])
                button.setObjectName(f"{button_config['text'].lower().replace(' ', '_')}_btn")
                controls[f"{button_config['text'].lower().replace(' ', '_')}_btn"] = button
                row_layout.addWidget(button)
            
            if row_config.get('add_stretch', True):
                row_layout.addStretch()
            
            # Store row widget reference
            if 'label' in row_config:
                row_widgets[row_config['label']] = row_widget
            
            # Always add to layout, even if initially hidden
            layout.addWidget(row_widget)
        
        widget.controls = controls
        widget.row_widgets = row_widgets
        widget.adjustSize()
        
        return widget
    
    @staticmethod
    def _create_control(config, parent):
        """Create individual control widget from configuration"""
        control_type = config['type']
        name = config['name']
        
        if control_type == 'lineedit':
            control = QLineEdit(parent)
            if 'placeholder' in config:
                control.setPlaceholderText(config['placeholder'])
            if 'default' in config:
                control.setText(config['default'])
            if config.get('password'):
                control.setEchoMode(QLineEdit.EchoMode.Password)
                
        elif control_type == 'combobox':
            control = QComboBox(parent)
            control.addItems(config.get('items', []))
            if 'default' in config:
                control.setCurrentText(config['default'])
            
        elif control_type == 'checkbox':
            control = QCheckBox(config.get('text', ''), parent)
            control.setChecked(config.get('checked', False))
            
        elif control_type == 'spinbox':
            control = QSpinBox(parent)
            control.setRange(config.get('min', 0), config.get('max', 100))
            control.setValue(config.get('default', 0))
            
        elif control_type == 'slider':
            from PyQt6.QtWidgets import QSlider
            control = QSlider(Qt.Orientation.Horizontal, parent)
            control.setRange(config.get('min', 0), config.get('max', 100))
            control.setValue(config.get('default', 50))
            control.setTickPosition(QSlider.TickPosition.TicksBelow)
            control.setTickInterval(50)
            
        elif control_type == 'label':
            control = QLabel(config.get('text', ''), parent)
            
        elif control_type == 'button':
            control = QPushButton(config.get('text', ''), parent)
            
        else:
            control = QWidget(parent)  # Fallback
        
        # Set visibility
        if 'visible' in config:
            control.setVisible(config['visible'])
            
        return control