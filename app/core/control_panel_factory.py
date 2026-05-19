from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QLineEdit, QComboBox, QCheckBox, QPushButton, QSpinBox, QSizePolicy)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QStandardItemModel, QStandardItem


class CheckableComboBox(QComboBox):
    """A QComboBox where each item has a checkbox for multi-select.
    
    Displays a summary of checked items in the combo display text.
    """
    
    def __init__(self, parent=None, group_label=""):
        super().__init__(parent)
        self._group_label = group_label
        self._model = QStandardItemModel(self)
        self.setModel(self._model)
        self._model.itemChanged.connect(self._update_display_text)
        # Prevent the combo from closing when clicking items
        self.view().pressed.connect(self._on_item_pressed)
        
    def addCheckableItems(self, items, checked_items=None):
        """Add items with checkboxes. checked_items is a list of item texts to pre-check."""
        checked_items = checked_items or []
        for text in items:
            item = QStandardItem(text)
            item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            item.setCheckState(Qt.CheckState.Checked if text in checked_items else Qt.CheckState.Unchecked)
            self._model.appendRow(item)
        self._update_display_text()
    
    def _on_item_pressed(self, index):
        """Toggle check state when an item is clicked."""
        item = self._model.itemFromIndex(index)
        if item and item.isCheckable():
            new_state = Qt.CheckState.Unchecked if item.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked
            item.setCheckState(new_state)
    
    def _update_display_text(self):
        """Update the display text to show group label + count of checked items."""
        checked = self.getCheckedItems()
        total = self._model.rowCount()
        if checked:
            self.setEditText(f"{self._group_label} ({len(checked)}/{total})")
        else:
            self.setEditText(f"{self._group_label} (0/{total})")
        # Use the line edit to show text without it being editable
        if self.lineEdit():
            self.lineEdit().setReadOnly(True)
    
    def getCheckedItems(self):
        """Return list of checked item texts."""
        checked = []
        for i in range(self._model.rowCount()):
            item = self._model.item(i)
            if item and item.checkState() == Qt.CheckState.Checked:
                checked.append(item.text())
        return checked
    
    def setCheckedItems(self, items_to_check):
        """Set which items are checked by text."""
        for i in range(self._model.rowCount()):
            item = self._model.item(i)
            if item:
                item.setCheckState(
                    Qt.CheckState.Checked if item.text() in items_to_check else Qt.CheckState.Unchecked
                )
    
    def showPopup(self):
        """Override to ensure popup shows properly."""
        super().showPopup()
    
    def hidePopup(self):
        """Only hide popup if click is outside the view."""
        # Let the view handle item clicks without closing
        if not self.view().underMouse():
            super().hidePopup()


class ControlPanelFactory:
    """Factory for creating enumeration tool control panels from configuration data"""
    
    @staticmethod
    def create_panel(config, parent=None):
        """Create a control panel widget from configuration dictionary"""
        widget = QWidget(parent)
        # Don't set a hard max height - let visibility toggling control panel size dynamically
        
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
            if 'row_id' in row_config:
                row_widgets[row_config['row_id']] = row_widget
            elif 'label' in row_config and row_config['label']:
                row_widgets[row_config['label']] = row_widget
            
            # Always add to layout, even if initially hidden
            layout.addWidget(row_widget)
        
        widget.controls = controls
        widget.row_widgets = row_widgets
        
        # Calculate initial height based on visible rows only
        visible_row_count = sum(
            1 for row_config in config.get('rows', [])
            if row_config.get('visible', True)
        )
        initial_height = visible_row_count * 30 + 4
        widget.setMinimumHeight(initial_height)
        widget.setMaximumHeight(initial_height)
        
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
        
        elif control_type == 'checkable_combobox':
            group_label = config.get('group_label', '')
            control = CheckableComboBox(parent, group_label=group_label)
            control.setEditable(True)  # Required for custom display text
            control.addCheckableItems(
                config.get('items', []),
                config.get('checked_items', [])
            )
            
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
