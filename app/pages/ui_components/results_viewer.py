# app/pages/ui_components/results_viewer.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget, 
                             QTextEdit, QTableWidget, QTreeWidget, QToolButton,
                             QTableWidgetItem, QTreeWidgetItem, QHeaderView)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QIcon
import os

class ResultsViewer(QWidget):
    """Reusable results viewer component with multiple view modes."""
    
    # Signals
    view_changed = pyqtSignal(str)  # Emits view type: "text", "table", "tree"
    
    def __init__(self, view_modes=None, parent=None):
        super().__init__(parent)
        self.view_modes = view_modes or ["text", "table"]
        self.current_view = "text"
        self.results_data = {}
        self.setup_ui()
        self.apply_styles()
    
    def setup_ui(self):
        """Setup the results viewer UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        # View controls
        controls_layout = QHBoxLayout()
        controls_layout.addStretch()
        
        self.view_buttons = {}
        for view_mode in self.view_modes:
            button = self.create_view_button(view_mode)
            self.view_buttons[view_mode] = button
            controls_layout.addWidget(button)
        
        layout.addLayout(controls_layout)
        
        # Results stack
        self.results_stack = QStackedWidget()
        self.setup_view_widgets()
        layout.addWidget(self.results_stack)
        
        # Set initial view
        if self.view_modes:
            self.set_view(self.view_modes[0])
    
    def create_view_button(self, view_mode):
        """Create a view toggle button."""
        button = QToolButton()
        button.setFixedWidth(40)
        button.setCheckable(True)
        
        # Try to load icon
        icon_name = f"{view_mode}.png"
        if hasattr(self.parent(), 'main_window') and self.parent().main_window:
            icon_path = os.path.join(self.parent().main_window.project_root, "resources", "icons", icon_name)
            if os.path.exists(icon_path):
                button.setIcon(QIcon(icon_path))
            else:
                button.setText(view_mode.title()[:4])
        else:
            button.setText(view_mode.title()[:4])
        
        button.clicked.connect(lambda: self.set_view(view_mode))
        return button
    
    def setup_view_widgets(self):
        """Setup the different view widgets."""
        self.view_widgets = {}
        
        for view_mode in self.view_modes:
            if view_mode == "text":
                widget = self.create_text_view()
            elif view_mode == "table":
                widget = self.create_table_view()
            elif view_mode == "tree":
                widget = self.create_tree_view()
            else:
                widget = QWidget()  # Placeholder
            
            self.view_widgets[view_mode] = widget
            self.results_stack.addWidget(widget)
    
    def create_text_view(self):
        """Create text/terminal view."""
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setPlaceholderText("Results will appear here...")
        return text_edit
    
    def create_table_view(self):
        """Create table view."""
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Item", "Type", "Details"])
        
        # Configure table
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        return table
    
    def create_tree_view(self):
        """Create tree view."""
        tree = QTreeWidget()
        tree.setHeaderLabels(["Category", "Count", "Details"])
        tree.setRootIsDecorated(True)
        
        # Configure tree
        header = tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        
        return tree
    
    def apply_styles(self):
        """Apply component styles."""
        self.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #DCDCDC;
                font-family: 'Consolas', monospace;
                font-size: 10pt;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
            QTableWidget {
                background-color: #1E1E1E;
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                gridline-color: rgba(100, 200, 255, 50);
            }
            QTableWidget::item {
                padding: 5px;
                border-bottom: 1px solid rgba(100, 200, 255, 30);
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
            }
            QTreeWidget {
                background-color: #1E1E1E;
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
            QTreeWidget::item {
                padding: 3px;
            }
            QTreeWidget::item:selected {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
            }
            QToolButton {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 5px;
            }
            QToolButton:checked {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
            }
            QToolButton:hover {
                background-color: rgba(40, 60, 80, 200);
            }
        """)
    
    def set_view(self, view_mode):
        """Set the current view mode."""
        if view_mode not in self.view_modes:
            return
        
        self.current_view = view_mode
        
        # Update button states
        for mode, button in self.view_buttons.items():
            button.setChecked(mode == view_mode)
        
        # Switch view
        view_index = self.view_modes.index(view_mode)
        self.results_stack.setCurrentIndex(view_index)
        
        self.view_changed.emit(view_mode)
    
    def update_results(self, results_data):
        """Update results in all views."""
        self.results_data = results_data
        
        # Update each view
        for view_mode in self.view_modes:
            if view_mode == "text":
                self.update_text_view(results_data)
            elif view_mode == "table":
                self.update_table_view(results_data)
            elif view_mode == "tree":
                self.update_tree_view(results_data)
    
    def update_text_view(self, results_data):
        """Update text view with results."""
        if "text" not in self.view_widgets:
            return
        
        text_widget = self.view_widgets["text"]
        
        if isinstance(results_data, dict):
            # Format dictionary data
            formatted_text = ""
            for key, value in results_data.items():
                formatted_text += f"<b>{key}:</b> {value}<br>"
            text_widget.setHtml(formatted_text)
        elif isinstance(results_data, str):
            text_widget.setPlainText(results_data)
        else:
            text_widget.setPlainText(str(results_data))
    
    def update_table_view(self, results_data):
        """Update table view with results."""
        if "table" not in self.view_widgets:
            return
        
        table = self.view_widgets["table"]
        table.setRowCount(0)
        
        if isinstance(results_data, dict):
            row = 0
            for key, value in results_data.items():
                table.insertRow(row)
                
                # Handle different value types
                if isinstance(value, list):
                    item_type = "List"
                    details = f"{len(value)} items"
                elif isinstance(value, dict):
                    item_type = "Dictionary"
                    details = f"{len(value)} keys"
                else:
                    item_type = "Value"
                    details = str(value)
                
                table.setItem(row, 0, QTableWidgetItem(str(key)))
                table.setItem(row, 1, QTableWidgetItem(item_type))
                table.setItem(row, 2, QTableWidgetItem(details))
                
                row += 1
    
    def update_tree_view(self, results_data):
        """Update tree view with results."""
        if "tree" not in self.view_widgets:
            return
        
        tree = self.view_widgets["tree"]
        tree.clear()
        
        if isinstance(results_data, dict):
            self.populate_tree_from_dict(tree, results_data)
        
        tree.expandAll()
    
    def populate_tree_from_dict(self, tree, data, parent=None):
        """Recursively populate tree from dictionary data."""
        for key, value in data.items():
            if parent is None:
                item = QTreeWidgetItem(tree)
            else:
                item = QTreeWidgetItem(parent)
            
            item.setText(0, str(key))
            
            if isinstance(value, dict):
                item.setText(1, str(len(value)))
                item.setText(2, "Dictionary")
                self.populate_tree_from_dict(tree, value, item)
            elif isinstance(value, list):
                item.setText(1, str(len(value)))
                item.setText(2, "List")
                for i, list_item in enumerate(value):
                    child = QTreeWidgetItem(item)
                    child.setText(0, f"[{i}]")
                    child.setText(1, "")
                    child.setText(2, str(list_item))
            else:
                item.setText(1, "")
                item.setText(2, str(value))
    
    def append_text(self, text):
        """Append text to the text view."""
        if "text" in self.view_widgets:
            text_widget = self.view_widgets["text"]
            if hasattr(text_widget, 'insertHtml'):
                text_widget.insertHtml(text)
            else:
                text_widget.append(text)
    
    def clear_results(self):
        """Clear all results."""
        self.results_data = {}
        
        # Clear each view
        for view_mode, widget in self.view_widgets.items():
            if view_mode == "text":
                widget.clear()
            elif view_mode == "table":
                widget.setRowCount(0)
            elif view_mode == "tree":
                widget.clear()
    
    def get_current_widget(self):
        """Get the currently displayed widget."""
        return self.view_widgets.get(self.current_view)