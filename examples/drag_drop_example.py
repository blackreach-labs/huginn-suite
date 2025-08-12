# examples/drag_drop_example.py
"""
Example usage of consolidated drag and drop components

This example demonstrates how to use the DragDropMixin with various widgets.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel
from app.widgets.drag_drop_combo import DragDropComboBox
from app.widgets.drag_drop_line_edit import DragDropLineEdit

class DragDropExampleWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Drag & Drop Example")
        self.setGeometry(100, 100, 500, 300)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        
        # Title
        title = QLabel("Drag & Drop Components Example")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; margin: 20px;")
        layout.addWidget(title)
        
        # Instructions
        instructions = QLabel("Drag .txt, .csv, or .json files onto the components below:")
        layout.addWidget(instructions)
        
        # DragDropComboBox
        combo_label = QLabel("DragDropComboBox:")
        layout.addWidget(combo_label)
        
        self.combo_box = DragDropComboBox()
        self.combo_box.addItems(["Select a file...", "Option 1", "Option 2"])
        self.combo_box.file_dropped.connect(self.on_combo_file_dropped)
        layout.addWidget(self.combo_box)
        
        # DragDropLineEdit
        line_edit_label = QLabel("DragDropLineEdit:")
        layout.addWidget(line_edit_label)
        
        self.line_edit = DragDropLineEdit()
        self.line_edit.setPlaceholderText("Drag a file here or type a path...")
        self.line_edit.file_dropped.connect(self.on_line_edit_file_dropped)
        layout.addWidget(self.line_edit)
        
        # Status
        self.status_label = QLabel("Ready - drag files to see them in action")
        self.status_label.setStyleSheet("color: blue; margin: 10px;")
        layout.addWidget(self.status_label)
    
    def on_combo_file_dropped(self, file_path):
        """Handle file dropped on combo box"""
        filename = os.path.basename(file_path)
        self.combo_box.setCurrentText(filename)
        self.status_label.setText(f"ComboBox: File dropped - {filename}")
    
    def on_line_edit_file_dropped(self, file_path):
        """Handle file dropped on line edit"""
        filename = os.path.basename(file_path)
        self.status_label.setText(f"LineEdit: File dropped - {filename}")

def main():
    """Run the drag drop example"""
    app = QApplication(sys.argv)
    
    window = DragDropExampleWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()