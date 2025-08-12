#!/usr/bin/env python3

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt

class MinimalHugginPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        label = QLabel("Huggin Advanced Scanner")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(label)
    
    def get_page_title(self):
        return "Huggin Advanced Scanner"
    
    def get_page_icon(self):
        return None

def test_minimal_page():
    try:
        print("Creating minimal page...")
        page = MinimalHugginPage(None)
        print("Page created successfully")
        print("Title:", page.get_page_title())
        return True
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_minimal_page()