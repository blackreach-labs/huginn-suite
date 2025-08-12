# tests/test_context_menu_manager.py
import unittest
from unittest.mock import Mock, patch
from PyQt6.QtWidgets import QApplication, QTextEdit
from app.core.context_menu_manager import ContextMenuManager

class TestContextMenuManager(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        if not QApplication.instance():
            cls.app = QApplication([])
        else:
            cls.app = QApplication.instance()
    
    def setUp(self):
        self.context_manager = ContextMenuManager()
        self.text_widget = QTextEdit()
    
    def test_terminal_menu_creation(self):
        menu = self.context_manager.create_terminal_menu(self.text_widget)
        self.assertIsNotNone(menu)
        actions = menu.actions()
        self.assertGreater(len(actions), 0)
    
    def test_terminal_menu_with_selection(self):
        menu = self.context_manager.create_terminal_menu(self.text_widget, "selected text")
        actions = [action.text() for action in menu.actions() if action.text()]
        self.assertIn("Copy", actions)
    
    def test_input_menu_creation(self):
        menu = self.context_manager.create_input_menu(self.text_widget)
        self.assertIsNotNone(menu)
        actions = [action.text() for action in menu.actions() if action.text()]
        self.assertIn("Paste", actions)
        self.assertIn("Select All", actions)

if __name__ == '__main__':
    unittest.main()