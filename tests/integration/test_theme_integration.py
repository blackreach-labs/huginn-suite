# tests/integration/test_theme_integration.py
import unittest
from unittest.mock import Mock, patch
from PyQt6.QtWidgets import QApplication
from app.core.advanced_theme_manager import AdvancedThemeManager
from app.core.context_menu_manager import ContextMenuManager

class TestThemeIntegration(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        if not QApplication.instance():
            cls.app = QApplication([])
        else:
            cls.app = QApplication.instance()
    
    def setUp(self):
        self.theme_manager = AdvancedThemeManager("/fake/path")
        self.context_manager = ContextMenuManager()
    
    @patch('PyQt6.QtWidgets.QApplication.instance')
    def test_theme_application_integration(self, mock_app):
        """Test theme application affects entire application"""
        mock_app_instance = Mock()
        mock_app.return_value = mock_app_instance
        
        # Apply cyberpunk theme
        result = self.theme_manager.apply_theme("cyberpunk")
        self.assertTrue(result)
        
        # Verify stylesheet was applied
        mock_app_instance.setStyleSheet.assert_called_once()
        
        # Verify theme changed signal
        self.assertEqual(self.theme_manager.get_current_theme(), "cyberpunk")
    
    def test_theme_context_menu_integration(self):
        """Test context menus work with different themes"""
        # Apply different themes and verify context menus still function
        for theme_name in ["dark", "light", "cyberpunk"]:
            self.theme_manager.apply_theme(theme_name)
            
            # Create mock widget
            mock_widget = Mock()
            menu = self.context_manager.create_terminal_menu(mock_widget)
            
            # Verify menu creation succeeds regardless of theme
            self.assertIsNotNone(menu)
            actions = menu.actions()
            self.assertGreater(len(actions), 0)

if __name__ == '__main__':
    unittest.main()