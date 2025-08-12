# tests/test_unified_theme_manager.py
import unittest
from unittest.mock import Mock, patch
from app.core.unified_theme_manager import UnifiedThemeManager

class TestUnifiedThemeManager(unittest.TestCase):
    
    def setUp(self):
        self.theme_manager = UnifiedThemeManager("/fake/path")
    
    def test_available_themes(self):
        themes = self.theme_manager.get_available_themes()
        self.assertGreater(len(themes), 0)
        self.assertIn(("dark", "Dark Theme"), themes)
        self.assertIn(("cyberpunk", "Cyberpunk"), themes)
    
    def test_theme_application(self):
        result = self.theme_manager.apply_theme("dark")
        self.assertTrue(result)
        self.assertEqual(self.theme_manager.get_current_theme(), "dark")
    
    def test_invalid_theme(self):
        result = self.theme_manager.apply_theme("nonexistent")
        self.assertFalse(result)
    
    def test_stylesheet_generation(self):
        theme = self.theme_manager.themes["dark"]
        stylesheet = self.theme_manager._generate_stylesheet(theme)
        self.assertIn("QMainWindow", stylesheet)
        self.assertIn(theme["background"], stylesheet)

if __name__ == '__main__':
    unittest.main()