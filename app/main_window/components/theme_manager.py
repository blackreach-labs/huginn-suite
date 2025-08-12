"""Theme management integration for main window."""
from app.core.unified_theme_manager import get_theme_manager


class MainWindowThemeManager:
    """Manages theme integration for the main window."""
    
    def __init__(self, main_window, project_root):
        self.main_window = main_window
        self.project_root = project_root
        self.theme_manager = get_theme_manager(project_root)
        self._setup_theme_connections()
    
    def _setup_theme_connections(self):
        """Set up theme-related signal connections."""
        self.theme_manager.theme_changed.connect(self.on_theme_changed)
    
    def apply_initial_theme(self):
        """Apply the initial theme."""
        self.theme_manager.apply_theme()
    
    def on_theme_changed(self, theme_name):
        """Handle theme change event."""
        theme_display_name = self.theme_manager.get_theme_colors(theme_name).get('name', theme_name)
        self.main_window.status_bar.showMessage(f"Theme changed to: {theme_display_name}")
        
        # Update background effects based on theme
        animations = self.theme_manager.get_theme_animations(theme_name)
        if hasattr(self.main_window, 'background_effects'):
            if animations.get('matrix_rain'):
                self.main_window.background_effects.set_effect('matrix_rain')
            elif animations.get('neon_glow'):
                self.main_window.background_effects.set_effect('neon_glow')
            elif animations.get('wave_effects'):
                self.main_window.background_effects.set_effect('wave_effects')
            elif animations.get('terminal_effects'):
                self.main_window.background_effects.set_effect('terminal_effects')
            elif animations.get('particle_field'):
                self.main_window.background_effects.set_effect('particle_field')
            else:
                self.main_window.background_effects.remove_effect()
    
    def open_theme_selector(self):
        """Open enhanced theme selector dialog."""
        from app.widgets.enhanced_theme_selector import ThemeSelectionDialog
        
        dialog = ThemeSelectionDialog(self.theme_manager, self.main_window)
        dialog.exec()
    
    def show_theme_upgrade_dialog(self, theme_name, message):
        """Show theme upgrade dialog."""
        from PyQt6.QtWidgets import QMessageBox
        
        msg_box = QMessageBox(self.main_window)
        msg_box.setWindowTitle("Premium Theme")
        msg_box.setIcon(QMessageBox.Icon.Information)
        msg_box.setText(f"Theme '{theme_name}' is locked.")
        msg_box.setInformativeText(message)
        
        upgrade_btn = msg_box.addButton("Upgrade License", QMessageBox.ButtonRole.AcceptRole)
        msg_box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        
        result = msg_box.exec()
        if msg_box.clickedButton() == upgrade_btn:
            self.main_window.open_license_manager()
    
    def get_available_themes(self):
        """Get available themes from the theme manager."""
        return self.theme_manager.get_available_themes()
    
    def get_theme_colors(self, theme_name=None):
        """Get theme colors from the theme manager."""
        return self.theme_manager.get_theme_colors(theme_name)
    
    def get_theme_animations(self, theme_name):
        """Get theme animations from the theme manager."""
        return self.theme_manager.get_theme_animations(theme_name)
    
    def set_theme(self, theme_name):
        """Set theme using the theme manager."""
        return self.theme_manager.set_theme(theme_name)
    
    def set_home_style(self, style):
        """Set the home page navigation style."""
        self.main_window._current_home_style = style
        
        if style == 'attack_chain':
            page = self.main_window.page_manager.get_page('attack_chain_home')
            if page:
                self.main_window.stack.animate_to_widget(page)
            self.main_window.status_bar.showMessage("Switched to Advanced Mode navigation")