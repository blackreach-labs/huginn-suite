# app/core/startup_optimizer.py
import os
from PyQt6.QtCore import QSettings

class StartupOptimizer:
    """Optimizes application startup based on user preferences"""
    
    def __init__(self):
        self.settings = QSettings('Huginn', 'StartupPrefs')
        
    def get_preferred_mode(self) -> str:
        """Get user's preferred mode to skip dialog"""
        return self.settings.value('preferred_mode', '')
        
    def set_preferred_mode(self, mode: str):
        """Save user's preferred mode"""
        self.settings.setValue('preferred_mode', mode)
        
    def get_last_profile(self) -> str:
        """Get last used profile"""
        return self.settings.value('last_profile', 'default')
        
    def set_last_profile(self, profile: str):
        """Save last used profile"""
        self.settings.setValue('last_profile', profile)
        
    def should_skip_mode_dialog(self) -> bool:
        """Check if mode dialog should be skipped"""
        return bool(self.get_preferred_mode())
        
    def get_startup_config(self) -> dict:
        """Get optimized startup configuration"""
        return {
            'mode': self.get_preferred_mode(),
            'profile': self.get_last_profile(),
            'skip_dialog': self.should_skip_mode_dialog()
        }