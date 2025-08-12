# app/core/lazy_initialization.py
from typing import Dict, Callable, Any
from PyQt6.QtCore import QObject

class LazyPageManager(QObject):
    """Lazy initialization manager for application pages"""
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.page_factories = {}
        self.initialized_pages = {}
        
    def register_page(self, name: str, factory: Callable):
        """Register a page factory function"""
        self.page_factories[name] = factory
        
    def get_page(self, name: str):
        """Get page, initializing if needed"""
        if name not in self.initialized_pages:
            if name in self.page_factories:
                self.initialized_pages[name] = self.page_factories[name]()
                self.main_window.stack.addWidget(self.initialized_pages[name])
        return self.initialized_pages.get(name)
        
    def preload_essential_pages(self):
        """Preload only essential pages based on mode"""
        essential = ['attack_chain_home', 'guided_workflow']
        for page_name in essential:
            self.get_page(page_name)