# app/core/professional_subdomain_worker.py
"""
Professional Subdomain Enumeration Worker
Qt integration for the comprehensive subdomain enumeration engine
"""

import asyncio
import json
from typing import Dict, List, Any
from PyQt6.QtCore import QThread, pyqtSignal, QObject
from app.core.subdomain_engine import subdomain_engine, ScanOptions, SubdomainResult
import logging
from app.core.logger import logger

logger = logging.getLogger(__name__)

class ProfessionalSubdomainWorker(QThread):
    """Professional subdomain enumeration worker thread"""
    
    # Signals
    progress_updated = pyqtSignal(str)
    subdomain_discovered = pyqtSignal(str, str)  # subdomain, source
    plugin_completed = pyqtSignal(str, int)  # plugin_name, count
    enumeration_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, domain: str, options: ScanOptions = None, parent=None):
        super().__init__(parent)
        self.domain = domain
        self.options = options or ScanOptions()
        self.stop_requested = False
        
        # Set up logging to capture progress
        self._setup_progress_logging()
    
    def _setup_progress_logging(self):
        """Set up logging handler to capture progress"""
        
        class ProgressHandler(logging.Handler):
            def __init__(self, worker):
                super().__init__()
                self.worker = worker
            
            def emit(self, record):
                if not self.worker.stop_requested:
                    message = self.format(record)
                    self.worker.progress_updated.emit(message)
        
        # Add progress handler to subdomain engine logger
        progress_handler = ProgressHandler(self)
        progress_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')
        progress_handler.setFormatter(formatter)
        
        # Get the subdomain engine logger
        engine_logger = logging.getLogger('app.core.subdomain_engine')
        engine_logger.addHandler(progress_handler)
        engine_logger.setLevel(logging.INFO)
    
    def run(self):
        """Main execution thread"""
        try:
            self.progress_updated.emit(f"🚀 Starting professional subdomain enumeration for {self.domain}")
            
            # On Windows, use SelectorEventLoop for better aiohttp compatibility
            import sys
            if sys.platform == 'win32':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Run the enumeration
                result = loop.run_until_complete(self._run_enumeration())
                
                if not self.stop_requested:
                    self.enumeration_completed.emit(result)
                
            finally:
                # Properly shut down the event loop
                try:
                    # Cancel all pending tasks
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    if pending:
                        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except Exception:
                    pass
                loop.close()
        
        except Exception as e:
            logger.error(f"Enumeration failed: {e}")
            self.error_occurred.emit(f"Enumeration failed: {str(e)}")
    
    async def _run_enumeration(self) -> Dict[str, Any]:
        """Run the enumeration with progress tracking"""
        
        # Emit initial progress
        self.progress_updated.emit(f"📋 Configuration: {len(self.options.sources)} sources enabled")
        self.progress_updated.emit(f"⚙️ Options: DNS resolution={self.options.resolve_dns}, Wildcard filtering={self.options.filter_wildcards}")
        
        # Check available plugins
        available_sources = []
        for source in self.options.sources:
            if source in subdomain_engine.plugins:
                plugin = subdomain_engine.plugins[source]
                if plugin.requires_auth and source not in subdomain_engine.api_keys:
                    self.progress_updated.emit(f"⚠️ {source.upper()}: API key not configured, skipping")
                else:
                    available_sources.append(source)
                    self.progress_updated.emit(f"✅ {source.upper()}: Ready")
            else:
                self.progress_updated.emit(f"❌ {source.upper()}: Plugin not available")
        
        if not available_sources:
            raise Exception("No available sources configured")
        
        # Update options with available sources
        self.options.sources = available_sources
        
        # Run enumeration
        self.progress_updated.emit(f"🔍 Starting enumeration with {len(available_sources)} sources...")
        
        result = await subdomain_engine.enumerate(self.domain, self.options)
        
        return result
    
    def stop(self):
        """Stop the enumeration"""
        self.stop_requested = True
        self.progress_updated.emit("🛑 Stopping enumeration...")

class ProfessionalSubdomainController(QObject):
    """Controller for professional subdomain enumeration"""
    
    # Signals
    progress_updated = pyqtSignal(str)
    enumeration_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.current_domain = None
    
    def start_enumeration(self, domain: str, sources: List[str] = None, 
                         resolve_dns: bool = True, filter_wildcards: bool = True,
                         rate_limit: float = 10.0):
        """Start professional subdomain enumeration"""
        
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        
        # Refresh API keys from global settings before starting
        self._refresh_api_keys()
        
        # Create scan options
        options = ScanOptions(
            sources=sources or ["crtsh", "certspotter", "virustotal", "wayback", "censys"],
            resolve_dns=resolve_dns,
            filter_wildcards=filter_wildcards,
            rate_limit=rate_limit,
            save_to_db=True
        )
        
        self.current_domain = domain
        self.worker = ProfessionalSubdomainWorker(domain, options)
        
        # Connect signals
        self.worker.progress_updated.connect(self.progress_updated.emit)
        self.worker.enumeration_completed.connect(self._on_enumeration_completed)
        self.worker.error_occurred.connect(self.error_occurred.emit)
        
        # Start worker
        self.worker.start()
    
    def stop_enumeration(self):
        """Stop current enumeration"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
    
    def _on_enumeration_completed(self, result: Dict[str, Any]):
        """Handle enumeration completion"""
        
        # Convert SubdomainResult objects to dictionaries for JSON serialization
        serializable_result = {
            'domain': result['domain'],
            'statistics': result['statistics'],
            'options': result['options'],
            'results': []
        }
        
        # Convert results to dictionaries
        for subdomain_result in result['results']:
            if isinstance(subdomain_result, SubdomainResult):
                result_dict = {
                    'host': subdomain_result.host,
                    'ip': subdomain_result.ip,
                    'source': subdomain_result.source,
                    'status': subdomain_result.status,
                    'first_seen': subdomain_result.first_seen.isoformat() if subdomain_result.first_seen else None,
                    'last_seen': subdomain_result.last_seen.isoformat() if subdomain_result.last_seen else None,
                    'raw_data': subdomain_result.raw_data
                }
                serializable_result['results'].append(result_dict)
        
        self.enumeration_completed.emit(serializable_result)
    
    def is_running(self) -> bool:
        """Check if enumeration is currently running"""
        return self.worker and self.worker.isRunning()
    
    def get_available_sources(self) -> List[Dict[str, Any]]:
        """Get list of available sources with their status"""
        
        # Always refresh API keys from global settings before checking
        self._refresh_api_keys()
        
        sources = []
        for name, plugin in subdomain_engine.plugins.items():
            status = "available"
            if plugin.requires_auth:
                if name not in subdomain_engine.api_keys:
                    status = "requires_api_key"
                else:
                    status = "configured"
            
            sources.append({
                'name': name,
                'description': plugin.description,
                'requires_auth': plugin.requires_auth,
                'status': status
            })
        
        return sources
    
    def _refresh_api_keys(self):
        """Refresh API keys from global settings"""
        try:
            from app.core.subdomain_engine import subdomain_engine
            # Reload API keys from global settings
            subdomain_engine.api_keys = subdomain_engine._load_api_keys()
        except ImportError as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)

# Global instance
professional_subdomain_controller = ProfessionalSubdomainController()