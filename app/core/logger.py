# app/core/logger.py
import logging
import os
from pathlib import Path
from datetime import datetime

class HugginLogger:
    """Centralized logging system for Huggin"""
    
    _instance = None
    _logger = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._logger is None:
            self._setup_logger()
    
    def _setup_logger(self):
        """Initialize the logging system"""
        # Find project root (where main.py is located)
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
        log_dir = project_root / "logs"
        log_dir.mkdir(exist_ok=True)
        
        # Create logger
        self._logger = logging.getLogger("huggin")
        self._logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self._logger.handlers.clear()
        
        # File handler for all logs
        log_file = log_dir / f"huggin_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        # Debug file handler for debug logs only
        debug_log_file = log_dir / "debug.log"
        debug_handler = logging.FileHandler(debug_log_file, encoding='utf-8')
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.addFilter(lambda record: record.levelno == logging.DEBUG)
        
        # Error file handler for error logs only
        error_log_file = log_dir / "error.log"
        error_handler = logging.FileHandler(error_log_file, encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        debug_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self._logger.addHandler(file_handler)
        self._logger.addHandler(debug_handler)
        self._logger.addHandler(error_handler)
        self._logger.addHandler(console_handler)
    
    def debug(self, message):
        """Log debug message"""
        self._logger.debug(message)
    
    def info(self, message):
        """Log info message"""
        self._logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self._logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self._logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        self._logger.critical(message)
    
    def log_scan_start(self, target, wordlist, record_types):
        """Log scan initiation"""
        self.info(f"DNS scan started - Target: {target}, Wordlist: {Path(wordlist).name}, Types: {record_types}")
    
    def log_scan_complete(self, target, results_count):
        """Log scan completion"""
        self.info(f"DNS scan completed - Target: {target}, Results: {results_count}")
    
    def log_validation_error(self, field, error):
        """Log validation errors"""
        self.warning(f"Validation failed - {field}: {error}")
    
    def log_dns_error(self, domain, error):
        """Log DNS resolution errors"""
        self.debug(f"DNS error for {domain}: {error}")

# Global logger instance
logger = HugginLogger()