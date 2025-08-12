"""Hash lookup UI component"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, 
                            QComboBox, QPushButton, QTextEdit, QLabel, QProgressBar)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont

from shared.configuration.hash_config import SOURCES
from infrastructure.data.repositories.sqlite_hash_repository import SQLiteHashRepository
from infrastructure.external.hash_source_updater import HashSourceUpdater
from domain.services.hash_lookup_manager import HashLookupManager
from application.services.hash_lookup_service import HashLookupService

class HashUpdateWorker(QThread):
    """Worker thread for hash database updates"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(int)
    error = pyqtSignal(str)
    
    def __init__(self, service, source_name):
        super().__init__()
        self.service = service
        self.source_name = source_name
    
    def run(self):
        try:
            self.progress.emit(f"Updating {self.source_name}...")
            
            # Create updater with progress callback
            from infrastructure.data.repositories.sqlite_hash_repository import SQLiteHashRepository
            from infrastructure.external.hash_source_updater import HashSourceUpdater
            from shared.configuration.hash_config import DB_PATH
            
            repo = SQLiteHashRepository(DB_PATH)
            updater = HashSourceUpdater(repo, progress_callback=self.progress.emit)
            
            count = updater.update_source(self.source_name)
            self.finished.emit(count)
        except Exception as e:
            self.error.emit(str(e))

class HashLookupComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.init_service()
        self.init_ui()
    
    def init_service(self):
        """Initialize hash lookup service"""
        from shared.configuration.hash_config import DB_PATH
        
        repo = SQLiteHashRepository(DB_PATH)
        updater = HashSourceUpdater(repo)  # Default updater for regular operations
        manager = HashLookupManager(repo)
        self.service = HashLookupService(manager, updater)
    
    def init_ui(self):
        """Initialize user interface"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Hash Lookup & Cracking")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Hash input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Hash:"))
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter hash (MD5, SHA1, SHA256, SHA512)")
        input_layout.addWidget(self.hash_input)
        layout.addLayout(input_layout)
        
        # Source selection
        source_layout = QHBoxLayout()
        source_layout.addWidget(QLabel("Source:"))
        self.source_combo = QComboBox()
        self.populate_sources()
        source_layout.addWidget(self.source_combo)
        layout.addLayout(source_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.lookup_btn = QPushButton("Lookup Hash")
        self.lookup_btn.clicked.connect(self.lookup_hash)
        button_layout.addWidget(self.lookup_btn)
        
        self.update_btn = QPushButton("📥 Update Database")
        self.update_btn.clicked.connect(self.update_database)
        self.update_btn.setToolTip("Download and install hash databases from external sources")
        button_layout.addWidget(self.update_btn)
        
        self.stats_btn = QPushButton("Show Stats")
        self.stats_btn.clicked.connect(self.show_stats)
        button_layout.addWidget(self.stats_btn)
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Results
        self.results_text = QTextEdit()
        self.results_text.setMaximumHeight(200)
        layout.addWidget(self.results_text)
        
        self.setLayout(layout)
    
    def populate_sources(self):
        """Populate source dropdown with local and online options"""
        self.source_combo.clear()
        
        # Add local sources
        stats = self.service.get_database_stats()
        for source_name, count in stats['sources'].items():
            if count > 0:
                self.source_combo.addItem(f"Local: {source_name}", f"Local: {source_name}")
        
        # Add online sources
        from shared.configuration.hash_config import API_PROVIDERS
        for provider in API_PROVIDERS.keys():
            self.source_combo.addItem(f"Online: {provider}", f"Online: {provider}")
    
    def lookup_hash(self):
        """Lookup hash value"""
        hash_value = self.hash_input.text().strip()
        if not hash_value:
            self.results_text.setText("Please enter a hash value")
            return
        
        source_data = self.source_combo.currentData()
        if not source_data:
            self.results_text.setText("Please select a valid lookup source")
            return
        
        # Get hash info
        hash_info = self.service.get_hash_info(hash_value)
        if not hash_info["valid"]:
            self.results_text.setText(f"Invalid hash format: {hash_value}")
            return
        
        # Show lookup in progress
        self.results_text.setText(f"Looking up {hash_value} using {source_data}...")
        
        # Perform lookup
        result = self.service.lookup_single_hash(hash_value, source_data)
        
        output = f"Hash: {hash_value}\n"
        output += f"Type: {hash_info['type']}\n"
        output += f"Source: {source_data}\n"
        
        if result:
            if result.plaintext == "<REDACTED>":
                output += "Status: FOUND (password redacted for privacy)\n"
                output += "Note: Hash found in breach database"
            else:
                output += f"Plaintext: {result.plaintext}\n"
                output += "Status: CRACKED ✓"
        else:
            output += "Status: NOT FOUND ✗"
        
        self.results_text.setText(output)
    
    def update_database(self):
        """Update hash database - show dialog to select source"""
        from PyQt6.QtWidgets import QInputDialog
        
        sources = list(SOURCES.keys())
        source_name, ok = QInputDialog.getItem(
            self, "Update Database", "Select source to update:", sources, 0, False
        )
        
        if not ok:
            return
        
        self.update_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        self.worker = HashUpdateWorker(self.service, source_name)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.update_finished)
        self.worker.error.connect(self.update_error)
        self.worker.start()
    
    def update_progress(self, message):
        """Update progress message"""
        self.results_text.append(message)
        # Auto-scroll to bottom
        scrollbar = self.results_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def update_finished(self, count):
        """Handle update completion"""
        self.progress_bar.setVisible(False)
        self.update_btn.setEnabled(True)
        self.results_text.append(f"\n[SUCCESS] Database updated successfully!")
        if count == 0:
            self.results_text.append("No new records added - all entries were duplicates")
        else:
            self.results_text.append(f"Added {count:,} new hash records.")
        
        # Show updated stats
        stats = self.service.get_database_stats()
        self.results_text.append(f"Total database size: {stats['total']:,} hashes")
        
        # Refresh source dropdown
        self.populate_sources()
    
    def update_error(self, error):
        """Handle update error"""
        self.progress_bar.setVisible(False)
        self.update_btn.setEnabled(True)
        self.results_text.append(f"\n[ERROR] Update failed: {error}")
        self.results_text.append("Check your internet connection and try again.")
    
    def show_stats(self):
        """Show database statistics"""
        stats = self.service.get_database_stats()
        
        output = "Database Statistics:\n"
        output += f"Total hashes: {stats['total']:,}\n\n"
        output += "By source:\n"
        for source, count in stats['sources'].items():
            output += f"  {source}: {count:,}\n"
        
        self.results_text.setText(output)