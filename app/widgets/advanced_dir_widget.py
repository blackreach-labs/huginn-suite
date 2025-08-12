# app/widgets/advanced_dir_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QSpinBox, QCheckBox, 
                            QTextEdit, QProgressBar, QGroupBox, QComboBox)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from app.core.advanced_dir_enum import advanced_dir_enum
import json

class DirectoryEnumWorker(QThread):
    """Worker thread for directory enumeration"""
    
    progress_update = pyqtSignal(str)
    result_found = pyqtSignal(dict)
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, target_url, wordlist_path, max_depth, max_threads):
        super().__init__()
        self.target_url = target_url
        self.wordlist_path = wordlist_path
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.running = True
    
    def run(self):
        """Execute directory enumeration"""
        try:
            # Configure enumerator
            advanced_dir_enum.max_depth = self.max_depth
            advanced_dir_enum.max_threads = self.max_threads
            
            # Start enumeration
            results = advanced_dir_enum.enumerate_directories(
                self.target_url,
                self.wordlist_path,
                progress_callback=self.progress_update.emit,
                result_callback=self.result_found.emit
            )
            
            self.scan_completed.emit(results)
            
        except Exception as e:
            self.scan_completed.emit({'error': str(e)})
    
    def stop(self):
        """Stop the enumeration"""
        self.running = False
        self.terminate()

class AdvancedDirectoryWidget(QWidget):
    """Widget for advanced directory enumeration"""
    
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Configuration group
        config_group = QGroupBox("🗂️ Advanced Directory Enumeration")
        config_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        config_layout = QVBoxLayout(config_group)
        
        # Target URL
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target URL:"))
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setStyleSheet(self._get_input_style())
        
        url_layout.addWidget(self.url_input)
        
        # Wordlist selection
        wordlist_layout = QHBoxLayout()
        wordlist_layout.addWidget(QLabel("Wordlist:"))
        
        self.wordlist_combo = QComboBox()
        self.wordlist_combo.addItems(["directories.txt", "common.txt", "big.txt"])
        self.wordlist_combo.setFixedWidth(150)
        
        wordlist_layout.addWidget(self.wordlist_combo)
        wordlist_layout.addStretch()
        
        # Scan options
        options_layout = QHBoxLayout()
        
        options_layout.addWidget(QLabel("Max Depth:"))
        self.depth_spinbox = QSpinBox()
        self.depth_spinbox.setRange(1, 5)
        self.depth_spinbox.setValue(3)
        self.depth_spinbox.setFixedWidth(60)
        
        options_layout.addWidget(self.depth_spinbox)
        
        options_layout.addWidget(QLabel("Threads:"))
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 50)
        self.threads_spinbox.setValue(20)
        self.threads_spinbox.setFixedWidth(60)
        
        options_layout.addWidget(self.threads_spinbox)
        
        self.recursive_checkbox = QCheckBox("Recursive Scanning")
        self.recursive_checkbox.setChecked(True)
        self.recursive_checkbox.setStyleSheet("color: #DCDCDC;")
        
        options_layout.addWidget(self.recursive_checkbox)
        options_layout.addStretch()
        
        # Control buttons with progress bar
        control_layout = QHBoxLayout()
        
        # Progress bar (uses available space to the left)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(20)  # Fixed height to prevent squishing
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555;
                border-radius: 4px;
                text-align: center;
                color: white;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: rgba(100, 200, 255, 150);
                border-radius: 3px;
            }
        """)
        control_layout.addWidget(self.progress_bar, 1)  # Stretch factor 1
        
        control_layout.addStretch()
        
        self.start_button = QPushButton("🚀 Start Enumeration")
        self.start_button.clicked.connect(self.start_enumeration)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 255, 100, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 11pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 255, 100, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888;
            }
        """)
        
        self.stop_button = QPushButton("⏹️ Stop")
        self.stop_button.clicked.connect(self.stop_enumeration)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 11pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 100, 100, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888;
            }
        """)
        
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        
        # Status section
        status_layout = QVBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        
        self.status_label = QLabel("Ready to start enumeration")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        status_layout.addWidget(self.status_label)
        
        # Results section
        results_layout = QVBoxLayout()
        results_layout.addWidget(QLabel("Results:"))
        
        self.results_text = QTextEdit()
        self.results_text.setFixedHeight(200)
        self.results_text.setReadOnly(True)
        self.results_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 9pt;
                padding: 5px;
                font-family: 'Courier New', monospace;
            }
        """)
        
        results_layout.addWidget(self.results_text)
        
        # Add to config layout
        config_layout.addLayout(url_layout)
        config_layout.addLayout(wordlist_layout)
        config_layout.addLayout(options_layout)
        config_layout.addLayout(control_layout)
        config_layout.addLayout(status_layout)
        config_layout.addLayout(results_layout)
        
        layout.addWidget(config_group)
        layout.addStretch()
        
    def _get_input_style(self):
        return """
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
        """
    
    def start_enumeration(self):
        """Start directory enumeration"""
        target_url = self.url_input.text().strip()
        if not target_url:
            self.status_label.setText("❌ Please enter target URL")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
            self.url_input.setText(target_url)
        
        # Get wordlist path (simplified)
        wordlist_name = self.wordlist_combo.currentText()
        wordlist_path = f"resources/wordlists/{wordlist_name}"
        
        # Configure parameters
        max_depth = self.depth_spinbox.value() if self.recursive_checkbox.isChecked() else 1
        max_threads = self.threads_spinbox.value()
        
        # Start worker thread
        self.worker = DirectoryEnumWorker(target_url, wordlist_path, max_depth, max_threads)
        self.worker.progress_update.connect(self.on_progress_update)
        self.worker.result_found.connect(self.on_result_found)
        self.worker.scan_completed.connect(self.on_scan_completed)
        self.worker.start()
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Reset to indeterminate
        self.results_text.clear()
        
        self.status_label.setText("🚀 Starting directory enumeration...")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
    
    def stop_enumeration(self):
        """Stop directory enumeration"""
        if self.worker:
            self.worker.stop()
            self.worker = None
        
        self.reset_ui_state()
        self.status_label.setText("⏹️ Enumeration stopped")
        self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
    
    def on_progress_update(self, message):
        """Handle progress updates"""
        self.status_label.setText(message)
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
    
    def on_result_found(self, finding):
        """Handle individual result"""
        status_code = finding.get('status_code', 0)
        url = finding.get('url', '')
        finding_type = finding.get('type', 'unknown')
        
        # Color code by status
        if status_code == 200:
            color = "#00FF41"  # Green
        elif status_code in [301, 302]:
            color = "#FFAA00"  # Orange
        elif status_code == 403:
            color = "#FF6600"  # Red-orange
        else:
            color = "#DCDCDC"  # Default
        
        # Add interesting indicator
        interesting = "⭐ " if finding.get('interesting', False) else ""
        
        result_line = f"<span style='color: {color};'>[{status_code}] {interesting}{url} ({finding_type})</span><br>"
        self.results_text.insertHtml(result_line)
        
        # Auto-scroll to bottom
        cursor = self.results_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.results_text.setTextCursor(cursor)
    
    def on_scan_completed(self, results):
        """Handle scan completion"""
        # Reset button states but keep progress bar visible
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Finish progress bar with 100% completion
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_bar.setFormat("100.0% - Complete")
        
        if 'error' in results:
            self.status_label.setText(f"❌ Error: {results['error']}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
        else:
            stats = results.get('scan_stats', {})
            dirs_found = stats.get('directories_found', 0)
            files_found = stats.get('files_found', 0)
            total_requests = stats.get('total_requests', 0)
            
            self.status_label.setText(f"✅ Complete: {dirs_found} dirs, {files_found} files ({total_requests} requests)")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            
            # Add summary to results
            summary = f"""
<br><span style='color: #64C8FF; font-weight: bold;'>--- SCAN SUMMARY ---</span><br>
<span style='color: #00FF41;'>Directories found: {dirs_found}</span><br>
<span style='color: #00FF41;'>Files found: {files_found}</span><br>
<span style='color: #FFAA00;'>Total requests: {total_requests}</span><br>
<span style='color: #FFAA00;'>Interesting findings: {len(results.get('interesting_findings', []))}</span><br>
            """
            self.results_text.insertHtml(summary)
        
        self.scan_completed.emit(results)
    
    def reset_ui_state(self):
        """Reset UI to initial state"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)