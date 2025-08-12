# app/widgets/multi_target_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QProgressBar, QGroupBox, QFileDialog)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from app.core.multi_target_manager import multi_target_manager
from app.core.drag_drop_handler import DragDropMixin

class MultiTargetWidget(QWidget, DragDropMixin):
    """Widget for multi-target scanning with drag and drop support"""
    
    scan_started = pyqtSignal(str)  # Signal when multi-scan starts
    scan_completed = pyqtSignal(str, dict)  # Signal when multi-scan completes
    
    def __init__(self, parent=None):
        QWidget.__init__(self, parent)
        DragDropMixin.__init__(self)
        self.current_scan_id = None
        self.setup_ui()
        self.setup_timer()
        self.set_drop_callback(self.handle_file_drop)
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Multi-target group
        target_group = QGroupBox("🎯 Multi-Target Scanning")
        target_group.setStyleSheet("""
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
        
        target_layout = QVBoxLayout(target_group)
        
        # Target input area
        input_layout = QVBoxLayout()
        input_layout.addWidget(QLabel("Targets (one per line, comma/semicolon separated):"))
        
        self.target_input = QTextEdit()
        self.target_input.setFixedHeight(120)
        self.target_input.setPlaceholderText("example.com\n192.168.1.1\ntest.org\n# Comments start with #\n\n📁 Drag & drop .txt files here")
        self.target_input.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
            QTextEdit:focus {
                border: 2px solid #64C8FF;
            }
        """)
        
        # File controls
        file_layout = QHBoxLayout()
        
        self.load_file_button = QPushButton("📁 Load from File")
        self.load_file_button.clicked.connect(self.load_targets_from_file)
        
        self.clear_button = QPushButton("🗑️ Clear")
        self.clear_button.clicked.connect(self.clear_targets)
        
        self.count_label = QLabel("0 targets")
        self.count_label.setStyleSheet("color: #888; font-size: 10pt;")
        
        file_layout.addWidget(self.load_file_button)
        file_layout.addWidget(self.clear_button)
        file_layout.addWidget(self.count_label)
        file_layout.addStretch()
        
        # Scan controls
        scan_layout = QHBoxLayout()
        
        self.start_button = QPushButton("🚀 Start Multi-Scan")
        self.start_button.clicked.connect(self.start_multi_scan)
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
        self.stop_button.clicked.connect(self.stop_multi_scan)
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
        
        scan_layout.addWidget(self.start_button)
        scan_layout.addWidget(self.stop_button)
        scan_layout.addStretch()
        
        # Progress section
        progress_layout = QVBoxLayout()
        progress_layout.addWidget(QLabel("Progress:"))
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
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
        
        self.status_text = QTextEdit()
        self.status_text.setFixedHeight(100)
        self.status_text.setReadOnly(True)
        self.status_text.setStyleSheet("""
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
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_text)
        
        # Button styling
        button_style = """
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """
        
        self.load_file_button.setStyleSheet(button_style)
        self.clear_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 150, 100"))
        
        # Connect text change to update count
        self.target_input.textChanged.connect(self.update_target_count)
        
        # Add to target layout
        target_layout.addLayout(input_layout)
        target_layout.addLayout(file_layout)
        target_layout.addLayout(scan_layout)
        target_layout.addLayout(progress_layout)
        
        layout.addWidget(target_group)
        layout.addStretch()
        
    def setup_timer(self):
        """Setup timer to update progress"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_progress)
        
    def update_target_count(self):
        """Update target count label"""
        targets = multi_target_manager.parse_target_list(self.target_input.toPlainText())
        count = len(targets)
        self.count_label.setText(f"{count} target{'s' if count != 1 else ''}")
        
        if count > 0:
            self.count_label.setStyleSheet("color: #00AA00; font-size: 10pt; font-weight: bold;")
        else:
            self.count_label.setStyleSheet("color: #888; font-size: 10pt;")
    
    def load_targets_from_file(self):
        """Load targets from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Target List", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            targets = multi_target_manager.load_targets_from_file(file_path)
            if targets:
                self.target_input.setPlainText('\n'.join(targets))
                self.log_message(f"Loaded {len(targets)} targets from file")
            else:
                self.log_message("Failed to load targets from file")
    
    def clear_targets(self):
        """Clear target input"""
        self.target_input.clear()
        self.log_message("Target list cleared")
    
    def start_multi_scan(self):
        """Start multi-target scan"""
        targets = multi_target_manager.parse_target_list(self.target_input.toPlainText())
        
        if not targets:
            self.log_message("❌ No targets specified")
            return
        
        if len(targets) > 20:
            self.log_message("❌ Maximum 20 targets allowed")
            return
        
        # Get parent scan function (would be implemented by parent)
        parent = self.parent()
        if not hasattr(parent, 'execute_single_target_scan'):
            self.log_message("❌ Scan function not available")
            return
        
        self.log_message(f"🚀 Starting multi-target scan for {len(targets)} targets...")
        
        # Start multi-target scan
        scan_params = {'scan_type': 'dns_enum'}  # Default, would be configurable
        self.current_scan_id = multi_target_manager.scan_multiple_targets(
            targets=targets,
            scan_function=parent.execute_single_target_scan,
            scan_params=scan_params,
            progress_callback=self.on_progress_update,
            result_callback=self.on_target_completed
        )
        
        # Update UI state
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        
        # Start progress updates
        self.update_timer.start(1000)  # Update every second
        
        self.scan_started.emit(self.current_scan_id)
    
    def stop_multi_scan(self):
        """Stop multi-target scan"""
        if self.current_scan_id:
            multi_target_manager.cancel_scan(self.current_scan_id)
            self.log_message("⏹️ Multi-target scan cancelled")
            self.reset_ui_state()
    
    def on_progress_update(self, message):
        """Handle progress updates"""
        self.log_message(message)
    
    def on_target_completed(self, target, result):
        """Handle individual target completion"""
        if isinstance(result, dict) and 'error' in result:
            self.log_message(f"❌ {target}: {result['error']}")
        else:
            result_count = len(result) if isinstance(result, dict) else 0
            self.log_message(f"✅ {target}: {result_count} results")
    
    def update_progress(self):
        """Update progress bar and status"""
        if not self.current_scan_id:
            return
        
        status = multi_target_manager.get_scan_status(self.current_scan_id)
        if not status:
            return
        
        # Update progress bar
        if status.get('total', 0) > 0:
            progress = (status.get('completed', 0) / status.get('total', 1)) * 100
            self.progress_bar.setValue(int(progress))
        
        # Check if scan completed
        if status.get('status') in ['completed', 'failed', 'cancelled']:
            self.update_timer.stop()
            self.reset_ui_state()
            
            if status.get('status') == 'completed':
                results = multi_target_manager.get_scan_results(self.current_scan_id)
                self.log_message(f"✅ Multi-target scan completed: {len(results)} targets processed")
                self.scan_completed.emit(self.current_scan_id, results)
    
    def reset_ui_state(self):
        """Reset UI to initial state"""
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.current_scan_id = None
    
    def log_message(self, message):
        """Add message to status log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_text.append(f"[{timestamp}] {message}")
        
        # Auto-scroll to bottom
        cursor = self.status_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.status_text.setTextCursor(cursor)
    
    def handle_file_drop(self, file_paths):
        """Handle dropped files"""
        for file_path in file_paths:
            targets = multi_target_manager.load_targets_from_file(file_path)
            if targets:
                # Add to existing content
                current_text = self.target_input.toPlainText()
                if current_text.strip():
                    new_text = current_text + '\n' + '\n'.join(targets)
                else:
                    new_text = '\n'.join(targets)
                
                self.target_input.setPlainText(new_text)
                self.log_message(f"📁 Dropped file: {len(targets)} targets from {file_path}")
                break  # Only process first valid file