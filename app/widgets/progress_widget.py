# app/widgets/progress_widget.py
from PyQt6.QtWidgets import QWidget, QProgressBar, QLabel, QVBoxLayout, QHBoxLayout
from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from datetime import datetime, timedelta

class ProgressWidget(QWidget):
    """Enhanced progress widget with ETA and statistics"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.start_time = None
        self.total_items = 0
        self.completed_items = 0
        self.results_found = 0
        
        self.setup_ui()
        
        # Timer for updating ETA
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(1000)  # Update every second
    
    def setup_ui(self):
        """Setup the progress widget UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Progress bar only
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #506478;
                border-radius: 8px;
                background-color: rgba(20, 30, 40, 180);
                text-align: center;
                font-size: 12pt;
                color: #DCDCDC;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00AA00, stop:1 #00FF41);
                border-radius: 7px;
            }
        """)
        layout.addWidget(self.progress_bar)
    
    def start_progress(self, total_items, status="Processing..."):
        """Start progress tracking"""
        self.total_items = total_items
        self.completed_items = 0
        self.results_found = 0
        self.start_time = datetime.now()
        
        self.progress_bar.setMaximum(total_items)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0.0% (0/" + str(total_items) + ")")
        self.update_display()
    
    def update_progress(self, completed_items, results_found=None, status_message=None):
        """Update progress values"""
        self.completed_items = completed_items
        if results_found is not None:
            self.results_found = results_found
        
        self.progress_bar.setValue(completed_items)
        
        # Update progress bar text with percentage
        if self.total_items > 0:
            percentage = (completed_items / self.total_items) * 100
            self.progress_bar.setFormat(f"{percentage:.1f}% ({completed_items}/{self.total_items})")
        else:
            self.progress_bar.setFormat(f"{completed_items} items")
        
        self.update_display()
    
    def increment_results(self):
        """Increment results counter"""
        self.results_found += 1
    
    def update_display(self):
        """Update display - simplified for progress bar only"""
        # No additional display updates needed for progress bar only
        pass
    
    def finish_progress(self, status="Complete"):
        """Finish progress tracking"""
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_bar.setFormat("100.0% - Complete")
    
    def reset_progress(self):
        """Reset progress to initial state"""
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0.0%")
        self.start_time = None
        self.completed_items = 0
        self.results_found = 0
        self.total_items = 0