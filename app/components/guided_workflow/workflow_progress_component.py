# app/components/guided_workflow/workflow_progress_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QProgressBar
from PyQt6.QtCore import pyqtSignal

class WorkflowProgressComponent(QWidget):
    """Workflow progress tracking component"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Progress header
        header_layout = QHBoxLayout()
        
        title = QLabel("🎯 Guided Penetration Testing Workflow")
        title.setStyleSheet("font-size: 24pt; font-weight: bold; color: white;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Mode toggle
        mode_btn = QPushButton("🧭 Guided Mode")
        mode_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                border: 2px solid #64C8FF;
                border-radius: 5px;
                color: #000000;
                font-weight: bold;
                padding: 8px 15px;
            }
        """)
        header_layout.addWidget(mode_btn)
        
        layout.addLayout(header_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(12)  # 12 workflow steps
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #64C8FF;
                border-radius: 5px;
                text-align: center;
                color: white;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #64C8FF;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Progress stats
        self.progress_stats = QLabel("Progress: 0/12 steps completed")
        self.progress_stats.setStyleSheet("color: #87CEEB; margin: 5px 0;")
        layout.addWidget(self.progress_stats)
    
    def update_progress(self, current_step, completed_steps):
        """Update progress display"""
        self.progress_bar.setValue(current_step + 1)
        self.progress_stats.setText(f"Progress: {completed_steps}/12 steps completed")
        
        # Update progress bar color based on completion
        if completed_steps == 12:
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    border: 2px solid #32CD32;
                    border-radius: 5px;
                    text-align: center;
                    color: white;
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: #32CD32;
                    border-radius: 3px;
                }
            """)