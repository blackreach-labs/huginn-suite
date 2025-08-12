# app/components/guided_workflow/workflow_navigation_component.py
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QPushButton, QLabel
from PyQt6.QtCore import pyqtSignal

class WorkflowNavigationComponent(QWidget):
    """Workflow navigation controls component"""
    
    previous_step = pyqtSignal()
    next_step = pyqtSignal()
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_step = 0
        self.total_steps = 12
        self.setup_ui()
    
    def setup_ui(self):
        layout = QHBoxLayout(self)
        
        # Previous button
        self.prev_button = QPushButton("⬅️ Previous Step")
        self.prev_button.clicked.connect(self.on_previous)
        layout.addWidget(self.prev_button)
        
        # Step counter
        self.step_counter = QLabel("Step 1 of 12")
        self.step_counter.setStyleSheet("color: #87CEEB; margin: 0 20px;")
        layout.addWidget(self.step_counter)
        
        layout.addStretch()
        
        # Next/Finish button
        self.next_button = QPushButton("Next Step ➡️")
        self.next_button.clicked.connect(self.on_next)
        layout.addWidget(self.next_button)
    
    def update_navigation(self, current_step, total_steps):
        """Update navigation state"""
        self.current_step = current_step
        self.total_steps = total_steps
        
        # Update step counter
        self.step_counter.setText(f"Step {current_step + 1} of {total_steps}")
        
        # Update button states
        self.prev_button.setEnabled(current_step > 0)
        
        if current_step >= total_steps - 1:
            self.next_button.setText("✅ Finish Workflow")
        else:
            self.next_button.setText("Next Step ➡️")
    
    def on_previous(self):
        """Handle previous button click"""
        self.previous_step.emit()
        self.status_updated.emit(f"Moved to step {self.current_step}")
    
    def on_next(self):
        """Handle next button click"""
        self.next_step.emit()
        if self.current_step >= self.total_steps - 1:
            self.status_updated.emit("Workflow completed!")
        else:
            self.status_updated.emit(f"Moved to step {self.current_step + 2}")