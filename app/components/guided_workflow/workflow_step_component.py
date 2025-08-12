# app/components/guided_workflow/workflow_step_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QCheckBox, QFrame)
from PyQt6.QtCore import pyqtSignal

class WorkflowStepComponent(QWidget):
    """Individual workflow step display component"""
    
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, step_data, parent=None):
        super().__init__(parent)
        self.step_data = step_data
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Step header
        self.step_title = QLabel(self.step_data.get('name', 'Step'))
        self.step_title.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(self.step_title)
        
        # Description
        self.step_description = QLabel(self.step_data.get('description', ''))
        self.step_description.setWordWrap(True)
        self.step_description.setStyleSheet("color: #DCDCDC; margin: 10px 0;")
        layout.addWidget(self.step_description)
        
        # Time estimate
        self.time_estimate = QLabel(f"⏱️ Estimated Time: {self.step_data.get('estimated_time', 'Unknown')}")
        self.time_estimate.setStyleSheet("color: #87CEEB; font-style: italic;")
        layout.addWidget(self.time_estimate)
        
        # Tools section
        tools_label = QLabel("🛠️ Required Tools:")
        tools_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF; margin-top: 15px;")
        layout.addWidget(tools_label)
        
        # Tool buttons
        for tool in self.step_data.get('tools', []):
            tool_btn = QPushButton(f"🔧 {tool}")
            tool_btn.clicked.connect(lambda checked, t=tool: self.launch_tool(t))
            layout.addWidget(tool_btn)
        
        # Action buttons
        self.create_action_buttons(layout)
        
        # Notes section
        self.create_notes_section(layout)
    
    def create_action_buttons(self, layout):
        """Create step action buttons"""
        actions_frame = QFrame()
        actions_layout = QHBoxLayout(actions_frame)
        
        # Complete step button
        self.complete_btn = QPushButton("✅ Mark Complete")
        self.complete_btn.clicked.connect(self.toggle_complete)
        actions_layout.addWidget(self.complete_btn)
        
        # Repeat step button
        repeat_btn = QPushButton("🔄 Repeat Step")
        repeat_btn.clicked.connect(self.repeat_step)
        actions_layout.addWidget(repeat_btn)
        
        # Auto-advance toggle
        self.auto_advance_cb = QCheckBox("Auto-advance after tool launch")
        actions_layout.addWidget(self.auto_advance_cb)
        
        layout.addWidget(actions_frame)
    
    def create_notes_section(self, layout):
        """Create expandable notes section"""
        self.notes_toggle = QPushButton("📌 Notes & Results (Click to expand)")
        self.notes_toggle.clicked.connect(self.toggle_notes)
        layout.addWidget(self.notes_toggle)
        
        # Notes area (initially hidden)
        self.notes_area = QTextEdit()
        self.notes_area.setMaximumHeight(120)
        self.notes_area.setPlaceholderText("Add your notes, findings, and observations...")
        self.notes_area.setVisible(False)
        layout.addWidget(self.notes_area)
    
    def launch_tool(self, tool_name):
        """Launch specified tool"""
        tool_mapping = {
            "Target Profiles": "home",
            "OSINT Collection": "osint",
            "DNS Records": "recon_enumeration",
            "Port Scanning": "recon_enumeration",
            "Huggin Advanced Scanner": "huggin_scanner",
            "Shell Management": "shell_management",
        }
        
        page = tool_mapping.get(tool_name, "home")
        self.navigate_signal.emit(page)
        self.status_updated.emit(f"🚀 Launched {tool_name}")
    
    def toggle_complete(self):
        """Toggle step completion"""
        if hasattr(self.step_data, 'completed'):
            self.step_data.completed = not self.step_data.completed
            if self.step_data.completed:
                self.complete_btn.setText("✅ Completed")
                self.status_updated.emit("Step marked as complete")
            else:
                self.complete_btn.setText("✅ Mark Complete")
                self.status_updated.emit("Step marked as incomplete")
    
    def repeat_step(self):
        """Reset step for repetition"""
        if hasattr(self.step_data, 'completed'):
            self.step_data.completed = False
        self.complete_btn.setText("✅ Mark Complete")
        self.notes_area.clear()
        self.status_updated.emit("Step reset for repetition")
    
    def toggle_notes(self):
        """Toggle notes section visibility"""
        visible = self.notes_area.isVisible()
        self.notes_area.setVisible(not visible)
        
        if not visible:
            self.notes_toggle.setText("📌 Notes & Results (Click to collapse)")
            self.notes_area.setFocus()
        else:
            self.notes_toggle.setText("📌 Notes & Results (Click to expand)")