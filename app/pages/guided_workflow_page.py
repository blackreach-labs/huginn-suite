# app/pages/guided_workflow_page.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QProgressBar, QFrame, QTextEdit, QScrollArea,
                             QDialog, QLineEdit, QComboBox, QCheckBox, QFormLayout, QDialogButtonBox,
                             QStackedWidget, QMessageBox, QSizePolicy, QGraphicsDropShadowEffect,
                             QSpacerItem)
from PyQt6.QtCore import pyqtSignal, Qt, QTimer, QThread, pyqtSlot, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QPixmap, QPainter, QPen, QColor, QLinearGradient
from app.core.questionnaire_graph import QuestionnaireGraph
from app.widgets.questionnaire_widget import QuestionnaireWidget
import os
import json


class WorkflowStep:
    def __init__(self, name, description, tools, estimated_time, prerequisites=None):
        self.name = name
        self.title = name
        self.description = description
        self.tools = tools
        self.estimated_time = estimated_time
        self.prerequisites = prerequisites or []
        self.completed = False
        self.results = {}


class StepTimelineWidget(QFrame):
    """Visual timeline sidebar showing all workflow steps with progress indicators"""
    
    step_clicked = pyqtSignal(int)
    
    def __init__(self, steps, parent=None):
        super().__init__(parent)
        self.steps = steps
        self.current_step = 0
        self.setFixedWidth(260)
        self.setObjectName("StepTimeline")
        self.setStyleSheet("""
            QFrame#StepTimeline {
                background-color: rgba(10, 15, 25, 200);
                border-radius: 12px;
                border: 1px solid rgba(100, 200, 255, 40);
            }
        """)
        self.setup_ui()
    
    def setup_ui(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("""
            QScrollArea { background: transparent; border: none; }
            QScrollBar:vertical {
                background: rgba(30, 40, 60, 100);
                width: 6px;
                border-radius: 3px;
            }
            QScrollBar::handle:vertical {
                background: rgba(100, 200, 255, 80);
                border-radius: 3px;
                min-height: 30px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """)
        
        container = QWidget()
        self.timeline_layout = QVBoxLayout(container)
        self.timeline_layout.setContentsMargins(12, 16, 12, 16)
        self.timeline_layout.setSpacing(4)
        
        # Timeline header
        header = QLabel("WORKFLOW STEPS")
        header.setStyleSheet("""
            font-size: 9pt; font-weight: bold; color: rgba(100, 200, 255, 180);
            letter-spacing: 2px; padding: 4px 8px;
        """)
        self.timeline_layout.addWidget(header)
        
        self.step_labels = []
        for i, step in enumerate(self.steps):
            step_widget = self._create_step_item(i, step)
            self.timeline_layout.addWidget(step_widget)
            self.step_labels.append(step_widget)
        
        self.timeline_layout.addStretch()
        scroll.setWidget(container)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)
    
    def _create_step_item(self, index, step):
        frame = QFrame()
        frame.setObjectName(f"step_item_{index}")
        frame.setCursor(Qt.CursorShape.PointingHandCursor)
        frame.mousePressEvent = lambda e, idx=index: self.step_clicked.emit(idx)
        
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(10)
        
        # Step number indicator (circle)
        indicator = QLabel(str(index + 1))
        indicator.setFixedSize(26, 26)
        indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        indicator.setObjectName(f"step_indicator_{index}")
        layout.addWidget(indicator)
        
        # Step name
        name_label = QLabel(step.name)
        name_label.setObjectName(f"step_name_{index}")
        name_label.setWordWrap(True)
        name_label.setStyleSheet("font-size: 9pt; color: #8899AA;")
        layout.addWidget(name_label, 1)
        
        frame.setStyleSheet("""
            QFrame { 
                border-radius: 6px; 
                background: transparent;
                padding: 2px;
            }
            QFrame:hover { background: rgba(100, 200, 255, 15); }
        """)
        
        return frame
    
    def set_current_step(self, index):
        self.current_step = index
        for i, frame in enumerate(self.step_labels):
            indicator = frame.findChild(QLabel, f"step_indicator_{i}")
            name_label = frame.findChild(QLabel, f"step_name_{i}")
            
            if i < index:
                # Completed
                indicator.setStyleSheet("""
                    background-color: #2ECC71; color: white; 
                    border-radius: 13px; font-size: 9pt; font-weight: bold;
                """)
                indicator.setText("✓")
                name_label.setStyleSheet("font-size: 9pt; color: #2ECC71; font-weight: bold;")
                frame.setStyleSheet("""
                    QFrame { border-radius: 6px; background: rgba(46, 204, 113, 10); padding: 2px; }
                    QFrame:hover { background: rgba(46, 204, 113, 25); }
                """)
            elif i == index:
                # Current
                indicator.setStyleSheet("""
                    background-color: #64C8FF; color: #0A0F19;
                    border-radius: 13px; font-size: 9pt; font-weight: bold;
                """)
                indicator.setText(str(i + 1))
                name_label.setStyleSheet("font-size: 9pt; color: #64C8FF; font-weight: bold;")
                frame.setStyleSheet("""
                    QFrame { 
                        border-radius: 6px; 
                        background: rgba(100, 200, 255, 15); 
                        border: 1px solid rgba(100, 200, 255, 60);
                        padding: 2px;
                    }
                """)
            else:
                # Upcoming
                indicator.setStyleSheet("""
                    background-color: rgba(60, 70, 90, 180); color: #556677;
                    border-radius: 13px; font-size: 9pt; font-weight: bold;
                """)
                indicator.setText(str(i + 1))
                name_label.setStyleSheet("font-size: 9pt; color: #556677;")
                frame.setStyleSheet("""
                    QFrame { border-radius: 6px; background: transparent; padding: 2px; }
                    QFrame:hover { background: rgba(100, 200, 255, 8); }
                """)


class GuidedWorkflowPage(QWidget):
    """Beginner-friendly guided penetration testing workflow"""
    
    navigate_signal = pyqtSignal(str)
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.current_step = 0
        self.current_session = None
        self.expert_mode = False
        self.neo4j_client = None
        self.questionnaire_widget = None
        self.setup_workflow_steps()
        self.setup_ui()
        self.update_step_display()
        self.init_questionnaire_system()
        
        self.current_session = "default_session"
        
    def create_workflow_steps(self):
        """Define the complete penetration testing workflow"""
        return [
            WorkflowStep(
                "Target Definition",
                "Define scope, gather initial target information, and set up engagement parameters.",
                ["Target Profiles", "Credential Management"],
                "10-15 minutes",
                []
            ),
            WorkflowStep(
                "Passive Reconnaissance", 
                "Gather information without directly interacting with the target. This includes OSINT, DNS lookups, and certificate transparency logs.",
                ["OSINT Collection", "DNS Records", "Certificate Transparency"],
                "20-30 minutes",
                ["Target Definition"]
            ),
            WorkflowStep(
                "Network Discovery",
                "Discover live hosts and open ports on the target network using port scanning and service detection.",
                ["Port Scanning", "Huginn Advanced Scanner"],
                "15-25 minutes", 
                ["Target Definition"]
            ),
            WorkflowStep(
                "Service Enumeration",
                "Identify and enumerate services running on discovered ports to understand the attack surface.",
                ["HTTP", "RPC", "SMB", "SMTP", "SNMP", "LDAP", "API", "AV/FW"],
                "30-45 minutes",
                ["Network Discovery"]
            ),
            WorkflowStep(
                "Automated Vulnerability Scanning",
                "Run automated scanners to identify potential security issues across discovered services.",
                ["Huginn Advanced Scanner", "Web Vulnerability Scanner"],
                "20-40 minutes",
                ["Service Enumeration"]
            ),
            WorkflowStep(
                "Manual Vulnerability Testing",
                "Manually test for common vulnerabilities based on discovered services, including parameter fuzzing and auth testing.",
                ["Parameter Fuzzing", "Authentication Testing", "Business Logic Testing"],
                "45-90 minutes",
                ["Automated Vulnerability Scanning"]
            ),
            WorkflowStep(
                "Exploit Development",
                "Develop and test exploits for confirmed vulnerabilities. Create proof-of-concept demonstrations.",
                ["Payload Generation", "Exploit Testing", "Proof of Concept"],
                "30-60 minutes",
                ["Manual Vulnerability Testing"]
            ),
            WorkflowStep(
                "Initial Access",
                "Gain initial access to target systems using developed exploits and validate access level.",
                ["Shell Management", "Access Validation", "Persistence Setup"],
                "20-40 minutes",
                ["Exploit Development"]
            ),
            WorkflowStep(
                "Privilege Escalation",
                "Escalate privileges on compromised systems through local enumeration and credential harvesting.",
                ["Local Enumeration", "Privilege Escalation", "Credential Harvesting"],
                "30-60 minutes",
                ["Initial Access"]
            ),
            WorkflowStep(
                "Lateral Movement",
                "Move laterally through the network to access additional systems and expand foothold.",
                ["Network Pivoting", "Credential Reuse", "Service Exploitation"],
                "45-90 minutes",
                ["Privilege Escalation"]
            ),
            WorkflowStep(
                "Evidence Collection",
                "Document findings and collect evidence for comprehensive reporting and proof.",
                ["Screenshot Capture", "Log Collection", "Proof Documentation"],
                "20-30 minutes",
                ["Lateral Movement"]
            ),
            WorkflowStep(
                "Report Generation",
                "Generate comprehensive penetration testing report with executive summary and remediation guidance.",
                ["Executive Summary", "Technical Report", "Remediation Guide"],
                "60-120 minutes",
                ["Evidence Collection"]
            )
        ]
    
    def setup_workflow_steps(self):
        """Setup workflow steps"""
        self.workflow_steps = self.create_workflow_steps()
    
    def setup_ui(self):
        """Setup the guided workflow UI"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)
        
        # Header bar
        header_frame = self._create_header()
        main_layout.addWidget(header_frame)
        
        # Overall progress bar
        self.overall_progress = QProgressBar()
        self.overall_progress.setFixedHeight(6)
        self.overall_progress.setTextVisible(False)
        self.overall_progress.setStyleSheet("""
            QProgressBar {
                background-color: rgba(40, 50, 70, 150);
                border-radius: 3px;
                border: none;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2ECC71, stop:1 #64C8FF);
                border-radius: 3px;
            }
        """)
        self.overall_progress.setMaximum(len(self.workflow_steps))
        main_layout.addWidget(self.overall_progress)
        
        # Stacked widget for workflow and questionnaire views
        self.stacked_widget = QStackedWidget()
        
        # Main workflow view (timeline + details)
        workflow_widget = QWidget()
        workflow_layout = QHBoxLayout(workflow_widget)
        workflow_layout.setContentsMargins(0, 0, 0, 0)
        workflow_layout.setSpacing(16)
        
        # Left: Step timeline sidebar
        self.timeline = StepTimelineWidget(self.workflow_steps)
        self.timeline.step_clicked.connect(self.jump_to_step)
        workflow_layout.addWidget(self.timeline)
        
        # Right: Step content area
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(12)
        
        # Step details card
        self.step_details_frame = self._create_step_details()
        content_layout.addWidget(self.step_details_frame, 1)
        
        # Navigation controls
        nav_frame = self._create_navigation_controls()
        content_layout.addWidget(nav_frame)
        
        workflow_layout.addWidget(content_widget, 1)
        
        self.stacked_widget.addWidget(workflow_widget)
        main_layout.addWidget(self.stacked_widget, 1)
    
    def _create_header(self):
        """Create the top header bar with title, progress info, and actions"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: rgba(10, 15, 25, 180);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 30);
            }
        """)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 12, 20, 12)
        
        # Title
        title = QLabel("🎯 Guided Penetration Testing Workflow")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; color: white;")
        layout.addWidget(title)
        
        layout.addStretch()
        
        # Step counter badge
        self.step_counter = QLabel("Step 1 / 12")
        self.step_counter.setStyleSheet("""
            font-size: 10pt; color: #64C8FF; font-weight: bold;
            background: rgba(100, 200, 255, 15);
            border: 1px solid rgba(100, 200, 255, 50);
            border-radius: 12px;
            padding: 4px 14px;
        """)
        layout.addWidget(self.step_counter)
        
        # Questionnaire button
        self.questionnaire_btn = QPushButton("📋 Questionnaire")
        self.questionnaire_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.questionnaire_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(46, 204, 113, 30);
                color: #2ECC71;
                border: 1px solid rgba(46, 204, 113, 80);
                border-radius: 8px;
                padding: 6px 16px;
                font-size: 10pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(46, 204, 113, 60);
                color: white;
            }
        """)
        self.questionnaire_btn.clicked.connect(self.start_questionnaire_directly)
        layout.addWidget(self.questionnaire_btn)
        
        return frame
    
    def _create_step_details(self):
        """Create the main step details content card"""
        frame = QFrame()
        frame.setObjectName("StepDetailsCard")
        frame.setStyleSheet("""
            QFrame#StepDetailsCard {
                background-color: rgba(10, 15, 25, 200);
                border-radius: 12px;
                border: 1px solid rgba(100, 200, 255, 40);
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)
        
        # Step title row
        title_row = QHBoxLayout()
        
        self.step_title = QLabel()
        self.step_title.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        title_row.addWidget(self.step_title)
        
        title_row.addStretch()
        
        # Time estimate badge
        self.time_estimate = QLabel()
        self.time_estimate.setStyleSheet("""
            font-size: 9pt; color: #87CEEB;
            background: rgba(135, 206, 235, 10);
            border: 1px solid rgba(135, 206, 235, 40);
            border-radius: 10px;
            padding: 4px 12px;
        """)
        title_row.addWidget(self.time_estimate)
        
        layout.addLayout(title_row)
        
        # Description
        self.step_description = QLabel()
        self.step_description.setWordWrap(True)
        self.step_description.setStyleSheet("""
            font-size: 11pt; color: #B0BEC5; line-height: 1.5;
            padding: 4px 0;
        """)
        layout.addWidget(self.step_description)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet("background-color: rgba(100, 200, 255, 30); max-height: 1px;")
        layout.addWidget(separator)
        
        # Prerequisites section (shown when applicable)
        self.prereq_frame = QFrame()
        prereq_layout = QHBoxLayout(self.prereq_frame)
        prereq_layout.setContentsMargins(0, 0, 0, 0)
        prereq_icon = QLabel("⚡")
        prereq_icon.setStyleSheet("font-size: 11pt;")
        prereq_layout.addWidget(prereq_icon)
        self.prereq_label = QLabel()
        self.prereq_label.setStyleSheet("font-size: 9pt; color: #F39C12; font-style: italic;")
        prereq_layout.addWidget(self.prereq_label, 1)
        layout.addWidget(self.prereq_frame)
        
        # Tools section header
        tools_header = QLabel("Available Tools")
        tools_header.setStyleSheet("""
            font-size: 11pt; font-weight: bold; color: rgba(100, 200, 255, 200);
            letter-spacing: 1px; padding-top: 4px;
        """)
        layout.addWidget(tools_header)
        
        # Tools grid area
        self.tools_scroll = QScrollArea()
        self.tools_scroll.setWidgetResizable(True)
        self.tools_scroll.setStyleSheet("""
            QScrollArea { background: transparent; border: none; }
            QScrollBar:vertical {
                background: rgba(30, 40, 60, 100);
                width: 6px;
                border-radius: 3px;
            }
            QScrollBar::handle:vertical {
                background: rgba(100, 200, 255, 80);
                border-radius: 3px;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        """)
        self.tools_container = QWidget()
        self.tools_layout = QVBoxLayout(self.tools_container)
        self.tools_layout.setContentsMargins(0, 0, 0, 0)
        self.tools_layout.setSpacing(8)
        self.tools_scroll.setWidget(self.tools_container)
        layout.addWidget(self.tools_scroll, 1)
        
        return frame
    
    def _create_navigation_controls(self):
        """Create bottom navigation controls"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: rgba(10, 15, 25, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 20);
            }
        """)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(16, 10, 16, 10)
        
        # Previous button
        self.prev_button = QPushButton("← Previous Step")
        self.prev_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.prev_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 60, 80, 150);
                color: #8899AA;
                border: 1px solid rgba(100, 120, 150, 80);
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 10pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(70, 85, 110, 180);
                color: #DCDCDC;
                border-color: rgba(100, 200, 255, 80);
            }
            QPushButton:disabled {
                background-color: rgba(30, 35, 50, 100);
                color: #445566;
                border-color: rgba(60, 70, 90, 50);
            }
        """)
        self.prev_button.clicked.connect(self.previous_step)
        layout.addWidget(self.prev_button)
        
        layout.addStretch()
        
        # Mark complete + next button
        self.next_button = QPushButton("Mark Complete & Continue →")
        self.next_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.next_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 30);
                color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                padding: 10px 24px;
                font-size: 10pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 60);
                color: white;
            }
        """)
        self.next_button.clicked.connect(self.next_step)
        layout.addWidget(self.next_button)
        
        return frame
    
    def update_step_display(self):
        """Update the display for current step"""
        if self.current_step >= len(self.workflow_steps):
            return
            
        step = self.workflow_steps[self.current_step]
        
        # Update header counter
        self.step_counter.setText(f"Step {self.current_step + 1} / {len(self.workflow_steps)}")
        
        # Update overall progress
        self.overall_progress.setValue(self.current_step)
        
        # Update timeline sidebar
        self.timeline.set_current_step(self.current_step)
        
        # Update step details
        self.step_title.setText(step.name)
        self.step_description.setText(step.description)
        self.time_estimate.setText(f"⏱️ {step.estimated_time}")
        
        # Prerequisites
        if step.prerequisites:
            self.prereq_frame.setVisible(True)
            self.prereq_label.setText(f"Prerequisites: {', '.join(step.prerequisites)}")
        else:
            self.prereq_frame.setVisible(False)
        
        # Clear and populate tools
        self._clear_layout(self.tools_layout)
        
        # Create tool buttons in a grid-like flow
        row_layout = None
        for i, tool in enumerate(step.tools):
            if i % 2 == 0:
                row_layout = QHBoxLayout()
                row_layout.setSpacing(10)
                self.tools_layout.addLayout(row_layout)
            
            tool_button = self._create_tool_button(tool)
            row_layout.addWidget(tool_button)
        
        # Balance last row if odd number of tools
        if len(step.tools) % 2 == 1 and row_layout:
            row_layout.addStretch()
        
        self.tools_layout.addStretch()
        
        # Update navigation buttons
        self.prev_button.setEnabled(self.current_step > 0)
        
        if self.current_step >= len(self.workflow_steps) - 1:
            self.next_button.setText("✅ Finish Workflow")
            self.next_button.setStyleSheet("""
                QPushButton {
                    background-color: rgba(46, 204, 113, 30);
                    color: #2ECC71;
                    border: 1px solid rgba(46, 204, 113, 100);
                    border-radius: 8px;
                    padding: 10px 24px;
                    font-size: 10pt;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: rgba(46, 204, 113, 60);
                    color: white;
                }
            """)
        else:
            self.next_button.setText("Mark Complete & Continue →")
            self.next_button.setStyleSheet("""
                QPushButton {
                    background-color: rgba(100, 200, 255, 30);
                    color: #64C8FF;
                    border: 1px solid rgba(100, 200, 255, 100);
                    border-radius: 8px;
                    padding: 10px 24px;
                    font-size: 10pt;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: rgba(100, 200, 255, 60);
                    color: white;
                }
            """)
    
    def _create_tool_button(self, tool_name):
        """Create a styled tool launch button"""
        btn = QPushButton(f"🔧  {tool_name}")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        btn.setFixedHeight(40)
        btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 60, 80, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 120, 150, 60);
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 10pt;
                text-align: left;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 25);
                border-color: rgba(100, 200, 255, 100);
                color: #64C8FF;
            }
            QPushButton:pressed {
                background-color: rgba(100, 200, 255, 40);
            }
        """)
        btn.clicked.connect(lambda checked, t=tool_name: self.launch_tool(t))
        return btn
    
    def jump_to_step(self, index):
        """Jump directly to a specific step via timeline click"""
        if 0 <= index < len(self.workflow_steps):
            self.current_step = index
            self.update_step_display()
            self.status_updated.emit(f"Jumped to step {index + 1}: {self.workflow_steps[index].name}")
    
    def launch_tool(self, tool_name):
        """Launch the appropriate tool or show question dialog"""
        # For Step 1 tools, show question dialogs instead of redirecting
        if self.current_step == 0:
            if tool_name == "Target Profiles":
                self.show_target_profiles_questions()
            elif tool_name == "Scope & ROE":
                self.show_scope_roe_questions()
            elif tool_name == "Credential Management":
                self.show_credential_questions()
            return
        
        # For other steps, use normal tool mapping
        tool_mapping = {
            "OSINT Collection": "osint",
            "DNS Records": "recon_enumeration",
            "Port Scanning": "recon_enumeration", 
            "Huginn Advanced Scanner": "huginn_scanner",
            "HTTP": "recon_enumeration",
            "RPC": "recon_enumeration",
            "SMB": "recon_enumeration",
            "SMTP": "recon_enumeration",
            "SNMP": "recon_enumeration",
            "LDAP": "recon_enumeration",
            "API": "recon_enumeration",
            "AV/FW": "recon_enumeration",
            "Shell Management": "shell_management",
        }
        
        page = tool_mapping.get(tool_name, "home")
        self.navigate_signal.emit(page)
        self.status_updated.emit(f"🚀 Launched {tool_name}")
        
        # Mark tool as used
        self.workflow_steps[self.current_step].results[f"tool_used_{tool_name}"] = True
    
    def previous_step(self):
        """Go to previous step"""
        if self.current_step > 0:
            self.current_step -= 1
            self.update_step_display()
            self.status_updated.emit(f"Moved to step {self.current_step + 1}")
    
    def next_step(self):
        """Go to next step or finish workflow"""
        if self.current_step < len(self.workflow_steps) - 1:
            self.workflow_steps[self.current_step].completed = True
            self.current_step += 1
            self.update_step_display()
            self.status_updated.emit(f"Moved to step {self.current_step + 1}")
        else:
            self.finish_workflow()
    
    def finish_workflow(self):
        """Complete the guided workflow"""
        self.workflow_steps[self.current_step].completed = True
        
        completed_steps = sum(1 for step in self.workflow_steps if step.completed)
        
        msg = QMessageBox(self)
        msg.setWindowTitle("🎉 Workflow Complete!")
        msg.setText(f"""
🎉 Congratulations! You've completed the guided penetration testing workflow.

📊 Progress Summary:
• Steps Completed: {completed_steps}/{len(self.workflow_steps)}
• Workflow Duration: Full methodology covered
• Tools Used: Multiple security assessment tools

📄 Next Steps:
• Review your findings and notes
• Generate comprehensive reports
• Plan remediation activities

🎆 Well done on completing your security assessment!
        """)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()
        
        self.overall_progress.setValue(len(self.workflow_steps))
        self.status_updated.emit("🎉 Guided workflow completed successfully!")
    
    def init_questionnaire_system(self):
        """Initialize questionnaire system"""
        try:
            self.neo4j_client = QuestionnaireGraph()
            self.status_updated.emit("✅ Questionnaire system ready")
        except Exception as e:
            self.status_updated.emit(f"⚠️ Questionnaire system unavailable: {str(e)}")
    
    def start_questionnaire_directly(self):
        """Start guided workflow questionnaire directly"""
        if not self.neo4j_client:
            QMessageBox.warning(self, "Questionnaire Unavailable", 
                               "Questionnaire system is not available.")
            return
        
        # Create questionnaire widget if not exists
        if not self.questionnaire_widget:
            self.questionnaire_widget = QuestionnaireWidget()
            self.questionnaire_widget.response_submitted.connect(self.save_questionnaire_response)
            self.questionnaire_widget.questionnaire_completed.connect(self.questionnaire_completed)
            self.questionnaire_widget.action_triggered.connect(self.handle_questionnaire_action)
            self.stacked_widget.addWidget(self.questionnaire_widget)
        
        # Load guided workflow questionnaire directly
        try:
            questionnaire = self.neo4j_client.get_questionnaire_by_environment('guided_workflow')
            self.questionnaire_widget.load_questionnaire('guided_workflow', questionnaire)
            self.stacked_widget.setCurrentWidget(self.questionnaire_widget)
            self.questionnaire_btn.setText("🔙 Back to Workflow")
            self.questionnaire_btn.clicked.disconnect()
            self.questionnaire_btn.clicked.connect(self.show_workflow)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load questionnaire: {str(e)}")
    
    def show_workflow(self):
        """Show workflow interface"""
        self.stacked_widget.setCurrentIndex(0)
        self.questionnaire_btn.setText("📋 Questionnaire")
        self.questionnaire_btn.clicked.disconnect()
        self.questionnaire_btn.clicked.connect(self.start_questionnaire_directly)
    
    @pyqtSlot(str, str, object)
    def save_questionnaire_response(self, session_id: str, question_id: str, response):
        """Save questionnaire response"""
        try:
            self.neo4j_client.save_response(session_id, question_id, response)
            
            # Handle workflow selection
            if question_id == 'workflow_select':
                if response == 'Guided Workflow (Step-by-step)':
                    questionnaire = self.neo4j_client.get_questionnaire_by_environment('guided_workflow')
                    self.questionnaire_widget.load_questionnaire('guided_workflow', questionnaire)
                elif response == 'Environment-Specific (AD/AWS/Azure/GCP)':
                    env_question = {'text': 'Which environment is in scope?', 'options': ['Standalone Server', 'Active Directory', 'Microsoft Azure', 'AWS', 'Google Cloud']}
                    self.questionnaire_widget.load_opening_question(env_question)
                    self.questionnaire_widget.current_question_id = 'env_select'
            
            # Handle environment selection
            elif question_id == 'env_select':
                env_mapping = {
                    'Standalone Server': 'standalone',
                    'Active Directory': 'ad', 
                    'Microsoft Azure': 'azure',
                    'AWS': 'aws',
                    'Google Cloud': 'gcp'
                }
                
                env_key = env_mapping.get(response)
                if env_key:
                    questionnaire = self.neo4j_client.get_questionnaire_by_environment(env_key)
                    self.questionnaire_widget.load_questionnaire(env_key, questionnaire)
                    
        except Exception as e:
            self.status_updated.emit(f"⚠️ Failed to save response: {str(e)}")
    
    @pyqtSlot(str, str)
    def questionnaire_completed(self, session_id: str, environment: str):
        """Handle questionnaire completion"""
        try:
            responses = self.neo4j_client.get_session_responses(session_id)
            
            msg = QMessageBox(self)
            msg.setWindowTitle("🎉 Questionnaire Complete!")
            msg.setText(f"""
🎉 {environment.upper()} Penetration Test Questionnaire Complete!

📊 Summary:
• Total Responses: {len(responses)}
• Environment: {environment.upper()}
• Session ID: {session_id[:8]}...

📋 Your responses have been saved and will guide the penetration test workflow.
            """)
            msg.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg.exec()
            
            self.show_workflow()
            self.status_updated.emit(f"✅ {environment.upper()} questionnaire completed")
            
        except Exception as e:
            self.status_updated.emit(f"⚠️ Error completing questionnaire: {str(e)}")
    
    @pyqtSlot(str, object)
    def handle_questionnaire_action(self, action: str, response):
        """Handle actions triggered by questionnaire responses"""
        action_mapping = {
            'launch_osint': 'osint',
            'launch_dns_enum': 'recon_enumeration',
            'launch_port_scan': 'network_discovery',
            'launch_http_enum': 'recon_enumeration',
            'launch_smb_enum': 'recon_enumeration', 
            'launch_rpc_enum': 'recon_enumeration',
            'launch_huginn_scanner': 'huginn_scanner',
            'shell_management': 'shell_management',
            'generate_report': 'reporting'
        }
        
        if action in action_mapping:
            page = action_mapping[action]
            self.navigate_signal.emit(page)
            self.status_updated.emit(f"🚀 Launched {action.replace('launch_', '').replace('_', ' ').title()}")
        elif action == 'target_management':
            self.status_updated.emit("🎯 Target management - Configure in Settings")
        elif action.startswith('set_') or action.startswith('enable_') or action.startswith('document_'):
            self.status_updated.emit(f"⚙️ {action.replace('_', ' ').title()}: {response}")
        else:
            self.status_updated.emit(f"📝 Action: {action} - {response}")
    
    def show_target_profiles_questions(self):
        """Show target profile questions dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("🎯 Target Profile & Scope Setup")
        dialog.setModal(True)
        dialog.resize(550, 520)
        dialog.setStyleSheet("""
            QDialog {
                background-color: #1A1F2E;
            }
            QLabel {
                color: #DCDCDC;
                font-size: 10pt;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: rgba(40, 50, 70, 200);
                color: white;
                border: 1px solid rgba(100, 200, 255, 60);
                border-radius: 6px;
                padding: 8px;
                font-size: 10pt;
            }
            QLineEdit:focus, QTextEdit:focus {
                border-color: #64C8FF;
            }
            QCheckBox {
                color: #DCDCDC;
                font-size: 10pt;
                spacing: 8px;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Dialog header
        header = QLabel("Define your target and engagement scope")
        header.setStyleSheet("font-size: 11pt; color: #87CEEB; font-style: italic; margin-bottom: 8px;")
        layout.addWidget(header)
        
        form_layout = QFormLayout()
        form_layout.setSpacing(12)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        target_name = QLineEdit()
        target_name.setPlaceholderText("e.g., Company XYZ Web Application")
        form_layout.addRow("Target Name:", target_name)
        
        target_url = QLineEdit()
        target_url.setPlaceholderText("e.g., https://example.com")
        form_layout.addRow("Primary URL:", target_url)
        
        in_scope = QTextEdit()
        in_scope.setPlaceholderText("List domains, IPs, or networks in scope...")
        in_scope.setMaximumHeight(70)
        form_layout.addRow("In Scope:", in_scope)
        
        out_of_scope = QTextEdit()
        out_of_scope.setPlaceholderText("List any exclusions...")
        out_of_scope.setMaximumHeight(70)
        form_layout.addRow("Out of Scope:", out_of_scope)
        
        engagement_type = QComboBox()
        engagement_type.addItems(["External Penetration Test", "Internal Penetration Test", 
                                  "Web Application Test", "Wireless Assessment"])
        form_layout.addRow("Engagement:", engagement_type)
        
        layout.addLayout(form_layout)
        
        # Permission checkboxes
        perms_label = QLabel("Permissions:")
        perms_label.setStyleSheet("font-size: 10pt; color: #64C8FF; font-weight: bold; margin-top: 8px;")
        layout.addWidget(perms_label)
        
        dos_allowed = QCheckBox("Denial of Service attacks allowed")
        social_eng_allowed = QCheckBox("Social engineering allowed")
        physical_allowed = QCheckBox("Physical access testing allowed")
        layout.addWidget(dos_allowed)
        layout.addWidget(social_eng_allowed)
        layout.addWidget(physical_allowed)
        
        layout.addStretch()
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton { background: rgba(50, 60, 80, 150); color: #8899AA;
                border: 1px solid rgba(100, 120, 150, 60); border-radius: 6px; padding: 8px 20px; }
            QPushButton:hover { background: rgba(70, 85, 110, 180); color: #DCDCDC; }
        """)
        cancel_btn.clicked.connect(dialog.reject)
        btn_layout.addWidget(cancel_btn)
        
        save_btn = QPushButton("💾  Save Target")
        save_btn.setStyleSheet("""
            QPushButton { background: rgba(100, 200, 255, 30); color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 100); border-radius: 6px; padding: 8px 20px; font-weight: bold; }
            QPushButton:hover { background: rgba(100, 200, 255, 60); color: white; }
        """)
        save_btn.clicked.connect(lambda: self.save_target_info(
            dialog, target_name.text(), target_url.text(), in_scope.toPlainText(),
            out_of_scope.toPlainText(), engagement_type.currentText(),
            dos_allowed.isChecked(), social_eng_allowed.isChecked(), physical_allowed.isChecked()))
        btn_layout.addWidget(save_btn)
        
        layout.addLayout(btn_layout)
        dialog.exec()
    
    def show_scope_roe_questions(self):
        """Show scope and rules of engagement questions"""
        dialog = QDialog(self)
        dialog.setWindowTitle("📋 Scope & Rules of Engagement")
        dialog.setModal(True)
        dialog.resize(500, 400)
        dialog.setStyleSheet("""
            QDialog { background-color: #1A1F2E; }
            QLabel { color: #DCDCDC; font-size: 10pt; }
            QTextEdit {
                background-color: rgba(40, 50, 70, 200); color: white;
                border: 1px solid rgba(100, 200, 255, 60); border-radius: 6px; padding: 8px; font-size: 10pt;
            }
            QTextEdit:focus { border-color: #64C8FF; }
            QCheckBox { color: #DCDCDC; font-size: 10pt; spacing: 8px; }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)
        
        header = QLabel("Define the rules of engagement for this assessment")
        header.setStyleSheet("font-size: 11pt; color: #87CEEB; font-style: italic;")
        layout.addWidget(header)
        
        form_layout = QFormLayout()
        form_layout.setSpacing(12)
        
        in_scope = QTextEdit()
        in_scope.setPlaceholderText("List domains, IPs, or networks in scope...")
        in_scope.setMaximumHeight(80)
        form_layout.addRow("In Scope:", in_scope)
        
        out_of_scope = QTextEdit()
        out_of_scope.setPlaceholderText("List any exclusions...")
        out_of_scope.setMaximumHeight(80)
        form_layout.addRow("Out of Scope:", out_of_scope)
        
        layout.addLayout(form_layout)
        
        perms_label = QLabel("Permissions:")
        perms_label.setStyleSheet("font-size: 10pt; color: #64C8FF; font-weight: bold;")
        layout.addWidget(perms_label)
        
        dos_allowed = QCheckBox("Denial of Service attacks allowed")
        social_eng_allowed = QCheckBox("Social engineering allowed")
        physical_allowed = QCheckBox("Physical access testing allowed")
        layout.addWidget(dos_allowed)
        layout.addWidget(social_eng_allowed)
        layout.addWidget(physical_allowed)
        
        layout.addStretch()
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton { background: rgba(50, 60, 80, 150); color: #8899AA;
                border: 1px solid rgba(100, 120, 150, 60); border-radius: 6px; padding: 8px 20px; }
            QPushButton:hover { background: rgba(70, 85, 110, 180); color: #DCDCDC; }
        """)
        cancel_btn.clicked.connect(dialog.reject)
        btn_layout.addWidget(cancel_btn)
        
        save_btn = QPushButton("💾  Save Rules")
        save_btn.setStyleSheet("""
            QPushButton { background: rgba(100, 200, 255, 30); color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 100); border-radius: 6px; padding: 8px 20px; font-weight: bold; }
            QPushButton:hover { background: rgba(100, 200, 255, 60); color: white; }
        """)
        save_btn.clicked.connect(lambda: self.save_scope_info(
            dialog, in_scope.toPlainText(), out_of_scope.toPlainText(),
            dos_allowed.isChecked(), social_eng_allowed.isChecked(), physical_allowed.isChecked()))
        btn_layout.addWidget(save_btn)
        layout.addLayout(btn_layout)
        
        dialog.exec()
    
    def show_credential_questions(self):
        """Show credential management questions"""
        dialog = QDialog(self)
        dialog.setWindowTitle("🔐 Credential Management")
        dialog.setModal(True)
        dialog.resize(480, 320)
        dialog.setStyleSheet("""
            QDialog { background-color: #1A1F2E; }
            QLabel { color: #DCDCDC; font-size: 10pt; }
            QLineEdit, QComboBox {
                background-color: rgba(40, 50, 70, 200); color: white;
                border: 1px solid rgba(100, 200, 255, 60); border-radius: 6px; padding: 8px; font-size: 10pt;
            }
            QLineEdit:focus { border-color: #64C8FF; }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)
        
        header = QLabel("Add credentials for authenticated testing")
        header.setStyleSheet("font-size: 11pt; color: #87CEEB; font-style: italic;")
        layout.addWidget(header)
        
        form_layout = QFormLayout()
        form_layout.setSpacing(12)
        
        cred_type = QComboBox()
        cred_type.addItems(["Username/Password", "NTLM Hash", "Kerberos Ticket", "API Key"])
        form_layout.addRow("Type:", cred_type)
        
        username = QLineEdit()
        username.setPlaceholderText("Username or email")
        form_layout.addRow("Username:", username)
        
        password = QLineEdit()
        password.setEchoMode(QLineEdit.EchoMode.Password)
        password.setPlaceholderText("Password or hash")
        form_layout.addRow("Password/Hash:", password)
        
        domain = QLineEdit()
        domain.setPlaceholderText("Domain (optional)")
        form_layout.addRow("Domain:", domain)
        
        layout.addLayout(form_layout)
        layout.addStretch()
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton { background: rgba(50, 60, 80, 150); color: #8899AA;
                border: 1px solid rgba(100, 120, 150, 60); border-radius: 6px; padding: 8px 20px; }
            QPushButton:hover { background: rgba(70, 85, 110, 180); color: #DCDCDC; }
        """)
        cancel_btn.clicked.connect(dialog.reject)
        btn_layout.addWidget(cancel_btn)
        
        save_btn = QPushButton("🔐  Add Credential")
        save_btn.setStyleSheet("""
            QPushButton { background: rgba(100, 200, 255, 30); color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 100); border-radius: 6px; padding: 8px 20px; font-weight: bold; }
            QPushButton:hover { background: rgba(100, 200, 255, 60); color: white; }
        """)
        save_btn.clicked.connect(lambda: self.save_credential_info(
            dialog, cred_type.currentText(), username.text(), password.text(), domain.text()))
        btn_layout.addWidget(save_btn)
        layout.addLayout(btn_layout)
        
        dialog.exec()
    
    def save_target_info(self, dialog, name, url, in_scope, out_scope, eng_type, dos, social, physical):
        """Save target profile and scope information to disk"""
        import os
        import json
        
        if not name.strip():
            QMessageBox.warning(dialog, "Missing Name", "Please enter a target name.")
            return
        
        if not self.workflow_steps[0].results:
            self.workflow_steps[0].results = {}
        
        self.workflow_steps[0].results['target_info'] = {
            'name': name,
            'url': url,
            'in_scope': in_scope,
            'out_of_scope': out_scope,
            'engagement_type': eng_type,
            'dos_allowed': dos,
            'social_eng_allowed': social,
            'physical_allowed': physical
        }
        
        # Save to profiles/ directory for persistence
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        profiles_dir = os.path.join(project_root, 'profiles')
        os.makedirs(profiles_dir, exist_ok=True)
        
        profile_data = {
            'target_name': name,
            'primary_target': url or in_scope,
            'scope': in_scope,
            'subdomains': '',
            'cloud_assets': '',
            'out_scope': out_scope,
            'restrictions': '',
            'dos_allowed': dos,
            'social_eng_allowed': social,
            'physical_allowed': physical,
            'credentials': {},
        }
        
        profile_file = os.path.join(profiles_dir, f"{name.strip()}.json")
        try:
            with open(profile_file, 'w') as f:
                json.dump(profile_data, f, indent=2)
        except Exception as e:
            self.status_updated.emit(f"⚠️ Could not save profile to disk: {e}")
        
        # Activate the profile
        try:
            from app.core.credential_manager import credential_manager
            credential_manager.set_profile(name.strip())
        except Exception:
            pass
        
        try:
            from app.core.tenant_aware_updater import tenant_aware_updater
            tenant_aware_updater.set_tenant(name.strip())
        except Exception:
            pass
        
        self.status_updated.emit(f"✅ Target profile saved: {name}")
        dialog.accept()
    
    def save_scope_info(self, dialog, in_scope, out_scope, dos, social, physical):
        """Save scope and ROE information"""
        if not self.workflow_steps[0].results:
            self.workflow_steps[0].results = {}
        
        self.workflow_steps[0].results['scope_roe'] = {
            'in_scope': in_scope,
            'out_of_scope': out_scope,
            'dos_allowed': dos,
            'social_eng_allowed': social,
            'physical_allowed': physical
        }
        
        self.status_updated.emit("✅ Scope & ROE information saved")
        dialog.accept()
    
    def save_credential_info(self, dialog, cred_type, username, password, domain):
        """Save credential information"""
        if not self.workflow_steps[0].results:
            self.workflow_steps[0].results = {}
        
        if 'credentials' not in self.workflow_steps[0].results:
            self.workflow_steps[0].results['credentials'] = []
        
        self.workflow_steps[0].results['credentials'].append({
            'type': cred_type,
            'username': username,
            'password': password,
            'domain': domain
        })
        
        self.status_updated.emit(f"✅ Credential added: {username}")
        dialog.accept()
    
    def _clear_layout(self, layout):
        """Clear all widgets from a layout"""
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
            elif child.layout():
                self._clear_layout(child.layout())
    
    # Keep old method name for compatibility
    def clear_layout(self, layout):
        self._clear_layout(layout)
    
    def closeEvent(self, event):
        """Clean up on close"""
        event.accept()
