# app/pages/guided_workflow_page.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QProgressBar, QFrame, QTextEdit, QScrollArea,
                             QDialog, QLineEdit, QComboBox, QCheckBox, QFormLayout, QDialogButtonBox,
                             QStackedWidget, QMessageBox)
from PyQt6.QtCore import pyqtSignal, Qt, QTimer, QThread, pyqtSlot
from PyQt6.QtGui import QFont, QPixmap, QPainter, QPen
from app.core.questionnaire_graph import QuestionnaireGraph
from app.widgets.questionnaire_widget import QuestionnaireWidget

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
                "Define scope, gather initial target information, and set up engagement parameters",
                ["Target Profiles", "Credential Management"],
                "10-15 minutes",
                []
            ),
            WorkflowStep(
                "Passive Reconnaissance", 
                "Gather information without directly interacting with the target",
                ["OSINT Collection", "DNS Records", "Certificate Transparency"],
                "20-30 minutes",
                ["Target Definition"]
            ),
            WorkflowStep(
                "Network Discovery",
                "Discover live hosts and open ports on the target network",
                ["Port Scanning", "Huginn Advanced Scanner"],
                "15-25 minutes", 
                ["Target Definition"]
            ),
            WorkflowStep(
                "Service Enumeration",
                "Identify and enumerate services running on discovered ports",
                ["HTTP", "RPC", "SMB", "SMTP", "SNMP", "LDAP", "API", "AV/FW"],
                "30-45 minutes",
                ["Network Discovery"]
            ),
            WorkflowStep(
                "Automated Vulnerability Scanning",
                "Run automated scanners to identify potential security issues",
                ["Huginn Advanced Scanner", "Web Vulnerability Scanner"],
                "20-40 minutes",
                ["Service Enumeration"]
            ),
            WorkflowStep(
                "Manual Vulnerability Testing",
                "Manually test for common vulnerabilities based on discovered services",
                ["Parameter Fuzzing", "Authentication Testing", "Business Logic Testing"],
                "45-90 minutes",
                ["Automated Vulnerability Scanning"]
            ),
            WorkflowStep(
                "Exploit Development",
                "Develop and test exploits for confirmed vulnerabilities",
                ["Payload Generation", "Exploit Testing", "Proof of Concept"],
                "30-60 minutes",
                ["Manual Vulnerability Testing"]
            ),
            WorkflowStep(
                "Initial Access",
                "Gain initial access to target systems using developed exploits",
                ["Shell Management", "Access Validation", "Persistence Setup"],
                "20-40 minutes",
                ["Exploit Development"]
            ),
            WorkflowStep(
                "Privilege Escalation",
                "Escalate privileges on compromised systems",
                ["Local Enumeration", "Privilege Escalation", "Credential Harvesting"],
                "30-60 minutes",
                ["Initial Access"]
            ),
            WorkflowStep(
                "Lateral Movement",
                "Move laterally through the network to access additional systems",
                ["Network Pivoting", "Credential Reuse", "Service Exploitation"],
                "45-90 minutes",
                ["Privilege Escalation"]
            ),
            WorkflowStep(
                "Evidence Collection",
                "Document findings and collect evidence for reporting",
                ["Screenshot Capture", "Log Collection", "Proof Documentation"],
                "20-30 minutes",
                ["Lateral Movement"]
            ),
            WorkflowStep(
                "Report Generation",
                "Generate comprehensive penetration testing report",
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
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        # Header with mode toggle
        header_layout = QHBoxLayout()
        
        title = QLabel("🎯 Guided Penetration Testing Workflow")
        title.setStyleSheet("font-size: 24pt; font-weight: bold; color: white;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # Start questionnaire directly
        self.questionnaire_btn = QPushButton("📋 Start Questionnaire")
        self.questionnaire_btn.clicked.connect(self.start_questionnaire_directly)
        header_layout.addWidget(self.questionnaire_btn)
        
        # Simple mode toggle
        mode_btn = QPushButton("🧭 Guided Mode")
        mode_btn.clicked.connect(lambda: self.status_updated.emit("Mode toggle clicked"))
        header_layout.addWidget(mode_btn)
        
        # Step counter
        self.step_counter = QLabel("Step 1 of 12")
        self.step_counter.setStyleSheet("font-size: 12pt; color: #87CEEB; margin: 10px;")
        header_layout.addWidget(self.step_counter)
        
        main_layout.addLayout(header_layout)
        
        # Stacked widget for workflow and questionnaire
        self.stacked_widget = QStackedWidget()
        
        # Workflow page
        workflow_widget = QWidget()
        workflow_layout = QVBoxLayout(workflow_widget)
        
        # Current Step Details
        self.step_details_frame = self.create_step_details()
        workflow_layout.addWidget(self.step_details_frame)
        
        # Navigation Controls
        nav_frame = self.create_navigation_controls()
        workflow_layout.addWidget(nav_frame)
        
        self.stacked_widget.addWidget(workflow_widget)
        main_layout.addWidget(self.stacked_widget)
        
    def create_step_details(self):
        """Create current step details panel"""
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 100);
            }
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Step header
        self.step_title = QLabel()
        self.step_title.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(self.step_title)
        
        self.step_description = QLabel()
        self.step_description.setWordWrap(True)
        self.step_description.setStyleSheet("font-size: 12pt; color: #DCDCDC; margin: 10px 0;")
        layout.addWidget(self.step_description)
        
        # Time estimate
        self.time_estimate = QLabel()
        self.time_estimate.setStyleSheet("font-size: 10pt; color: #87CEEB; font-style: italic;")
        layout.addWidget(self.time_estimate)
        
        # Tools section
        tools_label = QLabel("🛠️ Required Tools:")
        tools_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF; margin-top: 15px;")
        layout.addWidget(tools_label)
        
        self.tools_layout = QVBoxLayout()
        layout.addLayout(self.tools_layout)
        
        return frame
    
    def create_navigation_controls(self):
        """Create navigation controls"""
        frame = QFrame()
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(0, 10, 0, 0)
        
        # Previous button
        self.prev_button = QPushButton("⬅️ Previous Step")
        self.prev_button.clicked.connect(self.previous_step)
        layout.addWidget(self.prev_button)
        
        layout.addStretch()
        
        # Next/Finish button
        self.next_button = QPushButton("Next Step ➡️")
        self.next_button.clicked.connect(self.next_step)
        layout.addWidget(self.next_button)
        
        return frame
    
    def update_step_display(self):
        """Update the display for current step"""
        if self.current_step >= len(self.workflow_steps):
            return
            
        step = self.workflow_steps[self.current_step]
        
        # Update step details
        self.step_title.setText(f"Step {self.current_step + 1}: {step.name}")
        self.step_description.setText(step.description)
        self.time_estimate.setText(f"⏱️ Estimated Time: {step.estimated_time}")
        
        # Clear and populate tools
        self.clear_layout(self.tools_layout)
        for tool in step.tools:
            tool_button = QPushButton(f"🔧 {tool}")
            tool_button.setMaximumHeight(35)
            tool_button.clicked.connect(lambda checked, t=tool: self.launch_tool(t))
            self.tools_layout.addWidget(tool_button)
        
        # Add stretch to prevent tool buttons from expanding
        self.tools_layout.addStretch()
        
        # Update navigation
        self.prev_button.setEnabled(self.current_step > 0)
        
        # Update next button text and state
        if self.current_step >= len(self.workflow_steps) - 1:
            self.next_button.setText("✅ Finish Workflow")
            self.next_button.setEnabled(True)
        else:
            self.next_button.setText("Next Step ➡️")
            self.next_button.setEnabled(True)
            
        self.step_counter.setText(f"Step {self.current_step + 1} of {len(self.workflow_steps)}")
    
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
        
        # Mark tool as used and update button text
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
            # Mark current step as completed
            self.workflow_steps[self.current_step].completed = True
            self.current_step += 1
            self.update_step_display()
            self.status_updated.emit(f"Moved to step {self.current_step + 1}")
        else:
            # Finish workflow
            self.finish_workflow()
    
    def finish_workflow(self):
        """Complete the guided workflow"""
        from PyQt6.QtWidgets import QMessageBox
        
        # Mark final step as completed
        self.workflow_steps[self.current_step].completed = True
        
        # Show completion dialog
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
        self.questionnaire_btn.setText("📋 Start Questionnaire")
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
            
            # Show completion dialog
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
            
            # Return to workflow
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
        dialog.resize(500, 500)
        
        layout = QFormLayout(dialog)
        
        # Target information fields
        target_name = QLineEdit()
        target_name.setPlaceholderText("e.g., Company XYZ Web Application")
        layout.addRow("Target Name:", target_name)
        
        target_url = QLineEdit()
        target_url.setPlaceholderText("e.g., https://example.com")
        layout.addRow("Primary Target URL:", target_url)
        
        in_scope = QTextEdit()
        in_scope.setPlaceholderText("List domains, IPs, or networks in scope...")
        in_scope.setMaximumHeight(80)
        layout.addRow("In Scope:", in_scope)
        
        out_of_scope = QTextEdit()
        out_of_scope.setPlaceholderText("List any exclusions...")
        out_of_scope.setMaximumHeight(80)
        layout.addRow("Out of Scope:", out_of_scope)
        
        engagement_type = QComboBox()
        engagement_type.addItems(["External Penetration Test", "Internal Penetration Test", "Web Application Test", "Wireless Assessment"])
        layout.addRow("Engagement Type:", engagement_type)
        
        # Permission checkboxes
        dos_allowed = QCheckBox("Denial of Service attacks allowed")
        social_eng_allowed = QCheckBox("Social engineering allowed")
        physical_allowed = QCheckBox("Physical access testing allowed")
        
        layout.addRow("Permissions:", dos_allowed)
        layout.addRow("", social_eng_allowed)
        layout.addRow("", physical_allowed)
        
        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(lambda: self.save_target_info(dialog, target_name.text(), target_url.text(), in_scope.toPlainText(), out_of_scope.toPlainText(), engagement_type.currentText(), dos_allowed.isChecked(), social_eng_allowed.isChecked(), physical_allowed.isChecked()))
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def show_scope_roe_questions(self):
        """Show scope and rules of engagement questions"""
        dialog = QDialog(self)
        dialog.setWindowTitle("📋 Scope & Rules of Engagement")
        dialog.setModal(True)
        dialog.resize(500, 400)
        
        layout = QFormLayout(dialog)
        
        # Scope fields
        in_scope = QTextEdit()
        in_scope.setPlaceholderText("List domains, IPs, or networks in scope...")
        in_scope.setMaximumHeight(80)
        layout.addRow("In Scope:", in_scope)
        
        out_of_scope = QTextEdit()
        out_of_scope.setPlaceholderText("List any exclusions...")
        out_of_scope.setMaximumHeight(80)
        layout.addRow("Out of Scope:", out_of_scope)
        
        # Permission checkboxes
        dos_allowed = QCheckBox("Denial of Service attacks allowed")
        social_eng_allowed = QCheckBox("Social engineering allowed")
        physical_allowed = QCheckBox("Physical access testing allowed")
        
        layout.addRow("Permissions:", dos_allowed)
        layout.addRow("", social_eng_allowed)
        layout.addRow("", physical_allowed)
        
        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(lambda: self.save_scope_info(dialog, in_scope.toPlainText(), out_of_scope.toPlainText(), dos_allowed.isChecked(), social_eng_allowed.isChecked(), physical_allowed.isChecked()))
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def show_credential_questions(self):
        """Show credential management questions"""
        dialog = QDialog(self)
        dialog.setWindowTitle("🔐 Credential Management")
        dialog.setModal(True)
        dialog.resize(500, 300)
        
        layout = QFormLayout(dialog)
        
        # Credential fields
        cred_type = QComboBox()
        cred_type.addItems(["Username/Password", "NTLM Hash", "Kerberos Ticket", "API Key"])
        layout.addRow("Credential Type:", cred_type)
        
        username = QLineEdit()
        username.setPlaceholderText("Username or email")
        layout.addRow("Username:", username)
        
        password = QLineEdit()
        password.setEchoMode(QLineEdit.EchoMode.Password)
        password.setPlaceholderText("Password or hash")
        layout.addRow("Password/Hash:", password)
        
        domain = QLineEdit()
        domain.setPlaceholderText("Domain (optional)")
        layout.addRow("Domain:", domain)
        
        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(lambda: self.save_credential_info(dialog, cred_type.currentText(), username.text(), password.text(), domain.text()))
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        dialog.exec()
    
    def save_target_info(self, dialog, name, url, in_scope, out_scope, eng_type, dos, social, physical):
        """Save target profile and scope information"""
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
        
        self.status_updated.emit(f"✅ Target profile & scope saved: {name}")
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
    
    def clear_layout(self, layout):
        """Clear all widgets from a layout"""
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
    
    def closeEvent(self, event):
        """Clean up on close"""
        event.accept()