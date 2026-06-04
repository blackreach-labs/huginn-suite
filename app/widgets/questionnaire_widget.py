from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QRadioButton, QCheckBox, QButtonGroup,
                             QScrollArea, QFrame, QProgressBar, QTextEdit)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont
from typing import Dict, List, Any
import uuid


class QuestionnaireWidget(QWidget):
    """Widget for displaying and managing questionnaires"""
    
    response_submitted = pyqtSignal(str, str, object)  # session_id, question_id, response
    questionnaire_completed = pyqtSignal(str, str)     # session_id, environment
    action_triggered = pyqtSignal(str, object)         # action, response
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.session_id = str(uuid.uuid4())
        self.current_environment = None
        self.current_questionnaire = {}
        self.current_category = None
        self.current_question_index = 0
        self.responses = {}
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the questionnaire UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        # Header area
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(10, 15, 25, 180);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 30);
            }
        """)
        header_layout = QVBoxLayout(header_frame)
        header_layout.setContentsMargins(20, 14, 20, 14)
        header_layout.setSpacing(10)
        
        # Title row
        title_row = QHBoxLayout()
        self.header_label = QLabel("📋 Penetration Test Questionnaire")
        self.header_label.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        title_row.addWidget(self.header_label)
        title_row.addStretch()
        
        # Category badge
        self.category_badge = QLabel()
        self.category_badge.setStyleSheet("""
            font-size: 9pt; color: #87CEEB; font-weight: bold;
            background: rgba(135, 206, 235, 10);
            border: 1px solid rgba(135, 206, 235, 40);
            border-radius: 10px;
            padding: 4px 12px;
        """)
        self.category_badge.setVisible(False)
        title_row.addWidget(self.category_badge)
        
        header_layout.addLayout(title_row)
        
        # Progress bar
        progress_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: rgba(40, 50, 70, 150);
                border-radius: 4px;
                border: none;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #64C8FF, stop:1 #2ECC71);
                border-radius: 4px;
            }
        """)
        progress_row.addWidget(self.progress_bar, 1)
        
        self.progress_label = QLabel("0/0")
        self.progress_label.setStyleSheet("font-size: 9pt; color: #87CEEB; margin-left: 10px;")
        progress_row.addWidget(self.progress_label)
        
        header_layout.addLayout(progress_row)
        layout.addWidget(header_frame)
        
        # Question card area
        self.question_frame = QFrame()
        self.question_frame.setObjectName("QuestionCard")
        self.question_frame.setStyleSheet("""
            QFrame#QuestionCard {
                background-color: rgba(10, 15, 25, 200);
                border-radius: 12px;
                border: 1px solid rgba(100, 200, 255, 40);
            }
        """)
        self.question_layout = QVBoxLayout(self.question_frame)
        self.question_layout.setContentsMargins(28, 24, 28, 24)
        self.question_layout.setSpacing(14)
        layout.addWidget(self.question_frame, 1)
        
        # Navigation buttons
        nav_frame = QFrame()
        nav_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(10, 15, 25, 150);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 20);
            }
        """)
        nav_layout = QHBoxLayout(nav_frame)
        nav_layout.setContentsMargins(16, 10, 16, 10)
        
        self.prev_button = QPushButton("← Previous")
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
        self.prev_button.clicked.connect(self.previous_question)
        self.prev_button.setEnabled(False)
        nav_layout.addWidget(self.prev_button)
        
        nav_layout.addStretch()
        
        self.next_button = QPushButton("Next →")
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
        self.next_button.clicked.connect(self.next_question)
        nav_layout.addWidget(self.next_button)
        
        layout.addWidget(nav_frame)
    
    def load_opening_question(self, question_data: Dict):
        """Load the opening environment selection question"""
        self.clear_question_area()
        
        # Question text
        question_label = QLabel(question_data['text'])
        question_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: white; margin-bottom: 12px;")
        question_label.setWordWrap(True)
        self.question_layout.addWidget(question_label)
        
        # Options
        self.option_group = QButtonGroup()
        for i, option in enumerate(question_data['options']):
            radio = QRadioButton(option)
            radio.setStyleSheet("""
                QRadioButton {
                    font-size: 11pt; color: #DCDCDC; margin: 4px 0; padding: 10px 14px;
                    spacing: 10px;
                    background: rgba(50, 60, 80, 60);
                    border: 1px solid transparent;
                    border-radius: 6px;
                }
                QRadioButton:hover { 
                    background: rgba(100, 200, 255, 15);
                    color: #64C8FF; 
                }
                QRadioButton:checked {
                    background: rgba(100, 200, 255, 25);
                    border: 1px solid rgba(100, 200, 255, 150);
                    color: #64C8FF;
                    font-weight: bold;
                }
                QRadioButton::indicator {
                    width: 16px; height: 16px;
                }
            """)
            self.option_group.addButton(radio, i)
            self.question_layout.addWidget(radio)
        
        self.question_layout.addStretch()
        
        self.option_group.buttonClicked.connect(self.on_environment_selected)
        
        # Update navigation
        self.prev_button.setEnabled(False)
        self.next_button.setText("Start Questionnaire →")
        self.next_button.setEnabled(False)
    
    def on_environment_selected(self, button):
        """Handle environment selection"""
        self.selected_environment = button.text()
        self.next_button.setEnabled(True)
    
    def load_questionnaire(self, environment: str, questionnaire: Dict):
        """Load questionnaire for specific environment"""
        self.current_environment = environment
        self.current_questionnaire = questionnaire
        self.categories = list(questionnaire.keys())
        self.current_category = self.categories[0] if self.categories else None
        self.current_question_index = 0
        
        if self.current_category:
            self.display_current_question()
            self.update_progress()
    
    def display_current_question(self):
        """Display the current question"""
        if not self.current_category or not self.current_questionnaire:
            return
        
        questions = self.current_questionnaire[self.current_category]
        if self.current_question_index >= len(questions):
            self.next_category()
            return
        
        question = questions[self.current_question_index]
        self.clear_question_area()
        
        # Category header with icon
        category_label = QLabel(f"📂  {self.current_category}")
        category_label.setStyleSheet("""
            font-size: 10pt; font-weight: bold; color: rgba(135, 206, 235, 180);
            letter-spacing: 0.5px; padding-bottom: 4px;
        """)
        self.question_layout.addWidget(category_label)
        
        # Update category badge in header
        self.category_badge.setText(self.current_category)
        self.category_badge.setVisible(True)
        
        # Question text
        question_label = QLabel(question['text'])
        question_label.setStyleSheet("""
            font-size: 13pt; color: white; font-weight: bold;
            padding: 8px 0 12px 0;
        """)
        question_label.setWordWrap(True)
        self.question_layout.addWidget(question_label)
        
        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background-color: rgba(100, 200, 255, 20); max-height: 1px;")
        self.question_layout.addWidget(sep)
        
        # Store current question data for action handling
        self.current_question_data = question
        
        # Response area based on question type
        if question['type'] == 'boolean':
            self.create_boolean_response(question['id'])
        elif question['type'] == 'multi-choice':
            self.create_multi_choice_response(question['id'], question['options'])
        elif question['type'] == 'single-choice':
            self.create_single_choice_response(question['id'], question['options'])
        elif question['type'] == 'text_input':
            placeholder = question.get('placeholder', '')
            self.create_text_input_response(question['id'], placeholder)
        
        self.question_layout.addStretch()
        
        # Update navigation
        self.update_navigation()
    
    def create_boolean_response(self, question_id: str):
        """Create boolean (Yes/No) response options"""
        self.response_group = QButtonGroup()
        
        yes_radio = QRadioButton("  Yes")
        no_radio = QRadioButton("  No")
        
        yes_radio.setStyleSheet("""
            QRadioButton {
                font-size: 11pt; color: #90EE90; margin: 6px 0; padding: 10px 16px;
                spacing: 10px;
                background: rgba(46, 204, 113, 8);
                border: 1px solid transparent;
                border-radius: 6px;
            }
            QRadioButton:hover { background: rgba(46, 204, 113, 20); }
            QRadioButton:checked {
                background: rgba(46, 204, 113, 35);
                border: 1px solid rgba(46, 204, 113, 180);
                color: #2ECC71;
                font-weight: bold;
            }
            QRadioButton::indicator { width: 16px; height: 16px; }
        """)
        no_radio.setStyleSheet("""
            QRadioButton {
                font-size: 11pt; color: #FFB6C1; margin: 6px 0; padding: 10px 16px;
                spacing: 10px;
                background: rgba(255, 100, 100, 8);
                border: 1px solid transparent;
                border-radius: 6px;
            }
            QRadioButton:hover { background: rgba(255, 100, 100, 20); }
            QRadioButton:checked {
                background: rgba(255, 100, 100, 30);
                border: 1px solid rgba(255, 100, 100, 180);
                color: #FF6B6B;
                font-weight: bold;
            }
            QRadioButton::indicator { width: 16px; height: 16px; }
        """)
        
        self.response_group.addButton(yes_radio, 1)
        self.response_group.addButton(no_radio, 0)
        
        self.question_layout.addWidget(yes_radio)
        self.question_layout.addWidget(no_radio)
        
        # Load existing response
        if question_id in self.responses:
            button = self.response_group.button(1 if self.responses[question_id] else 0)
            if button:
                button.setChecked(True)
        
        self.response_group.buttonClicked.connect(
            lambda btn: self.handle_response_with_action(question_id, btn.group().id(btn) == 1)
        )
    
    def create_single_choice_response(self, question_id: str, options: List[str]):
        """Create single choice response options"""
        self.response_group = QButtonGroup()
        
        for i, option in enumerate(options):
            radio = QRadioButton(f"  {option}")
            radio.setStyleSheet("""
                QRadioButton {
                    font-size: 11pt; color: #DCDCDC; margin: 3px 0; padding: 8px 14px;
                    spacing: 10px;
                    background: rgba(50, 60, 80, 60);
                    border: 1px solid transparent;
                    border-radius: 6px;
                }
                QRadioButton:hover { 
                    background: rgba(100, 200, 255, 15); 
                    color: #64C8FF;
                }
                QRadioButton:checked {
                    background: rgba(100, 200, 255, 25);
                    border: 1px solid rgba(100, 200, 255, 150);
                    color: #64C8FF;
                    font-weight: bold;
                }
                QRadioButton::indicator { width: 16px; height: 16px; }
            """)
            self.response_group.addButton(radio, i)
            self.question_layout.addWidget(radio)
        
        # Load existing response
        if question_id in self.responses:
            response = self.responses[question_id]
            for i, option in enumerate(options):
                if option == response:
                    button = self.response_group.button(i)
                    if button:
                        button.setChecked(True)
                    break
        
        self.response_group.buttonClicked.connect(
            lambda btn: self.handle_response_with_action(question_id, options[btn.group().id(btn)])
        )
    
    def create_text_input_response(self, question_id: str, placeholder: str = ""):
        """Create text input response"""
        from PyQt6.QtWidgets import QLineEdit
        
        self.text_input = QLineEdit()
        self.text_input.setPlaceholderText(placeholder)
        self.text_input.setStyleSheet("""
            QLineEdit {
                font-size: 11pt;
                color: white;
                background-color: rgba(40, 50, 70, 200);
                border: 2px solid rgba(100, 200, 255, 50);
                border-radius: 8px;
                padding: 12px 16px;
                margin: 8px 0;
            }
            QLineEdit:focus {
                border-color: #64C8FF;
                background-color: rgba(50, 60, 80, 220);
            }
        """)
        
        # Load existing response
        if question_id in self.responses:
            self.text_input.setText(str(self.responses[question_id]))
        
        self.text_input.textChanged.connect(
            lambda text: self.handle_response_with_action(question_id, text)
        )
        
        self.question_layout.addWidget(self.text_input)
    
    def handle_response_with_action(self, question_id: str, response: Any):
        """Handle response and trigger associated action"""
        self.save_response(question_id, response)
        
        # Special handling for target selection
        if question_id == 'target_selection':
            if response == 'Define New Target':
                self.show_target_definition_dialog()
                return
            elif response == 'Select Existing Target':
                self.show_load_profile_dialog()
                return
        
        # Get question data to check for actions
        if hasattr(self, 'current_question_data') and 'action' in self.current_question_data:
            action = self.current_question_data['action']
            if (response == True or (isinstance(response, str) and response)) and action:
                self.trigger_action(action, response)
    
    def create_multi_choice_response(self, question_id: str, options: List[str]):
        """Create multi-choice response options"""
        self.checkboxes = []
        
        for option in options:
            checkbox = QCheckBox(f"  {option}")
            checkbox.setStyleSheet("""
                QCheckBox {
                    font-size: 11pt; color: #DCDCDC; margin: 3px 0; padding: 8px 14px;
                    spacing: 10px;
                    background: rgba(50, 60, 80, 60);
                    border: 1px solid transparent;
                    border-radius: 6px;
                }
                QCheckBox:hover { 
                    background: rgba(100, 200, 255, 15);
                    color: #64C8FF;
                }
                QCheckBox:checked {
                    background: rgba(100, 200, 255, 25);
                    border: 1px solid rgba(100, 200, 255, 150);
                    color: #64C8FF;
                    font-weight: bold;
                }
                QCheckBox::indicator { width: 16px; height: 16px; }
            """)
            self.checkboxes.append(checkbox)
            self.question_layout.addWidget(checkbox)
            
            checkbox.stateChanged.connect(
                lambda: self.save_multi_choice_response(question_id)
            )
        
        # Load existing responses
        if question_id in self.responses:
            selected = self.responses[question_id]
            for checkbox in self.checkboxes:
                if checkbox.text().strip() in selected:
                    checkbox.setChecked(True)
    
    def save_response(self, question_id: str, response: Any):
        """Save response and emit signal"""
        self.responses[question_id] = response
        self.response_submitted.emit(self.session_id, question_id, response)
    
    def save_multi_choice_response(self, question_id: str):
        """Save multi-choice response"""
        selected = [cb.text().strip() for cb in self.checkboxes if cb.isChecked()]
        self.handle_response_with_action(question_id, selected)
    
    def trigger_action(self, action: str, response: Any):
        """Trigger action based on questionnaire response"""
        self.action_triggered.emit(action, response)
    
    def show_target_definition_dialog(self):
        """Show target definition dialog"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QComboBox, QCheckBox, QPushButton
        
        dialog = QDialog(self)
        dialog.setWindowTitle("🎯 Define New Target")
        dialog.setModal(True)
        dialog.resize(600, 500)
        dialog.setStyleSheet("""
            QDialog { background-color: #1A1F2E; }
            QLabel { color: #DCDCDC; font-size: 10pt; }
            QLineEdit, QTextEdit, QComboBox {
                background-color: rgba(40, 50, 70, 200); color: white;
                border: 1px solid rgba(100, 200, 255, 60); border-radius: 6px; padding: 8px; font-size: 10pt;
            }
            QLineEdit:focus, QTextEdit:focus { border-color: #64C8FF; }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        form_layout = QFormLayout()
        form_layout.setSpacing(12)
        
        self.target_name = QLineEdit()
        self.target_name.setPlaceholderText("e.g., Company XYZ Web Application")
        form_layout.addRow("Target Name:", self.target_name)
        
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("e.g., https://example.com")
        form_layout.addRow("Primary URL:", self.target_url)
        
        self.target_scope = QTextEdit()
        self.target_scope.setPlaceholderText("List domains, IPs, or networks in scope...")
        self.target_scope.setMaximumHeight(80)
        form_layout.addRow("In Scope:", self.target_scope)
        
        self.engagement_type = QComboBox()
        self.engagement_type.addItems(["External Penetration Test", "Internal Penetration Test", "Web Application Test"])
        form_layout.addRow("Engagement Type:", self.engagement_type)
        
        layout.addLayout(form_layout)
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
        
        save_btn = QPushButton("Save Target & Continue")
        save_btn.setStyleSheet("""
            QPushButton { background: rgba(100, 200, 255, 30); color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 100); border-radius: 6px; padding: 8px 20px; font-weight: bold; }
            QPushButton:hover { background: rgba(100, 200, 255, 60); color: white; }
        """)
        save_btn.clicked.connect(lambda: self.save_target_and_continue(dialog))
        btn_layout.addWidget(save_btn)
        
        layout.addLayout(btn_layout)
        dialog.exec()
    
    def save_target_and_continue(self, dialog):
        """Save target information to disk as a profile and continue to next question"""
        import os
        import json
        
        target_name = self.target_name.text().strip()
        if not target_name:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(dialog, "Missing Name", "Please enter a target name.")
            return
        
        target_info = {
            'name': target_name,
            'url': self.target_url.text(),
            'scope': self.target_scope.toPlainText(),
            'engagement_type': self.engagement_type.currentText()
        }
        
        # Save to the profiles/ directory in the same format as attack_chain_home
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        profiles_dir = os.path.join(project_root, 'profiles')
        os.makedirs(profiles_dir, exist_ok=True)
        
        profile_data = {
            'target_name': target_name,
            'primary_target': self.target_url.text() or self.target_scope.toPlainText(),
            'scope': self.target_scope.toPlainText(),
            'subdomains': '',
            'cloud_assets': '',
            'out_scope': '',
            'restrictions': '',
            'dos_allowed': False,
            'social_eng_allowed': False,
            'physical_allowed': False,
            'credentials': {},
        }
        
        profile_file = os.path.join(profiles_dir, f"{target_name}.json")
        try:
            with open(profile_file, 'w') as f:
                json.dump(profile_data, f, indent=2)
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(dialog, "Error", f"Failed to save profile: {str(e)}")
            return
        
        # Activate the profile in the application
        try:
            from app.core.credential_manager import credential_manager
            credential_manager.set_profile(target_name)
        except Exception:
            pass
        
        try:
            from app.core.tenant_aware_updater import tenant_aware_updater
            tenant_aware_updater.set_tenant(target_name)
        except Exception:
            pass
        
        # Save target info to responses
        self.responses['target_definition'] = target_info
        self.responses['selected_profile'] = target_name
        
        # Emit the response
        self.response_submitted.emit(self.session_id, 'selected_profile', target_name)
        
        dialog.accept()
        self.next_question()
    
    def show_load_profile_dialog(self):
        """Show load profile dialog with real saved profiles from disk"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QPushButton, QLabel, QMessageBox
        import os
        import json
        
        # Resolve the profiles directory relative to the project root
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        profiles_dir = os.path.join(project_root, 'profiles')
        
        if not os.path.exists(profiles_dir):
            QMessageBox.information(self, "No Profiles", "No saved profiles found. Define a new target first.")
            return
        
        # Scan for saved profile JSON files
        profile_files = sorted([f for f in os.listdir(profiles_dir) if f.endswith('.json')])
        if not profile_files:
            QMessageBox.information(self, "No Profiles", "No saved profiles found. Define a new target first.")
            return
        
        # Load profile metadata for display
        profiles_data = {}
        display_names = []
        for filename in profile_files:
            profile_path = os.path.join(profiles_dir, filename)
            try:
                with open(profile_path, 'r', encoding='utf-8-sig') as f:
                    data = json.load(f)
                profile_name = filename.replace('.json', '')
                target = data.get('primary_target', '') or data.get('scope', '')
                display = f"{data.get('target_name', profile_name)}"
                if target:
                    # Show first line of scope, truncated
                    first_line = target.strip().splitlines()[0] if target.strip() else ''
                    if len(first_line) > 50:
                        first_line = first_line[:48] + '…'
                    display += f"  —  {first_line}"
                display_names.append(display)
                profiles_data[display] = {'name': profile_name, 'path': profile_path, 'data': data}
            except Exception:
                continue
        
        if not display_names:
            QMessageBox.information(self, "No Profiles", "No valid profiles found. Define a new target first.")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("📁 Load Existing Target Profile")
        dialog.setModal(True)
        dialog.resize(550, 420)
        dialog.setStyleSheet("""
            QDialog { background-color: #1A1F2E; }
            QLabel { color: #DCDCDC; font-size: 10pt; }
            QListWidget {
                background-color: rgba(40, 50, 70, 200); color: white;
                border: 1px solid rgba(100, 200, 255, 60); border-radius: 6px;
                padding: 8px; font-size: 10pt;
            }
            QListWidget::item { padding: 10px; border-radius: 4px; }
            QListWidget::item:selected { background: rgba(100, 200, 255, 30); color: #64C8FF; }
            QListWidget::item:hover { background: rgba(100, 200, 255, 15); }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)
        
        label = QLabel(f"Select from {len(display_names)} saved profile(s):")
        label.setStyleSheet("font-size: 11pt; color: #87CEEB;")
        layout.addWidget(label)
        
        self.profile_list = QListWidget()
        self.profile_list.addItems(display_names)
        self.profile_list.setCurrentRow(0)
        self.profile_list.itemDoubleClicked.connect(lambda _: dialog.accept())
        layout.addWidget(self.profile_list)
        
        # Profile detail preview
        self.profile_detail_label = QLabel()
        self.profile_detail_label.setStyleSheet("""
            font-size: 9pt; color: #8899AA; 
            background: rgba(30, 40, 60, 150); 
            border-radius: 6px; padding: 10px;
        """)
        self.profile_detail_label.setWordWrap(True)
        layout.addWidget(self.profile_detail_label)
        
        def update_detail():
            selected = self.profile_list.currentItem()
            if selected and selected.text() in profiles_data:
                data = profiles_data[selected.text()]['data']
                scope = data.get('primary_target', '') or data.get('scope', 'Not specified')
                out_scope = data.get('out_scope', '') or 'None'
                perms = []
                if data.get('dos_allowed'): perms.append('DoS')
                if data.get('social_eng_allowed'): perms.append('Social Eng')
                if data.get('physical_allowed'): perms.append('Physical')
                perm_str = ', '.join(perms) if perms else 'None'
                self.profile_detail_label.setText(
                    f"Scope: {scope}\nOut of Scope: {out_scope}\nPermissions: {perm_str}"
                )
        
        self.profile_list.currentItemChanged.connect(lambda: update_detail())
        update_detail()
        
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
        
        load_btn = QPushButton("Load & Continue")
        load_btn.setStyleSheet("""
            QPushButton { background: rgba(100, 200, 255, 30); color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 100); border-radius: 6px; padding: 8px 20px; font-weight: bold; }
            QPushButton:hover { background: rgba(100, 200, 255, 60); color: white; }
        """)
        load_btn.clicked.connect(lambda: dialog.accept())
        btn_layout.addWidget(load_btn)
        
        layout.addLayout(btn_layout)
        
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        
        selected_item = self.profile_list.currentItem()
        if not selected_item or selected_item.text() not in profiles_data:
            return
        
        # Load the selected profile data
        profile_info = profiles_data[selected_item.text()]
        profile_data = profile_info['data']
        profile_name = profile_info['name']
        
        # Store the loaded profile in responses
        self.responses['selected_profile'] = profile_name
        self.responses['target_definition'] = {
            'name': profile_data.get('target_name', profile_name),
            'url': profile_data.get('primary_target', '') or profile_data.get('scope', ''),
            'scope': profile_data.get('primary_target', '') or profile_data.get('scope', ''),
            'out_scope': profile_data.get('out_scope', ''),
            'engagement_type': 'Loaded from profile',
            'dos_allowed': profile_data.get('dos_allowed', False),
            'social_eng_allowed': profile_data.get('social_eng_allowed', False),
            'physical_allowed': profile_data.get('physical_allowed', False),
        }
        
        # Pre-fill subsequent questionnaire responses from the loaded profile
        scope_text = profile_data.get('primary_target', '') or profile_data.get('scope', '')
        self.responses['target_scope'] = scope_text
        
        # Infer target type from the scope data
        target_type = self._infer_target_type(scope_text)
        self.responses['target_type'] = target_type
        
        # Mark the target_selection question as answered
        self.responses['target_selection'] = 'Select Existing Target'
        
        # Activate the profile in the application
        try:
            from app.core.credential_manager import credential_manager
            credential_manager.set_profile(profile_name)
        except Exception:
            pass
        
        try:
            from app.core.tenant_aware_updater import tenant_aware_updater
            tenant_aware_updater.set_tenant(profile_name)
        except Exception:
            pass
        
        # Emit the response
        self.response_submitted.emit(self.session_id, 'selected_profile', profile_name)
        
        # Skip remaining Target Definition questions — they're answered by the profile.
        # Jump to the next category (Reconnaissance).
        if self.categories and self.current_category == self.categories[0]:
            current_idx = self.categories.index(self.current_category)
            if current_idx < len(self.categories) - 1:
                self.current_category = self.categories[current_idx + 1]
                self.current_question_index = 0
                self.display_current_question()
                self.update_progress()
                return
        
        # Fallback: just advance to next question
        self.next_question()
    
    def next_question(self):
        """Move to next question"""
        if not self.current_environment:
            return
        
        self.current_question_index += 1
        
        if self.current_category and self.current_question_index >= len(self.current_questionnaire[self.current_category]):
            self.next_category()
        else:
            self.display_current_question()
            self.update_progress()
    
    def previous_question(self):
        """Move to previous question"""
        if self.current_question_index > 0:
            self.current_question_index -= 1
        else:
            self.previous_category()
        
        self.display_current_question()
        self.update_progress()
    
    def next_category(self):
        """Move to next category"""
        if not self.categories:
            return
        
        current_idx = self.categories.index(self.current_category)
        if current_idx < len(self.categories) - 1:
            self.current_category = self.categories[current_idx + 1]
            self.current_question_index = 0
            self.display_current_question()
        else:
            self.questionnaire_completed.emit(self.session_id, self.current_environment)
    
    def previous_category(self):
        """Move to previous category"""
        if not self.categories:
            return
        
        current_idx = self.categories.index(self.current_category)
        if current_idx > 0:
            self.current_category = self.categories[current_idx - 1]
            questions = self.current_questionnaire[self.current_category]
            self.current_question_index = len(questions) - 1
    
    def update_navigation(self):
        """Update navigation button states"""
        # Previous button
        is_first = (self.categories.index(self.current_category) == 0 and 
                   self.current_question_index == 0)
        self.prev_button.setEnabled(not is_first)
        
        # Next button
        is_last_category = self.categories.index(self.current_category) == len(self.categories) - 1
        is_last_question = self.current_question_index >= len(self.current_questionnaire[self.current_category]) - 1
        
        if is_last_category and is_last_question:
            self.next_button.setText("Complete ✅")
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
            self.next_button.setText("Next →")
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
    
    def update_progress(self):
        """Update progress bar"""
        if not self.categories:
            return
        
        total_questions = sum(len(questions) for questions in self.current_questionnaire.values())
        current_position = 0
        
        for i, category in enumerate(self.categories):
            if category == self.current_category:
                current_position += self.current_question_index
                break
            current_position += len(self.current_questionnaire[category])
        
        progress = int((current_position / total_questions) * 100) if total_questions > 0 else 0
        self.progress_bar.setValue(progress)
        self.progress_label.setText(f"{current_position + 1} / {total_questions}")
    
    def clear_question_area(self):
        """Clear the question display area"""
        while self.question_layout.count():
            child = self.question_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()
    
    def _infer_target_type(self, scope_text: str) -> str:
        """Infer the target type from scope text for pre-filling questionnaire responses"""
        import re
        
        if not scope_text:
            return "Single Host"
        
        scope_lower = scope_text.lower().strip()
        
        # Check for URL patterns (web application)
        if any(pattern in scope_lower for pattern in ['http://', 'https://', 'www.']):
            return "Web Application"
        
        # Parse individual targets
        targets = [t.strip() for t in scope_text.split(',') if t.strip()]
        
        has_cidr = any(re.search(r'\d+\.\d+\.\d+\.\d+/\d+', t) for t in targets)
        has_ip = any(re.match(r'^\d+\.\d+\.\d+\.\d+$', t) for t in targets)
        has_domain = any(re.match(r'^[a-zA-Z]', t) and '.' in t for t in targets)
        
        # Mix of IPs/CIDRs and domains → organization-wide scope
        if (has_ip or has_cidr) and has_domain:
            return "Domain/Organization"
        
        # CIDR notation or multiple IPs → network range
        if has_cidr or (has_ip and len(targets) > 1):
            return "Network Range"
        
        # Single IP
        if has_ip:
            return "Single Host"
        
        # Domain(s) only
        if has_domain:
            return "Domain/Organization"
        
        return "Single Host"
