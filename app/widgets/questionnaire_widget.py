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
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        self.header_label = QLabel("📋 Penetration Test Questionnaire")
        self.header_label.setStyleSheet("font-size: 20pt; font-weight: bold; color: #64C8FF; margin-bottom: 20px;")
        layout.addWidget(self.header_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #64C8FF;
                border-radius: 5px;
                text-align: center;
                background-color: rgba(0, 0, 0, 100);
            }
            QProgressBar::chunk {
                background-color: #64C8FF;
                border-radius: 3px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # Question area
        self.question_frame = QFrame()
        self.question_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 100);
                padding: 20px;
                margin: 20px 0;
            }
        """)
        self.question_layout = QVBoxLayout(self.question_frame)
        layout.addWidget(self.question_frame)
        
        # Navigation buttons
        nav_layout = QHBoxLayout()
        
        self.prev_button = QPushButton("⬅️ Previous")
        self.prev_button.clicked.connect(self.previous_question)
        self.prev_button.setEnabled(False)
        nav_layout.addWidget(self.prev_button)
        
        nav_layout.addStretch()
        
        self.next_button = QPushButton("Next ➡️")
        self.next_button.clicked.connect(self.next_question)
        nav_layout.addWidget(self.next_button)
        
        layout.addLayout(nav_layout)
    
    def load_opening_question(self, question_data: Dict):
        """Load the opening environment selection question"""
        self.clear_question_area()
        
        # Question text
        question_label = QLabel(question_data['text'])
        question_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: white; margin-bottom: 15px;")
        question_label.setWordWrap(True)
        self.question_layout.addWidget(question_label)
        
        # Options
        self.option_group = QButtonGroup()
        for i, option in enumerate(question_data['options']):
            radio = QRadioButton(option)
            radio.setStyleSheet("font-size: 12pt; color: #DCDCDC; margin: 5px;")
            self.option_group.addButton(radio, i)
            self.question_layout.addWidget(radio)
        
        self.option_group.buttonClicked.connect(self.on_environment_selected)
        
        # Update navigation
        self.prev_button.setEnabled(False)
        self.next_button.setText("Start Questionnaire ➡️")
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
        
        # Category header
        category_label = QLabel(f"📂 {self.current_category}")
        category_label.setStyleSheet("font-size: 16pt; font-weight: bold; color: #87CEEB; margin-bottom: 10px;")
        self.question_layout.addWidget(category_label)
        
        # Question text
        question_label = QLabel(question['text'])
        question_label.setStyleSheet("font-size: 14pt; color: white; margin-bottom: 15px;")
        question_label.setWordWrap(True)
        self.question_layout.addWidget(question_label)
        
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
        
        # Update navigation
        self.update_navigation()
    
    def create_boolean_response(self, question_id: str):
        """Create boolean (Yes/No) response options"""
        self.response_group = QButtonGroup()
        
        yes_radio = QRadioButton("Yes")
        no_radio = QRadioButton("No")
        
        yes_radio.setStyleSheet("font-size: 12pt; color: #90EE90; margin: 5px;")
        no_radio.setStyleSheet("font-size: 12pt; color: #FFB6C1; margin: 5px;")
        
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
            radio = QRadioButton(option)
            radio.setStyleSheet("font-size: 12pt; color: #DCDCDC; margin: 5px;")
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
                font-size: 12pt;
                color: white;
                background-color: rgba(50, 50, 50, 150);
                border: 2px solid #64C8FF;
                border-radius: 5px;
                padding: 8px;
                margin: 5px;
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
            checkbox = QCheckBox(option)
            checkbox.setStyleSheet("font-size: 12pt; color: #DCDCDC; margin: 5px;")
            self.checkboxes.append(checkbox)
            self.question_layout.addWidget(checkbox)
            
            checkbox.stateChanged.connect(
                lambda: self.save_multi_choice_response(question_id)
            )
        
        # Load existing responses
        if question_id in self.responses:
            selected = self.responses[question_id]
            for checkbox in self.checkboxes:
                if checkbox.text() in selected:
                    checkbox.setChecked(True)
    
    def save_response(self, question_id: str, response: Any):
        """Save response and emit signal"""
        self.responses[question_id] = response
        self.response_submitted.emit(self.session_id, question_id, response)
    
    def save_multi_choice_response(self, question_id: str):
        """Save multi-choice response"""
        selected = [cb.text() for cb in self.checkboxes if cb.isChecked()]
        self.handle_response_with_action(question_id, selected)
    
    def trigger_action(self, action: str, response: Any):
        """Trigger action based on questionnaire response"""
        # Emit signal to parent to handle the action
        self.action_triggered.emit(action, response)
    
    def show_target_definition_dialog(self):
        """Show target definition dialog"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit, QComboBox, QCheckBox, QPushButton
        
        dialog = QDialog(self)
        dialog.setWindowTitle("🎯 Define New Target")
        dialog.setModal(True)
        dialog.resize(600, 500)
        
        layout = QVBoxLayout(dialog)
        form_layout = QFormLayout()
        
        # Target fields
        self.target_name = QLineEdit()
        self.target_name.setPlaceholderText("e.g., Company XYZ Web Application")
        form_layout.addRow("Target Name:", self.target_name)
        
        self.target_url = QLineEdit()
        self.target_url.setPlaceholderText("e.g., https://example.com")
        form_layout.addRow("Primary Target URL:", self.target_url)
        
        self.target_scope = QTextEdit()
        self.target_scope.setPlaceholderText("List domains, IPs, or networks in scope...")
        self.target_scope.setMaximumHeight(80)
        form_layout.addRow("In Scope:", self.target_scope)
        
        self.engagement_type = QComboBox()
        self.engagement_type.addItems(["External Penetration Test", "Internal Penetration Test", "Web Application Test"])
        form_layout.addRow("Engagement Type:", self.engagement_type)
        
        layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QVBoxLayout()
        save_btn = QPushButton("Save Target & Continue")
        save_btn.clicked.connect(lambda: self.save_target_and_continue(dialog))
        button_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        dialog.exec()
    
    def save_target_and_continue(self, dialog):
        """Save target information and continue to next question"""
        target_info = {
            'name': self.target_name.text(),
            'url': self.target_url.text(),
            'scope': self.target_scope.toPlainText(),
            'engagement_type': self.engagement_type.currentText()
        }
        
        # Save target info to responses
        self.responses['target_definition'] = target_info
        
        dialog.accept()
        # Move to next question
        self.next_question()
    
    def show_load_profile_dialog(self):
        """Show load profile dialog"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QPushButton, QLabel
        
        dialog = QDialog(self)
        dialog.setWindowTitle("📁 Load Existing Target Profile")
        dialog.setModal(True)
        dialog.resize(500, 400)
        
        layout = QVBoxLayout(dialog)
        
        # Instructions
        label = QLabel("Select an existing target profile:")
        layout.addWidget(label)
        
        # Profile list (mock data for now)
        self.profile_list = QListWidget()
        profiles = [
            "Company ABC - Web Application (https://abc.com)",
            "Internal Network - 192.168.1.0/24",
            "Client XYZ - API Testing (api.xyz.com)",
            "E-commerce Site - shop.example.com"
        ]
        self.profile_list.addItems(profiles)
        layout.addWidget(self.profile_list)
        
        # Buttons
        button_layout = QVBoxLayout()
        load_btn = QPushButton("Load Selected Profile & Continue")
        load_btn.clicked.connect(lambda: self.load_profile_and_continue(dialog))
        button_layout.addWidget(load_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        dialog.exec()
    
    def load_profile_and_continue(self, dialog):
        """Load selected profile and continue to next question"""
        selected_items = self.profile_list.selectedItems()
        if selected_items:
            profile_name = selected_items[0].text()
            
            # Save selected profile to responses
            self.responses['selected_profile'] = profile_name
            
            dialog.accept()
            # Move to next question
            self.next_question()
        else:
            # Show warning if no profile selected
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(dialog, "No Selection", "Please select a profile to load.")
    
    def next_question(self):
        """Move to next question"""
        if not self.current_environment:
            # This is the opening question
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
            # Questionnaire completed
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
        else:
            self.next_button.setText("Next ➡️")
    
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
        self.progress_bar.setFormat(f"{current_position + 1}/{total_questions} Questions")
    
    def clear_question_area(self):
        """Clear the question display area"""
        while self.question_layout.count():
            child = self.question_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()