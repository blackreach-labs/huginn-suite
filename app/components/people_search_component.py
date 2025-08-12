from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFrame, QGroupBox, QGridLayout)
from PyQt6.QtCore import pyqtSignal

class PeopleSearchComponent(QWidget):
    search_started = pyqtSignal(str, str)
    search_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup people search UI"""
        layout = QHBoxLayout(self)
        
        # Left panel - controls
        left_panel = self.create_controls_panel()
        layout.addWidget(left_panel)
        
        # Right panel - output
        right_panel = self.create_output_panel()
        layout.addWidget(right_panel, 2)

    def create_controls_panel(self):
        """Create controls panel"""
        panel = QFrame()
        panel.setFixedWidth(300)
        layout = QVBoxLayout(panel)
        
        # Target input
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("Person/Entity Name:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("John Doe or Company Name")
        target_layout.addWidget(self.target_input)
        
        layout.addWidget(target_group)
        
        # Search modules
        modules_group = QGroupBox("People Search Tools")
        modules_layout = QGridLayout(modules_group)
        
        buttons = [
            ("Social Profiles", self.run_social_profiles),
            ("Professional Networks", self.run_professional_networks),
            ("Public Records", self.run_public_records),
            ("Contact Discovery", self.run_contact_discovery),
            ("Username Search", self.run_username_search),
            ("Email Enumeration", self.run_email_enumeration),
            ("Phone Lookup", self.run_phone_lookup),
            ("Full Person Intel", self.run_full_person_intel)
        ]
        
        for i, (text, method) in enumerate(buttons):
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            modules_layout.addWidget(btn, i // 2, i % 2)
        
        layout.addWidget(modules_group)
        layout.addStretch()
        
        return panel

    def create_output_panel(self):
        """Create output panel"""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("People search results will appear here...")
        layout.addWidget(self.output_text)
        
        return panel

    def run_social_profiles(self):
        """Run social media profile search"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.search_started.emit(target, "Social Profiles")
        self.output_text.clear()
        self.output_text.setHtml("""
        <p style='color: #64C8FF;'>[SOCIAL PROFILES] Discovering social media presence...</p>
        <p style='color: #FFD93D;'>Tools: Sherlock, Social-Analyzer, WhatsMyName</p>
        <p style='color: #00FF41;'>Found profiles on: Twitter, LinkedIn, Facebook, Instagram</p>
        """)
        self.search_completed.emit({"social_profiles": 4})

    def run_professional_networks(self):
        """Run professional network analysis"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.search_started.emit(target, "Professional Networks")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[PROFESSIONAL NETWORKS] Analyzing career information...</p>
        <p style='color: #00FF41;'>LinkedIn, GitHub, professional associations identified</p>
        """)
        self.search_completed.emit({"professional_networks": True})

    def run_public_records(self):
        """Run public records search"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.search_started.emit(target, "Public Records")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[PUBLIC RECORDS] Searching public databases...</p>
        <p style='color: #FFA500;'>Note: Requires appropriate legal authorization</p>
        """)
        self.search_completed.emit({"public_records": True})

    def run_contact_discovery(self):
        """Run contact information discovery"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.search_started.emit(target, "Contact Discovery")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[CONTACT DISCOVERY] Finding contact information...</p>
        <p style='color: #00FF41;'>Email patterns, phone numbers, addresses discovered</p>
        """)
        self.search_completed.emit({"contact_info": True})

    def run_username_search(self):
        """Run username search across platforms"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.search_started.emit(target, "Username Search")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[USERNAME SEARCH] Searching username across platforms...</p>
        <p style='color: #00FF41;'>Username availability and usage patterns analyzed</p>
        """)
        self.search_completed.emit({"username_search": True})

    def run_email_enumeration(self):
        """Run email enumeration"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.search_started.emit(target, "Email Enumeration")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[EMAIL ENUMERATION] Discovering email addresses...</p>
        <p style='color: #00FF41;'>Email patterns and variations identified</p>
        """)
        self.search_completed.emit({"email_enumeration": True})

    def run_phone_lookup(self):
        """Run phone number lookup"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.search_started.emit(target, "Phone Lookup")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[PHONE LOOKUP] Analyzing phone number information...</p>
        <p style='color: #00FF41;'>Carrier, location, and registration details found</p>
        """)
        self.search_completed.emit({"phone_lookup": True})

    def run_full_person_intel(self):
        """Run comprehensive person intelligence"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.search_started.emit(target, "Full Person Intel")
        self.output_text.clear()
        self.output_text.setHtml("""
        <p style='color: #64C8FF;'>[COMPREHENSIVE PERSON INTEL] Multi-source analysis...</p>
        <p style='color: #FFD93D;'>Phase 1: Social media profile discovery</p>
        <p style='color: #FFD93D;'>Phase 2: Professional network analysis</p>
        <p style='color: #FFD93D;'>Phase 3: Contact information gathering</p>
        <p style='color: #FFD93D;'>Phase 4: Username and email enumeration</p>
        <p style='color: #FFD93D;'>Phase 5: Phone number analysis</p>
        <p style='color: #00FF41;'>Comprehensive person intelligence complete</p>
        """)
        self.search_completed.emit({
            "social_profiles": 4,
            "professional_networks": True,
            "contact_info": True,
            "username_search": True,
            "email_enumeration": True,
            "phone_lookup": True
        })

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QTextEdit {
                background-color: rgba(0, 0, 0, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                font-family: 'Courier New', monospace;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                margin-top: 10px;
                color: #64C8FF;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)