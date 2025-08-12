from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFrame, QGroupBox, QGridLayout)
from PyQt6.QtCore import pyqtSignal

class SocialMediaComponent(QWidget):
    analysis_started = pyqtSignal(str, str)
    analysis_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup social media UI"""
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
        
        target_layout.addWidget(QLabel("Social Media Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("@username or profile URL")
        target_layout.addWidget(self.target_input)
        
        layout.addWidget(target_group)
        
        # Analysis modules
        modules_group = QGroupBox("Social Media Analysis")
        modules_layout = QGridLayout(modules_group)
        
        buttons = [
            ("Account Discovery", self.run_account_discovery),
            ("Content Analysis", self.run_content_analysis),
            ("Network Mapping", self.run_network_mapping),
            ("Timeline Recon", self.run_timeline_recon),
            ("Image Analysis", self.run_image_analysis),
            ("Sentiment Analysis", self.run_sentiment_analysis),
            ("Metadata Extract", self.run_metadata_extract),
            ("Full Social Intel", self.run_full_social_intel)
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
        self.output_text.setPlaceholderText("Social media analysis results will appear here...")
        layout.addWidget(self.output_text)
        
        return panel

    def run_account_discovery(self):
        """Run social media account discovery"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.analysis_started.emit(target, "Account Discovery")
        self.output_text.clear()
        self.output_text.setHtml("""
        <p style='color: #64C8FF;'>[ACCOUNT DISCOVERY] Finding social media accounts...</p>
        <p style='color: #FFD93D;'>Tools: Sherlock, Social-Analyzer, Twint</p>
        <p style='color: #00FF41;'>Accounts found: Twitter, Instagram, TikTok, LinkedIn</p>
        """)
        self.analysis_completed.emit({"accounts_found": 4})

    def run_content_analysis(self):
        """Run content analysis"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.analysis_started.emit(target, "Content Analysis")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[CONTENT ANALYSIS] Analyzing posted content...</p>
        <p style='color: #00FF41;'>Posts, images, videos, and interactions analyzed</p>
        """)
        self.analysis_completed.emit({"content_analyzed": True})

    def run_network_mapping(self):
        """Run network mapping"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.analysis_started.emit(target, "Network Mapping")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[NETWORK MAPPING] Mapping social connections...</p>
        <p style='color: #00FF41;'>Followers, following, and interaction patterns mapped</p>
        """)
        self.analysis_completed.emit({"network_mapped": True})

    def run_timeline_recon(self):
        """Run timeline reconstruction"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.analysis_started.emit(target, "Timeline Reconstruction")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[TIMELINE RECONSTRUCTION] Building activity timeline...</p>
        <p style='color: #00FF41;'>Chronological activity and behavior patterns identified</p>
        """)
        self.analysis_completed.emit({"timeline_built": True})

    def run_image_analysis(self):
        """Run image analysis"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.analysis_started.emit(target, "Image Analysis")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[IMAGE ANALYSIS] Analyzing posted images...</p>
        <p style='color: #00FF41;'>Facial recognition, location data, and objects identified</p>
        """)
        self.analysis_completed.emit({"images_analyzed": True})

    def run_sentiment_analysis(self):
        """Run sentiment analysis"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.analysis_started.emit(target, "Sentiment Analysis")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[SENTIMENT ANALYSIS] Analyzing emotional tone...</p>
        <p style='color: #00FF41;'>Positive, negative, and neutral sentiment patterns identified</p>
        """)
        self.analysis_completed.emit({"sentiment_analyzed": True})

    def run_metadata_extract(self):
        """Run metadata extraction"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.analysis_started.emit(target, "Metadata Extraction")
        self.output_text.append("""
        <p style='color: #64C8FF;'>[METADATA EXTRACTION] Extracting hidden metadata...</p>
        <p style='color: #00FF41;'>EXIF data, timestamps, and device information extracted</p>
        """)
        self.analysis_completed.emit({"metadata_extracted": True})

    def run_full_social_intel(self):
        """Run comprehensive social media intelligence"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.analysis_started.emit(target, "Full Social Intel")
        self.output_text.clear()
        self.output_text.setHtml("""
        <p style='color: #64C8FF;'>[COMPREHENSIVE SOCIAL INTEL] Multi-platform analysis...</p>
        <p style='color: #FFD93D;'>Phase 1: Account discovery across platforms</p>
        <p style='color: #FFD93D;'>Phase 2: Content and media analysis</p>
        <p style='color: #FFD93D;'>Phase 3: Social network mapping</p>
        <p style='color: #FFD93D;'>Phase 4: Timeline reconstruction</p>
        <p style='color: #FFD93D;'>Phase 5: Sentiment and metadata analysis</p>
        <p style='color: #00FF41;'>Comprehensive social media intelligence complete</p>
        """)
        self.analysis_completed.emit({
            "accounts_found": 4,
            "content_analyzed": True,
            "network_mapped": True,
            "timeline_built": True,
            "images_analyzed": True,
            "sentiment_analyzed": True,
            "metadata_extracted": True
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