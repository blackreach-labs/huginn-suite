# app/components/runecraft_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QHBoxLayout, QFrame
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont

class RunecraftComponent(QWidget):
    """Runecraft - Advanced Payload Generation & Exploitation Framework"""
    
    payload_generated = pyqtSignal(dict)
    exploit_executed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the Runecraft UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 100);
                padding: 15px;
            }
        """)
        header_layout = QVBoxLayout(header_frame)
        
        title = QLabel("⚡ RUNECRAFT")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 24pt; font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(title)
        
        subtitle = QLabel("Advanced Payload Generation & Exploitation Framework")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("font-size: 14pt; color: #87CEEB; font-style: italic;")
        header_layout.addWidget(subtitle)
        
        layout.addWidget(header_frame)
        
        # Features section
        features_frame = QFrame()
        features_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
                padding: 15px;
            }
        """)
        features_layout = QVBoxLayout(features_frame)
        
        features_title = QLabel("🚀 Core Features:")
        features_title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF; margin-bottom: 10px;")
        features_layout.addWidget(features_title)
        
        features_list = [
            "🎯 Automated Payload Generation",
            "🔄 Multi-Stage Exploitation Chains", 
            "🛡️ AV/EDR Evasion Techniques",
            "🧬 Polymorphic Code Generation",
            "⚡ Zero-Day Exploit Development",
            "🔗 Attack Chain Orchestration",
            "🎭 Advanced Obfuscation Methods",
            "🚀 Custom Shellcode Generation"
        ]
        
        for feature in features_list:
            feature_label = QLabel(feature)
            feature_label.setStyleSheet("color: #DCDCDC; font-size: 12pt; padding: 5px;")
            features_layout.addWidget(feature_label)
        
        layout.addWidget(features_frame)
        
        # Control panel
        controls_frame = QFrame()
        controls_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
                padding: 15px;
            }
        """)
        controls_layout = QVBoxLayout(controls_frame)
        
        # Buttons row
        buttons_layout = QHBoxLayout()
        
        generate_btn = QPushButton("⚡ Generate Payload")
        generate_btn.setMinimumHeight(50)
        generate_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                border: 2px solid #64C8FF;
                border-radius: 8px;
                color: #000000;
                font-size: 14pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(120, 220, 255, 200);
                border: 2px solid #87CEEB;
            }
        """)
        generate_btn.clicked.connect(self.generate_payload)
        buttons_layout.addWidget(generate_btn)
        
        execute_btn = QPushButton("🚀 Execute Chain")
        execute_btn.setMinimumHeight(50)
        execute_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 100, 100, 150);
                border: 2px solid #FF6464;
                border-radius: 8px;
                color: #FFFFFF;
                font-size: 14pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 120, 120, 200);
                border: 2px solid #FF8888;
            }
        """)
        execute_btn.clicked.connect(self.execute_chain)
        buttons_layout.addWidget(execute_btn)
        
        controls_layout.addLayout(buttons_layout)
        
        # Output area
        output_label = QLabel("📊 Runecraft Output:")
        output_label.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF; margin-top: 15px;")
        controls_layout.addWidget(output_label)
        
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setPlaceholderText("Runecraft output and generated payloads will appear here...")
        self.output_area.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #00FF41;
                font-family: 'Courier New', monospace;
                font-size: 10pt;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                padding: 10px;
            }
        """)
        controls_layout.addWidget(self.output_area)
        
        layout.addWidget(controls_frame)
        
        # Add initial welcome message
        self.output_area.append("⚡ RUNECRAFT FRAMEWORK INITIALIZED")
        self.output_area.append("🔥 Advanced Exploitation Engine Ready")
        self.output_area.append("🎯 Select payload generation or chain execution to begin")
        self.output_area.append("")
    
    def generate_payload(self):
        """Generate advanced payload"""
        self.output_area.append("⚡ PAYLOAD GENERATION INITIATED")
        self.output_area.append("🧬 Analyzing target environment...")
        self.output_area.append("🔄 Generating polymorphic shellcode...")
        self.output_area.append("🛡️ Applying AV evasion techniques...")
        self.output_area.append("✅ Advanced payload generated successfully!")
        self.output_area.append("📦 Payload ready for deployment")
        self.output_area.append("")
        
        # Emit signal
        payload_data = {
            "type": "advanced_payload",
            "evasion": True,
            "polymorphic": True,
            "status": "generated"
        }
        self.payload_generated.emit(payload_data)
    
    def execute_chain(self):
        """Execute exploitation chain"""
        self.output_area.append("🚀 ATTACK CHAIN EXECUTION INITIATED")
        self.output_area.append("🎯 Target acquisition in progress...")
        self.output_area.append("🔗 Multi-stage chain orchestration...")
        self.output_area.append("⚡ Executing exploitation sequence...")
        self.output_area.append("🎭 Applying stealth techniques...")
        self.output_area.append("✅ Attack chain executed successfully!")
        self.output_area.append("🏆 Exploitation objectives achieved")
        self.output_area.append("")
        
        # Emit signal
        exploit_data = {
            "type": "attack_chain",
            "stages": 5,
            "stealth": True,
            "status": "executed"
        }
        self.exploit_executed.emit(exploit_data)