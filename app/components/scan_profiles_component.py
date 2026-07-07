from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QListWidget, QListWidgetItem, QFrame)
from PyQt6.QtCore import pyqtSignal

class ScanProfilesComponent(QWidget):
    profile_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup scan profiles UI"""
        layout = QVBoxLayout(self)
        

        
        # Main content
        content_layout = QHBoxLayout()
        
        # Left panel - profile list
        left_panel = self.create_profile_list()
        content_layout.addWidget(left_panel)
        
        # Right panel - profile details
        right_panel = self.create_profile_details()
        content_layout.addWidget(right_panel, 2)
        
        layout.addLayout(content_layout)
        
        # AI Features overview
        ai_overview = self.create_ai_overview()
        layout.addWidget(ai_overview)

    def create_profile_list(self):
        """Create profile list panel"""
        panel = QFrame()
        panel.setFixedWidth(250)
        layout = QVBoxLayout(panel)
        
        layout.addWidget(QLabel("🎯 Scan Profiles:"))
        
        self.profile_list = QListWidget()
        profiles = [
            ("🟢 Light", "Light"),
            ("🟡 Normal", "Normal"), 
            ("🟠 Aggressive", "Aggressive"),
            ("🔴 Insane", "Insane")
        ]
        
        for display_name, profile_name in profiles:
            item = QListWidgetItem(display_name)
            item.setData(1, profile_name)  # Store actual profile name
            self.profile_list.addItem(item)
        
        self.profile_list.currentItemChanged.connect(self.on_profile_selected)
        self.profile_list.setCurrentRow(1)  # Default to Normal
        
        layout.addWidget(self.profile_list)
        
        # Profile comparison button
        compare_btn = QPushButton("📈 Compare Profiles")
        compare_btn.clicked.connect(self.show_profile_comparison)
        layout.addWidget(compare_btn)
        
        return panel

    def create_profile_details(self):
        """Create profile details panel"""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        layout.addWidget(QLabel("Profile Details:"))
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        layout.addWidget(self.details_text)
        
        # Show default profile details
        self.show_profile_details("Normal")
        
        return panel

    def on_profile_selected(self, current, previous):
        """Handle profile selection"""
        if current:
            profile_name = current.data(1)  # Get actual profile name
            self.show_profile_details(profile_name)
            self.profile_selected.emit(profile_name)

    def show_profile_details(self, profile_name):
        """Show details for selected profile"""
        # Check if details_text exists
        if not hasattr(self, 'details_text'):
            return
            
        profiles = {
            "Light": {
                "description": "Basic vulnerability checks with minimal resource usage",
                "concurrent": 20,
                "timeout": "5s",
                "features": [
                    "Basic SQL injection testing",
                    "Simple XSS detection",
                    "Directory enumeration",
                    "Basic authentication bypass",
                    "Security headers analysis"
                ],
                "ai_features": "Disabled",
                "ai_details": [],
                "estimated_time": "5-10 minutes",
                "resource_usage": "Low",
                "detection_risk": "Minimal"
            },
            "Normal": {
                "description": "Balanced comprehensive scan with moderate resource usage",
                "concurrent": 50,
                "timeout": "10s",
                "features": [
                    "Comprehensive vulnerability testing",
                    "Advanced injection techniques",
                    "Business logic testing",
                    "Session management analysis",
                    "OSINT intelligence gathering",
                    "API security testing"
                ],
                "ai_features": "Basic AI enabled",
                "ai_details": [
                    "Pattern recognition for anomaly detection",
                    "Basic machine learning vulnerability prediction",
                    "Response time analysis"
                ],
                "estimated_time": "15-30 minutes",
                "resource_usage": "Moderate",
                "detection_risk": "Low"
            },
            "Aggressive": {
                "description": "Full-spectrum testing with high resource usage",
                "concurrent": 100,
                "timeout": "15s",
                "features": [
                    "Deep vulnerability analysis",
                    "Advanced exploitation techniques",
                    "WAF evasion testing",
                    "Binary response analysis",
                    "Comprehensive OSINT integration",
                    "Advanced API security testing"
                ],
                "ai_features": "Advanced AI enabled",
                "ai_details": [
                    "Neural network vulnerability analysis",
                    "Advanced pattern recognition",
                    "ML-based payload generation",
                    "Behavioral anomaly detection",
                    "Adaptive fuzzing algorithms"
                ],
                "estimated_time": "30-60 minutes",
                "resource_usage": "High",
                "detection_risk": "Moderate"
            },
            "Insane": {
                "description": "All AI features enabled with maximum resource usage",
                "concurrent": 200,
                "timeout": "20s",
                "features": [
                    "Quantum-inspired fuzzing",
                    "Autonomous security agent (7-state AI)",
                    "Zero-day discovery engine",
                    "Advanced exploitation framework",
                    "Complete OSINT gathering",
                    "Binary analysis and reverse engineering"
                ],
                "ai_features": "All AI features enabled",
                "ai_details": [
                    "Quantum superposition fuzzing",
                    "7-state autonomous security agent",
                    "Deep neural network vulnerability engine",
                    "ML vulnerability prediction with 95% accuracy",
                    "Evolutionary fuzzing for zero-day discovery",
                    "Advanced exploit generation and validation",
                    "Comprehensive threat intelligence correlation"
                ],
                "estimated_time": "1-2 hours",
                "resource_usage": "Maximum",
                "detection_risk": "High"
            }
        }
        
        profile = profiles.get(profile_name, profiles["Normal"])
        
        # Get profile icon
        profile_icons = {
            "Light": "🟢",
            "Normal": "🟡", 
            "Aggressive": "🟠",
            "Insane": "🔴"
        }
        
        details_html = f"""
        <h3 style='color: #64C8FF;'>{profile_icons.get(profile_name, '')} {profile_name} Profile</h3>
        <p><b>Description:</b> {profile['description']}</p>
        
        <h4 style='color: #FFD93D;'>Configuration:</h4>
        <ul>
            <li><b>Concurrent Requests:</b> {profile['concurrent']}</li>
            <li><b>Request Timeout:</b> {profile['timeout']}</li>
            <li><b>Resource Usage:</b> {profile['resource_usage']}</li>
            <li><b>Detection Risk:</b> {profile['detection_risk']}</li>
            <li><b>Estimated Time:</b> {profile['estimated_time']}</li>
        </ul>
        
        <h4 style='color: #FFD93D;'>Core Features:</h4>
        <ul>
        """
        
        for feature in profile['features']:
            details_html += f"<li>{feature}</li>"
        
        details_html += "</ul>"
        
        # Add AI features if available
        if profile['ai_details']:
            details_html += "<h4 style='color: #FF6B6B;'>AI Features:</h4><ul>"
            for ai_feature in profile['ai_details']:
                details_html += f"<li>🧠 {ai_feature}</li>"
            details_html += "</ul>"
        
        # Add warnings based on profile
        if profile_name in ["Aggressive", "Insane"]:
            details_html += f"""
            <div style='background-color: rgba(255, 107, 107, 20); padding: 10px; border-radius: 5px; margin-top: 10px;'>
            <p style='color: #FF6B6B;'><b>⚠️ Warning:</b> {profile_name} profile may:</p>
            <ul style='color: #FFA500;'>
                <li>Generate significant network traffic</li>
                <li>Trigger security monitoring systems</li>
                <li>Consume substantial system resources</li>
                {'<li>Potentially cause service disruption</li>' if profile_name == 'Insane' else ''}
            </ul>
            </div>
            """
        
        details_html += """
        <p style='color: #87CEEB; margin-top: 15px;'><b>💡 Tip:</b> Start with Normal profile and escalate based on initial findings.</p>
        """
        
        self.details_text.setHtml(details_html)
    
    def create_ai_overview(self):
        """Create AI features overview panel"""
        panel = QFrame()
        panel.setMaximumHeight(200)
        layout = QVBoxLayout(panel)
        
        layout.addWidget(QLabel("🧠 AI Features Overview:"))
        
        ai_overview = QTextEdit()
        ai_overview.setReadOnly(True)
        ai_overview.setMaximumHeight(150)
        
        overview_html = """
        <div style='font-size: 11pt;'>
        <p><b>🔬 Quantum-Inspired Fuzzing:</b> Advanced payload generation using quantum computing concepts</p>
        <p><b>🤖 Autonomous Security Agent:</b> Self-directed penetration testing with 7-state AI decision making</p>
        <p><b>📊 ML Vulnerability Prediction:</b> Machine learning models predict vulnerability likelihood</p>
        <p><b>🧠 Neural Network Analysis:</b> Deep learning pattern recognition for complex attack vectors</p>
        <p><b>⚡ Zero-Day Discovery:</b> Evolutionary fuzzing algorithms for unknown vulnerability discovery</p>
        </div>
        """
        
        ai_overview.setHtml(overview_html)
        layout.addWidget(ai_overview)
        
        return panel
    
    def show_profile_comparison(self):
        """Show profile comparison dialog"""
        comparison_html = """
        <table border='1' style='border-collapse: collapse; width: 100%;'>
        <tr style='background-color: rgba(100, 200, 255, 50);'>
            <th>Feature</th><th>Light</th><th>Normal</th><th>Aggressive</th><th>Insane</th>
        </tr>
        <tr><td>Concurrent Requests</td><td>20</td><td>50</td><td>100</td><td>200</td></tr>
        <tr><td>AI Features</td><td>❌</td><td>🟡</td><td>🟠</td><td>✅</td></tr>
        <tr><td>Neural Networks</td><td>❌</td><td>❌</td><td>✅</td><td>✅</td></tr>
        <tr><td>Quantum Fuzzing</td><td>❌</td><td>❌</td><td>❌</td><td>✅</td></tr>
        <tr><td>Autonomous Agent</td><td>❌</td><td>❌</td><td>❌</td><td>✅</td></tr>
        <tr><td>Zero-Day Discovery</td><td>❌</td><td>❌</td><td>❌</td><td>✅</td></tr>
        <tr><td>Detection Risk</td><td>Minimal</td><td>Low</td><td>Moderate</td><td>High</td></tr>
        </table>
        """
        
        # Create a simple dialog to show comparison
        from PyQt6.QtWidgets import QDialog, QVBoxLayout as DialogVBoxLayout
        dialog = QDialog(self)
        dialog.setWindowTitle("Profile Comparison")
        dialog.setFixedSize(600, 400)
        
        dialog_layout = DialogVBoxLayout(dialog)
        comparison_text = QTextEdit()
        comparison_text.setHtml(comparison_html)
        comparison_text.setReadOnly(True)
        dialog_layout.addWidget(comparison_text)
        
        dialog.exec()

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass