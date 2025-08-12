# app/widgets/security_dashboard_widget.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QProgressBar
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
import random

class SecurityDashboardWidget(QWidget):
    """Security dashboard widget showing real-time security metrics"""
    
    threat_detected = pyqtSignal(str, str)  # threat_type, severity
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.setup_timer()
    
    def setup_ui(self):
        """Setup the security dashboard UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Metrics row
        metrics_layout = QHBoxLayout()
        
        # Threat Level
        threat_frame = self.create_metric_frame("🚨 Threat Level", "MEDIUM", "#FFA500")
        metrics_layout.addWidget(threat_frame)
        
        # Active Scans
        scans_frame = self.create_metric_frame("🔍 Active Scans", "3", "#64C8FF")
        metrics_layout.addWidget(scans_frame)
        
        # Vulnerabilities
        vulns_frame = self.create_metric_frame("⚠️ Vulnerabilities", "12", "#FF6B6B")
        metrics_layout.addWidget(vulns_frame)
        
        layout.addLayout(metrics_layout)
        
        # System Health
        health_frame = QFrame()
        health_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 30);
                padding: 10px;
            }
        """)
        health_layout = QVBoxLayout(health_frame)
        
        health_title = QLabel("💚 System Health")
        health_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        health_layout.addWidget(health_title)
        
        # Health bars
        self.cpu_bar = self.create_health_bar("CPU Usage", 45)
        self.memory_bar = self.create_health_bar("Memory", 67)
        self.network_bar = self.create_health_bar("Network", 23)
        
        health_layout.addWidget(self.cpu_bar)
        health_layout.addWidget(self.memory_bar)
        health_layout.addWidget(self.network_bar)
        
        layout.addWidget(health_frame)
        
        # Recent Activity
        activity_frame = QFrame()
        activity_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 30);
                padding: 10px;
            }
        """)
        activity_layout = QVBoxLayout(activity_frame)
        
        activity_title = QLabel("📊 Recent Activity")
        activity_title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        activity_layout.addWidget(activity_title)
        
        self.activity_label = QLabel("🔍 Port scan completed on 192.168.1.0/24\n⚠️ Vulnerability detected in HTTP service\n✅ Security assessment in progress")
        self.activity_label.setStyleSheet("color: #DCDCDC; font-size: 10pt; line-height: 1.4;")
        self.activity_label.setWordWrap(True)
        activity_layout.addWidget(self.activity_label)
        
        layout.addWidget(activity_frame)
    
    def create_metric_frame(self, title, value, color):
        """Create a metric display frame"""
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: rgba(0, 0, 0, 50);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 30);
                padding: 10px;
            }}
        """)
        
        layout = QVBoxLayout(frame)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 10pt; color: #87CEEB;")
        layout.addWidget(title_label)
        
        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setStyleSheet(f"font-size: 16pt; font-weight: bold; color: {color};")
        layout.addWidget(value_label)
        
        return frame
    
    def create_health_bar(self, name, value):
        """Create a health progress bar"""
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        
        label = QLabel(f"{name}:")
        label.setFixedWidth(80)
        label.setStyleSheet("color: #DCDCDC; font-size: 10pt;")
        layout.addWidget(label)
        
        bar = QProgressBar()
        bar.setMinimum(0)
        bar.setMaximum(100)
        bar.setValue(value)
        bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                text-align: center;
                background-color: rgba(0, 0, 0, 100);
                color: #DCDCDC;
                font-size: 9pt;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #64C8FF, stop:1 #87CEEB);
                border-radius: 2px;
            }
        """)
        layout.addWidget(bar)
        
        value_label = QLabel(f"{value}%")
        value_label.setFixedWidth(40)
        value_label.setStyleSheet("color: #64C8FF; font-size: 10pt;")
        layout.addWidget(value_label)
        
        return container
    
    def setup_timer(self):
        """Setup timer for real-time updates"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_metrics)
        self.update_timer.start(5000)  # Update every 5 seconds
    
    def update_metrics(self):
        """Update dashboard metrics with simulated data"""
        # Simulate changing values
        activities = [
            "🔍 DNS enumeration completed",
            "⚠️ New vulnerability discovered", 
            "✅ Service scan in progress",
            "🛡️ Security check completed",
            "📊 Report generation started"
        ]
        
        activity = random.choice(activities)
        current_text = self.activity_label.text()
        lines = current_text.split('\n')
        
        # Add new activity and keep only last 3
        lines.insert(0, activity)
        if len(lines) > 3:
            lines = lines[:3]
        
        self.activity_label.setText('\n'.join(lines))
    
    def refresh_dashboard(self):
        """Refresh dashboard data"""
        self.update_metrics()