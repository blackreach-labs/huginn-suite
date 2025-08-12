# app/widgets/api_integration_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QComboBox, QLineEdit, QTextEdit, QGroupBox)
from PyQt6.QtCore import pyqtSignal
from app.core.api_integration import api_integration

class APIIntegrationWidget(QWidget):
    """Widget for API integration management and execution."""
    
    api_executed = pyqtSignal(str, dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup API integration widget UI."""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("API Integration")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(title)
        
        # API Services section
        services_group = QGroupBox("API Services")
        services_layout = QVBoxLayout(services_group)
        
        # Service selection
        service_layout = QHBoxLayout()
        service_layout.addWidget(QLabel("Service:"))
        
        self.service_combo = QComboBox()
        self.service_combo.addItems(["Shodan", "VirusTotal", "URLVoid", "Custom API"])
        service_layout.addWidget(self.service_combo)
        
        self.query_button = QPushButton("Query API")
        self.query_button.clicked.connect(self.execute_api_query)
        service_layout.addWidget(self.query_button)
        
        service_layout.addStretch()
        services_layout.addLayout(service_layout)
        
        # API Key input
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("API Key:"))
        
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("Enter API key (if required)")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addWidget(self.api_key_input)
        
        services_layout.addLayout(key_layout)
        layout.addWidget(services_group)
        
        # Custom API section
        custom_group = QGroupBox("Custom API Request")
        custom_layout = QVBoxLayout(custom_group)
        
        # URL input
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("URL:"))
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://api.example.com/endpoint")
        url_layout.addWidget(self.url_input)
        
        custom_layout.addLayout(url_layout)
        layout.addWidget(custom_group)
        
        # Results area
        results_label = QLabel("API Results:")
        results_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(results_label)
        
        self.results_output = QTextEdit()
        self.results_output.setMaximumHeight(250)
        self.results_output.setPlaceholderText("API results will appear here...")
        layout.addWidget(self.results_output)
        
        layout.addStretch()
        
    def connect_signals(self):
        """Connect API integration signals."""
        api_integration.api_response.connect(self.on_api_response)
        
    def execute_api_query(self):
        """Execute API query based on selected service."""
        service = self.service_combo.currentText()
        api_key = self.api_key_input.text().strip()
        
        # Get target from parent if available
        target = "example.com"
        if hasattr(self.parent(), 'target_input'):
            target = self.parent().target_input.text().strip() or target
            
        self.results_output.append(f"Querying {service} for {target}...")
        
        if service == "Shodan":
            result = api_integration.query_shodan(target, api_key)
        elif service == "VirusTotal":
            result = api_integration.query_virustotal(target, api_key)
        elif service == "URLVoid":
            result = api_integration.query_urlvoid(target)
        elif service == "Custom API":
            url = self.url_input.text().strip()
            if url:
                result = api_integration.custom_api_request(url)
            else:
                result = {"error": "Please enter API URL"}
        else:
            result = {"error": "Unknown service"}
            
        if 'error' in result:
            self.results_output.append(f"Error: {result['error']}")
        
    def on_api_response(self, source, result):
        """Handle API response."""
        self.results_output.append(f"Source: {source}")
        
        if source == "shodan":
            self.results_output.append(f"IP: {result.get('ip', 'N/A')}")
            self.results_output.append(f"Ports: {', '.join(map(str, result.get('ports', [])))}")
            self.results_output.append(f"Country: {result.get('country', 'N/A')}")
        elif source == "virustotal":
            self.results_output.append(f"Malicious: {result.get('malicious', 0)}")
            self.results_output.append(f"Suspicious: {result.get('suspicious', 0)}")
            self.results_output.append(f"Reputation: {result.get('reputation', 0)}")
        elif source == "custom":
            self.results_output.append(f"Status: {result.get('status_code', 'N/A')}")
            self.results_output.append(f"Success: {result.get('success', False)}")
            
        self.results_output.append("---")
        self.api_executed.emit(source, result)