# app/components/owasp_api/api_risk_list_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QScrollArea, QSizePolicy
from PyQt6.QtCore import pyqtSignal

class HoverButton(QPushButton):
    """Button that emits hover signals"""
    enter_signal = pyqtSignal(str, str)
    leave_signal = pyqtSignal()

    def __init__(self, title, description, parent=None):
        super().__init__(parent)
        self.title = title
        self.description = description

    def enterEvent(self, event):
        super().enterEvent(event)
        self.enter_signal.emit(self.title, self.description)

    def leaveEvent(self, event):
        super().leaveEvent(event)
        self.leave_signal.emit()

class APIRiskListComponent(QWidget):
    """OWASP API Security Top 10 risk list component"""
    
    risk_selected = pyqtSignal(dict)
    risk_hovered = pyqtSignal(str, str)
    risk_unhovered = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.setup_risk_data()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Create scroll area for risk buttons
        scroll_area = QScrollArea()
        scroll_widget = QWidget()
        self.scroll_layout = QVBoxLayout(scroll_widget)
        
        scroll_area.setWidget(scroll_widget)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)
    
    def setup_risk_data(self):
        """Setup OWASP API Security Top 10 risk data"""
        self.api_risks_data = [
            {
                "id": "api1",
                "title": "API1:2023 - Broken Object Level Authorization",
                "desc": "APIs expose endpoints that handle object identifiers, creating access control issues.",
                "details": """
                <b>Description:</b> Broken Object Level Authorization
                <br><br><b>Attack:</b> Manipulate object IDs in API calls to access other users' data
                <br><br><b>Prevention:</b> Implement proper authorization checks for every object
                """
            },
            {
                "id": "api2",
                "title": "API2:2023 - Broken Authentication",
                "desc": "Authentication mechanisms are often implemented incorrectly.",
                "details": """
                <b>Description:</b> Broken Authentication
                <br><br><b>Attack:</b> Brute force attacks, token manipulation, session hijacking
                <br><br><b>Prevention:</b> Implement strong authentication and session management
                """
            },
            {
                "id": "api3",
                "title": "API3:2023 - Broken Object Property Level Authorization",
                "desc": "Combines excessive data exposure and mass assignment vulnerabilities.",
                "details": """
                <b>Description:</b> Broken Object Property Level Authorization
                <br><br><b>Attack:</b> Mass assignment and excessive data exposure
                <br><br><b>Prevention:</b> Use allow-lists for modifiable properties
                """
            },
            {
                "id": "api4",
                "title": "API4:2023 - Unrestricted Resource Consumption",
                "desc": "API requests consume resources without proper limits.",
                "details": """
                <b>Description:</b> Unrestricted Resource Consumption
                <br><br><b>Attack:</b> DoS through resource exhaustion
                <br><br><b>Prevention:</b> Implement rate limiting and request size limits
                """
            },
            {
                "id": "api5",
                "title": "API5:2023 - Broken Function Level Authorization",
                "desc": "Complex access control policies create authorization confusion.",
                "details": """
                <b>Description:</b> Broken Function Level Authorization
                <br><br><b>Attack:</b> Access unauthorized functions or admin features
                <br><br><b>Prevention:</b> Implement proper function-level access controls
                """
            },
            {
                "id": "api6",
                "title": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
                "desc": "APIs lack protection against automated threats targeting business flows.",
                "details": """
                <b>Description:</b> Unrestricted Access to Sensitive Business Flows
                <br><br><b>Attack:</b> Automated abuse of business-critical flows
                <br><br><b>Prevention:</b> Implement business flow protection mechanisms
                """
            },
            {
                "id": "api7",
                "title": "API7:2023 - Server Side Request Forgery",
                "desc": "SSRF flaws occur when APIs fetch remote resources without validating URLs.",
                "details": """
                <b>Description:</b> Server Side Request Forgery
                <br><br><b>Attack:</b> Force server to make requests to unintended locations
                <br><br><b>Prevention:</b> Validate and sanitize all user-supplied URLs
                """
            },
            {
                "id": "api8",
                "title": "API8:2023 - Security Misconfiguration",
                "desc": "APIs often have configuration issues that expose sensitive data.",
                "details": """
                <b>Description:</b> Security Misconfiguration
                <br><br><b>Attack:</b> Exploit misconfigurations to access sensitive data
                <br><br><b>Prevention:</b> Implement secure configuration management
                """
            },
            {
                "id": "api9",
                "title": "API9:2023 - Improper Inventory Management",
                "desc": "APIs lack proper documentation and inventory management.",
                "details": """
                <b>Description:</b> Improper Inventory Management
                <br><br><b>Attack:</b> Target undocumented or deprecated API versions
                <br><br><b>Prevention:</b> Maintain proper API inventory and documentation
                """
            },
            {
                "id": "api10",
                "title": "API10:2023 - Unsafe Consumption of APIs",
                "desc": "Developers trust third-party APIs more than user input.",
                "details": """
                <b>Description:</b> Unsafe Consumption of APIs
                <br><br><b>Attack:</b> Exploit trust in third-party API responses
                <br><br><b>Prevention:</b> Validate and sanitize all API responses
                """
            }
        ]
        
        # Create buttons for each risk
        self.risk_buttons = []
        for risk in self.api_risks_data:
            button = HoverButton(risk["title"], risk["desc"], self)
            button.setMinimumHeight(50)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(lambda checked, r=risk: self.risk_selected.emit(r))
            button.enter_signal.connect(self.risk_hovered.emit)
            button.leave_signal.connect(self.risk_unhovered.emit)
            
            # Apply styling
            button.setStyleSheet("""
                QPushButton {
                    background-color: rgba(30, 40, 50, 150);
                    border: 2px solid rgba(100, 200, 255, 100);
                    border-radius: 8px;
                    color: #DCDCDC;
                    font-weight: bold;
                    padding: 8px;
                    text-align: left;
                }
                QPushButton:hover {
                    background-color: rgba(50, 70, 90, 200);
                    border: 2px solid #64C8FF;
                }
            """)
            
            self.scroll_layout.addWidget(button)
            self.risk_buttons.append(button)