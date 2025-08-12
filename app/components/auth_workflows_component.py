from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

class AuthWorkflowsComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        """Setup auth workflows UI"""
        layout = QVBoxLayout(self)
        
        try:
            from app.widgets.auth_workflows_widget import AuthWorkflowsWidget
            main_window = getattr(self.parent(), 'main_window', None)
            self.auth_widget = AuthWorkflowsWidget(main_window)
            layout.addWidget(self.auth_widget)
        except ImportError:
            info_label = QLabel("Authentication Workflows - Widget not available")
            info_label.setStyleSheet("color: #FF6B6B; font-size: 14pt; padding: 20px;")
            layout.addWidget(info_label)
            
            # Placeholder for future implementation
            details_label = QLabel("""
            Planned Features:
            • Multi-factor authentication bypass
            • Session management testing
            • OAuth/SAML workflow analysis
            • JWT token manipulation
            • Password reset flow testing
            """)
            details_label.setStyleSheet("color: #DCDCDC; padding: 20px;")
            layout.addWidget(details_label)