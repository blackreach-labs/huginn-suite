# app/widgets/aws_sam_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, 
                            QLabel, QLineEdit, QPushButton, QSpinBox, QComboBox, 
                            QCheckBox, QMessageBox, QTabWidget)
from PyQt6.QtCore import pyqtSignal
from app.core.aws_sam_deployment import sam_deployment_manager

class AWSSAMWidget(QWidget):
    status_updated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        sam_deployment_manager.deployment_started.connect(self.on_deployment_started)
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Credentials
        creds_group = QGroupBox("Credentials")
        creds_layout = QVBoxLayout(creds_group)
        
        # GitLab
        gitlab_layout = QHBoxLayout()
        gitlab_layout.addWidget(QLabel("GitLab URL:"))
        self.gitlab_url = QLineEdit("https://gitlab.com")
        gitlab_layout.addWidget(self.gitlab_url)
        creds_layout.addLayout(gitlab_layout)
        
        token_layout = QHBoxLayout()
        token_layout.addWidget(QLabel("Token:"))
        self.gitlab_token = QLineEdit()
        self.gitlab_token.setEchoMode(QLineEdit.EchoMode.Password)
        token_layout.addWidget(self.gitlab_token)
        creds_layout.addLayout(token_layout)
        
        project_layout = QHBoxLayout()
        project_layout.addWidget(QLabel("Project ID:"))
        self.project_id = QLineEdit()
        project_layout.addWidget(self.project_id)
        creds_layout.addLayout(project_layout)
        
        # AWS
        aws_layout = QHBoxLayout()
        aws_layout.addWidget(QLabel("AWS Access Key:"))
        self.aws_access_key = QLineEdit()
        aws_layout.addWidget(self.aws_access_key)
        creds_layout.addLayout(aws_layout)
        
        secret_layout = QHBoxLayout()
        secret_layout.addWidget(QLabel("AWS Secret Key:"))
        self.aws_secret_key = QLineEdit()
        self.aws_secret_key.setEchoMode(QLineEdit.EchoMode.Password)
        secret_layout.addWidget(self.aws_secret_key)
        creds_layout.addLayout(secret_layout)
        
        region_layout = QHBoxLayout()
        region_layout.addWidget(QLabel("Region:"))
        self.aws_region = QComboBox()
        self.aws_region.addItems(["us-east-1", "us-west-2", "eu-west-1"])
        region_layout.addWidget(self.aws_region)
        creds_layout.addLayout(region_layout)
        
        test_btn = QPushButton("Test Connections")
        test_btn.clicked.connect(self.test_connections)
        creds_layout.addWidget(test_btn)
        
        layout.addWidget(creds_group)
        
        # Deployment tabs
        tabs = QTabWidget()
        
        # Proxy tab
        proxy_tab = QWidget()
        proxy_layout = QVBoxLayout(proxy_tab)
        
        proxy_config = QGroupBox("Proxy Configuration")
        proxy_config_layout = QVBoxLayout(proxy_config)
        
        count_layout = QHBoxLayout()
        count_layout.addWidget(QLabel("Server Count:"))
        self.proxy_count = QSpinBox()
        self.proxy_count.setRange(1, 10)
        self.proxy_count.setValue(2)
        count_layout.addWidget(self.proxy_count)
        proxy_config_layout.addLayout(count_layout)
        
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Instance Type:"))
        self.proxy_instance_type = QComboBox()
        self.proxy_instance_type.addItems(["t3.micro", "t3.small", "t3.medium"])
        type_layout.addWidget(self.proxy_instance_type)
        proxy_config_layout.addLayout(type_layout)
        
        self.proxy_auth = QCheckBox("Enable Authentication")
        proxy_config_layout.addWidget(self.proxy_auth)
        
        proxy_layout.addWidget(proxy_config)
        
        deploy_proxy_btn = QPushButton("Deploy Proxy Servers")
        deploy_proxy_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; padding: 10px; }")
        deploy_proxy_btn.clicked.connect(self.deploy_proxy_servers)
        proxy_layout.addWidget(deploy_proxy_btn)
        
        tabs.addTab(proxy_tab, "Proxy Servers")
        
        # VPN tab
        vpn_tab = QWidget()
        vpn_layout = QVBoxLayout(vpn_tab)
        
        vpn_config = QGroupBox("VPN Configuration")
        vpn_config_layout = QVBoxLayout(vpn_config)
        
        vpn_count_layout = QHBoxLayout()
        vpn_count_layout.addWidget(QLabel("Server Count:"))
        self.vpn_count = QSpinBox()
        self.vpn_count.setRange(1, 5)
        self.vpn_count.setValue(1)
        vpn_count_layout.addWidget(self.vpn_count)
        vpn_config_layout.addLayout(vpn_count_layout)
        
        vpn_type_layout = QHBoxLayout()
        vpn_type_layout.addWidget(QLabel("Instance Type:"))
        self.vpn_instance_type = QComboBox()
        self.vpn_instance_type.addItems(["t3.small", "t3.medium", "t3.large"])
        type_layout.addWidget(self.vpn_instance_type)
        vpn_config_layout.addLayout(vpn_type_layout)
        
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("VPN Type:"))
        self.vpn_protocol = QComboBox()
        self.vpn_protocol.addItems(["OpenVPN", "WireGuard"])
        protocol_layout.addWidget(self.vpn_protocol)
        vpn_config_layout.addLayout(protocol_layout)
        
        vpn_layout.addWidget(vpn_config)
        
        deploy_vpn_btn = QPushButton("Deploy VPN Servers")
        deploy_vpn_btn.setStyleSheet("QPushButton { background-color: #2196F3; color: white; padding: 10px; }")
        deploy_vpn_btn.clicked.connect(self.deploy_vpn_servers)
        vpn_layout.addWidget(deploy_vpn_btn)
        
        tabs.addTab(vpn_tab, "VPN Servers")
        
        layout.addWidget(tabs)
        
    def test_connections(self):
        gitlab_ok = sam_deployment_manager.configure_gitlab(
            self.gitlab_url.text(), self.gitlab_token.text(), self.project_id.text()
        )
        aws_ok = sam_deployment_manager.configure_aws(
            self.aws_access_key.text(), self.aws_secret_key.text(), self.aws_region.currentText()
        )
        
        if gitlab_ok and aws_ok:
            QMessageBox.information(self, "Success", "All connections tested successfully!")
        else:
            QMessageBox.warning(self, "Error", "Connection test failed")
    
    def deploy_proxy_servers(self):
        config = {
            'count': self.proxy_count.value(),
            'instance_type': self.proxy_instance_type.currentText(),
            'authentication': self.proxy_auth.isChecked()
        }
        
        job_id = sam_deployment_manager.deploy_proxy_servers(config)
        if job_id:
            self.status_updated.emit(f"Proxy deployment started: {job_id}")
        else:
            QMessageBox.warning(self, "Error", "Failed to start deployment")
    
    def deploy_vpn_servers(self):
        config = {
            'count': self.vpn_count.value(),
            'instance_type': self.vpn_instance_type.currentText(),
            'protocol': self.vpn_protocol.currentText()
        }
        
        job_id = sam_deployment_manager.deploy_vpn_servers(config)
        if job_id:
            self.status_updated.emit(f"VPN deployment started: {job_id}")
        else:
            QMessageBox.warning(self, "Error", "Failed to start deployment")
    
    def on_deployment_started(self, deployment_type: str, job_id: str):
        self.status_updated.emit(f"{deployment_type} deployment pipeline started: {job_id}")