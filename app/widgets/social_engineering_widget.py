# app/widgets/social_engineering_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QComboBox, QPushButton, QTextEdit, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QTabWidget, QLineEdit, QSpinBox, QPlainTextEdit)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor
from app.core.social_engineering import social_engineering
from app.core.license_manager import license_manager

class SEWorker(QThread):
    """Worker thread for social engineering operations"""
    operation_completed = pyqtSignal(dict)
    
    def __init__(self, operation, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
        
    def run(self):
        if self.operation == 'send_emails':
            result = social_engineering.send_phishing_emails(
                self.kwargs['campaign_id'], 
                self.kwargs['smtp_config']
            )
        elif self.operation == 'simulate_interactions':
            result = social_engineering.simulate_user_interactions(self.kwargs['campaign_id'])
        elif self.operation == 'analyze_campaign':
            result = social_engineering.analyze_campaign_effectiveness(self.kwargs['campaign_id'])
        else:
            result = {'error': 'Unknown operation'}
            
        self.operation_completed.emit(result)

class SocialEngineeringWidget(QWidget):
    """Social engineering toolkit widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.se_worker = None
        self.current_campaign_id = None
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Social Engineering Toolkit")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #FF6B6B;")
        layout.addWidget(header)
        
        # Warning
        warning = QLabel("⚠️ FOR AUTHORIZED TESTING ONLY - ENTERPRISE LICENSE REQUIRED")
        warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px; background: rgba(255,107,107,0.1);")
        layout.addWidget(warning)
        
        # License warning
        self.license_warning = QLabel("❌ Social Engineering requires Enterprise license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Tabs
        self.tabs = QTabWidget()
        
        # Campaign Creation Tab
        self.campaign_tab = self.create_campaign_tab()
        self.tabs.addTab(self.campaign_tab, "Campaigns")
        
        # Email Templates Tab
        self.templates_tab = self.create_templates_tab()
        self.tabs.addTab(self.templates_tab, "Templates")
        
        # Analytics Tab
        self.analytics_tab = self.create_analytics_tab()
        self.tabs.addTab(self.analytics_tab, "Analytics")
        
        layout.addWidget(self.tabs)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(120)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def create_campaign_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Campaign Creation
        create_group = QGroupBox("Create Phishing Campaign")
        create_layout = QVBoxLayout(create_group)
        
        # Campaign details
        details_layout = QHBoxLayout()
        details_layout.addWidget(QLabel("Campaign Name:"))
        self.campaign_name = QLineEdit()
        self.campaign_name.setPlaceholderText("Q4 Security Assessment")
        details_layout.addWidget(self.campaign_name)
        
        details_layout.addWidget(QLabel("Template:"))
        self.template_combo = QComboBox()
        self.template_combo.addItems(["office365", "banking", "it_support"])
        details_layout.addWidget(self.template_combo)
        create_layout.addLayout(details_layout)
        
        # Phishing URL
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Phishing URL:"))
        self.phishing_url = QLineEdit()
        self.phishing_url.setPlaceholderText("https://secure-login.example.com")
        url_layout.addWidget(self.phishing_url)
        create_layout.addLayout(url_layout)
        
        # Target list
        targets_layout = QVBoxLayout()
        targets_layout.addWidget(QLabel("Target Email Addresses (one per line):"))
        self.targets_text = QPlainTextEdit()
        self.targets_text.setPlaceholderText("user1@company.com\nuser2@company.com\nuser3@company.com")
        self.targets_text.setMaximumHeight(100)
        targets_layout.addWidget(self.targets_text)
        create_layout.addLayout(targets_layout)
        
        self.create_campaign_btn = QPushButton("Create Campaign")
        self.create_campaign_btn.setStyleSheet("background-color: #FF6B6B; font-weight: bold;")
        create_layout.addWidget(self.create_campaign_btn)
        
        layout.addWidget(create_group)
        
        # Campaign Management
        manage_group = QGroupBox("Campaign Management")
        manage_layout = QVBoxLayout(manage_group)
        
        # Campaigns table
        self.campaigns_table = QTableWidget()
        self.campaigns_table.setColumnCount(6)
        self.campaigns_table.setHorizontalHeaderLabels(["ID", "Name", "Template", "Targets", "Status", "Effectiveness"])
        self.campaigns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        manage_layout.addWidget(self.campaigns_table)
        
        # Campaign actions
        actions_layout = QHBoxLayout()
        self.send_emails_btn = QPushButton("Send Emails")
        self.simulate_btn = QPushButton("Simulate Interactions")
        self.analyze_btn = QPushButton("Analyze Campaign")
        
        actions_layout.addWidget(self.send_emails_btn)
        actions_layout.addWidget(self.simulate_btn)
        actions_layout.addWidget(self.analyze_btn)
        manage_layout.addLayout(actions_layout)
        
        layout.addWidget(manage_group)
        
        return widget
        
    def create_templates_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Template Selection
        template_group = QGroupBox("Email Templates")
        template_layout = QVBoxLayout(template_group)
        
        template_select_layout = QHBoxLayout()
        template_select_layout.addWidget(QLabel("Template:"))
        self.template_preview_combo = QComboBox()
        self.template_preview_combo.addItems(["office365", "banking", "it_support"])
        template_select_layout.addWidget(self.template_preview_combo)
        
        self.preview_template_btn = QPushButton("Preview Template")
        template_select_layout.addWidget(self.preview_template_btn)
        template_layout.addLayout(template_select_layout)
        
        # Template preview
        self.template_preview = QTextEdit()
        self.template_preview.setReadOnly(True)
        template_layout.addWidget(self.template_preview)
        
        layout.addWidget(template_group)
        
        # Phishing Page Generator
        page_group = QGroupBox("Phishing Page Generator")
        page_layout = QVBoxLayout(page_group)
        
        page_config_layout = QHBoxLayout()
        page_config_layout.addWidget(QLabel("Page Template:"))
        self.page_template_combo = QComboBox()
        self.page_template_combo.addItems(["office365", "banking"])
        page_config_layout.addWidget(self.page_template_combo)
        
        page_config_layout.addWidget(QLabel("Target URL:"))
        self.page_target_url = QLineEdit()
        self.page_target_url.setPlaceholderText("https://harvest.example.com/collect")
        page_config_layout.addWidget(self.page_target_url)
        page_layout.addLayout(page_config_layout)
        
        self.generate_page_btn = QPushButton("Generate Phishing Page")
        page_layout.addWidget(self.generate_page_btn)
        
        # Generated page display
        self.generated_page = QTextEdit()
        self.generated_page.setReadOnly(True)
        page_layout.addWidget(self.generated_page)
        
        layout.addWidget(page_group)
        
        return widget
        
    def create_analytics_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Campaign Analytics
        analytics_group = QGroupBox("Campaign Analytics")
        analytics_layout = QVBoxLayout(analytics_group)
        
        # Metrics display
        self.metrics_table = QTableWidget()
        self.metrics_table.setColumnCount(2)
        self.metrics_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self.metrics_table.setMaximumHeight(200)
        analytics_layout.addWidget(self.metrics_table)
        
        # Recommendations
        rec_layout = QVBoxLayout()
        rec_layout.addWidget(QLabel("Security Recommendations:"))
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        self.recommendations_text.setMaximumHeight(150)
        rec_layout.addWidget(self.recommendations_text)
        analytics_layout.addLayout(rec_layout)
        
        layout.addWidget(analytics_group)
        
        # Risk Assessment
        risk_group = QGroupBox("Risk Assessment")
        risk_layout = QVBoxLayout(risk_group)
        
        self.risk_display = QTextEdit()
        self.risk_display.setReadOnly(True)
        self.risk_display.setMaximumHeight(100)
        risk_layout.addWidget(self.risk_display)
        
        layout.addWidget(risk_group)
        
        return widget
        
    def connect_signals(self):
        self.create_campaign_btn.clicked.connect(self.create_campaign)
        self.send_emails_btn.clicked.connect(self.send_emails)
        self.simulate_btn.clicked.connect(self.simulate_interactions)
        self.analyze_btn.clicked.connect(self.analyze_campaign)
        self.preview_template_btn.clicked.connect(self.preview_template)
        self.generate_page_btn.clicked.connect(self.generate_phishing_page)
        
        self.campaigns_table.itemSelectionChanged.connect(self.on_campaign_selected)
        social_engineering.se_event.connect(self.handle_se_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('social_engineering'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def create_campaign(self):
        if not license_manager.is_feature_enabled('social_engineering'):
            self.status_text.append("❌ Social Engineering requires Enterprise license")
            return
            
        name = self.campaign_name.text().strip()
        template = self.template_combo.currentText()
        url = self.phishing_url.text().strip()
        targets_text = self.targets_text.toPlainText().strip()
        
        if not all([name, url, targets_text]):
            self.status_text.append("❌ Please fill in all campaign details")
            return
            
        targets = [email.strip() for email in targets_text.split('\n') if email.strip()]
        
        result = social_engineering.create_phishing_campaign(name, template, targets, url)
        
        if result.get('success'):
            self.current_campaign_id = result['campaign_id']
            self.status_text.append(f"✅ Campaign '{name}' created with ID {self.current_campaign_id}")
            self.update_campaigns_table()
            
            # Clear form
            self.campaign_name.clear()
            self.phishing_url.clear()
            self.targets_text.clear()
        else:
            self.status_text.append(f"❌ Campaign creation failed: {result.get('error', 'Unknown error')}")
            
    def send_emails(self):
        if not self.current_campaign_id:
            self.status_text.append("❌ Please select a campaign first")
            return
            
        # Simulate SMTP config
        smtp_config = {
            'server': 'smtp.example.com',
            'port': 587,
            'username': 'sender@example.com',
            'password': 'password'
        }
        
        self.send_emails_btn.setEnabled(False)
        self.status_text.append(f"📧 Sending phishing emails for campaign {self.current_campaign_id}...")
        
        self.se_worker = SEWorker('send_emails', campaign_id=self.current_campaign_id, smtp_config=smtp_config)
        self.se_worker.operation_completed.connect(self.handle_send_emails_completed)
        self.se_worker.start()
        
    def simulate_interactions(self):
        if not self.current_campaign_id:
            self.status_text.append("❌ Please select a campaign first")
            return
            
        self.simulate_btn.setEnabled(False)
        self.status_text.append(f"🎭 Simulating user interactions for campaign {self.current_campaign_id}...")
        
        self.se_worker = SEWorker('simulate_interactions', campaign_id=self.current_campaign_id)
        self.se_worker.operation_completed.connect(self.handle_simulate_completed)
        self.se_worker.start()
        
    def analyze_campaign(self):
        if not self.current_campaign_id:
            self.status_text.append("❌ Please select a campaign first")
            return
            
        self.analyze_btn.setEnabled(False)
        self.status_text.append(f"📊 Analyzing campaign {self.current_campaign_id}...")
        
        self.se_worker = SEWorker('analyze_campaign', campaign_id=self.current_campaign_id)
        self.se_worker.operation_completed.connect(self.handle_analyze_completed)
        self.se_worker.start()
        
    def preview_template(self):
        template = self.template_preview_combo.currentText()
        
        # Get template content
        templates = social_engineering.templates
        if template in templates:
            template_data = templates[template]
            preview_text = f"""Subject: {template_data['subject']}
From: {template_data['sender']}

{template_data['body']}"""
            
            self.template_preview.setPlainText(preview_text)
            self.status_text.append(f"📧 Previewing {template} template")
        else:
            self.status_text.append(f"❌ Template {template} not found")
            
    def generate_phishing_page(self):
        template = self.page_template_combo.currentText()
        target_url = self.page_target_url.text().strip()
        
        if not target_url:
            self.status_text.append("❌ Please enter target URL")
            return
            
        result = social_engineering.generate_phishing_page(template, target_url)
        
        if result.get('success'):
            self.generated_page.setPlainText(result['html_content'])
            self.status_text.append(f"🌐 Generated {template} phishing page")
        else:
            self.status_text.append(f"❌ Page generation failed: {result.get('error', 'Unknown error')}")
            
    def update_campaigns_table(self):
        summary = social_engineering.get_campaign_summary()
        campaigns = summary.get('campaigns', [])
        
        self.campaigns_table.setRowCount(len(campaigns))
        
        for row, campaign in enumerate(campaigns):
            self.campaigns_table.setItem(row, 0, QTableWidgetItem(str(campaign['id'])))
            self.campaigns_table.setItem(row, 1, QTableWidgetItem(campaign['name']))
            self.campaigns_table.setItem(row, 2, QTableWidgetItem(campaign['template']))
            self.campaigns_table.setItem(row, 3, QTableWidgetItem(str(campaign['targets'])))
            self.campaigns_table.setItem(row, 4, QTableWidgetItem(campaign['status']))
            
            # Color code effectiveness
            effectiveness = campaign['effectiveness']
            effectiveness_item = QTableWidgetItem(effectiveness)
            
            if 'Highly Effective' in effectiveness:
                effectiveness_item.setForeground(QColor("#FF0000"))
            elif 'Effective' in effectiveness:
                effectiveness_item.setForeground(QColor("#FF6B6B"))
            elif 'Moderately' in effectiveness:
                effectiveness_item.setForeground(QColor("#FFA500"))
            else:
                effectiveness_item.setForeground(QColor("#00FF41"))
                
            self.campaigns_table.setItem(row, 5, effectiveness_item)
            
    def on_campaign_selected(self):
        current_row = self.campaigns_table.currentRow()
        if current_row >= 0:
            campaign_id_item = self.campaigns_table.item(current_row, 0)
            if campaign_id_item:
                self.current_campaign_id = int(campaign_id_item.text())
                self.status_text.append(f"📋 Selected campaign {self.current_campaign_id}")
                
    def handle_send_emails_completed(self, result):
        self.send_emails_btn.setEnabled(True)
        
        if 'error' not in result:
            sent = result.get('sent_successfully', 0)
            failed = result.get('failed_sends', 0)
            self.status_text.append(f"📧 Email sending completed: {sent} sent, {failed} failed")
            self.update_campaigns_table()
        else:
            self.status_text.append(f"❌ Email sending failed: {result['error']}")
            
    def handle_simulate_completed(self, result):
        self.simulate_btn.setEnabled(True)
        
        if 'error' not in result:
            opened = result.get('emails_opened', 0)
            clicked = result.get('links_clicked', 0)
            credentials = result.get('credentials_harvested', 0)
            
            self.status_text.append(f"🎭 Simulation completed:")
            self.status_text.append(f"   Opened: {opened} | Clicked: {clicked} | Credentials: {credentials}")
            self.update_campaigns_table()
        else:
            self.status_text.append(f"❌ Simulation failed: {result['error']}")
            
    def handle_analyze_completed(self, result):
        self.analyze_btn.setEnabled(True)
        
        if 'error' not in result:
            # Update metrics table
            metrics = result.get('metrics', {})
            self.metrics_table.setRowCount(len(metrics))
            
            for row, (metric, value) in enumerate(metrics.items()):
                self.metrics_table.setItem(row, 0, QTableWidgetItem(metric.replace('_', ' ').title()))
                if isinstance(value, float):
                    self.metrics_table.setItem(row, 1, QTableWidgetItem(f"{value:.1f}%"))
                else:
                    self.metrics_table.setItem(row, 1, QTableWidgetItem(str(value)))
                    
            # Update recommendations
            recommendations = result.get('recommendations', [])
            rec_text = '\n'.join(f"• {rec}" for rec in recommendations)
            self.recommendations_text.setPlainText(rec_text)
            
            # Update risk assessment
            risk = result.get('risk_assessment', {})
            risk_text = f"""Risk Level: {risk.get('level', 'Unknown')}
Risk Score: {risk.get('score', 0)}/10
Description: {risk.get('description', 'No description available')}"""
            
            self.risk_display.setPlainText(risk_text)
            
            self.status_text.append(f"📊 Campaign analysis completed - Risk Level: {risk.get('level', 'Unknown')}")
        else:
            self.status_text.append(f"❌ Analysis failed: {result['error']}")
            
    def handle_se_event(self, event_type, message, data):
        self.status_text.append(f"🎯 {message}")