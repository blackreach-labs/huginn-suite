# app/core/huggin_dashboard.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QTextEdit, QTableWidget, QTableWidgetItem, 
                            QTabWidget, QPushButton, QProgressBar, QFrame,
                            QScrollArea, QGridLayout, QGroupBox, QSplitter)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QPalette, QColor, QPixmap, QPainter
import json
from datetime import datetime
from .huggin_results_analyzer import huggin_analyzer
from .vulnerability_correlation_engine import correlation_engine
from .centralized_scan_data import centralized_scan_data

class VulnerabilityCard(QFrame):
    """Individual vulnerability card widget"""
    
    def __init__(self, vulnerability: dict):
        super().__init__()
        self.vulnerability = vulnerability
        self.setup_ui()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet(self._get_card_style())
        
        layout = QVBoxLayout()
        
        # Header with severity and type
        header_layout = QHBoxLayout()
        
        severity_label = QLabel(self.vulnerability.get('severity', 'Unknown'))
        severity_label.setStyleSheet(self._get_severity_style())
        severity_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        severity_label.setMaximumWidth(80)
        
        type_label = QLabel(self.vulnerability.get('type', 'Unknown Vulnerability'))
        type_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        
        header_layout.addWidget(severity_label)
        header_layout.addWidget(type_label)
        header_layout.addStretch()
        
        # CVSS Score
        cvss_score = self.vulnerability.get('cvss_score', 0)
        if cvss_score > 0:
            cvss_label = QLabel(f"CVSS: {cvss_score}")
            cvss_label.setStyleSheet("color: #666; font-weight: bold;")
            header_layout.addWidget(cvss_label)
        
        layout.addLayout(header_layout)
        
        # Description
        desc_label = QLabel(self.vulnerability.get('description', 'No description available'))
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #444; margin: 5px 0;")
        layout.addWidget(desc_label)
        
        # Remediation
        remediation = self.vulnerability.get('remediation', 'No remediation provided')
        if len(remediation) > 100:
            remediation = remediation[:100] + "..."
        
        remediation_label = QLabel(f"🔧 {remediation}")
        remediation_label.setWordWrap(True)
        remediation_label.setStyleSheet("color: #007bff; font-size: 9px; margin-top: 5px;")
        layout.addWidget(remediation_label)
        
        self.setLayout(layout)
    
    def _get_card_style(self):
        return """
            QFrame {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 10px;
                margin: 5px;
            }
            QFrame:hover {
                border-color: #007bff;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
        """
    
    def _get_severity_style(self):
        severity = self.vulnerability.get('severity', 'Low').lower()
        colors = {
            'critical': 'background-color: #dc3545; color: white;',
            'high': 'background-color: #fd7e14; color: white;',
            'medium': 'background-color: #ffc107; color: black;',
            'low': 'background-color: #28a745; color: white;'
        }
        base_style = "padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 9px;"
        return base_style + colors.get(severity, colors['low'])

class AttackChainWidget(QFrame):
    """Widget to display attack chain analysis"""
    
    def __init__(self, attack_chain):
        super().__init__()
        self.attack_chain = attack_chain
        self.setup_ui()
    
    def setup_ui(self):
        self.setFrameStyle(QFrame.Shape.Box)
        self.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel(f"🔗 Attack Chain: {self.attack_chain.chain_id}")
        title_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        
        risk_label = QLabel(f"Risk: {self.attack_chain.risk_score:.1f}/10")
        risk_label.setStyleSheet(self._get_risk_style())
        
        priority_label = QLabel(f"Priority: {self.attack_chain.mitigation_priority}")
        priority_label.setStyleSheet("color: #dc3545; font-weight: bold;")
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(risk_label)
        header_layout.addWidget(priority_label)
        
        layout.addLayout(header_layout)
        
        # Description
        desc_label = QLabel(self.attack_chain.description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #495057; margin: 10px 0;")
        layout.addWidget(desc_label)
        
        # Attack path
        path_label = QLabel("Attack Path:")
        path_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        layout.addWidget(path_label)
        
        for step in self.attack_chain.attack_path:
            step_label = QLabel(f"  {step}")
            step_label.setStyleSheet("color: #6c757d; margin-left: 10px;")
            layout.addWidget(step_label)
        
        # Involved vulnerabilities
        vulns_label = QLabel(f"Vulnerabilities: {', '.join(self.attack_chain.vulnerabilities)}")
        vulns_label.setWordWrap(True)
        vulns_label.setStyleSheet("color: #007bff; font-size: 9px; margin-top: 10px;")
        layout.addWidget(vulns_label)
        
        self.setLayout(layout)
    
    def _get_risk_style(self):
        risk_score = self.attack_chain.risk_score
        if risk_score >= 8:
            return "background-color: #dc3545; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;"
        elif risk_score >= 6:
            return "background-color: #fd7e14; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;"
        elif risk_score >= 4:
            return "background-color: #ffc107; color: black; padding: 4px 8px; border-radius: 4px; font-weight: bold;"
        else:
            return "background-color: #28a745; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold;"

class HugginDashboard(QWidget):
    """Comprehensive Huggin scanner results dashboard"""
    
    refresh_requested = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_results = {}
        self.analysis_results = {}
        self.attack_chains = []
        self.setup_ui()
        self.setup_refresh_timer()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("🚀 Huggin Advanced Security Scanner - Results Dashboard")
        title_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #2c3e50; margin: 10px 0;")
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_data)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0056b3;
            }
        """)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Main content tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #ddd;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #f8f9fa;
                padding: 8px 16px;
                margin-right: 2px;
                border: 1px solid #ddd;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 1px solid white;
            }
        """)
        
        # Overview tab
        self.overview_tab = self.create_overview_tab()
        self.tab_widget.addTab(self.overview_tab, "📊 Overview")
        
        # Vulnerabilities tab
        self.vulnerabilities_tab = self.create_vulnerabilities_tab()
        self.tab_widget.addTab(self.vulnerabilities_tab, "🔍 Vulnerabilities")
        
        # Attack chains tab
        self.attack_chains_tab = self.create_attack_chains_tab()
        self.tab_widget.addTab(self.attack_chains_tab, "🔗 Attack Chains")
        
        # Remediation tab
        self.remediation_tab = self.create_remediation_tab()
        self.tab_widget.addTab(self.remediation_tab, "🛠️ Remediation")
        
        # Reports tab
        self.reports_tab = self.create_reports_tab()
        self.tab_widget.addTab(self.reports_tab, "📋 Reports")
        
        layout.addWidget(self.tab_widget)
        self.setLayout(layout)
    
    def create_overview_tab(self):
        """Create overview tab with key metrics"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Metrics cards
        metrics_layout = QGridLayout()
        
        # Risk score card
        self.risk_score_card = self.create_metric_card("Overall Risk", "0%", "#dc3545")
        metrics_layout.addWidget(self.risk_score_card, 0, 0)
        
        # Vulnerability count card
        self.vuln_count_card = self.create_metric_card("Vulnerabilities", "0", "#007bff")
        metrics_layout.addWidget(self.vuln_count_card, 0, 1)
        
        # Critical issues card
        self.critical_card = self.create_metric_card("Critical Issues", "0", "#dc3545")
        metrics_layout.addWidget(self.critical_card, 0, 2)
        
        # Compliance score card
        self.compliance_card = self.create_metric_card("OWASP Compliance", "0%", "#28a745")
        metrics_layout.addWidget(self.compliance_card, 0, 3)
        
        layout.addLayout(metrics_layout)
        
        # Recent scans table
        recent_group = QGroupBox("Recent Scans")
        recent_layout = QVBoxLayout()
        
        self.recent_scans_table = QTableWidget()
        self.recent_scans_table.setColumnCount(5)
        self.recent_scans_table.setHorizontalHeaderLabels([
            "Target", "Scan Time", "Vulnerabilities", "Risk Level", "Status"
        ])
        self.recent_scans_table.horizontalHeader().setStretchLastSection(True)
        
        recent_layout.addWidget(self.recent_scans_table)
        recent_group.setLayout(recent_layout)
        
        layout.addWidget(recent_group)
        
        tab.setLayout(layout)
        return tab
    
    def create_vulnerabilities_tab(self):
        """Create vulnerabilities tab with detailed view"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        severity_filter = QPushButton("All Severities")
        type_filter = QPushButton("All Types")
        
        filter_layout.addWidget(QLabel("Filters:"))
        filter_layout.addWidget(severity_filter)
        filter_layout.addWidget(type_filter)
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Vulnerabilities scroll area
        self.vulnerabilities_scroll = QScrollArea()
        self.vulnerabilities_scroll.setWidgetResizable(True)
        self.vulnerabilities_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        self.vulnerabilities_container = QWidget()
        self.vulnerabilities_layout = QVBoxLayout()
        self.vulnerabilities_container.setLayout(self.vulnerabilities_layout)
        self.vulnerabilities_scroll.setWidget(self.vulnerabilities_container)
        
        layout.addWidget(self.vulnerabilities_scroll)
        
        tab.setLayout(layout)
        return tab
    
    def create_attack_chains_tab(self):
        """Create attack chains analysis tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("🔗 Identified Attack Chains")
        header_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        header_label.setStyleSheet("color: #2c3e50; margin: 10px 0;")
        layout.addWidget(header_label)
        
        # Attack chains scroll area
        self.attack_chains_scroll = QScrollArea()
        self.attack_chains_scroll.setWidgetResizable(True)
        self.attack_chains_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        self.attack_chains_container = QWidget()
        self.attack_chains_layout = QVBoxLayout()
        self.attack_chains_container.setLayout(self.attack_chains_layout)
        self.attack_chains_scroll.setWidget(self.attack_chains_container)
        
        layout.addWidget(self.attack_chains_scroll)
        
        tab.setLayout(layout)
        return tab
    
    def create_remediation_tab(self):
        """Create remediation roadmap tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Remediation roadmap table
        roadmap_group = QGroupBox("Remediation Roadmap")
        roadmap_layout = QVBoxLayout()
        
        self.roadmap_table = QTableWidget()
        self.roadmap_table.setColumnCount(5)
        self.roadmap_table.setHorizontalHeaderLabels([
            "Priority", "Vulnerability", "Effort", "Timeline", "Business Impact"
        ])
        self.roadmap_table.horizontalHeader().setStretchLastSection(True)
        
        roadmap_layout.addWidget(self.roadmap_table)
        roadmap_group.setLayout(roadmap_layout)
        
        layout.addWidget(roadmap_group)
        
        # Mitigation strategies
        strategies_group = QGroupBox("Mitigation Strategies")
        strategies_layout = QVBoxLayout()
        
        self.strategies_text = QTextEdit()
        self.strategies_text.setReadOnly(True)
        self.strategies_text.setMaximumHeight(200)
        
        strategies_layout.addWidget(self.strategies_text)
        strategies_group.setLayout(strategies_layout)
        
        layout.addWidget(strategies_group)
        
        tab.setLayout(layout)
        return tab
    
    def create_reports_tab(self):
        """Create reports generation tab"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Report generation controls
        controls_layout = QHBoxLayout()
        
        generate_html_btn = QPushButton("📄 Generate HTML Report")
        generate_html_btn.clicked.connect(self.generate_html_report)
        
        generate_json_btn = QPushButton("📊 Export JSON Data")
        generate_json_btn.clicked.connect(self.export_json_data)
        
        generate_executive_btn = QPushButton("👔 Executive Summary")
        generate_executive_btn.clicked.connect(self.generate_executive_summary)
        
        controls_layout.addWidget(generate_html_btn)
        controls_layout.addWidget(generate_json_btn)
        controls_layout.addWidget(generate_executive_btn)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Report preview
        preview_group = QGroupBox("Report Preview")
        preview_layout = QVBoxLayout()
        
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        
        preview_layout.addWidget(self.report_preview)
        preview_group.setLayout(preview_layout)
        
        layout.addWidget(preview_group)
        
        tab.setLayout(layout)
        return tab
    
    def create_metric_card(self, title: str, value: str, color: str):
        """Create a metric card widget"""
        card = QFrame()
        card.setFrameStyle(QFrame.Shape.Box)
        card.setStyleSheet(f"""
            QFrame {{
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 15px;
                margin: 5px;
            }}
            QLabel {{
                color: {color};
            }}
        """)
        
        layout = QVBoxLayout()
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 10))
        title_label.setStyleSheet("color: #666;")
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        
        card.setLayout(layout)
        return card
    
    def setup_refresh_timer(self):
        """Setup automatic refresh timer"""
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(30000)  # Refresh every 30 seconds
    
    def load_scan_results(self, scan_results: dict):
        """Load and analyze scan results"""
        self.scan_results = scan_results
        
        # Analyze results
        self.analysis_results = huggin_analyzer.analyze_scan_results(scan_results)
        
        # Generate attack chains
        vulnerabilities = scan_results.get('vulnerabilities', [])
        self.attack_chains = correlation_engine.analyze_attack_chains(vulnerabilities)
        
        # Update UI
        self.update_overview_tab()
        self.update_vulnerabilities_tab()
        self.update_attack_chains_tab()
        self.update_remediation_tab()
    
    def update_overview_tab(self):
        """Update overview tab with current data"""
        if not self.analysis_results:
            return
        
        # Update metric cards
        risk_assessment = self.analysis_results.get('risk_assessment', {})
        scan_summary = self.analysis_results.get('scan_summary', {})
        compliance = self.analysis_results.get('compliance_status', {})
        
        # Risk score
        risk_score = risk_assessment.get('overall_risk_score', 0)
        self.risk_score_card.findChild(QLabel).setText(f"{risk_score:.1f}%")
        
        # Vulnerability count
        total_vulns = scan_summary.get('total_vulnerabilities', 0)
        self.vuln_count_card.findChild(QLabel).setText(str(total_vulns))
        
        # Critical issues
        severity_breakdown = scan_summary.get('severity_breakdown', {})
        critical_count = severity_breakdown.get('Critical', 0)
        self.critical_card.findChild(QLabel).setText(str(critical_count))
        
        # OWASP compliance
        owasp_score = compliance.get('owasp_top_10', {}).get('score', 0)
        self.compliance_card.findChild(QLabel).setText(f"{owasp_score}%")
    
    def update_vulnerabilities_tab(self):
        """Update vulnerabilities tab with vulnerability cards"""
        # Clear existing cards
        for i in reversed(range(self.vulnerabilities_layout.count())):
            child = self.vulnerabilities_layout.itemAt(i).widget()
            if child:
                child.setParent(None)
        
        # Add vulnerability cards
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            card = VulnerabilityCard(vuln)
            self.vulnerabilities_layout.addWidget(card)
        
        # Add stretch to push cards to top
        self.vulnerabilities_layout.addStretch()
    
    def update_attack_chains_tab(self):
        """Update attack chains tab"""
        # Clear existing chains
        for i in reversed(range(self.attack_chains_layout.count())):
            child = self.attack_chains_layout.itemAt(i).widget()
            if child:
                child.setParent(None)
        
        # Add attack chain widgets
        for chain in self.attack_chains:
            widget = AttackChainWidget(chain)
            self.attack_chains_layout.addWidget(widget)
        
        # Add stretch to push chains to top
        self.attack_chains_layout.addStretch()
    
    def update_remediation_tab(self):
        """Update remediation tab with roadmap and strategies"""
        if not self.analysis_results:
            return
        
        # Update roadmap table
        roadmap = self.analysis_results.get('remediation_roadmap', [])
        self.roadmap_table.setRowCount(len(roadmap))
        
        for row, item in enumerate(roadmap):
            self.roadmap_table.setItem(row, 0, QTableWidgetItem(str(item.get('priority', ''))))
            self.roadmap_table.setItem(row, 1, QTableWidgetItem(item.get('vulnerability_type', '')))
            self.roadmap_table.setItem(row, 2, QTableWidgetItem(item.get('effort_estimate', '')))
            self.roadmap_table.setItem(row, 3, QTableWidgetItem(item.get('timeline', '')))
            self.roadmap_table.setItem(row, 4, QTableWidgetItem(item.get('business_impact', '')))
        
        # Update mitigation strategies
        strategies = correlation_engine.generate_mitigation_strategy(self.attack_chains)
        strategies_text = ""
        
        for category, items in strategies.items():
            strategies_text += f"\n{category.replace('_', ' ').title()}:\n"
            for item in items:
                strategies_text += f"• {item}\n"
        
        self.strategies_text.setPlainText(strategies_text)
    
    def refresh_data(self):
        """Refresh dashboard data"""
        self.refresh_requested.emit()
    
    def generate_html_report(self):
        """Generate HTML report"""
        if self.analysis_results:
            html_report = huggin_analyzer.generate_detailed_report(self.analysis_results)
            self.report_preview.setHtml(html_report)
    
    def export_json_data(self):
        """Export JSON data"""
        if self.scan_results:
            json_data = json.dumps(self.scan_results, indent=2)
            self.report_preview.setPlainText(json_data)
    
    def generate_executive_summary(self):
        """Generate executive summary"""
        if self.analysis_results:
            insights = self.analysis_results.get('executive_insights', [])
            summary = "\n".join(insights)
            self.report_preview.setPlainText(f"Executive Summary:\n\n{summary}")

# Global dashboard instance
huggin_dashboard = HugginDashboard()