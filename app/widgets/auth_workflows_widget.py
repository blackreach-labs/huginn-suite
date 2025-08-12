# app/widgets/auth_workflows_widget.py
import json
import time
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                            QLabel, QTextEdit, QTableWidget, QTableWidgetItem,
                            QTabWidget, QGroupBox, QLineEdit, QComboBox,
                            QSplitter, QTreeWidget, QTreeWidgetItem, QProgressBar,
                            QCheckBox, QSpinBox, QFileDialog, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor

from app.core.auth_flow_recorder import AuthFlowRecorder
from app.core.auth_state_model import AuthStateModel
from app.core.auth_replay_engine import AuthReplayEngine
from app.core.auth_token_analyzer import AuthTokenAnalyzer
from app.core.proxy_engine import ProxyEngine

class AuthWorkflowsWidget(QWidget):
    """Main widget for authentication workflow analysis"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        
        # Core components
        self.flow_recorder = AuthFlowRecorder()
        self.state_model = AuthStateModel()
        self.replay_engine = AuthReplayEngine()
        self.token_analyzer = AuthTokenAnalyzer()
        
        # Get proxy engine from main window
        self.proxy_engine = getattr(parent, 'proxy_engine', None)
        if not self.proxy_engine:
            self.proxy_engine = ProxyEngine()
        
        # State
        self.current_session = None
        self.recorded_flows = {}
        self.active_tests = {}
        
        self.setup_ui()
        self.connect_signals()
        self.apply_theme()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        
        # Header
        header = self.create_header()
        layout.addWidget(header)
        
        # Main content tabs
        self.tab_widget = QTabWidget()
        
        # Flow Recording Tab
        self.recording_tab = self.create_recording_tab()
        self.tab_widget.addTab(self.recording_tab, "🎯 Flow Recording")
        
        # State Model Tab
        self.model_tab = self.create_model_tab()
        self.tab_widget.addTab(self.model_tab, "🧩 State Model")
        
        # Replay & Testing Tab
        self.testing_tab = self.create_testing_tab()
        self.tab_widget.addTab(self.testing_tab, "⚡ Replay & Testing")
        
        # Token Analysis Tab
        self.token_tab = self.create_token_tab()
        self.tab_widget.addTab(self.token_tab, "🔐 Token Analysis")
        
        # Results Tab
        self.results_tab = self.create_results_tab()
        self.tab_widget.addTab(self.results_tab, "📊 Results")
        
        layout.addWidget(self.tab_widget)
    
    def create_header(self):
        """Create header with title and controls"""
        header = QGroupBox("Auth Workflows - Capture, Model & Test Authentication Flows")
        layout = QHBoxLayout(header)
        
        # Status indicator
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #64C8FF; font-weight: bold;")
        
        # Proxy status
        self.proxy_status = QLabel("Proxy: Disconnected")
        self.proxy_status.setStyleSheet("color: #FF6B6B;")
        
        layout.addWidget(self.status_label)
        layout.addStretch()
        layout.addWidget(self.proxy_status)
        
        return header
    
    def create_recording_tab(self):
        """Create flow recording tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Recording controls
        controls = QGroupBox("Recording Controls")
        controls_layout = QHBoxLayout(controls)
        
        self.session_name_input = QLineEdit()
        self.session_name_input.setPlaceholderText("Session name (optional)")
        
        self.start_recording_btn = QPushButton("🔴 Start Recording")
        self.start_recording_btn.clicked.connect(self.start_recording)
        
        self.stop_recording_btn = QPushButton("⏹️ Stop Recording")
        self.stop_recording_btn.clicked.connect(self.stop_recording)
        self.stop_recording_btn.setEnabled(False)
        
        controls_layout.addWidget(QLabel("Session Name:"))
        controls_layout.addWidget(self.session_name_input)
        controls_layout.addWidget(self.start_recording_btn)
        controls_layout.addWidget(self.stop_recording_btn)
        controls_layout.addStretch()
        
        layout.addWidget(controls)
        
        # Recorded flows list
        flows_group = QGroupBox("Recorded Flows")
        flows_layout = QVBoxLayout(flows_group)
        
        self.flows_table = QTableWidget()
        self.flows_table.setColumnCount(5)
        self.flows_table.setHorizontalHeaderLabels(["Session", "Requests", "Duration", "Tokens", "Actions"])
        self.flows_table.horizontalHeader().setStretchLastSection(True)
        
        flows_layout.addWidget(self.flows_table)
        
        # Flow actions
        flow_actions = QHBoxLayout()
        
        self.analyze_flow_btn = QPushButton("📊 Analyze Flow")
        self.analyze_flow_btn.clicked.connect(self.analyze_selected_flow)
        
        self.export_flow_btn = QPushButton("💾 Export Flow")
        self.export_flow_btn.clicked.connect(self.export_flow)
        
        self.import_flow_btn = QPushButton("📁 Import Flow")
        self.import_flow_btn.clicked.connect(self.import_flow)
        
        flow_actions.addWidget(self.analyze_flow_btn)
        flow_actions.addWidget(self.export_flow_btn)
        flow_actions.addWidget(self.import_flow_btn)
        flow_actions.addStretch()
        
        flows_layout.addLayout(flow_actions)
        layout.addWidget(flows_group)
        
        # Live request feed
        feed_group = QGroupBox("Live Request Feed")
        feed_layout = QVBoxLayout(feed_group)
        
        self.request_feed = QTextEdit()
        self.request_feed.setMaximumHeight(200)
        self.request_feed.setReadOnly(True)
        
        feed_layout.addWidget(self.request_feed)
        layout.addWidget(feed_group)
        
        return tab
    
    def create_model_tab(self):
        """Create state model visualization tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Model controls
        controls = QGroupBox("Model Controls")
        controls_layout = QHBoxLayout(controls)
        
        self.flow_selector = QComboBox()
        self.flow_selector.currentTextChanged.connect(self.load_flow_model)
        
        self.build_model_btn = QPushButton("🏗️ Build Model")
        self.build_model_btn.clicked.connect(self.build_state_model)
        
        self.export_model_btn = QPushButton("💾 Export Model")
        self.export_model_btn.clicked.connect(self.export_model)
        
        controls_layout.addWidget(QLabel("Flow:"))
        controls_layout.addWidget(self.flow_selector)
        controls_layout.addWidget(self.build_model_btn)
        controls_layout.addWidget(self.export_model_btn)
        controls_layout.addStretch()
        
        layout.addWidget(controls)
        
        # Model visualization
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Flow graph (simplified text representation)
        graph_group = QGroupBox("Flow Graph")
        graph_layout = QVBoxLayout(graph_group)
        
        self.flow_graph = QTreeWidget()
        self.flow_graph.setHeaderLabels(["Node", "Type", "Auth Required", "Parameters"])
        
        graph_layout.addWidget(self.flow_graph)
        splitter.addWidget(graph_group)
        
        # Node details
        details_group = QGroupBox("Node Details")
        details_layout = QVBoxLayout(details_group)
        
        self.node_details = QTextEdit()
        self.node_details.setReadOnly(True)
        
        details_layout.addWidget(self.node_details)
        splitter.addWidget(details_group)
        
        layout.addWidget(splitter)
        
        # Security issues
        issues_group = QGroupBox("Security Issues")
        issues_layout = QVBoxLayout(issues_group)
        
        self.security_issues = QTableWidget()
        self.security_issues.setColumnCount(4)
        self.security_issues.setHorizontalHeaderLabels(["Type", "Severity", "Node", "Description"])
        self.security_issues.setMaximumHeight(150)
        
        issues_layout.addWidget(self.security_issues)
        layout.addWidget(issues_group)
        
        return tab
    
    def create_testing_tab(self):
        """Create replay and testing tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Test controls
        controls = QGroupBox("Test Controls")
        controls_layout = QVBoxLayout(controls)
        
        # Flow selection and basic controls
        flow_controls = QHBoxLayout()
        
        self.test_flow_selector = QComboBox()
        
        self.replay_btn = QPushButton("▶️ Basic Replay")
        self.replay_btn.clicked.connect(self.replay_flow)
        
        self.security_test_btn = QPushButton("🔒 Security Tests")
        self.security_test_btn.clicked.connect(self.run_security_tests)
        
        flow_controls.addWidget(QLabel("Flow:"))
        flow_controls.addWidget(self.test_flow_selector)
        flow_controls.addWidget(self.replay_btn)
        flow_controls.addWidget(self.security_test_btn)
        flow_controls.addStretch()
        
        controls_layout.addLayout(flow_controls)
        
        # Mutation options
        mutations_group = QGroupBox("Mutation Tests")
        mutations_layout = QHBoxLayout(mutations_group)
        
        self.remove_token_cb = QCheckBox("Remove Tokens")
        self.remove_state_cb = QCheckBox("Remove State")
        self.modify_redirect_cb = QCheckBox("Modify Redirect URI")
        self.remove_csrf_cb = QCheckBox("Remove CSRF")
        self.privilege_escalation_cb = QCheckBox("Privilege Escalation")
        
        self.run_mutations_btn = QPushButton("🧪 Run Selected Mutations")
        self.run_mutations_btn.clicked.connect(self.run_mutation_tests)
        
        mutations_layout.addWidget(self.remove_token_cb)
        mutations_layout.addWidget(self.remove_state_cb)
        mutations_layout.addWidget(self.modify_redirect_cb)
        mutations_layout.addWidget(self.remove_csrf_cb)
        mutations_layout.addWidget(self.privilege_escalation_cb)
        mutations_layout.addWidget(self.run_mutations_btn)
        
        controls_layout.addWidget(mutations_group)
        layout.addWidget(controls)
        
        # Test results
        results_group = QGroupBox("Test Results")
        results_layout = QVBoxLayout(results_group)
        
        self.test_results = QTextEdit()
        self.test_results.setReadOnly(True)
        
        results_layout.addWidget(self.test_results)
        layout.addWidget(results_group)
        
        return tab
    
    def create_token_tab(self):
        """Create token analysis tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Token controls
        controls = QGroupBox("Token Analysis")
        controls_layout = QHBoxLayout(controls)
        
        self.token_flow_selector = QComboBox()
        
        self.analyze_tokens_btn = QPushButton("🔍 Analyze Tokens")
        self.analyze_tokens_btn.clicked.connect(self.analyze_flow_tokens)
        
        controls_layout.addWidget(QLabel("Flow:"))
        controls_layout.addWidget(self.token_flow_selector)
        controls_layout.addWidget(self.analyze_tokens_btn)
        controls_layout.addStretch()
        
        layout.addWidget(controls)
        
        # Token list
        tokens_group = QGroupBox("Discovered Tokens")
        tokens_layout = QVBoxLayout(tokens_group)
        
        self.tokens_table = QTableWidget()
        self.tokens_table.setColumnCount(6)
        self.tokens_table.setHorizontalHeaderLabels(["Name", "Type", "Length", "Entropy", "Vulnerabilities", "Actions"])
        self.tokens_table.itemSelectionChanged.connect(self.show_token_details)
        
        tokens_layout.addWidget(self.tokens_table)
        layout.addWidget(tokens_group)
        
        # Token details
        details_group = QGroupBox("Token Details")
        details_layout = QVBoxLayout(details_group)
        
        self.token_details = QTextEdit()
        self.token_details.setReadOnly(True)
        
        details_layout.addWidget(self.token_details)
        layout.addWidget(details_group)
        
        return tab
    
    def create_results_tab(self):
        """Create results summary tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Summary stats
        stats_group = QGroupBox("Summary Statistics")
        stats_layout = QHBoxLayout(stats_group)
        
        self.flows_count_label = QLabel("Flows: 0")
        self.tokens_count_label = QLabel("Tokens: 0")
        self.vulns_count_label = QLabel("Vulnerabilities: 0")
        self.tests_count_label = QLabel("Tests: 0")
        
        stats_layout.addWidget(self.flows_count_label)
        stats_layout.addWidget(self.tokens_count_label)
        stats_layout.addWidget(self.vulns_count_label)
        stats_layout.addWidget(self.tests_count_label)
        stats_layout.addStretch()
        
        layout.addWidget(stats_group)
        
        # Vulnerabilities summary
        vulns_group = QGroupBox("Vulnerabilities Found")
        vulns_layout = QVBoxLayout(vulns_group)
        
        self.vulnerabilities_table = QTableWidget()
        self.vulnerabilities_table.setColumnCount(5)
        self.vulnerabilities_table.setHorizontalHeaderLabels(["Type", "Severity", "Source", "Description", "Recommendation"])
        
        vulns_layout.addWidget(self.vulnerabilities_table)
        layout.addWidget(vulns_group)
        
        # Export options
        export_group = QGroupBox("Export Results")
        export_layout = QHBoxLayout(export_group)
        
        self.export_json_btn = QPushButton("📄 Export JSON")
        self.export_json_btn.clicked.connect(self.export_results_json)
        
        self.export_html_btn = QPushButton("🌐 Export HTML Report")
        self.export_html_btn.clicked.connect(self.export_results_html)
        
        export_layout.addWidget(self.export_json_btn)
        export_layout.addWidget(self.export_html_btn)
        export_layout.addStretch()
        
        layout.addWidget(export_group)
        
        return tab
    
    def connect_signals(self):
        """Connect signals from core components"""
        # Flow recorder signals
        self.flow_recorder.session_started.connect(self.on_session_started)
        self.flow_recorder.session_ended.connect(self.on_session_ended)
        self.flow_recorder.flow_recorded.connect(self.on_flow_recorded)
        
        # Replay engine signals
        self.replay_engine.replay_started.connect(self.on_replay_started)
        self.replay_engine.replay_completed.connect(self.on_replay_completed)
        self.replay_engine.vulnerability_found.connect(self.on_vulnerability_found)
        
        # Token analyzer signals
        self.token_analyzer.token_analyzed.connect(self.on_token_analyzed)
        self.token_analyzer.vulnerability_found.connect(self.on_vulnerability_found)
        
        # Proxy engine signals (if available)
        if self.proxy_engine:
            self.proxy_engine.request_logged.connect(self.on_request_logged)
            self.proxy_engine.response_received.connect(self.on_response_received)
            self.proxy_engine.proxy_started.connect(self.on_proxy_started)
            self.proxy_engine.proxy_stopped.connect(self.on_proxy_stopped)
    
    def start_recording(self):
        """Start recording authentication flow"""
        session_name = self.session_name_input.text().strip()
        session_id = self.flow_recorder.start_recording(session_name)
        
        self.current_session = session_id
        self.start_recording_btn.setEnabled(False)
        self.stop_recording_btn.setEnabled(True)
        self.status_label.setText(f"Recording: {session_id}")
        self.status_label.setStyleSheet("color: #FF6B6B; font-weight: bold;")
        
        # Start proxy if not running
        if self.proxy_engine and not hasattr(self.proxy_engine, 'master'):
            self.proxy_engine.start_proxy(8080)
    
    def stop_recording(self):
        """Stop recording authentication flow"""
        flow_data = self.flow_recorder.stop_recording()
        
        self.current_session = None
        self.start_recording_btn.setEnabled(True)
        self.stop_recording_btn.setEnabled(False)
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("color: #64C8FF; font-weight: bold;")
        
        if flow_data:
            self.recorded_flows[flow_data['session_id']] = flow_data
            self.update_flows_table()
            self.update_flow_selectors()
    
    def on_request_logged(self, http_request):
        """Handle logged HTTP request"""
        if self.flow_recorder.recording:
            # Add to request feed
            self.request_feed.append(f"[{time.strftime('%H:%M:%S')}] {http_request.method} {http_request.url}")
            
            # Scroll to bottom
            scrollbar = self.request_feed.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
    
    def on_response_received(self, http_response):
        """Handle HTTP response"""
        if self.flow_recorder.recording and http_response.request:
            self.flow_recorder.process_request(http_response.request, http_response)
    
    def on_session_started(self, session_id):
        """Handle session started"""
        self.request_feed.append(f"\n=== Started recording session: {session_id} ===")
    
    def on_session_ended(self, session_id):
        """Handle session ended"""
        self.request_feed.append(f"\n=== Ended recording session: {session_id} ===")
    
    def on_flow_recorded(self, flow_data):
        """Handle flow recorded"""
        session_id = flow_data['session_id']
        request_count = len(flow_data.get('requests', []))
        token_count = len(flow_data.get('tokens', {}))
        
        self.request_feed.append(f"Flow recorded: {request_count} requests, {token_count} tokens")
    
    def update_flows_table(self):
        """Update the flows table"""
        self.flows_table.setRowCount(len(self.recorded_flows))
        
        for row, (session_id, flow_data) in enumerate(self.recorded_flows.items()):
            self.flows_table.setItem(row, 0, QTableWidgetItem(session_id))
            self.flows_table.setItem(row, 1, QTableWidgetItem(str(len(flow_data.get('requests', [])))))
            
            duration = flow_data.get('duration', 0)
            self.flows_table.setItem(row, 2, QTableWidgetItem(f"{duration:.1f}s"))
            
            self.flows_table.setItem(row, 3, QTableWidgetItem(str(len(flow_data.get('tokens', {})))))
            
            # Actions column with buttons would be more complex in real implementation
            self.flows_table.setItem(row, 4, QTableWidgetItem("View | Delete"))
    
    def update_flow_selectors(self):
        """Update flow selector comboboxes"""
        flow_names = list(self.recorded_flows.keys())
        
        self.flow_selector.clear()
        self.flow_selector.addItems(flow_names)
        
        self.test_flow_selector.clear()
        self.test_flow_selector.addItems(flow_names)
        
        self.token_flow_selector.clear()
        self.token_flow_selector.addItems(flow_names)
    
    def analyze_selected_flow(self):
        """Analyze the selected flow"""
        current_row = self.flows_table.currentRow()
        if current_row >= 0:
            session_id = self.flows_table.item(current_row, 0).text()
            self.tab_widget.setCurrentIndex(1)  # Switch to model tab
            self.flow_selector.setCurrentText(session_id)
            self.build_state_model()
    
    def build_state_model(self):
        """Build state model for selected flow"""
        flow_name = self.flow_selector.currentText()
        if flow_name in self.recorded_flows:
            flow_data = self.recorded_flows[flow_name]
            self.state_model.build_model(flow_data)
            self.update_flow_graph()
            self.update_security_issues()
    
    def load_flow_model(self):
        """Load flow model when selector changes"""
        pass  # Placeholder for future implementation
    
    def update_flow_graph(self):
        """Update the flow graph display"""
        self.flow_graph.clear()
        
        for node_id, node in self.state_model.nodes.items():
            item = QTreeWidgetItem([
                f"{node.method} {node.endpoint}",
                node.node_type,
                "Yes" if node.requires_auth else "No",
                ", ".join(node.parameters.keys())[:50]
            ])
            
            # Color code based on node type
            color = QColor(self.state_model._get_node_color(node))
            item.setBackground(0, color)
            
            self.flow_graph.addTopLevelItem(item)
    
    def update_security_issues(self):
        """Update security issues table"""
        issues = self.state_model.find_security_issues()
        self.security_issues.setRowCount(len(issues))
        
        for row, issue in enumerate(issues):
            self.security_issues.setItem(row, 0, QTableWidgetItem(issue['type']))
            self.security_issues.setItem(row, 1, QTableWidgetItem(issue['severity']))
            self.security_issues.setItem(row, 2, QTableWidgetItem(issue.get('node_id', '')))
            self.security_issues.setItem(row, 3, QTableWidgetItem(issue['description']))
    
    def replay_flow(self):
        """Replay selected flow"""
        flow_name = self.test_flow_selector.currentText()
        if flow_name in self.recorded_flows:
            flow_data = self.recorded_flows[flow_name]
            test_id = self.replay_engine.replay_flow(flow_data, "basic_replay")
            self.test_results.append(f"Started basic replay: {test_id}")
    
    def run_security_tests(self):
        """Run security tests on selected flow"""
        flow_name = self.test_flow_selector.currentText()
        if flow_name in self.recorded_flows:
            flow_data = self.recorded_flows[flow_name]
            test_id = self.replay_engine.run_security_tests(flow_data)
            self.test_results.append(f"Started security tests: {test_id}")
    
    def run_mutation_tests(self):
        """Run selected mutation tests"""
        flow_name = self.test_flow_selector.currentText()
        if flow_name in self.recorded_flows:
            mutations = []
            
            if self.remove_token_cb.isChecked():
                mutations.append('remove_token')
            if self.remove_state_cb.isChecked():
                mutations.append('remove_state')
            if self.modify_redirect_cb.isChecked():
                mutations.append('modify_redirect_uri')
            if self.remove_csrf_cb.isChecked():
                mutations.append('remove_csrf')
            if self.privilege_escalation_cb.isChecked():
                mutations.append('privilege_escalation')
            
            if mutations:
                flow_data = self.recorded_flows[flow_name]
                test_id = self.replay_engine.test_mutations(flow_data, mutations)
                self.test_results.append(f"Started mutation tests: {test_id} ({', '.join(mutations)})")
    
    def analyze_flow_tokens(self):
        """Analyze tokens in selected flow"""
        flow_name = self.token_flow_selector.currentText()
        if flow_name in self.recorded_flows:
            flow_data = self.recorded_flows[flow_name]
            tokens = flow_data.get('tokens', {})
            
            if tokens:
                analysis = self.token_analyzer.analyze_multiple_tokens(tokens)
                self.update_tokens_table(analysis)
                self.token_details.setText(self.token_analyzer.generate_token_report(analysis))
            else:
                self.token_details.setText("No tokens found in this flow.")
    
    def update_tokens_table(self, analysis):
        """Update tokens table with analysis results"""
        individual_analyses = analysis['individual_analyses']
        self.tokens_table.setRowCount(len(individual_analyses))
        
        for row, (token_name, token_analysis) in enumerate(individual_analyses.items()):
            self.tokens_table.setItem(row, 0, QTableWidgetItem(token_name))
            self.tokens_table.setItem(row, 1, QTableWidgetItem(token_analysis['type']))
            self.tokens_table.setItem(row, 2, QTableWidgetItem(str(token_analysis['length'])))
            self.tokens_table.setItem(row, 3, QTableWidgetItem(f"{token_analysis['entropy']:.2f}"))
            self.tokens_table.setItem(row, 4, QTableWidgetItem(str(len(token_analysis['vulnerabilities']))))
            self.tokens_table.setItem(row, 5, QTableWidgetItem("View Details"))
    
    def show_token_details(self):
        """Show details for selected token"""
        current_row = self.tokens_table.currentRow()
        if current_row >= 0:
            token_name = self.tokens_table.item(current_row, 0).text()
            # Would show detailed token analysis here
            self.token_details.append(f"\nSelected token: {token_name}")
    
    def on_replay_started(self, test_id):
        """Handle replay started"""
        self.test_results.append(f"Test started: {test_id}")
    
    def on_replay_completed(self, test_id, results):
        """Handle replay completed"""
        success_rate = (results['successful_requests'] / results['requests_sent']) * 100 if results['requests_sent'] > 0 else 0
        self.test_results.append(f"Test completed: {test_id} - {success_rate:.1f}% success rate")
        
        if results.get('vulnerabilities'):
            self.test_results.append(f"  Found {len(results['vulnerabilities'])} vulnerabilities")
    
    def on_vulnerability_found(self, test_id, vuln_info):
        """Handle vulnerability found"""
        self.test_results.append(f"🚨 VULNERABILITY: {vuln_info['type']} - {vuln_info['description']}")
    
    def on_token_analyzed(self, analysis):
        """Handle token analyzed"""
        pass  # Already handled in analyze_flow_tokens
    
    def on_proxy_started(self, port):
        """Handle proxy started"""
        self.proxy_status.setText(f"Proxy: Running on port {port}")
        self.proxy_status.setStyleSheet("color: #4ECDC4;")
    
    def on_proxy_stopped(self):
        """Handle proxy stopped"""
        self.proxy_status.setText("Proxy: Disconnected")
        self.proxy_status.setStyleSheet("color: #FF6B6B;")
    
    def export_flow(self):
        """Export selected flow to JSON"""
        current_row = self.flows_table.currentRow()
        if current_row >= 0:
            session_id = self.flows_table.item(current_row, 0).text()
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Flow", f"{session_id}.json", "JSON Files (*.json)"
            )
            
            if filename:
                self.flow_recorder.export_flow(session_id, filename)
                QMessageBox.information(self, "Export Complete", f"Flow exported to {filename}")
    
    def import_flow(self):
        """Import flow from JSON file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Import Flow", "", "JSON Files (*.json)"
        )
        
        if filename:
            session_id = self.flow_recorder.import_flow(filename)
            if session_id:
                flow_data = self.flow_recorder.get_flow_data(session_id)
                self.recorded_flows[session_id] = flow_data
                self.update_flows_table()
                self.update_flow_selectors()
                QMessageBox.information(self, "Import Complete", f"Flow imported as {session_id}")
            else:
                QMessageBox.warning(self, "Import Failed", "Failed to import flow")
    
    def export_model(self):
        """Export state model"""
        if self.state_model.nodes:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Model", "auth_model.json", "JSON Files (*.json)"
            )
            
            if filename:
                self.state_model.export_model(filename)
                QMessageBox.information(self, "Export Complete", f"Model exported to {filename}")
    
    def export_results_json(self):
        """Export all results to JSON"""
        results = {
            'flows': self.recorded_flows,
            'timestamp': time.time(),
            'summary': {
                'total_flows': len(self.recorded_flows),
                'total_tokens': sum(len(flow.get('tokens', {})) for flow in self.recorded_flows.values()),
                'total_requests': sum(len(flow.get('requests', [])) for flow in self.recorded_flows.values())
            }
        }
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "auth_results.json", "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            QMessageBox.information(self, "Export Complete", f"Results exported to {filename}")
    
    def export_results_html(self):
        """Export results to HTML report"""
        # Simplified HTML export - would be more comprehensive in real implementation
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Auth Workflows Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                .vulnerability {{ background: #ffebee; padding: 10px; margin: 5px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Authentication Workflows Analysis Report</h1>
                <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="section">
                <h2>Summary</h2>
                <p>Total Flows: {len(self.recorded_flows)}</p>
                <p>Total Requests: {sum(len(flow.get('requests', [])) for flow in self.recorded_flows.values())}</p>
                <p>Total Tokens: {sum(len(flow.get('tokens', {})) for flow in self.recorded_flows.values())}</p>
            </div>
            
            <div class="section">
                <h2>Recorded Flows</h2>
        """
        
        for session_id, flow_data in self.recorded_flows.items():
            html_content += f"""
                <h3>{session_id}</h3>
                <p>Requests: {len(flow_data.get('requests', []))}</p>
                <p>Duration: {flow_data.get('duration', 0):.1f}s</p>
                <p>Tokens: {len(flow_data.get('tokens', {}))}</p>
            """
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export HTML Report", "auth_report.html", "HTML Files (*.html)"
        )
        
        if filename:
            with open(filename, 'w') as f:
                f.write(html_content)
            QMessageBox.information(self, "Export Complete", f"HTML report exported to {filename}")
    
    def apply_theme(self):
        """Apply dark theme styling"""
        self.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: rgba(0, 0, 0, 50);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #64C8FF;
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton:pressed {
                background-color: rgba(70, 90, 110, 250);
            }
            QPushButton:disabled {
                background-color: rgba(20, 20, 20, 100);
                border: 2px solid rgba(100, 100, 100, 50);
                color: #666;
            }
            QLineEdit, QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QTextEdit {
                background-color: rgba(10, 20, 30, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                color: #DCDCDC;
                font-family: 'Courier New', monospace;
            }
            QTableWidget {
                background-color: rgba(10, 20, 30, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                color: #DCDCDC;
                gridline-color: rgba(100, 200, 255, 50);
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 100);
            }
            QTreeWidget {
                background-color: rgba(10, 20, 30, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                color: #DCDCDC;
            }
            QTabWidget::pane {
                border: 1px solid rgba(100, 200, 255, 50);
                background-color: rgba(0, 0, 0, 30);
            }
            QTabBar::tab {
                background-color: rgba(30, 40, 50, 150);
                color: #DCDCDC;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: rgba(50, 70, 90, 200);
                color: #64C8FF;
            }
            QCheckBox {
                color: #DCDCDC;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 2px solid rgba(100, 200, 255, 100);
                background-color: rgba(20, 30, 40, 150);
            }
            QCheckBox::indicator:checked {
                border: 2px solid #64C8FF;
                background-color: #64C8FF;
            }
        """)