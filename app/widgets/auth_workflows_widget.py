# app/widgets/auth_workflows_widget.py
"""Enterprise-grade Auth Workflows widget.

Provides a comprehensive UI for capturing, modeling, and testing
authentication flows across all major protocols (OAuth 2.0, OIDC,
NTLM, Kerberos, SAML, FBA, certificate-based, JWT, API keys).
"""
import json
import time
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTextEdit,
    QTableWidget, QTableWidgetItem, QTabWidget, QGroupBox, QLineEdit,
    QComboBox, QSplitter, QTreeWidget, QTreeWidgetItem, QProgressBar,
    QCheckBox, QSpinBox, QFileDialog, QMessageBox, QHeaderView,
    QFrame, QScrollArea, QGridLayout,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor

from app.core.auth_flow_recorder import AuthFlowRecorder
from app.core.auth_state_model import AuthStateModel
from app.core.auth_replay_engine import AuthReplayEngine, MUTATION_CATEGORIES
from app.core.auth_token_analyzer import AuthTokenAnalyzer
from app.core.logger import logger

try:
    from app.core.proxy_engine import ProxyEngine
except ImportError:
    ProxyEngine = None


class AuthWorkflowsWidget(QWidget):
    """Main widget for authentication workflow analysis."""

    status_updated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent

        # Core engines
        self.flow_recorder = AuthFlowRecorder()
        self.state_model = AuthStateModel()
        self.replay_engine = AuthReplayEngine()
        self.token_analyzer = AuthTokenAnalyzer()

        # Proxy engine (shared with HTTP Interceptor if available)
        self.proxy_engine = None
        self._request_handler = None
        self._resolve_proxy_engine()

        # State
        self.current_session = None
        self.recorded_flows: dict = {}
        self.active_tests: dict = {}
        self.proxy_running = False

        self.setup_ui()
        self.connect_signals()
        self.apply_theme()

    def _resolve_proxy_engine(self):
        """Resolve the shared proxy engine from the HTTP Interceptor/CurlWidget."""
        # Try to get from main window's existing CurlWidget (shared instance)
        if self.main_window:
            # Look for CurlWidget in the page stack
            stack = getattr(self.main_window, 'stack', None)
            if stack:
                for i in range(stack.count()):
                    page = stack.widget(i)
                    # WebExploitsPage contains CurlWidget via HttpInterceptorComponent
                    curl = self._find_curl_widget(page)
                    if curl and hasattr(curl, 'request_handler'):
                        self._request_handler = curl.request_handler
                        self.proxy_engine = curl.request_handler.proxy_engine
                        return

        # Fallback: create own UnifiedRequestHandler (shares proxy with nothing)
        try:
            from app.core.unified_request_handler import UnifiedRequestHandler
            self._request_handler = UnifiedRequestHandler()
            self.proxy_engine = self._request_handler.proxy_engine
        except Exception:
            self.proxy_engine = None

    def _find_curl_widget(self, widget):
        """Recursively search for a CurlWidget instance."""
        try:
            from app.widgets.curl_widget import CurlWidget
        except ImportError:
            return None
        if isinstance(widget, CurlWidget):
            return widget
        # Check direct children
        for child in (widget.findChildren(QWidget) if widget else []):
            if isinstance(child, CurlWidget):
                return child
        return None

    # ──────────────────────────────────────────────────────────────────────
    # UI Setup
    # ──────────────────────────────────────────────────────────────────────

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(6)
        layout.setContentsMargins(4, 4, 4, 4)

        # Header
        header = self._create_header()
        layout.addWidget(header)

        # Main tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.addTab(self._create_recording_tab(), "🎯 Flow Recording")
        self.tab_widget.addTab(self._create_model_tab(), "🧩 State Model")
        self.tab_widget.addTab(self._create_testing_tab(), "⚡ Replay && Testing")
        self.tab_widget.addTab(self._create_token_tab(), "🔐 Token Analysis")
        self.tab_widget.addTab(self._create_results_tab(), "📊 Results")
        layout.addWidget(self.tab_widget)

    def _create_header(self):
        header = QGroupBox("Auth Workflows - Capture, Model && Test Authentication Flows")
        layout = QHBoxLayout(header)
        self.status_label = QLabel("Ready")
        self.proxy_status = QLabel("Proxy: Disconnected")
        self.protocol_label = QLabel("Protocols: —")

        self.proxy_toggle_btn = QPushButton("Start Proxy")
        self.proxy_toggle_btn.clicked.connect(self.toggle_proxy)

        layout.addWidget(self.status_label)
        layout.addWidget(self.protocol_label)
        layout.addStretch()
        layout.addWidget(self.proxy_status)
        layout.addWidget(self.proxy_toggle_btn)
        return header

    # ──── Recording Tab ───────────────────────────────────────────────────

    def _create_recording_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Controls
        controls = QGroupBox("Recording Controls")
        cl = QHBoxLayout(controls)
        self.session_name_input = QLineEdit()
        self.session_name_input.setPlaceholderText("Session name (optional)")
        self.start_recording_btn = QPushButton("🔴 Start Recording")
        self.start_recording_btn.clicked.connect(self.start_recording)
        self.stop_recording_btn = QPushButton("⏹️ Stop Recording")
        self.stop_recording_btn.clicked.connect(self.stop_recording)
        self.stop_recording_btn.setEnabled(False)
        cl.addWidget(QLabel("Session:"))
        cl.addWidget(self.session_name_input)
        cl.addWidget(self.start_recording_btn)
        cl.addWidget(self.stop_recording_btn)
        cl.addStretch()
        layout.addWidget(controls)

        # Flows table
        flows_group = QGroupBox("Recorded Flows")
        fl = QVBoxLayout(flows_group)
        self.flows_table = QTableWidget()
        self.flows_table.setColumnCount(6)
        self.flows_table.setHorizontalHeaderLabels(
            ["Session", "Requests", "Protocols", "Tokens", "Duration", "Actions"])
        self.flows_table.horizontalHeader().setStretchLastSection(True)
        self.flows_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        fl.addWidget(self.flows_table)

        # Flow action buttons
        btn_row = QHBoxLayout()
        self.analyze_flow_btn = QPushButton("📊 Analyze Flow")
        self.analyze_flow_btn.clicked.connect(self.analyze_selected_flow)
        self.export_flow_btn = QPushButton("💾 Export")
        self.export_flow_btn.clicked.connect(self.export_flow)
        self.import_flow_btn = QPushButton("📁 Import")
        self.import_flow_btn.clicked.connect(self.import_flow)
        self.delete_flow_btn = QPushButton("🗑️ Delete")
        self.delete_flow_btn.clicked.connect(self.delete_selected_flow)
        btn_row.addWidget(self.analyze_flow_btn)
        btn_row.addWidget(self.export_flow_btn)
        btn_row.addWidget(self.import_flow_btn)
        btn_row.addWidget(self.delete_flow_btn)
        btn_row.addStretch()
        fl.addLayout(btn_row)
        layout.addWidget(flows_group)

        # Live feed
        feed_group = QGroupBox("Live Request Feed")
        feed_l = QVBoxLayout(feed_group)
        self.request_feed = QTextEdit()
        self.request_feed.setMaximumHeight(180)
        self.request_feed.setReadOnly(True)
        feed_l.addWidget(self.request_feed)
        layout.addWidget(feed_group)

        return tab

    # ──── State Model Tab ─────────────────────────────────────────────────

    def _create_model_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Controls
        controls = QGroupBox("Model Controls")
        cl = QHBoxLayout(controls)
        self.flow_selector = QComboBox()
        self.flow_selector.setMinimumWidth(200)
        self.build_model_btn = QPushButton("🏗️ Build Model")
        self.build_model_btn.clicked.connect(self.build_state_model)
        self.export_model_btn = QPushButton("💾 Export Model")
        self.export_model_btn.clicked.connect(self.export_model)
        cl.addWidget(QLabel("Flow:"))
        cl.addWidget(self.flow_selector)
        cl.addWidget(self.build_model_btn)
        cl.addWidget(self.export_model_btn)
        cl.addStretch()
        layout.addWidget(controls)

        # Splitter: Flow graph + Details
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Flow graph
        graph_group = QGroupBox("Flow Graph")
        gl = QVBoxLayout(graph_group)
        self.flow_graph = QTreeWidget()
        self.flow_graph.setHeaderLabels(["Node", "Type", "Protocol", "Auth Required"])
        self.flow_graph.setColumnCount(4)
        self.flow_graph.itemClicked.connect(self.on_node_clicked)
        gl.addWidget(self.flow_graph)
        splitter.addWidget(graph_group)

        # Node details
        details_group = QGroupBox("Node Details")
        dl = QVBoxLayout(details_group)
        self.node_details = QTextEdit()
        self.node_details.setReadOnly(True)
        dl.addWidget(self.node_details)
        splitter.addWidget(details_group)
        splitter.setSizes([400, 300])

        layout.addWidget(splitter)

        # Security issues table
        issues_group = QGroupBox("Security Issues")
        il = QVBoxLayout(issues_group)
        self.security_issues_table = QTableWidget()
        self.security_issues_table.setColumnCount(6)
        self.security_issues_table.setHorizontalHeaderLabels(
            ["ID", "Severity", "Protocol", "Type", "Description", "CWE"])
        self.security_issues_table.horizontalHeader().setStretchLastSection(True)
        self.security_issues_table.setMaximumHeight(200)
        il.addWidget(self.security_issues_table)
        layout.addWidget(issues_group)

        return tab

    # ──── Replay & Testing Tab ────────────────────────────────────────────

    def _create_testing_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Flow selection and quick actions
        top_controls = QGroupBox("Test Configuration")
        tc_layout = QVBoxLayout(top_controls)

        row1 = QHBoxLayout()
        self.test_flow_selector = QComboBox()
        self.test_flow_selector.setMinimumWidth(200)
        self.replay_btn = QPushButton("▶️ Baseline Replay")
        self.replay_btn.clicked.connect(self.replay_flow)
        self.auto_test_btn = QPushButton("🔒 Auto Security Test")
        self.auto_test_btn.clicked.connect(self.run_auto_security_test)
        self.full_audit_btn = QPushButton("🛡️ Full Audit (All Mutations)")
        self.full_audit_btn.clicked.connect(self.run_full_audit)
        row1.addWidget(QLabel("Flow:"))
        row1.addWidget(self.test_flow_selector)
        row1.addWidget(self.replay_btn)
        row1.addWidget(self.auto_test_btn)
        row1.addWidget(self.full_audit_btn)
        row1.addStretch()
        tc_layout.addLayout(row1)

        # Protocol-specific mutation checkboxes
        mutations_group = QGroupBox("Protocol-Specific Mutations")
        mg_layout = QGridLayout(mutations_group)

        self.mutation_checkboxes: dict = {}
        col = 0
        row = 0
        for category, mutations in MUTATION_CATEGORIES.items():
            # Category label
            cat_label = QLabel(f"━ {category.upper()} ━")
            mg_layout.addWidget(cat_label, row, col * 2, 1, 2)
            row += 1
            for mutation in mutations:
                cb = QCheckBox(mutation.replace('_', ' ').title())
                cb.setObjectName(mutation)
                self.mutation_checkboxes[mutation] = cb
                mg_layout.addWidget(cb, row, col * 2, 1, 2)
                row += 1
            col += 1
            row = 0
            if col > 3:
                col = 0
                row = max(mg_layout.rowCount(), row)

        tc_layout.addWidget(mutations_group)

        # Run selected mutations button
        run_row = QHBoxLayout()
        self.run_selected_btn = QPushButton("🧪 Run Selected Mutations")
        self.run_selected_btn.clicked.connect(self.run_selected_mutations)
        self.select_all_btn = QPushButton("Select All")
        self.select_all_btn.clicked.connect(self._select_all_mutations)
        self.clear_all_btn = QPushButton("Clear All")
        self.clear_all_btn.clicked.connect(self._clear_all_mutations)
        run_row.addWidget(self.run_selected_btn)
        run_row.addWidget(self.select_all_btn)
        run_row.addWidget(self.clear_all_btn)
        run_row.addStretch()
        tc_layout.addLayout(run_row)

        layout.addWidget(top_controls)

        # Progress
        self.test_progress = QProgressBar()
        self.test_progress.setMaximumHeight(20)
        self.test_progress.setVisible(False)
        layout.addWidget(self.test_progress)

        # Test results output
        results_group = QGroupBox("Test Results")
        rl = QVBoxLayout(results_group)
        self.test_results = QTextEdit()
        self.test_results.setReadOnly(True)
        rl.addWidget(self.test_results)
        layout.addWidget(results_group)

        return tab

    # ──── Token Analysis Tab ──────────────────────────────────────────────

    def _create_token_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Controls
        controls = QGroupBox("Token Analysis")
        cl = QHBoxLayout(controls)
        self.token_flow_selector = QComboBox()
        self.token_flow_selector.setMinimumWidth(200)
        self.analyze_tokens_btn = QPushButton("🔍 Analyze Tokens")
        self.analyze_tokens_btn.clicked.connect(self.analyze_flow_tokens)
        cl.addWidget(QLabel("Flow:"))
        cl.addWidget(self.token_flow_selector)
        cl.addWidget(self.analyze_tokens_btn)
        cl.addStretch()
        layout.addWidget(controls)

        # Token table
        tokens_group = QGroupBox("Discovered Tokens")
        tl = QVBoxLayout(tokens_group)
        self.tokens_table = QTableWidget()
        self.tokens_table.setColumnCount(7)
        self.tokens_table.setHorizontalHeaderLabels(
            ["Name", "Type", "Length", "Entropy", "Algorithm", "Vulns", "Source"])
        self.tokens_table.horizontalHeader().setStretchLastSection(True)
        self.tokens_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tokens_table.itemSelectionChanged.connect(self.show_token_details)
        tl.addWidget(self.tokens_table)
        layout.addWidget(tokens_group)

        # Token detail view
        detail_group = QGroupBox("Token Details")
        dl = QVBoxLayout(detail_group)
        self.token_details = QTextEdit()
        self.token_details.setReadOnly(True)
        dl.addWidget(self.token_details)
        layout.addWidget(detail_group)

        return tab

    # ──── Results Tab ─────────────────────────────────────────────────────

    def _create_results_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Summary stats
        stats_group = QGroupBox("Summary")
        sl = QHBoxLayout(stats_group)
        self.stat_flows = QLabel("Flows: 0")
        self.stat_tokens = QLabel("Tokens: 0")
        self.stat_vulns = QLabel("Vulnerabilities: 0")
        self.stat_critical = QLabel("Critical: 0")
        self.stat_high = QLabel("High: 0")
        self.stat_tests = QLabel("Tests Run: 0")
        sl.addWidget(self.stat_flows)
        sl.addWidget(self.stat_tokens)
        sl.addWidget(self.stat_vulns)
        sl.addWidget(self.stat_critical)
        sl.addWidget(self.stat_high)
        sl.addWidget(self.stat_tests)
        sl.addStretch()
        layout.addWidget(stats_group)

        # Vulnerabilities table
        vuln_group = QGroupBox("All Vulnerabilities")
        vl = QVBoxLayout(vuln_group)
        self.all_vulns_table = QTableWidget()
        self.all_vulns_table.setColumnCount(6)
        self.all_vulns_table.setHorizontalHeaderLabels(
            ["Severity", "Protocol", "Type", "URL", "Description", "Mutation"])
        self.all_vulns_table.horizontalHeader().setStretchLastSection(True)
        vl.addWidget(self.all_vulns_table)
        layout.addWidget(vuln_group)

        # Export
        export_group = QGroupBox("Export Results")
        el = QHBoxLayout(export_group)
        self.export_json_btn = QPushButton("📄 Export JSON")
        self.export_json_btn.clicked.connect(self.export_results_json)
        self.export_html_btn = QPushButton("🌐 Export HTML Report")
        self.export_html_btn.clicked.connect(self.export_results_html)
        el.addWidget(self.export_json_btn)
        el.addWidget(self.export_html_btn)
        el.addStretch()
        layout.addWidget(export_group)

        return tab

    # ──────────────────────────────────────────────────────────────────────
    # Signal Connections
    # ──────────────────────────────────────────────────────────────────────

    def connect_signals(self):
        # Flow recorder
        self.flow_recorder.session_started.connect(self._on_session_started)
        self.flow_recorder.session_ended.connect(self._on_session_ended)
        self.flow_recorder.flow_recorded.connect(self._on_flow_recorded)
        self.flow_recorder.protocol_detected.connect(self._on_protocol_detected)

        # Replay engine
        self.replay_engine.replay_started.connect(self._on_replay_started)
        self.replay_engine.replay_completed.connect(self._on_replay_completed)
        self.replay_engine.vulnerability_found.connect(self._on_vulnerability_found)
        self.replay_engine.progress_updated.connect(self._on_progress_updated)
        self.replay_engine.request_sent.connect(self._on_request_sent)

        # Proxy (if available)
        if self.proxy_engine:
            if hasattr(self.proxy_engine, 'proxy_started'):
                self.proxy_engine.proxy_started.connect(self._on_proxy_started)
            if hasattr(self.proxy_engine, 'proxy_stopped'):
                self.proxy_engine.proxy_stopped.connect(self._on_proxy_stopped)
            if hasattr(self.proxy_engine, 'request_logged'):
                self.proxy_engine.request_logged.connect(self._on_request_logged)
            if hasattr(self.proxy_engine, 'response_received'):
                self.proxy_engine.response_received.connect(self._on_response_received)

    # ──────────────────────────────────────────────────────────────────────
    # Recording Actions
    # ──────────────────────────────────────────────────────────────────────

    def toggle_proxy(self):
        """Start or stop the proxy server (same as HTTP Interceptor)."""
        if not self._request_handler:
            # Late-resolve in case pages were loaded after init
            self._resolve_proxy_engine()

        if not self._request_handler:
            QMessageBox.warning(self, "Proxy Unavailable",
                                "Proxy engine is not available.\nInstall mitmproxy: pip install mitmproxy")
            return

        if not self.proxy_running:
            if self._request_handler.start_proxy(8080):
                self.request_feed.append("\n[INFO] Starting proxy server on port 8080...")
            else:
                self.request_feed.append("\n[ERROR] Failed to start proxy — install mitmproxy: pip install mitmproxy")
        else:
            self._request_handler.stop_proxy()
            self.request_feed.append("\n[INFO] Stopping proxy server...")

    def start_recording(self):
        name = self.session_name_input.text().strip()
        session_id = self.flow_recorder.start_recording(name)
        self.current_session = session_id
        self.start_recording_btn.setEnabled(False)
        self.stop_recording_btn.setEnabled(True)
        self.status_label.setText(f"🔴 Recording: {session_id}")
        self.request_feed.append(f"\n═══ Started recording: {session_id} ═══")

        # Prompt user to start proxy if not running
        if not self.proxy_running:
            self.request_feed.append("[INFO] Proxy is not running — click 'Start Proxy' to capture traffic")

    def stop_recording(self):
        flow_data = self.flow_recorder.stop_recording()
        self.current_session = None
        self.start_recording_btn.setEnabled(True)
        self.stop_recording_btn.setEnabled(False)
        self.status_label.setText("Ready")

        if flow_data:
            sid = flow_data['session_id']
            self.recorded_flows[sid] = flow_data
            self._refresh_flows_table()
            self._refresh_flow_selectors()
            protocols = flow_data.get('detected_protocols', [])
            self.request_feed.append(
                f"═══ Stopped. Captured {len(flow_data.get('requests', []))} requests, "
                f"protocols: {', '.join(protocols) or 'none'} ═══\n")

    def delete_selected_flow(self):
        row = self.flows_table.currentRow()
        if row < 0:
            return
        sid = self.flows_table.item(row, 0).text()
        self.recorded_flows.pop(sid, None)
        self._refresh_flows_table()
        self._refresh_flow_selectors()

    # ──────────────────────────────────────────────────────────────────────
    # Model Actions
    # ──────────────────────────────────────────────────────────────────────

    def analyze_selected_flow(self):
        row = self.flows_table.currentRow()
        if row >= 0:
            sid = self.flows_table.item(row, 0).text()
            self.flow_selector.setCurrentText(sid)
            self.tab_widget.setCurrentIndex(1)
            self.build_state_model()

    def build_state_model(self):
        flow_name = self.flow_selector.currentText()
        if flow_name not in self.recorded_flows:
            return
        flow_data = self.recorded_flows[flow_name]
        self.state_model.build_model(flow_data)
        self._update_flow_graph()
        self._update_security_issues_table()
        self.status_updated.emit(f"Model built: {len(self.state_model.nodes)} nodes, "
                                 f"{len(self.state_model.security_issues)} issues")

    def _update_flow_graph(self):
        self.flow_graph.clear()
        for node in self.state_model.nodes.values():
            from urllib.parse import urlparse
            path = urlparse(node.url).path or '/'
            label = f"{node.method} {path}"
            item = QTreeWidgetItem([label, node.node_type, node.protocol,
                                    "Yes" if node.requires_auth else "No"])
            color = QColor(self.state_model._get_node_color(node))
            item.setBackground(0, color)
            item.setData(0, Qt.ItemDataRole.UserRole, node.id)
            self.flow_graph.addTopLevelItem(item)

    def on_node_clicked(self, item, column):
        node_id = item.data(0, Qt.ItemDataRole.UserRole)
        node = self.state_model.nodes.get(node_id)
        if not node:
            return
        from dataclasses import asdict
        details = json.dumps(asdict(node), indent=2, default=str)
        self.node_details.setText(details)

    def _update_security_issues_table(self):
        issues = self.state_model.security_issues
        self.security_issues_table.setRowCount(len(issues))
        for row, issue in enumerate(issues):
            from dataclasses import asdict
            d = asdict(issue)
            self.security_issues_table.setItem(row, 0, QTableWidgetItem(d['issue_id']))
            sev_item = QTableWidgetItem(d['severity'].upper())
            sev_colors = {'critical': '#FF4444', 'high': '#FF8C00', 'medium': '#FFD700', 'low': '#87CEEB'}
            sev_item.setForeground(QColor(sev_colors.get(d['severity'], '#DCDCDC')))
            self.security_issues_table.setItem(row, 1, sev_item)
            self.security_issues_table.setItem(row, 2, QTableWidgetItem(d['protocol']))
            self.security_issues_table.setItem(row, 3, QTableWidgetItem(d['issue_type']))
            self.security_issues_table.setItem(row, 4, QTableWidgetItem(d['description'][:100]))
            self.security_issues_table.setItem(row, 5, QTableWidgetItem(d['cwe_id']))

    def export_model(self):
        if not self.state_model.nodes:
            QMessageBox.information(self, "No Model", "Build a model first.")
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Model", "auth_model.json", "JSON Files (*.json)")
        if filename:
            self.state_model.export_model(filename)
            QMessageBox.information(self, "Exported", f"Model exported to {filename}")

    # ──────────────────────────────────────────────────────────────────────
    # Testing Actions
    # ──────────────────────────────────────────────────────────────────────

    def replay_flow(self):
        flow_name = self.test_flow_selector.currentText()
        if flow_name in self.recorded_flows:
            test_id = self.replay_engine.replay_flow(self.recorded_flows[flow_name])
            self.test_results.append(f"[{self._ts()}] Started baseline replay: {test_id}")

    def run_auto_security_test(self):
        flow_name = self.test_flow_selector.currentText()
        if flow_name in self.recorded_flows:
            test_id = self.replay_engine.run_security_tests(self.recorded_flows[flow_name])
            self.test_results.append(f"[{self._ts()}] Started auto security test: {test_id}")

    def run_full_audit(self):
        flow_name = self.test_flow_selector.currentText()
        if flow_name in self.recorded_flows:
            test_id = self.replay_engine.run_all_protocol_tests(self.recorded_flows[flow_name])
            self.test_results.append(f"[{self._ts()}] Started full audit (all mutations): {test_id}")

    def run_selected_mutations(self):
        flow_name = self.test_flow_selector.currentText()
        if flow_name not in self.recorded_flows:
            QMessageBox.warning(self, "No Flow", "Select a recorded flow first.")
            return
        selected = [name for name, cb in self.mutation_checkboxes.items() if cb.isChecked()]
        if not selected:
            QMessageBox.warning(self, "No Mutations", "Select at least one mutation to test.")
            return
        test_id = self.replay_engine.test_mutations(
            self.recorded_flows[flow_name], selected)
        self.test_results.append(
            f"[{self._ts()}] Running {len(selected)} mutations: {test_id}\n"
            f"  Mutations: {', '.join(selected)}")

    def _select_all_mutations(self):
        for cb in self.mutation_checkboxes.values():
            cb.setChecked(True)

    def _clear_all_mutations(self):
        for cb in self.mutation_checkboxes.values():
            cb.setChecked(False)

    # ──────────────────────────────────────────────────────────────────────
    # Token Analysis Actions
    # ──────────────────────────────────────────────────────────────────────

    def analyze_flow_tokens(self):
        flow_name = self.token_flow_selector.currentText()
        if flow_name not in self.recorded_flows:
            return
        flow_data = self.recorded_flows[flow_name]
        tokens = flow_data.get('tokens', {})
        if not tokens:
            self.token_details.setText("No tokens found in this flow.")
            return

        results = self.token_analyzer.analyze_multiple_tokens(tokens)
        self._update_tokens_table(results)
        report = self.token_analyzer.generate_token_report(results)
        self.token_details.setText(report)

        # Update results tab
        self._update_results_summary()

    def _update_tokens_table(self, results: dict):
        analyses = results.get('individual_analyses', {})
        self.tokens_table.setRowCount(len(analyses))
        for row, (name, a) in enumerate(analyses.items()):
            self.tokens_table.setItem(row, 0, QTableWidgetItem(name))
            self.tokens_table.setItem(row, 1, QTableWidgetItem(a.get('type', '')))
            self.tokens_table.setItem(row, 2, QTableWidgetItem(str(a.get('length', 0))))
            self.tokens_table.setItem(row, 3, QTableWidgetItem(f"{a.get('entropy', 0):.2f}"))
            alg = a.get('properties', {}).get('algorithm', '—')
            self.tokens_table.setItem(row, 4, QTableWidgetItem(str(alg)))
            vuln_count = len(a.get('vulnerabilities', []))
            vuln_item = QTableWidgetItem(str(vuln_count))
            if vuln_count > 0:
                vuln_item.setForeground(QColor('#FF4444'))
            self.tokens_table.setItem(row, 5, vuln_item)
            self.tokens_table.setItem(row, 6, QTableWidgetItem(a.get('source', '')))

    def show_token_details(self):
        row = self.tokens_table.currentRow()
        if row < 0:
            return
        token_name = self.tokens_table.item(row, 0).text()
        # Find analysis for this token
        flow_name = self.token_flow_selector.currentText()
        if flow_name not in self.recorded_flows:
            return
        tokens = self.recorded_flows[flow_name].get('tokens', {})
        token_info = tokens.get(token_name, {})
        if token_info:
            analysis = self.token_analyzer.analyze_token(
                token_name, token_info.get('value', ''), token_info.get('source', ''), token_info)
            self.token_details.setText(json.dumps(analysis, indent=2, default=str))

    # ──────────────────────────────────────────────────────────────────────
    # Signal Handlers
    # ──────────────────────────────────────────────────────────────────────

    def _on_session_started(self, session_id):
        self.request_feed.append(f"[{self._ts()}] Session started: {session_id}")

    def _on_session_ended(self, session_id):
        self.request_feed.append(f"[{self._ts()}] Session ended: {session_id}")

    def _on_flow_recorded(self, flow_data):
        n_req = len(flow_data.get('requests', []))
        n_tok = len(flow_data.get('tokens', {}))
        protocols = flow_data.get('detected_protocols', [])
        self.request_feed.append(
            f"[{self._ts()}] Flow recorded: {n_req} requests, {n_tok} tokens, "
            f"protocols: {', '.join(protocols) or 'none'}")

    def _on_protocol_detected(self, session_id, protocol):
        self.protocol_label.setText(f"Protocols: {protocol}")
        self.request_feed.append(f"[{self._ts()}] 🔎 Protocol detected: {protocol}")

    def _on_request_logged(self, http_request):
        if self.flow_recorder.recording:
            self.request_feed.append(
                f"[{self._ts()}] {http_request.method} {http_request.url}")
            scrollbar = self.request_feed.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())

    def _on_response_received(self, http_response):
        if self.flow_recorder.recording and hasattr(http_response, 'request'):
            self.flow_recorder.process_request(http_response.request, http_response)

    def _on_proxy_started(self, port):
        self.proxy_running = True
        self.proxy_toggle_btn.setText("Stop Proxy")
        self.proxy_status.setText(f"Proxy: Running on port {port}")
        self.request_feed.append(f"\n[SUCCESS] Proxy started on port {port}")
        self.request_feed.append(f"[INFO] Configure browser proxy: 127.0.0.1:{port}")

    def _on_proxy_stopped(self):
        self.proxy_running = False
        self.proxy_toggle_btn.setText("Start Proxy")
        self.proxy_status.setText("Proxy: Stopped")
        self.request_feed.append("\n[INFO] Proxy stopped")

    def _on_replay_started(self, test_id):
        self.test_progress.setVisible(True)
        self.test_progress.setValue(0)
        self.test_results.append(f"\n[{self._ts()}] ▶ Test started: {test_id}")

    def _on_replay_completed(self, test_id, results):
        self.test_progress.setVisible(False)
        vulns = results.get('vulnerabilities', [])
        duration = results.get('duration', 0)
        self.test_results.append(
            f"[{self._ts()}] ✓ Test completed: {test_id}\n"
            f"  Requests sent: {results.get('requests_sent', 0)}\n"
            f"  Vulnerabilities: {len(vulns)}\n"
            f"  Duration: {duration:.1f}s")
        if vulns:
            self.test_results.append("  ─── Findings ───")
            for v in vulns:
                self.test_results.append(
                    f"  🚨 [{v.get('severity', '?').upper()}] {v.get('type')}: {v.get('description', '')[:80]}")
        self._update_results_summary()

    def _on_vulnerability_found(self, test_id, vuln):
        self.test_results.append(
            f"[{self._ts()}] 🚨 [{vuln.get('severity', '?').upper()}] "
            f"{vuln.get('type')}: {vuln.get('description', '')[:100]}")
        # Add to results table
        self._add_vuln_to_table(vuln)

    def _on_progress_updated(self, test_id, current, total):
        if total > 0:
            self.test_progress.setMaximum(total)
            self.test_progress.setValue(current)

    def _on_request_sent(self, test_id, info):
        mutation = info.get('mutation', 'baseline')
        self.test_results.append(
            f"  → {info.get('method')} {info.get('url', '')[:60]} [{mutation}]")

    # ──────────────────────────────────────────────────────────────────────
    # Results & Export
    # ──────────────────────────────────────────────────────────────────────

    def _update_results_summary(self):
        """Update the Results tab summary counters."""
        total_flows = len(self.recorded_flows)
        total_tokens = sum(len(f.get('tokens', {})) for f in self.recorded_flows.values())
        total_vulns = self.all_vulns_table.rowCount()
        critical = 0
        high = 0
        for row in range(total_vulns):
            sev = self.all_vulns_table.item(row, 0)
            if sev:
                if sev.text().lower() == 'critical':
                    critical += 1
                elif sev.text().lower() == 'high':
                    high += 1
        self.stat_flows.setText(f"Flows: {total_flows}")
        self.stat_tokens.setText(f"Tokens: {total_tokens}")
        self.stat_vulns.setText(f"Vulnerabilities: {total_vulns}")
        self.stat_critical.setText(f"Critical: {critical}")
        self.stat_high.setText(f"High: {high}")

    def _add_vuln_to_table(self, vuln: dict):
        row = self.all_vulns_table.rowCount()
        self.all_vulns_table.insertRow(row)
        sev = vuln.get('severity', 'info')
        sev_item = QTableWidgetItem(sev.upper())
        sev_colors = {'critical': '#FF4444', 'high': '#FF8C00', 'medium': '#FFD700', 'low': '#87CEEB'}
        sev_item.setForeground(QColor(sev_colors.get(sev, '#DCDCDC')))
        self.all_vulns_table.setItem(row, 0, sev_item)
        self.all_vulns_table.setItem(row, 1, QTableWidgetItem(vuln.get('protocol', vuln.get('mutation', ''))))
        self.all_vulns_table.setItem(row, 2, QTableWidgetItem(vuln.get('type', '')))
        self.all_vulns_table.setItem(row, 3, QTableWidgetItem(vuln.get('url', '')[:50]))
        self.all_vulns_table.setItem(row, 4, QTableWidgetItem(vuln.get('description', '')[:80]))
        self.all_vulns_table.setItem(row, 5, QTableWidgetItem(vuln.get('mutation', '')))

    def export_results_json(self):
        data = {
            'flows': {k: {kk: vv for kk, vv in v.items() if kk != 'endpoints' or not isinstance(vv, set)}
                      for k, v in self.recorded_flows.items()},
            'timestamp': time.time(),
            'security_issues': [self._table_row_to_dict(self.all_vulns_table, r)
                               for r in range(self.all_vulns_table.rowCount())],
        }
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "auth_results.json", "JSON Files (*.json)")
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            QMessageBox.information(self, "Exported", f"Results exported to {filename}")

    def export_results_html(self):
        vulns = []
        for r in range(self.all_vulns_table.rowCount()):
            vulns.append(self._table_row_to_dict(self.all_vulns_table, r))
        html = self._generate_html_report(vulns)
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export HTML Report", "auth_report.html", "HTML Files (*.html)")
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
            QMessageBox.information(self, "Exported", f"HTML report exported to {filename}")

    def export_flow(self):
        row = self.flows_table.currentRow()
        if row < 0:
            return
        sid = self.flows_table.item(row, 0).text()
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Flow", f"{sid}.json", "JSON Files (*.json)")
        if filename:
            self.flow_recorder.export_flow(sid, filename)

    def import_flow(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Import Flow", "", "JSON Files (*.json)")
        if filename:
            sid = self.flow_recorder.import_flow(filename)
            if sid:
                flow_data = self.flow_recorder.get_flow_data(sid)
                if flow_data:
                    self.recorded_flows[sid] = flow_data
                    self._refresh_flows_table()
                    self._refresh_flow_selectors()
                    QMessageBox.information(self, "Imported", f"Flow imported as '{sid}'")

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _refresh_flows_table(self):
        self.flows_table.setRowCount(len(self.recorded_flows))
        for row, (sid, fd) in enumerate(self.recorded_flows.items()):
            self.flows_table.setItem(row, 0, QTableWidgetItem(sid))
            self.flows_table.setItem(row, 1, QTableWidgetItem(str(len(fd.get('requests', [])))))
            protocols = ', '.join(fd.get('detected_protocols', []))
            self.flows_table.setItem(row, 2, QTableWidgetItem(protocols or '—'))
            self.flows_table.setItem(row, 3, QTableWidgetItem(str(len(fd.get('tokens', {})))))
            dur = fd.get('duration', 0)
            self.flows_table.setItem(row, 4, QTableWidgetItem(f"{dur:.1f}s"))
            self.flows_table.setItem(row, 5, QTableWidgetItem("Analyze | Export | Delete"))

    def _refresh_flow_selectors(self):
        names = list(self.recorded_flows.keys())
        for selector in (self.flow_selector, self.test_flow_selector, self.token_flow_selector):
            selector.clear()
            selector.addItems(names)

    def _ts(self) -> str:
        return time.strftime('%H:%M:%S')

    def _table_row_to_dict(self, table: QTableWidget, row: int) -> dict:
        headers = [table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else f"col{c}"
                   for c in range(table.columnCount())]
        return {headers[c]: (table.item(row, c).text() if table.item(row, c) else '')
                for c in range(table.columnCount())}

    def _generate_html_report(self, vulns: list) -> str:
        rows = ''
        for v in vulns:
            sev = v.get('Severity', 'info')
            color = {'CRITICAL': '#FF4444', 'HIGH': '#FF8C00', 'MEDIUM': '#FFD700'}.get(sev, '#87CEEB')
            rows += (f"<tr><td style='color:{color};font-weight:bold'>{sev}</td>"
                     f"<td>{v.get('Protocol', '')}</td>"
                     f"<td>{v.get('Type', '')}</td>"
                     f"<td>{v.get('URL', '')}</td>"
                     f"<td>{v.get('Description', '')}</td></tr>\n")
        return f"""<!DOCTYPE html>
<html><head><title>Auth Workflows Security Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#1a1f2e;color:#dcdcdc;padding:20px}}
h1{{color:#64C8FF}}h2{{color:#87CEEB}}
table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #64C8FF;padding:8px;text-align:left}}
th{{background:rgba(100,200,255,0.2)}}
.summary{{display:flex;gap:20px;margin:20px 0}}
.stat{{background:rgba(100,200,255,0.1);padding:15px;border-radius:8px;border:1px solid #64C8FF}}
</style></head><body>
<h1>Authentication Workflows Security Report</h1>
<p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="summary">
<div class="stat"><b>Flows Analyzed:</b> {len(self.recorded_flows)}</div>
<div class="stat"><b>Vulnerabilities:</b> {len(vulns)}</div>
<div class="stat"><b>Protocols Tested:</b> {', '.join(set(v.get('Protocol','') for v in vulns)) or 'N/A'}</div>
</div>
<h2>Vulnerabilities</h2>
<table><tr><th>Severity</th><th>Protocol</th><th>Type</th><th>URL</th><th>Description</th></tr>
{rows}</table></body></html>"""

    # ──────────────────────────────────────────────────────────────────────
    # Theme
    # ──────────────────────────────────────────────────────────────────────

    def apply_theme(self):
        """Theme is applied at the WebExploitsPage level for consistency."""
        pass
