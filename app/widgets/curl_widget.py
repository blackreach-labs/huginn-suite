# app/widgets/curl_widget.py
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QVBoxLayout, QHBoxLayout, QFrame, QCheckBox, QListWidget, 
                            QSplitter, QComboBox, QSpinBox, QTabWidget, QGridLayout, 
                            QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView,
                            QMessageBox, QDialog, QStackedWidget, QTreeWidget,
                            QTreeWidgetItem)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QBrush
import json
from app.core.logger import logger

try:
    from app.core.unified_request_handler import UnifiedRequestHandler
    from app.core.http_client import HttpRequest, HttpResponse
    from app.core.obfuscation_engine import ObfuscationEngine
    from app.widgets.request_viewer import RequestViewerDialog
    from app.core.session_harvester import SessionHarvester
except ImportError:
    from ..core.unified_request_handler import UnifiedRequestHandler
    from ..core.http_client import HttpRequest, HttpResponse
    from ..core.obfuscation_engine import ObfuscationEngine
    from ..widgets.request_viewer import RequestViewerDialog
    from ..core.session_harvester import SessionHarvester

class CurlWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.request_handler = UnifiedRequestHandler()
        
        # Connect signals
        self.request_handler.request_sent.connect(self.on_request_sent)
        self.request_handler.request_failed.connect(self.on_request_failed)
        self.request_handler.request_intercepted.connect(self.on_request_intercepted)
        self.request_handler.proxy_engine.history_updated.connect(self.refresh_history_table)
        self.request_handler.proxy_engine.history_updated.connect(self._harvest_from_history)
        self.request_handler.finding_detected.connect(self.on_security_finding)
        self.request_handler.scan_completed.connect(self.on_scan_completed)
        
        self.paused_requests = {}
        self.proxy_running = False
        self.session_harvester = SessionHarvester()
        self.curl_preview = QTextEdit()  # Hidden compatibility widget
        self.status_badge = QLabel()  # Hidden compatibility widget
        self.paused_requests_list = QListWidget()  # Hidden compatibility widget
        self.paused_frame = QFrame()  # Hidden compatibility widget
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Control panel - right-aligned proxy controls with status + button on top,
        # intercept checkbox below
        control_frame = QFrame()
        control_outer = QVBoxLayout(control_frame)
        control_outer.setContentsMargins(0, 0, 0, 0)
        control_outer.setSpacing(4)
        
        # Top row: stretch | status | start proxy button
        top_row = QHBoxLayout()
        top_row.addStretch()
        
        self.proxy_status = QLabel("Proxy: Stopped")
        top_row.addWidget(self.proxy_status)
        
        self.start_proxy_btn = QPushButton("Start Proxy")
        self.start_proxy_btn.clicked.connect(self.toggle_proxy)
        top_row.addWidget(self.start_proxy_btn)
        
        control_outer.addLayout(top_row)
        
        # Bottom row: intercept checkbox aligned right
        bottom_row = QHBoxLayout()
        bottom_row.addStretch()
        
        self.intercept_checkbox = QCheckBox("Intercept requests")
        self.intercept_checkbox.toggled.connect(self.toggle_intercept)
        self.intercept_checkbox.setEnabled(False)  # Disabled until proxy starts
        bottom_row.addWidget(self.intercept_checkbox)
        
        control_outer.addLayout(bottom_row)
        
        layout.addWidget(control_frame)
        
        # Connect proxy signals
        self.request_handler.proxy_engine.proxy_started.connect(self.on_proxy_started)
        self.request_handler.proxy_engine.proxy_stopped.connect(self.on_proxy_stopped)
        
        self.proxy_running = False
        
        # Tab widget for different views
        self.main_tabs = QTabWidget()
        
        # Repeater tab
        repeater_tab = self.create_repeater_tab()
        self.main_tabs.addTab(repeater_tab, "Repeater")
        
        # Interceptor tab
        interceptor_tab = self.create_interceptor_tab()
        self.main_tabs.addTab(interceptor_tab, "Interceptor")
        
        # History tab
        history_tab = self.create_history_tab()
        self.main_tabs.addTab(history_tab, "History")
        
        # Scanner tab
        scanner_tab = self.create_scanner_tab()
        self.main_tabs.addTab(scanner_tab, "Scanner")
        
        # Decoder tab
        decoder_tab = self.create_decoder_tab()
        self.main_tabs.addTab(decoder_tab, "Decoder")
        
        # Sessions tab
        sessions_tab = self.create_sessions_tab()
        self.main_tabs.addTab(sessions_tab, "Sessions")
        
        layout.addWidget(self.main_tabs)
    
    def create_repeater_tab(self):
        """Create the redesigned repeater tab - Burp-style layout"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)
        
        # Top bar: Method + URL + Send button
        url_bar = QFrame()
        url_bar.setStyleSheet(
            "QFrame { background-color: rgba(30, 30, 50, 150); "
            "border-radius: 4px; padding: 2px; }"
        )
        url_bar_layout = QHBoxLayout(url_bar)
        url_bar_layout.setContentsMargins(6, 4, 6, 4)
        url_bar_layout.setSpacing(6)
        
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self.method_combo.setFixedWidth(140)
        self.method_combo.setStyleSheet(
            "QComboBox { font-weight: bold; padding: 4px; }"
        )
        url_bar_layout.addWidget(self.method_combo)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.com/api/endpoint")
        self.url_input.setStyleSheet("QLineEdit { padding: 5px; font-size: 10pt; }")
        url_bar_layout.addWidget(self.url_input)
        
        send_btn = QPushButton("Send")
        send_btn.setFixedWidth(70)
        send_btn.setStyleSheet(
            "QPushButton { background-color: #FF6633; color: white; "
            "font-weight: bold; border-radius: 4px; padding: 6px; }"
            "QPushButton:hover { background-color: #FF7744; }"
        )
        send_btn.clicked.connect(self.send_request)
        url_bar_layout.addWidget(send_btn)
        
        layout.addWidget(url_bar)
        
        # Main splitter: Request (top) / Response (bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Request panel (top)
        request_panel = self._create_request_panel()
        splitter.addWidget(request_panel)
        
        # Response panel (bottom)
        response_panel = self._create_response_panel()
        splitter.addWidget(response_panel)
        
        splitter.setSizes([300, 400])
        layout.addWidget(splitter, 1)
        
        return tab
    
    def _create_request_panel(self):
        """Create the request editing panel with tabs"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        request_tabs = QTabWidget()
        request_tabs.setStyleSheet("QTabWidget::pane { border-top: 1px solid #444; }")
        
        # Headers tab
        headers_widget = QWidget()
        headers_layout = QVBoxLayout(headers_widget)
        headers_layout.setContentsMargins(6, 6, 6, 6)
        
        # Quick header buttons
        header_btns = QHBoxLayout()
        header_btns.setSpacing(4)
        
        self.json_btn = QPushButton("JSON")
        self.json_btn.setCheckable(True)
        self.json_btn.setFixedHeight(24)
        self.json_btn.clicked.connect(lambda: self.toggle_header("Content-Type: application/json", self.json_btn))
        header_btns.addWidget(self.json_btn)
        
        self.form_btn = QPushButton("Form")
        self.form_btn.setCheckable(True)
        self.form_btn.setFixedHeight(24)
        self.form_btn.clicked.connect(lambda: self.toggle_header("Content-Type: application/x-www-form-urlencoded", self.form_btn))
        header_btns.addWidget(self.form_btn)
        
        self.auth_btn = QPushButton("Bearer")
        self.auth_btn.setCheckable(True)
        self.auth_btn.setFixedHeight(24)
        self.auth_btn.clicked.connect(lambda: self.toggle_header("Authorization: Bearer ", self.auth_btn))
        header_btns.addWidget(self.auth_btn)
        
        header_btns.addStretch()
        headers_layout.addLayout(header_btns)
        
        self.headers_text = QTextEdit()
        self.headers_text.setPlaceholderText("Content-Type: application/json\nAuthorization: Bearer token123")
        self.headers_text.setStyleSheet(
            "QTextEdit { font-family: 'Neuropol X', monospace; font-size: 9pt; }"
        )
        headers_layout.addWidget(self.headers_text)
        
        request_tabs.addTab(headers_widget, "Headers")
        
        # Body tab
        body_widget = QWidget()
        body_layout = QVBoxLayout(body_widget)
        body_layout.setContentsMargins(6, 6, 6, 6)
        
        # Body format buttons
        body_btns = QHBoxLayout()
        body_btns.setSpacing(4)
        
        json_format_btn = QPushButton("Pretty JSON")
        json_format_btn.setFixedHeight(24)
        json_format_btn.clicked.connect(self.format_json)
        body_btns.addWidget(json_format_btn)
        
        url_encode_btn = QPushButton("URL Encode")
        url_encode_btn.setFixedHeight(24)
        url_encode_btn.clicked.connect(self.url_encode_body)
        body_btns.addWidget(url_encode_btn)

        load_payload_btn = QPushButton("📂 Load Payload")
        load_payload_btn.setFixedHeight(24)
        load_payload_btn.setToolTip("Load a saved payload file into the request body")
        load_payload_btn.clicked.connect(self._load_payload_file)
        body_btns.addWidget(load_payload_btn)
        
        body_btns.addStretch()
        body_layout.addLayout(body_btns)
        
        self.body_text = QTextEdit()
        self.body_text.setPlaceholderText('{"email": "test@example.com"}')
        self.body_text.setStyleSheet(
            "QTextEdit { font-family: 'Neuropol X', monospace; font-size: 9pt; }"
        )
        self.body_text.setAcceptRichText(False)
        body_layout.addWidget(self.body_text)
        
        request_tabs.addTab(body_widget, "Body")
        
        # Auth tab
        auth_widget = QWidget()
        auth_layout = QVBoxLayout(auth_widget)
        auth_layout.setContentsMargins(6, 10, 6, 6)
        
        auth_form = QGridLayout()
        auth_form.setSpacing(8)
        auth_form.addWidget(QLabel("Username:"), 0, 0)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("username")
        auth_form.addWidget(self.username_input, 0, 1)
        
        auth_form.addWidget(QLabel("Password:"), 1, 0)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("password")
        auth_form.addWidget(self.password_input, 1, 1)
        auth_layout.addLayout(auth_form)
        auth_layout.addStretch()
        
        request_tabs.addTab(auth_widget, "Auth")
        
        # Options tab
        options_widget = QWidget()
        options_layout = QVBoxLayout(options_widget)
        options_layout.setContentsMargins(6, 10, 6, 6)
        
        options_form = QGridLayout()
        options_form.setSpacing(8)
        
        options_form.addWidget(QLabel("Timeout (s):"), 0, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setFixedWidth(80)
        options_form.addWidget(self.timeout_spin, 0, 1)
        
        self.follow_redirects_cb = QCheckBox("Follow redirects")
        self.follow_redirects_cb.setChecked(True)
        options_form.addWidget(self.follow_redirects_cb, 1, 0, 1, 2)
        
        self.verify_ssl_cb = QCheckBox("Verify SSL certificates")
        self.verify_ssl_cb.setChecked(True)
        options_form.addWidget(self.verify_ssl_cb, 2, 0, 1, 2)
        
        options_layout.addLayout(options_form)
        options_layout.addStretch()
        
        request_tabs.addTab(options_widget, "Options")
        
        layout.addWidget(request_tabs)
        return panel
    
    def _create_response_panel(self):
        """Create the response display panel with tabs"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Response info bar
        self.response_info = QLabel("  No response yet")
        self.response_info.setStyleSheet(
            "QLabel { color: #888; padding: 4px 8px; font-size: 9pt; "
            "background-color: rgba(30, 30, 50, 100); }"
        )
        self.response_info.setFixedHeight(24)
        layout.addWidget(self.response_info)
        
        self.response_tabs = QTabWidget()
        self.response_tabs.setStyleSheet("QTabWidget::pane { border-top: 1px solid #444; }")
        
        # Body tab (pretty-printed)
        self.response_body = QTextEdit()
        self.response_body.setReadOnly(True)
        self.response_body.setStyleSheet(
            "QTextEdit { font-family: 'Neuropol X', monospace; font-size: 9pt; "
            "background-color: #1a1a2e; color: #e0e0e0; }"
        )
        self.response_body.setPlaceholderText("Send a request to see the response...")
        self.response_tabs.addTab(self.response_body, "Body")
        
        # Headers tab
        self.response_headers = QTextEdit()
        self.response_headers.setReadOnly(True)
        self.response_headers.setStyleSheet(
            "QTextEdit { font-family: 'Neuropol X', monospace; font-size: 9pt; "
            "background-color: #1a1a2e; color: #e0e0e0; }"
        )
        self.response_tabs.addTab(self.response_headers, "Headers")
        
        # Raw tab
        self.response_raw = QTextEdit()
        self.response_raw.setReadOnly(True)
        self.response_raw.setStyleSheet(
            "QTextEdit { font-family: 'Neuropol X', monospace; font-size: 9pt; "
            "background-color: #1a1a2e; color: #e0e0e0; }"
        )
        self.response_tabs.addTab(self.response_raw, "Raw")
        
        layout.addWidget(self.response_tabs, 1)
        
        # Keep curl_response as a hidden compatibility widget (other code references it)
        self.curl_response = QTextEdit()
        self.curl_response.setVisible(False)
        layout.addWidget(self.curl_response)
        
        return panel
    
    def create_request_builder(self):
        """Legacy method - returns an empty frame for compatibility"""
        return QFrame()

    def create_interceptor_tab(self):
        """Create the Interceptor tab for viewing/editing intercepted requests"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        
        # Top: intercepted requests list
        list_frame = QFrame()
        list_frame.setStyleSheet(
            "QFrame { background-color: rgba(30, 30, 50, 100); border-radius: 4px; }"
        )
        list_layout = QVBoxLayout(list_frame)
        list_layout.setContentsMargins(8, 8, 8, 8)
        
        list_header = QHBoxLayout()
        list_header.addWidget(QLabel("Intercepted Requests"))
        list_header.addStretch()
        
        self.intercept_status_label = QLabel("Intercept: OFF")
        self.intercept_status_label.setStyleSheet("color: #FF4444; font-weight: bold;")
        list_header.addWidget(self.intercept_status_label)
        list_layout.addLayout(list_header)
        
        self.interceptor_list = QListWidget()
        self.interceptor_list.setMaximumHeight(120)
        self.interceptor_list.currentRowChanged.connect(self._on_interceptor_selection_changed)
        list_layout.addWidget(self.interceptor_list)
        
        layout.addWidget(list_frame)
        
        # Bottom: editable request view + action buttons
        editor_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Request editor
        editor_panel = QWidget()
        editor_layout = QVBoxLayout(editor_panel)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.setSpacing(4)
        
        # Request line (method + URL) - editable
        req_line_layout = QHBoxLayout()
        self.intercept_method = QComboBox()
        self.intercept_method.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self.intercept_method.setFixedWidth(140)
        req_line_layout.addWidget(self.intercept_method)
        
        self.intercept_url = QLineEdit()
        self.intercept_url.setPlaceholderText("Select an intercepted request above...")
        self.intercept_url.setStyleSheet("QLineEdit { padding: 5px; font-size: 10pt; }")
        req_line_layout.addWidget(self.intercept_url)
        editor_layout.addLayout(req_line_layout)
        
        # Tabs for headers and body editing
        self.intercept_editor_tabs = QTabWidget()
        
        # Headers editor
        self.intercept_headers_edit = QTextEdit()
        self.intercept_headers_edit.setPlaceholderText("Request headers will appear here for editing...")
        self.intercept_headers_edit.setStyleSheet(
            "QTextEdit { font-family: 'Neuropol X', monospace; font-size: 9pt; }"
        )
        self.intercept_editor_tabs.addTab(self.intercept_headers_edit, "Headers")
        
        # Body editor
        self.intercept_body_edit = QTextEdit()
        self.intercept_body_edit.setPlaceholderText("Request body will appear here for editing...")
        self.intercept_body_edit.setStyleSheet(
            "QTextEdit { font-family: 'Neuropol X', monospace; font-size: 9pt; }"
        )
        self.intercept_editor_tabs.addTab(self.intercept_body_edit, "Body")
        
        editor_layout.addWidget(self.intercept_editor_tabs)
        
        # Action buttons
        action_layout = QHBoxLayout()
        
        forward_btn = QPushButton("Forward")
        forward_btn.setStyleSheet(
            "QPushButton { background-color: #2E7D32; color: white; "
            "font-weight: bold; border-radius: 4px; padding: 6px 16px; }"
            "QPushButton:hover { background-color: #388E3C; }"
        )
        forward_btn.clicked.connect(self._intercept_forward_modified)
        action_layout.addWidget(forward_btn)
        
        drop_btn = QPushButton("Drop")
        drop_btn.setStyleSheet(
            "QPushButton { background-color: #C62828; color: white; "
            "font-weight: bold; border-radius: 4px; padding: 6px 16px; }"
            "QPushButton:hover { background-color: #D32F2F; }"
        )
        drop_btn.clicked.connect(self._intercept_drop)
        action_layout.addWidget(drop_btn)
        
        action_layout.addStretch()
        
        send_to_repeater_btn = QPushButton("Send to Repeater")
        send_to_repeater_btn.setStyleSheet(
            "QPushButton { background-color: #1565C0; color: white; "
            "border-radius: 4px; padding: 6px 16px; }"
            "QPushButton:hover { background-color: #1976D2; }"
        )
        send_to_repeater_btn.clicked.connect(self._intercept_send_to_repeater)
        action_layout.addWidget(send_to_repeater_btn)
        
        editor_layout.addLayout(action_layout)
        
        editor_splitter.addWidget(editor_panel)
        layout.addWidget(editor_splitter, 1)
        
        return tab

    def _on_interceptor_selection_changed(self, row):
        """Load the selected intercepted request into the editor"""
        if row < 0:
            return
        
        item = self.interceptor_list.item(row)
        if not item:
            return
        
        item_text = item.text()
        try:
            flow_id = int(item_text.split(']')[0][1:])
        except (ValueError, IndexError):
            return
        
        request = self.paused_requests.get(flow_id)
        if not request:
            return
        
        # Populate editor fields
        self.intercept_method.setCurrentText(request.method)
        self.intercept_url.setText(request.url)
        
        # Headers
        if request.headers:
            headers_text = '\n'.join([f"{k}: {v}" for k, v in request.headers.items()])
            self.intercept_headers_edit.setPlainText(headers_text)
        else:
            self.intercept_headers_edit.clear()
        
        # Body
        if request.data:
            self.intercept_body_edit.setPlainText(request.data)
        else:
            self.intercept_body_edit.clear()

    def _get_selected_flow_id(self):
        """Get the flow_id of the currently selected intercepted request"""
        row = self.interceptor_list.currentRow()
        if row < 0:
            return None
        item = self.interceptor_list.item(row)
        if not item:
            return None
        try:
            return int(item.text().split(']')[0][1:])
        except (ValueError, IndexError):
            return None

    def _intercept_forward(self):
        """Forward the selected request without modification"""
        flow_id = self._get_selected_flow_id()
        if flow_id is None:
            return
        
        if self.request_handler.forward_request(flow_id):
            self._remove_intercepted(flow_id)

    def _intercept_forward_modified(self):
        """Forward the selected request with modifications from the editor"""
        flow_id = self._get_selected_flow_id()
        if flow_id is None:
            return
        
        # Build modified request from editor fields
        headers = {}
        headers_text = self.intercept_headers_edit.toPlainText().strip()
        if headers_text:
            for line in headers_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        modified_request = HttpRequest(
            method=self.intercept_method.currentText(),
            url=self.intercept_url.text(),
            headers=headers,
            data=self.intercept_body_edit.toPlainText(),
        )
        
        if self.request_handler.modify_and_forward_request(flow_id, modified_request):
            self._remove_intercepted(flow_id)

    def _intercept_drop(self):
        """Drop the selected intercepted request"""
        flow_id = self._get_selected_flow_id()
        if flow_id is None:
            return
        
        if self.request_handler.drop_request(flow_id):
            self._remove_intercepted(flow_id)

    def _intercept_send_to_repeater(self):
        """Send the selected intercepted request to the Repeater tab"""
        flow_id = self._get_selected_flow_id()
        if flow_id is None:
            return
        
        # Load current editor state into repeater
        self.method_combo.setCurrentText(self.intercept_method.currentText())
        self.url_input.setText(self.intercept_url.text())
        self.headers_text.setPlainText(self.intercept_headers_edit.toPlainText())
        self.body_text.setPlainText(self.intercept_body_edit.toPlainText())
        
        # Switch to Repeater tab
        self.main_tabs.setCurrentIndex(0)

    def _remove_intercepted(self, flow_id):
        """Remove a request from the interceptor list and paused_requests"""
        for i in range(self.interceptor_list.count()):
            item = self.interceptor_list.item(i)
            if item and f"[{flow_id}]" in item.text():
                self.interceptor_list.takeItem(i)
                break
        
        if flow_id in self.paused_requests:
            del self.paused_requests[flow_id]
        
        # Clear editor if list is empty
        if self.interceptor_list.count() == 0:
            self.intercept_method.setCurrentText("GET")
            self.intercept_url.clear()
            self.intercept_headers_edit.clear()
            self.intercept_body_edit.clear()
    
    def toggle_header(self, header, button):
        current = self.headers_text.toPlainText().strip()
        lines = [line for line in current.split('\n') if line.strip()] if current else []
        header_key = header.split(':')[0]
        
        if button.isChecked():
            # Add header if not present
            if not any(line.strip().startswith(header_key + ':') for line in lines):
                lines.append(header)
            self.headers_text.setPlainText('\n'.join(lines))
        else:
            # Remove header
            filtered_lines = [line for line in lines if not line.strip().startswith(header_key + ':')]
            self.headers_text.setPlainText('\n'.join(filtered_lines))
        
        # Uncheck other content-type buttons if this is a content-type
        if header_key == 'Content-Type':
            if button == self.json_btn and button.isChecked():
                self.form_btn.setChecked(False)
            elif button == self.form_btn and button.isChecked():
                self.json_btn.setChecked(False)
    
    def format_json(self):
        try:
            text = self.body_text.toPlainText()
            if text:
                formatted = json.dumps(json.loads(text), indent=2)
                self.body_text.setPlainText(formatted)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def url_encode_body(self):
        import urllib.parse
        text = self.body_text.toPlainText()
        if text:
            encoded = urllib.parse.quote(text)
            self.body_text.setPlainText(encoded)

    def _load_payload_file(self):
        """Load a payload file into the request body.
        
        Opens a file dialog starting in the exports/payloads/ directory
        (where Shell Management saves payloads) so users can quickly
        reference generated payloads.
        """
        from pathlib import Path
        from PyQt6.QtWidgets import QFileDialog

        # Start in the payload library directory if it exists
        project_root = Path(__file__).parent.parent.parent
        payloads_dir = project_root / "exports" / "payloads"
        start_dir = str(payloads_dir) if payloads_dir.exists() else ""

        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Payload File", start_dir,
            "All Files (*);;Text Files (*.txt);;Shell Scripts (*.sh);;PowerShell (*.ps1)"
        )

        if filename:
            try:
                with open(filename, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                self.body_text.setPlainText(content)
            except Exception as e:
                from PyQt6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Error", f"Failed to load payload: {str(e)}")

    def update_curl_preview(self):
        request = self.build_http_request()
        # Generate curl command preview
        curl_cmd = self._http_to_curl(request)
        self.curl_preview.setPlainText(curl_cmd)
    
    def _http_to_curl(self, request: HttpRequest):
        """Convert HttpRequest to curl command for preview"""
        import shlex
        cmd = f"curl -X {request.method}"
        
        for key, value in request.headers.items():
            cmd += f' -H "{key}: {value}"'
        
        if request.data:
            cmd += f' --data {shlex.quote(request.data)}'
        
        if request.auth:
            cmd += f' -u "{request.auth[0]}:{request.auth[1]}"'
        
        if request.timeout != 30:
            cmd += f' --max-time {request.timeout}'
        
        if not request.verify:
            cmd += ' -k'
        
        if request.allow_redirects:
            cmd += ' -L'
        
        cmd += f' "{request.url}"'
        return cmd
    
    def build_http_request(self):
        """Build HttpRequest from GUI inputs"""
        # Parse headers
        headers = {}
        headers_text = self.headers_text.toPlainText().strip()
        if headers_text:
            for line in headers_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Auth
        auth = None
        if self.username_input.text() or self.password_input.text():
            auth = (self.username_input.text(), self.password_input.text())
        
        return HttpRequest(
            method=self.method_combo.currentText(),
            url=self.url_input.text(),
            headers=headers,
            data=self.body_text.toPlainText(),
            auth=auth,
            timeout=self.timeout_spin.value(),
            allow_redirects=self.follow_redirects_cb.isChecked(),
            verify=self.verify_ssl_cb.isChecked()
        )
    
    def send_request(self):
        if not self.url_input.text():
            self.curl_response.append("\n[ERROR] Please enter a URL")
            return
        
        request = self.build_http_request()
        self.request_handler.send_request(request)
    
    def send_with_pause(self):
        if not self.url_input.text():
            self.curl_response.append("\n[ERROR] Please enter a URL")
            return
        
        if not self.request_handler.proxy_available:
            self.curl_response.append("\n[WARNING] Pause functionality requires proxy - sending normally")
            self.send_request()
            return
        
        # Enable intercept temporarily
        self.request_handler.enable_intercept(True)
        request = self.build_http_request()
        self.request_handler.send_request(request)
    
    def clear_all(self):
        self.url_input.clear()
        self.headers_text.clear()
        self.body_text.clear()
        self.username_input.clear()
        self.password_input.clear()
        self.curl_response.clear()
        self.curl_preview.clear()
        self.response_body.clear()
        self.response_headers.clear()
        self.response_raw.clear()
        self.response_info.setText("  No response yet")
        self.response_info.setStyleSheet(
            "QLabel { color: #888; padding: 4px 8px; font-size: 9pt; "
            "background-color: rgba(30, 30, 50, 100); }"
        )
        self.status_badge.setText("")
        self.status_badge.setStyleSheet(
            "QLabel { font-weight: bold; border-radius: 3px; padding: 3px; }"
        )
        self.method_combo.setCurrentText("GET")
        self.timeout_spin.setValue(30)
        self.follow_redirects_cb.setChecked(True)
        self.verify_ssl_cb.setChecked(True)
    
    def toggle_proxy(self):
        """Start or stop the proxy server.
        
        On start, checks if the mitmproxy CA certificate is installed in the
        Windows trusted root store. If not, prompts the user to install it.
        """
        if not self.proxy_running:
            # Check if CA cert is installed before starting
            if not self._is_ca_cert_installed():
                self._prompt_ca_cert_install()
            
            if self.request_handler.start_proxy(8080):
                self.curl_response.append("\n[INFO] Starting proxy server on port 8080...")
            else:
                self.curl_response.append("\n[ERROR] Failed to start proxy - install mitmproxy: pip install mitmproxy")
        else:
            self.request_handler.stop_proxy()
            self.curl_response.append("\n[INFO] Stopping proxy server...")
    
    def _is_ca_cert_installed(self):
        """Check if the mitmproxy CA certificate is already in the Windows trusted root store."""
        import subprocess
        try:
            result = subprocess.run(
                ["certutil", "-verifystore", "root", "mitmproxy"],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            # certutil returns 0 and includes the cert subject if found
            return result.returncode == 0 and "mitmproxy" in result.stdout.lower()
        except Exception:
            # If certutil fails, assume not installed
            return False
    
    def _prompt_ca_cert_install(self):
        """Show a dialog asking the user to install the CA certificate."""
        from PyQt6.QtWidgets import QMessageBox
        
        msg = QMessageBox(self)
        msg.setWindowTitle("CA Certificate Not Installed")
        msg.setIcon(QMessageBox.Icon.Question)
        msg.setText(
            "The mitmproxy CA certificate is not installed in your trusted root store.\n\n"
            "HTTPS interception requires this certificate to avoid browser errors.\n\n"
            "Would you like to install it now? (Requires admin privileges)"
        )
        msg.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        msg.setDefaultButton(QMessageBox.StandardButton.Yes)
        
        if msg.exec() == QMessageBox.StandardButton.Yes:
            self.install_proxy_certificate()
    
    def on_proxy_started(self, port):
        """Handle proxy started event"""
        self.proxy_running = True
        self.start_proxy_btn.setText("Stop Proxy")
        self.proxy_status.setText(f"Proxy: Running on port {port}")
        self.intercept_checkbox.setEnabled(True)
        self.curl_response.append(f"\n[SUCCESS] Proxy started on port {port}")
        self.curl_response.append(f"\n[INFO] Configure browser proxy: 127.0.0.1:{port}")
    
    def on_proxy_stopped(self):
        """Handle proxy stopped event"""
        self.proxy_running = False
        self.start_proxy_btn.setText("Start Proxy")
        self.proxy_status.setText("Proxy: Stopped")
        self.intercept_checkbox.setEnabled(False)
        self.intercept_checkbox.setChecked(False)
        self.curl_response.append("\n[INFO] Proxy stopped")
    
    def toggle_intercept(self, enabled):
        if self.proxy_running and self.request_handler.proxy_available:
            self.request_handler.enable_intercept(enabled)
            status = "enabled" if enabled else "disabled"
            self.curl_response.append(f"\n[INFO] Request interception {status}")
            # Update interceptor tab status
            if enabled:
                self.intercept_status_label.setText("Intercept: ON")
                self.intercept_status_label.setStyleSheet("color: #00CC00; font-weight: bold;")
            else:
                self.intercept_status_label.setText("Intercept: OFF")
                self.intercept_status_label.setStyleSheet("color: #FF4444; font-weight: bold;")
        else:
            self.intercept_checkbox.setChecked(False)
            if not self.proxy_running:
                self.curl_response.append("\n[WARNING] Start proxy first to enable interception")
            else:
                self.curl_response.append("\n[WARNING] Proxy not available - install mitmproxy for interception")

    def install_proxy_certificate(self):
        """Install mitmproxy CA certificate to Windows trusted root store."""
        import os
        import subprocess
        
        # Find the mitmproxy CA certificate
        cert_path = os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.cer")
        
        if not os.path.exists(cert_path):
            # Try to generate it by starting proxy briefly if cert doesn't exist
            pem_path = os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.pem")
            if os.path.exists(pem_path):
                cert_path = pem_path
            else:
                QMessageBox.warning(
                    self, "Certificate Not Found",
                    "The mitmproxy CA certificate was not found.\n\n"
                    "Start the proxy at least once to generate it, then try again.\n\n"
                    f"Expected location: {cert_path}"
                )
                return
        
        # Install using certutil (requires admin)
        try:
            result = subprocess.run(
                ["certutil", "-addstore", "root", cert_path],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                QMessageBox.information(
                    self, "Certificate Installed",
                    "The mitmproxy CA certificate has been installed to the "
                    "Trusted Root Certification Authorities store.\n\n"
                    "HTTPS interception will now work without certificate errors.\n"
                    "You may need to restart your browser."
                )
                self.curl_response.append("\n[SUCCESS] CA certificate installed to trusted root store")
            elif "Access is denied" in result.stderr or "access is denied" in result.stdout.lower():
                # Need elevation — retry with runas
                self._install_cert_elevated(cert_path)
            else:
                QMessageBox.warning(
                    self, "Installation Failed",
                    f"Failed to install certificate:\n\n{result.stdout}\n{result.stderr}"
                )
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to install certificate: {e}")

    def _install_cert_elevated(self, cert_path):
        """Install certificate with UAC elevation."""
        import ctypes
        import subprocess
        
        try:
            # Use ShellExecute with 'runas' verb for UAC prompt
            ret = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "certutil",
                f'-addstore root "{cert_path}"',
                None, 0  # SW_HIDE
            )
            if ret > 32:
                QMessageBox.information(
                    self, "Certificate Installation",
                    "UAC prompt was shown. If you approved it, the certificate "
                    "is now installed.\n\nRestart your browser for changes to take effect."
                )
                self.curl_response.append("\n[SUCCESS] CA certificate installation initiated (elevated)")
            else:
                QMessageBox.warning(
                    self, "Installation Cancelled",
                    "Certificate installation was cancelled or failed.\n"
                    "You can install manually by running as admin:\n\n"
                    f'certutil -addstore root "{cert_path}"'
                )
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Elevated installation failed: {e}")

    def on_request_intercepted(self, flow_id, http_request):
        """Handle intercepted request"""
        item_text = f"{http_request.method} {http_request.url}"
        self.paused_requests[flow_id] = http_request
        
        # Add to the Interceptor tab list
        self.interceptor_list.addItem(f"[{flow_id}] {item_text}")
        
        # Auto-select the new item and switch to Interceptor tab
        self.interceptor_list.setCurrentRow(self.interceptor_list.count() - 1)
        self.main_tabs.setCurrentIndex(1)  # Interceptor tab
        
        # Update intercept status
        self.intercept_status_label.setText("Intercept: ON")
        self.intercept_status_label.setStyleSheet("color: #00CC00; font-weight: bold;")
        
        self.curl_response.append(f"\n[INTERCEPTED] {item_text}")
    
    def on_request_sent(self, request, response):
        """Handle request sent and response received"""
        import json as json_mod
        
        # Harvest session data from the response
        try:
            req_headers = request.headers if hasattr(request, 'headers') else {}
            resp_headers = response.headers if hasattr(response, 'headers') else {}
            resp_body = response.text if hasattr(response, 'text') else ""
            self.session_harvester.process_response(
                url=request.url,
                request_headers=req_headers,
                response_headers=resp_headers,
                response_body=resp_body,
            )
        except Exception:
            pass
        
        # Update status badge
        status = response.status_code
        if 200 <= status < 300:
            color = "#2E7D32"
        elif 300 <= status < 400:
            color = "#F57C00"
        elif 400 <= status < 500:
            color = "#C62828"
        else:
            color = "#6A1B9A"
        self.status_badge.setText(str(status))
        self.status_badge.setStyleSheet(
            f"QLabel {{ font-weight: bold; border-radius: 3px; padding: 3px; "
            f"background-color: {color}; color: white; }}"
        )
        
        # Update response info bar
        time_ms = response.elapsed_time * 1000
        size = len(response.text)
        self.response_info.setText(
            f"  Status: {status}  •  Time: {time_ms:.0f}ms  •  Size: {size} bytes"
        )
        self.response_info.setStyleSheet(
            f"QLabel {{ color: white; padding: 4px 8px; font-size: 9pt; "
            f"background-color: {color}; }}"
        )
        
        # Populate Body tab (pretty-printed JSON or raw)
        self.response_body.clear()
        try:
            parsed = json_mod.loads(response.text)
            formatted = json_mod.dumps(parsed, indent=2)
            self.response_body.setPlainText(formatted)
        except (json_mod.JSONDecodeError, ValueError):
            self.response_body.setPlainText(response.text)
        
        # Populate Headers tab
        self.response_headers.clear()
        if hasattr(response, 'headers') and response.headers:
            header_lines = []
            for key, value in response.headers.items():
                header_lines.append(f"{key}: {value}")
            self.response_headers.setPlainText("\n".join(header_lines))
        
        # Populate Raw tab
        self.response_raw.clear()
        raw_lines = [f"HTTP/1.1 {status}"]
        if hasattr(response, 'headers') and response.headers:
            for key, value in response.headers.items():
                raw_lines.append(f"{key}: {value}")
        raw_lines.append("")
        raw_lines.append(response.text[:10000])
        self.response_raw.setPlainText("\n".join(raw_lines))
        
        # Also update hidden curl_response for compatibility
        self.curl_response.append(f"[{request.method}] {request.url} → {status}")

    def on_request_failed(self, request, error):
        """Handle failed request"""
        self.status_badge.setText("ERR")
        self.status_badge.setStyleSheet(
            "QLabel { font-weight: bold; border-radius: 3px; padding: 3px; "
            "background-color: #C62828; color: white; }"
        )
        self.response_info.setText(f"  Error: Request failed")
        self.response_info.setStyleSheet(
            "QLabel { color: white; padding: 4px 8px; font-size: 9pt; "
            "background-color: #C62828; }"
        )
        
        self.response_body.clear()
        self.response_body.setPlainText(f"ERROR\n\n{error}")
        self.response_headers.clear()
        self.response_raw.clear()
        self.response_raw.setPlainText(f"Request failed:\n{error}")
        
        self.curl_response.append(f"[ERROR] {request.method} {request.url}: {error}")
    
    def _harvest_from_history(self, request_id):
        """Harvest session data from proxy history when a new request is logged"""
        try:
            if request_id <= 0:
                return
            details = self.request_handler.proxy_engine.get_request_details(request_id)
            if details:
                req_headers = details.get('request_headers', {})
                resp_headers = details.get('response_headers', {})
                resp_body = details.get('response_body', '')
                url = details.get('url', '')
                self.session_harvester.process_response(
                    url=url,
                    request_headers=req_headers,
                    response_headers=resp_headers,
                    response_body=resp_body,
                )
        except Exception:
            pass
    
    def forward_paused_request(self):
        current_row = self.paused_requests_list.currentRow()
        if current_row >= 0:
            item_text = self.paused_requests_list.item(current_row).text()
            flow_id = int(item_text.split(']')[0][1:])  # Extract flow_id from [ID] format
            
            if self.request_handler.forward_request(flow_id):
                self.paused_requests_list.takeItem(current_row)
                del self.paused_requests[flow_id]
                self.curl_response.append(f"\n[INFO] Forwarded request {flow_id}")
                if self.paused_requests_list.count() == 0:
                    self.paused_frame.setVisible(False)
    
    def drop_paused_request(self):
        current_row = self.paused_requests_list.currentRow()
        if current_row >= 0:
            item_text = self.paused_requests_list.item(current_row).text()
            flow_id = int(item_text.split(']')[0][1:])  # Extract flow_id from [ID] format
            
            if self.request_handler.drop_request(flow_id):
                self.paused_requests_list.takeItem(current_row)
                del self.paused_requests[flow_id]
                self.curl_response.append(f"\n[INFO] Dropped request {flow_id}")
                if self.paused_requests_list.count() == 0:
                    self.paused_frame.setVisible(False)
    
    def edit_paused_request(self, item):
        """Edit a paused request"""
        item_text = item.text()
        flow_id = int(item_text.split(']')[0][1:])  # Extract flow_id from [ID] format
        
        if flow_id in self.paused_requests:
            http_request = self.paused_requests[flow_id]
            dialog = EditableRequestDialog(http_request, flow_id, self)
            dialog.request_modified.connect(self.on_request_modified)
            dialog.exec()
    
    def on_request_modified(self, flow_id, modified_request):
        """Handle modified request"""
        if self.request_handler.modify_and_forward_request(flow_id, modified_request):
            # Remove from paused list
            for i in range(self.paused_requests_list.count()):
                item = self.paused_requests_list.item(i)
                if item and f"[{flow_id}]" in item.text():
                    self.paused_requests_list.takeItem(i)
                    break
            del self.paused_requests[flow_id]
            self.curl_response.append(f"\n[INFO] Modified and forwarded request {flow_id}")
    
    def repeat_request(self, times):
        """Repeat current request multiple times"""
        if not self.url_input.text():
            self.curl_response.append("\n[ERROR] Please enter a URL")
            return
        
        request = self.build_http_request()
        self.request_handler.send_multiple(request, times)
        self.curl_response.append(f"\n[INFO] Sending request {times} times...")
    
    def create_history_tab(self):
        """Create request history tab with Burp Suite-style tree view"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create stacked widget to switch between history tree and details view
        self.history_stack = QStackedWidget()
        
        # History tree page
        history_page = QWidget()
        history_layout = QVBoxLayout(history_page)
        
        # Controls
        controls = QHBoxLayout()
        clear_history_btn = QPushButton("Clear History")
        clear_history_btn.clicked.connect(self.clear_history)
        controls.addWidget(clear_history_btn)
        
        self.expand_all_btn = QPushButton("Expand All")
        self.expand_all_btn.clicked.connect(lambda: self.history_tree.expandAll())
        controls.addWidget(self.expand_all_btn)
        
        self.collapse_all_btn = QPushButton("Collapse All")
        self.collapse_all_btn.clicked.connect(lambda: self.history_tree.collapseAll())
        controls.addWidget(self.collapse_all_btn)
        
        controls.addStretch()
        history_layout.addLayout(controls)
        
        # History tree widget (Burp Suite-style site map tree)
        self.history_tree = QTreeWidget()
        self.history_tree.setColumnCount(5)
        self.history_tree.setHeaderLabels(["Host / Path", "Method", "Status", "Timing", "Size"])
        
        # Set column widths - right-side columns sized to fit header text without truncation
        header = self.history_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)  # Host/Path stretches
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)    # Method
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)    # Status
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)    # Timing
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)    # Size
        header.setStretchLastSection(False)
        
        self.history_tree.setColumnWidth(1, 90)   # Method - fits "Method" header + content
        self.history_tree.setColumnWidth(2, 80)   # Status - fits "Status" header + content
        self.history_tree.setColumnWidth(3, 100)  # Timing - fits "Timing" header + content
        self.history_tree.setColumnWidth(4, 90)   # Size - fits "Size" header + content
        
        # Align right-side columns to the right
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        
        self.history_tree.setStyleSheet("""
            QTreeWidget {
                font-family: 'Neuropol X', monospace;
                font-size: 9pt;
            }
            QTreeWidget::item {
                padding: 2px 0;
            }
            QHeaderView::section {
                font-family: 'Neuropol X', monospace;
                font-size: 9pt;
                padding: 4px 6px;
            }
            QTreeWidget::branch:has-children:!has-siblings:closed,
            QTreeWidget::branch:closed:has-children:has-siblings {
                image: none;
                border-image: none;
            }
            QTreeWidget::branch:open:has-children:!has-siblings,
            QTreeWidget::branch:open:has-children:has-siblings {
                image: none;
                border-image: none;
            }
        """)
        
        self.history_tree.itemDoubleClicked.connect(self._on_history_tree_double_click)
        
        # Context menu for history tree
        self.history_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_tree.customContextMenuRequested.connect(self.show_history_context_menu)
        
        history_layout.addWidget(self.history_tree)
        
        # Details page
        self.details_page = self.create_request_details_page()
        
        # Add pages to stack
        self.history_stack.addWidget(history_page)
        self.history_stack.addWidget(self.details_page)
        
        layout.addWidget(self.history_stack)
        
        # Load initial history
        self.refresh_history_table()
        
        return tab
    
    def create_request_details_page(self):
        """Create the request details page that shows within the History tab"""
        page = QWidget()
        layout = QVBoxLayout(page)
        
        # Back button
        back_layout = QHBoxLayout()
        self.back_btn = QPushButton("← Back to History")
        self.back_btn.clicked.connect(self.show_history_table)
        self.back_btn.setFixedWidth(190)
        back_layout.addWidget(self.back_btn)
        back_layout.addStretch()
        layout.addLayout(back_layout)
        
        # Request details content (will be populated dynamically)
        self.details_content = QWidget()
        layout.addWidget(self.details_content)
        
        return page
    
    def show_request_details_inline(self, request_data):
        """Show request details inline within the History tab"""
        # Clear existing content
        if self.details_content.layout():
            while self.details_content.layout().count():
                child = self.details_content.layout().takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
        else:
            self.details_content.setLayout(QVBoxLayout())
        
        layout = self.details_content.layout()
        
        # Header info
        header_layout = QHBoxLayout()
        
        method_label = QLabel(f"Method: {request_data.get('method', 'N/A')}")
        method_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(method_label)
        
        status_code = request_data.get('status_code')
        if status_code:
            color = "#00FF41" if 200 <= status_code < 300 else "#FF4500" if status_code >= 400 else "#FFAA00"
            status_label = QLabel(f"Status: {status_code}")
            status_label.setStyleSheet(f"font-weight: bold; color: {color};")
            header_layout.addWidget(status_label)
        
        response_time = request_data.get('response_time', 0)
        time_label = QLabel(f"Time: {response_time*1000:.2f}ms")
        time_label.setStyleSheet("font-weight: bold; color: #DCDCDC;")
        header_layout.addWidget(time_label)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # URL
        url_label = QLabel(f"URL: {request_data.get('url', 'N/A')}")
        url_label.setStyleSheet("color: #DCDCDC; margin: 5px 0;")
        url_label.setWordWrap(True)
        layout.addWidget(url_label)
        
        # Main content tabs
        tab_widget = QTabWidget()
        
        # Request tab
        request_tab = self.create_inline_request_tab(request_data)
        tab_widget.addTab(request_tab, "Request")
        
        # Response tab
        response_tab = self.create_inline_response_tab(request_data)
        tab_widget.addTab(response_tab, "Response")
        
        # Headers tab
        headers_tab = self.create_inline_headers_tab(request_data)
        tab_widget.addTab(headers_tab, "Headers")
        
        layout.addWidget(tab_widget)
        
        # Switch to details view
        self.history_stack.setCurrentIndex(1)
    
    def create_inline_request_tab(self, request_data):
        """Create request details tab for inline view"""
        widget = QSplitter(Qt.Orientation.Vertical)
        
        # Request info
        info_text = QTextEdit()
        info_text.setMaximumHeight(100)
        info_text.setReadOnly(True)
        
        info_content = f"""Method: {request_data.get('method', 'N/A')}
URL: {request_data.get('url', 'N/A')}
Host: {request_data.get('host', 'N/A')}
Path: {request_data.get('path', 'N/A')}
Size: {request_data.get('request_size', 0)} bytes"""
        
        info_text.setPlainText(info_content)
        widget.addWidget(info_text)
        
        # Request body
        body_label = QLabel("Request Body:")
        body_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        
        body_text = QTextEdit()
        body_text.setReadOnly(True)
        body_text.setFont(QFont("Neuropol X", 10))
        
        request_body = request_data.get('request_body', '')
        if request_body:
            try:
                if request_body.strip().startswith(('{', '[')):
                    formatted_body = json.dumps(json.loads(request_body), indent=2)
                    body_text.setPlainText(formatted_body)
                else:
                    body_text.setPlainText(request_body)
            except:
                body_text.setPlainText(request_body)
        else:
            body_text.setPlainText("No request body")
        
        body_container = QVBoxLayout()
        body_widget = QWidget()
        body_container.addWidget(body_label)
        body_container.addWidget(body_text)
        body_widget.setLayout(body_container)
        
        widget.addWidget(body_widget)
        widget.setSizes([100, 400])
        
        return widget
    
    def create_inline_response_tab(self, request_data):
        """Create response details tab for inline view"""
        widget = QSplitter(Qt.Orientation.Vertical)
        
        # Response info
        info_text = QTextEdit()
        info_text.setMaximumHeight(100)
        info_text.setReadOnly(True)
        
        status_code = request_data.get('status_code', 'N/A')
        content_type = request_data.get('content_type', 'N/A')
        response_size = request_data.get('response_size', 0)
        
        info_content = f"""Status Code: {status_code}
Content-Type: {content_type}
Response Size: {response_size} bytes
Response Time: {request_data.get('response_time', 0)*1000:.2f}ms"""
        
        info_text.setPlainText(info_content)
        widget.addWidget(info_text)
        
        # Response body
        body_label = QLabel("Response Body:")
        body_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        
        body_text = QTextEdit()
        body_text.setReadOnly(True)
        body_text.setFont(QFont("Neuropol X", 10))
        
        response_body = request_data.get('response_body', '')
        if response_body:
            try:
                if response_body.strip().startswith(('{', '[')):
                    formatted_body = json.dumps(json.loads(response_body), indent=2)
                    body_text.setPlainText(formatted_body)
                else:
                    if len(response_body) > 10000:
                        body_text.setPlainText(response_body[:10000] + "\n\n... (truncated)")
                    else:
                        body_text.setPlainText(response_body)
            except:
                if len(response_body) > 10000:
                    body_text.setPlainText(response_body[:10000] + "\n\n... (truncated)")
                else:
                    body_text.setPlainText(response_body)
        else:
            body_text.setPlainText("No response body")
        
        body_container = QVBoxLayout()
        body_widget = QWidget()
        body_container.addWidget(body_label)
        body_container.addWidget(body_text)
        body_widget.setLayout(body_container)
        
        widget.addWidget(body_widget)
        widget.setSizes([100, 400])
        
        return widget
    
    def create_inline_headers_tab(self, request_data):
        """Create headers tab for inline view"""
        widget = QSplitter(Qt.Orientation.Horizontal)
        
        # Request headers
        req_headers_widget = QWidget()
        req_layout = QVBoxLayout(req_headers_widget)
        req_layout.addWidget(QLabel("Request Headers:"))
        
        req_headers_table = QTableWidget()
        req_headers_table.setColumnCount(2)
        req_headers_table.setHorizontalHeaderLabels(["Header", "Value"])
        req_headers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        request_headers = request_data.get('request_headers', {})
        req_headers_table.setRowCount(len(request_headers))
        
        for i, (key, value) in enumerate(request_headers.items()):
            req_headers_table.setItem(i, 0, QTableWidgetItem(str(key)))
            req_headers_table.setItem(i, 1, QTableWidgetItem(str(value)))
        
        req_layout.addWidget(req_headers_table)
        widget.addWidget(req_headers_widget)
        
        # Response headers
        resp_headers_widget = QWidget()
        resp_layout = QVBoxLayout(resp_headers_widget)
        resp_layout.addWidget(QLabel("Response Headers:"))
        
        resp_headers_table = QTableWidget()
        resp_headers_table.setColumnCount(2)
        resp_headers_table.setHorizontalHeaderLabels(["Header", "Value"])
        resp_headers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        response_headers = request_data.get('response_headers', {})
        resp_headers_table.setRowCount(len(response_headers))
        
        for i, (key, value) in enumerate(response_headers.items()):
            resp_headers_table.setItem(i, 0, QTableWidgetItem(str(key)))
            resp_headers_table.setItem(i, 1, QTableWidgetItem(str(value)))
        
        resp_layout.addWidget(resp_headers_table)
        widget.addWidget(resp_headers_widget)
        
        return widget
    
    def show_history_table(self):
        """Switch back to the history table view"""
        self.history_stack.setCurrentIndex(0)
    
    def create_scanner_tab(self):
        """Create vulnerability scanner tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Scanner controls
        controls = QHBoxLayout()
        scan_btn = QPushButton("Scan Current Request")
        scan_btn.clicked.connect(self.scan_current_request)
        controls.addWidget(scan_btn)
        
        clear_findings_btn = QPushButton("Clear Findings")
        clear_findings_btn.clicked.connect(self.clear_findings)
        controls.addWidget(clear_findings_btn)
        controls.addStretch()
        layout.addLayout(controls)
        
        # Findings table
        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels(["Type", "Severity", "Title", "URL"])
        self.findings_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.findings_table)
        
        return tab
    
    def create_decoder_tab(self):
        """Create encoder/decoder tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Input area
        layout.addWidget(QLabel("Input:"))
        self.decoder_input = QTextEdit()
        self.decoder_input.setMaximumHeight(100)
        layout.addWidget(self.decoder_input)
        
        # Method selection
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Method:"))
        self.decoder_method = QComboBox()
        self.decoder_method.addItems([
            "Base64 Encode", "Base64 Decode", "URL Encode", "URL Decode",
            "PowerShell Base64", "PowerShell Decode", "JavaScript CharCode", 
            "JavaScript Decode", "ROT13", "Hex Encode", "Hex Decode",
            "ASCII Encode", "ASCII Decode",
            "Emoji Embed (Hide in emoji)", "Emoji Extract (Recover from emoji)"
        ])
        method_layout.addWidget(self.decoder_method)
        
        encode_btn = QPushButton("Encode/Decode")
        encode_btn.clicked.connect(self.perform_encoding)
        method_layout.addWidget(encode_btn)
        
        auto_decode_btn = QPushButton("Auto-Decode")
        auto_decode_btn.clicked.connect(self.auto_decode)
        method_layout.addWidget(auto_decode_btn)
        
        method_layout.addStretch()
        layout.addLayout(method_layout)
        
        # Output area
        layout.addWidget(QLabel("Output:"))
        self.decoder_output = QTextEdit()
        self.decoder_output.setReadOnly(True)
        layout.addWidget(self.decoder_output)
        
        return tab
    
    def create_sessions_tab(self):
        """Create the Sessions tab for viewing harvested cookies/tokens"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)
        
        # Controls bar
        controls = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_sessions_view)
        controls.addWidget(refresh_btn)
        
        export_btn = QPushButton("Export for Replay")
        export_btn.setToolTip("Copy session tokens formatted for request injection")
        export_btn.clicked.connect(self.export_sessions_for_replay)
        controls.addWidget(export_btn)
        
        findings_btn = QPushButton("Security Findings")
        findings_btn.setToolTip("Analyze harvested tokens for security issues")
        findings_btn.clicked.connect(self.show_session_findings)
        controls.addWidget(findings_btn)
        
        controls.addStretch()
        
        self.session_count_label = QLabel("Tokens: 0")
        self.session_count_label.setStyleSheet("color: #64C8FF; font-weight: bold;")
        controls.addWidget(self.session_count_label)
        
        clear_sessions_btn = QPushButton("Clear")
        clear_sessions_btn.clicked.connect(self.clear_sessions)
        controls.addWidget(clear_sessions_btn)
        
        layout.addLayout(controls)
        
        # Category filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.session_filter_combo = QComboBox()
        self.session_filter_combo.addItems([
            "All", "Session Cookies", "JWT Tokens", "CSRF Tokens",
            "Remember Me", "Analytics/Debug", "Feature/Role", "Unknown"
        ])
        self.session_filter_combo.currentIndexChanged.connect(self.refresh_sessions_view)
        filter_layout.addWidget(self.session_filter_combo)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Sessions table
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(7)
        self.sessions_table.setHorizontalHeaderLabels([
            "Category", "Name", "Value", "Domain", "Source", "Flags", "Last Seen"
        ])
        header = self.sessions_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # Category
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Name
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)           # Value
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)  # Domain
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Source
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Flags
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)  # Last Seen
        
        self.sessions_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.sessions_table.itemDoubleClicked.connect(self.view_token_details)
        
        # Context menu
        self.sessions_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.sessions_table.customContextMenuRequested.connect(self.show_session_context_menu)
        
        layout.addWidget(self.sessions_table)
        
        # Token detail view at bottom
        self.token_detail_text = QTextEdit()
        self.token_detail_text.setReadOnly(True)
        self.token_detail_text.setMaximumHeight(150)
        self.token_detail_text.setStyleSheet(
            "QTextEdit { font-family: 'Neuropol X', monospace; font-size: 9pt; "
            "background-color: #1a1a2e; color: #e0e0e0; }"
        )
        self.token_detail_text.setPlaceholderText("Double-click a token to view details...")
        layout.addWidget(self.token_detail_text)
        
        # Connect harvester signal
        self.session_harvester.tokens_updated.connect(self.refresh_sessions_view)
        
        return tab
    
    def refresh_sessions_view(self):
        """Refresh the sessions table with current harvested data"""
        filter_map = {
            0: None,  # All
            1: 'session',
            2: 'jwt',
            3: 'csrf',
            4: 'remember_me',
            5: 'analytics',
            6: 'feature_role',
            7: 'unknown',
        }
        
        selected_filter = filter_map.get(self.session_filter_combo.currentIndex())
        
        tokens = list(self.session_harvester.tokens.values())
        if selected_filter:
            tokens = [t for t in tokens if t.category == selected_filter]
        
        self.sessions_table.setRowCount(len(tokens))
        self.session_count_label.setText(f"Tokens: {len(self.session_harvester.tokens)}")
        
        category_colors = {
            'session': '#FF6633',
            'jwt': '#FFD700',
            'csrf': '#00BFFF',
            'remember_me': '#9370DB',
            'analytics': '#808080',
            'feature_role': '#32CD32',
            'unknown': '#AAAAAA',
        }
        
        category_labels = {
            'session': 'Session',
            'jwt': 'JWT',
            'csrf': 'CSRF',
            'remember_me': 'Remember Me',
            'analytics': 'Analytics',
            'feature_role': 'Feature/Role',
            'unknown': 'Unknown',
        }
        
        import datetime
        
        for i, token in enumerate(tokens):
            # Category
            cat_item = QTableWidgetItem(category_labels.get(token.category, token.category))
            color = category_colors.get(token.category, '#AAAAAA')
            cat_item.setForeground(Qt.GlobalColor.white)
            cat_item.setBackground(Qt.GlobalColor.darkGray)
            from PyQt6.QtGui import QColor
            cat_item.setForeground(QColor(color))
            self.sessions_table.setItem(i, 0, cat_item)
            
            # Name
            self.sessions_table.setItem(i, 1, QTableWidgetItem(token.name))
            
            # Value (truncated for display)
            value_display = token.value[:50] + "..." if len(token.value) > 50 else token.value
            value_item = QTableWidgetItem(value_display)
            value_item.setToolTip(token.value)
            self.sessions_table.setItem(i, 2, value_item)
            
            # Domain
            self.sessions_table.setItem(i, 3, QTableWidgetItem(token.domain))
            
            # Source
            self.sessions_table.setItem(i, 4, QTableWidgetItem(token.source))
            
            # Flags
            flags = []
            if token.secure:
                flags.append("Secure")
            if token.httponly:
                flags.append("HttpOnly")
            if token.samesite:
                flags.append(f"SS={token.samesite}")
            self.sessions_table.setItem(i, 5, QTableWidgetItem(" | ".join(flags) if flags else "-"))
            
            # Last seen
            last_seen = datetime.datetime.fromtimestamp(token.last_seen).strftime("%H:%M:%S")
            self.sessions_table.setItem(i, 6, QTableWidgetItem(last_seen))
    
    def view_token_details(self, item):
        """Show detailed token information"""
        row = item.row()
        
        filter_map = {
            0: None, 1: 'session', 2: 'jwt', 3: 'csrf',
            4: 'remember_me', 5: 'analytics', 6: 'feature_role', 7: 'unknown',
        }
        selected_filter = filter_map.get(self.session_filter_combo.currentIndex())
        
        tokens = list(self.session_harvester.tokens.values())
        if selected_filter:
            tokens = [t for t in tokens if t.category == selected_filter]
        
        if row >= len(tokens):
            return
        
        token = tokens[row]
        import datetime
        
        details = f"Name: {token.name}\n"
        details += f"Category: {token.category}\n"
        details += f"Domain: {token.domain}\n"
        details += f"Path: {token.path}\n"
        details += f"Source: {token.source}\n"
        details += f"Secure: {token.secure}\n"
        details += f"HttpOnly: {token.httponly}\n"
        details += f"SameSite: {token.samesite or 'Not set'}\n"
        details += f"First Seen: {datetime.datetime.fromtimestamp(token.first_seen).strftime('%Y-%m-%d %H:%M:%S')}\n"
        details += f"Last Seen: {datetime.datetime.fromtimestamp(token.last_seen).strftime('%Y-%m-%d %H:%M:%S')}\n"
        details += f"\nValue:\n{token.value}\n"
        
        # If JWT, decode it
        if token.category == 'jwt' and self.session_harvester._is_jwt(token.value):
            decoded = self.session_harvester.decode_jwt(token.value)
            if decoded:
                details += f"\n--- JWT Decoded ---\n"
                details += f"Header: {json.dumps(decoded['header'], indent=2)}\n"
                details += f"Payload: {json.dumps(decoded['payload'], indent=2)}\n"
                details += f"Signature: {decoded['signature']}\n"
        
        if token.raw_header:
            details += f"\nRaw Set-Cookie:\n{token.raw_header}\n"
        
        self.token_detail_text.setPlainText(details)
    
    def show_session_context_menu(self, position):
        """Context menu for sessions table"""
        from PyQt6.QtWidgets import QMenu
        from PyQt6.QtGui import QAction
        
        item = self.sessions_table.itemAt(position)
        if not item:
            return
        
        menu = QMenu(self)
        
        copy_value_action = QAction("Copy Value", self)
        copy_value_action.triggered.connect(lambda: self._copy_token_value(item.row()))
        menu.addAction(copy_value_action)
        
        copy_cookie_action = QAction("Copy as Cookie Header", self)
        copy_cookie_action.triggered.connect(lambda: self._copy_as_cookie_header(item.row()))
        menu.addAction(copy_cookie_action)
        
        inject_action = QAction("Send to Repeater Headers", self)
        inject_action.triggered.connect(lambda: self._inject_to_repeater(item.row()))
        menu.addAction(inject_action)
        
        menu.exec(self.sessions_table.mapToGlobal(position))
    
    def _get_token_at_row(self, row):
        """Get the token object at a given table row"""
        filter_map = {
            0: None, 1: 'session', 2: 'jwt', 3: 'csrf',
            4: 'remember_me', 5: 'analytics', 6: 'feature_role', 7: 'unknown',
        }
        selected_filter = filter_map.get(self.session_filter_combo.currentIndex())
        
        tokens = list(self.session_harvester.tokens.values())
        if selected_filter:
            tokens = [t for t in tokens if t.category == selected_filter]
        
        if row < len(tokens):
            return tokens[row]
        return None
    
    def _copy_token_value(self, row):
        """Copy token value to clipboard"""
        token = self._get_token_at_row(row)
        if token:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(token.value)
    
    def _copy_as_cookie_header(self, row):
        """Copy token formatted as a Cookie header"""
        token = self._get_token_at_row(row)
        if token:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            if token.source == 'header' and 'bearer' in token.name.lower():
                clipboard.setText(f"Authorization: Bearer {token.value}")
            else:
                clipboard.setText(f"Cookie: {token.name}={token.value}")
    
    def _inject_to_repeater(self, row):
        """Inject the token into the Repeater's headers"""
        token = self._get_token_at_row(row)
        if not token:
            return
        
        current_headers = self.headers_text.toPlainText()
        
        if token.source == 'header' and 'bearer' in token.name.lower():
            new_header = f"Authorization: Bearer {token.value}"
        elif token.source == 'header':
            new_header = f"{token.name}: {token.value}"
        else:
            # Cookie - append to existing Cookie header or create new one
            lines = current_headers.split('\n') if current_headers else []
            cookie_line_idx = None
            for idx, line in enumerate(lines):
                if line.lower().startswith('cookie:'):
                    cookie_line_idx = idx
                    break
            
            if cookie_line_idx is not None:
                # Append to existing Cookie header
                lines[cookie_line_idx] = lines[cookie_line_idx].rstrip() + f"; {token.name}={token.value}"
                self.headers_text.setPlainText('\n'.join(lines))
                self.main_tabs.setCurrentIndex(0)  # Switch to Repeater
                return
            else:
                new_header = f"Cookie: {token.name}={token.value}"
        
        if current_headers:
            self.headers_text.setPlainText(current_headers + '\n' + new_header)
        else:
            self.headers_text.setPlainText(new_header)
        
        self.main_tabs.setCurrentIndex(0)  # Switch to Repeater
    
    def export_sessions_for_replay(self):
        """Export session tokens to clipboard for replay"""
        export_text = self.session_harvester.export_for_replay()
        if export_text:
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(export_text)
            QMessageBox.information(self, "Exported", 
                f"Session tokens copied to clipboard.\n\n{export_text[:200]}...")
        else:
            QMessageBox.information(self, "No Tokens", "No session/JWT/CSRF tokens harvested yet.")
    
    def show_session_findings(self):
        """Show security findings from harvested tokens"""
        findings = self.session_harvester.get_security_findings()
        
        if not findings:
            QMessageBox.information(self, "Security Findings", 
                "No security issues found in harvested tokens.\n\n"
                "Harvest more traffic to detect cookie misconfigurations.")
            return
        
        findings_text = f"Found {len(findings)} security issue(s):\n\n"
        for f in findings:
            findings_text += f"[{f['severity']}] {f['title']}\n"
            findings_text += f"  Domain: {f['domain']}\n"
            findings_text += f"  Detail: {f['detail']}\n\n"
        
        self.token_detail_text.setPlainText(findings_text)
    
    def clear_sessions(self):
        """Clear all harvested sessions"""
        self.session_harvester.clear()
        self.sessions_table.setRowCount(0)
        self.token_detail_text.clear()
        self.session_count_label.setText("Tokens: 0")
    
    def refresh_history_table(self, request_id=None):
        """Refresh the history tree from database (Burp Suite-style site map)"""
        try:
            from urllib.parse import urlparse
            
            history = self.request_handler.proxy_engine.get_history(limit=1000)
            self.history_tree.clear()
            
            # Build tree structure: host -> path segments -> leaf (request)
            # Track host nodes so we can reuse them
            host_nodes = {}  # host -> QTreeWidgetItem
            
            for entry in history:
                url = entry['url']
                parsed = urlparse(url)
                
                # Determine host display (include scheme and port if non-standard)
                scheme = parsed.scheme or 'http'
                host = parsed.hostname or url
                port = parsed.port
                
                if port and not (scheme == 'http' and port == 80) and not (scheme == 'https' and port == 443):
                    host_key = f"{scheme}://{host}:{port}"
                else:
                    host_key = f"{scheme}://{host}"
                
                # Get or create host node
                if host_key not in host_nodes:
                    host_item = QTreeWidgetItem(self.history_tree)
                    host_item.setText(0, host_key)
                    host_item.setForeground(0, QBrush(QColor("#64C8FF")))
                    font = host_item.font(0)
                    font.setBold(True)
                    host_item.setFont(0, font)
                    host_item.setExpanded(True)
                    host_nodes[host_key] = host_item
                
                parent_node = host_nodes[host_key]
                
                # Split path into segments and build intermediate nodes
                path = parsed.path or '/'
                query = parsed.query
                
                # Build path segments (skip empty segments from leading slash)
                segments = [s for s in path.split('/') if s]
                
                # Navigate/create intermediate path nodes
                current_parent = parent_node
                for i, segment in enumerate(segments[:-1] if segments else []):
                    # Look for existing child with this segment name
                    found = None
                    for child_idx in range(current_parent.childCount()):
                        child = current_parent.child(child_idx)
                        # Only match directory nodes (those without request data)
                        if child.text(0) == segment + '/' and child.data(0, Qt.ItemDataRole.UserRole) is None:
                            found = child
                            break
                    
                    if found:
                        current_parent = found
                    else:
                        dir_item = QTreeWidgetItem(current_parent)
                        dir_item.setText(0, segment + '/')
                        dir_item.setForeground(0, QBrush(QColor("#AAAAAA")))
                        dir_item.setExpanded(True)
                        current_parent = dir_item
                
                # Create the leaf node (the actual request)
                leaf_text = segments[-1] if segments else '/'
                if query:
                    leaf_text += f'?{query}'
                
                leaf_item = QTreeWidgetItem(current_parent)
                leaf_item.setText(0, leaf_text)
                leaf_item.setData(0, Qt.ItemDataRole.UserRole, entry['id'])  # Store request ID
                
                # Method column
                leaf_item.setText(1, entry['method'])
                leaf_item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                method_color = {
                    'GET': '#00FF41', 'POST': '#FF6633', 'PUT': '#FFAA00',
                    'DELETE': '#FF4444', 'PATCH': '#AA88FF', 'HEAD': '#888888',
                    'OPTIONS': '#888888'
                }.get(entry['method'], '#DCDCDC')
                leaf_item.setForeground(1, QBrush(QColor(method_color)))
                
                # Status column (color-coded)
                status_code = entry['status_code']
                if status_code:
                    leaf_item.setText(2, str(status_code))
                    leaf_item.setTextAlignment(2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    if 200 <= status_code < 300:
                        leaf_item.setForeground(2, QBrush(QColor("#00FF41")))
                    elif 300 <= status_code < 400:
                        leaf_item.setForeground(2, QBrush(QColor("#FFAA00")))
                    elif status_code >= 400:
                        leaf_item.setForeground(2, QBrush(QColor("#FF4444")))
                else:
                    leaf_item.setText(2, 'N/A')
                    leaf_item.setTextAlignment(2, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                
                # Timing column
                leaf_item.setText(3, f"{entry['response_time']*1000:.0f}ms")
                leaf_item.setTextAlignment(3, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                
                # Size column
                leaf_item.setText(4, f"{entry['response_size']}B")
                leaf_item.setTextAlignment(4, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            
        except Exception as e:
            print(f"Error refreshing history: {e}")
    
    def _on_history_tree_double_click(self, item, column):
        """Handle double-click on history tree item"""
        request_id = item.data(0, Qt.ItemDataRole.UserRole)
        if request_id:
            self.view_request_details_by_id(request_id)
    
    def view_request_details(self, item):
        """View detailed request information (legacy compatibility)"""
        request_id = item.data(0, Qt.ItemDataRole.UserRole)
        if request_id:
            self.view_request_details_by_id(request_id)
    
    def view_request_details_by_id(self, request_id):
        """View detailed request information within the History tab"""
        try:
            if request_id:
                request_data = self.request_handler.proxy_engine.get_request_details(request_id)
                if request_data:
                    self.show_request_details_inline(request_data)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not load request details: {e}")
    
    def show_history_context_menu(self, position):
        """Show context menu for history tree"""
        from PyQt6.QtWidgets import QMenu
        from PyQt6.QtGui import QAction
        
        item = self.history_tree.itemAt(position)
        if item:
            request_id = item.data(0, Qt.ItemDataRole.UserRole)
            if request_id:
                menu = QMenu(self)
                
                view_action = QAction("View Details", self)
                view_action.triggered.connect(lambda: self.view_request_details_by_id(request_id))
                menu.addAction(view_action)
                
                send_to_repeater_action = QAction("Send to Repeater", self)
                send_to_repeater_action.triggered.connect(lambda: self._send_tree_item_to_repeater(request_id))
                menu.addAction(send_to_repeater_action)
                
                menu.exec(self.history_tree.mapToGlobal(position))
    
    def _send_tree_item_to_repeater(self, request_id):
        """Send request from history tree to repeater by request ID"""
        try:
            if request_id:
                request_data = self.request_handler.proxy_engine.get_request_details(request_id)
                if request_data:
                    # Load into repeater
                    self.method_combo.setCurrentText(request_data['method'])
                    self.url_input.setText(request_data['url'])
                    
                    # Load headers
                    headers = request_data.get('request_headers', {})
                    headers_text = '\n'.join([f"{k}: {v}" for k, v in headers.items()])
                    self.headers_text.setPlainText(headers_text)
                    
                    # Load body
                    self.body_text.setPlainText(request_data.get('request_body', ''))
                    
                    # Switch to repeater tab
                    self.main_tabs.setCurrentIndex(0)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not load request: {e}")
    
    def send_to_repeater(self, item):
        """Send request from history to repeater (legacy compatibility)"""
        request_id = item.data(0, Qt.ItemDataRole.UserRole)
        if request_id:
            self._send_tree_item_to_repeater(request_id)
    
    def clear_history(self):
        """Clear request history"""
        self.request_handler.proxy_engine.clear_history()
        self.history_tree.clear()
        self.refresh_history_table()
    
    def scan_current_request(self):
        """Scan current request for vulnerabilities"""
        if not self.url_input.text():
            return
        
        request = self.build_http_request()
        self.request_handler.scan_request(request)
        self.curl_response.append("\n[INFO] Active scan started...")
    
    def clear_findings(self):
        """Clear security findings"""
        self.request_handler.clear_findings()
        self.findings_table.setRowCount(0)
    
    def on_security_finding(self, finding):
        """Handle new security finding"""
        self.update_findings_table()
    
    def on_scan_completed(self, result):
        """Handle scan completion"""
        self.curl_response.append(f"\n[SCAN] Completed - {result['total']} findings")
        self.update_findings_table()
    
    def update_findings_table(self):
        """Update the findings table"""
        findings = self.request_handler.get_findings()
        self.findings_table.setRowCount(len(findings))
        
        for i, finding in enumerate(findings):
            self.findings_table.setItem(i, 0, QTableWidgetItem(finding['type']))
            self.findings_table.setItem(i, 1, QTableWidgetItem(finding['severity']))
            self.findings_table.setItem(i, 2, QTableWidgetItem(finding['title']))
            self.findings_table.setItem(i, 3, QTableWidgetItem(finding['url']))
    
    def perform_encoding(self):
        """Perform encoding/decoding"""
        text = self.decoder_input.toPlainText().strip()
        if not text:
            return

        method = self.decoder_method.currentText()

        try:
            if method == "Emoji Embed (Hide in emoji)":
                if '|||' not in text:
                    self.decoder_output.setPlainText(
                        "Error: to embed, provide input as: <carrier_emojis>|||<secret_text>\n"
                        "Example: 😀😃😄😁|||Hello World!"
                    )
                    return
                carrier, secret = text.split('|||', 1)
                carrier = carrier.strip()
                secret = secret
                try:
                    result = ObfuscationEngine.embed_in_emojis(carrier, secret)
                    self.decoder_output.setPlainText(result)
                except Exception as e:
                    self.decoder_output.setPlainText(f"Error embedding: {e}")

            elif method == "Emoji Extract (Recover from emoji)":
                try:
                    result = ObfuscationEngine.extract_from_emojis(text)
                    self.decoder_output.setPlainText(result)
                except Exception as e:
                    self.decoder_output.setPlainText(f"Error extracting hidden data: {e}")

            else:
                if "Decode" in method or method.endswith("Decode"):
                    result = ObfuscationEngine.deobfuscate(text, method)
                else:
                    result = ObfuscationEngine.obfuscate(text, method)

                self.decoder_output.setPlainText(result)
        except Exception as e:
            self.decoder_output.setPlainText(f"Error: {str(e)}")
    
    def auto_decode(self):
        """Auto-detect and decode obfuscated text"""
        text = self.decoder_input.toPlainText().strip()
        if not text:
            return
        
        try:
            results = ObfuscationEngine.auto_detect_and_decode(text)
            
            if not results:
                self.decoder_output.setPlainText("No obfuscation detected")
                return
            
            output = "Auto-detection results:\n\n"
            for method, decoded, confidence in results:
                output += f"Method: {method} (Confidence: {confidence:.1%})\n"
                output += f"Result: {decoded}\n\n"
            
            self.decoder_output.setPlainText(output)
        except Exception as e:
            self.decoder_output.setPlainText(f"Error: {str(e)}")

class EditableRequestDialog(QDialog):
    request_modified = pyqtSignal(int, object)  # flow_id, modified_request
    
    def __init__(self, http_request, flow_id, parent=None):
        super().__init__(parent)
        self.http_request = http_request
        self.flow_id = flow_id
        self.setWindowTitle(f"Edit Request - {http_request.method} {http_request.url}")
        self.setMinimumSize(800, 600)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Method and URL
        method_url_layout = QHBoxLayout()
        method_url_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self.method_combo.setCurrentText(self.http_request.method)
        method_url_layout.addWidget(self.method_combo)
        
        method_url_layout.addWidget(QLabel("URL:"))
        self.url_edit = QLineEdit(self.http_request.url)
        method_url_layout.addWidget(self.url_edit)
        layout.addLayout(method_url_layout)
        
        # Headers
        layout.addWidget(QLabel("Headers:"))
        self.headers_edit = QTextEdit()
        headers_text = '\n'.join([f"{k}: {v}" for k, v in self.http_request.headers.items()])
        self.headers_edit.setPlainText(headers_text)
        self.headers_edit.setMaximumHeight(150)
        layout.addWidget(self.headers_edit)
        
        # Body
        layout.addWidget(QLabel("Body:"))
        self.body_edit = QTextEdit()
        self.body_edit.setPlainText(self.http_request.data)
        layout.addWidget(self.body_edit)
        
        # Buttons
        button_layout = QHBoxLayout()
        forward_btn = QPushButton("Forward Modified")
        forward_btn.clicked.connect(self.forward_modified)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(forward_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
    
    def forward_modified(self):
        # Parse headers
        headers = {}
        headers_text = self.headers_edit.toPlainText().strip()
        if headers_text:
            for line in headers_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Create modified request
        modified_request = HttpRequest(
            method=self.method_combo.currentText(),
            url=self.url_edit.text(),
            headers=headers,
            data=self.body_edit.toPlainText(),
            auth=self.http_request.auth,
            timeout=self.http_request.timeout,
            allow_redirects=self.http_request.allow_redirects,
            verify=self.http_request.verify
        )
        
        self.request_modified.emit(self.flow_id, modified_request)
        self.accept()