# app/widgets/curl_widget.py
from PyQt6.QtWidgets import (QWidget, QPushButton, QLabel, QLineEdit, QTextEdit, 
                            QVBoxLayout, QHBoxLayout, QFrame, QCheckBox, QListWidget, 
                            QSplitter, QComboBox, QSpinBox, QTabWidget, QGridLayout, 
                            QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView,
                            QMessageBox, QDialog, QStackedWidget)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
import json
from app.core.logger import logger

try:
    from app.core.unified_request_handler import UnifiedRequestHandler
    from app.core.http_client import HttpRequest, HttpResponse
    from app.core.obfuscation_engine import ObfuscationEngine
    from app.widgets.request_viewer import RequestViewerDialog
except ImportError:
    from ..core.unified_request_handler import UnifiedRequestHandler
    from ..core.http_client import HttpRequest, HttpResponse
    from ..core.obfuscation_engine import ObfuscationEngine
    from ..widgets.request_viewer import RequestViewerDialog

class CurlWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.request_handler = UnifiedRequestHandler()
        
        # Connect signals
        self.request_handler.request_sent.connect(self.on_request_sent)
        self.request_handler.request_intercepted.connect(self.on_request_intercepted)
        self.request_handler.proxy_engine.history_updated.connect(self.refresh_history_table)
        self.request_handler.finding_detected.connect(self.on_security_finding)
        self.request_handler.scan_completed.connect(self.on_scan_completed)
        
        self.paused_requests = {}
        self.proxy_running = False
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Control panel
        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        
        # Proxy controls
        self.start_proxy_btn = QPushButton("Start Proxy")
        self.start_proxy_btn.clicked.connect(self.toggle_proxy)
        control_layout.addWidget(self.start_proxy_btn)
        
        self.proxy_status = QLabel("Proxy: Stopped")
        self.proxy_status.setStyleSheet("color: #FF4500;")
        control_layout.addWidget(self.proxy_status)
        
        self.intercept_checkbox = QCheckBox("Intercept requests")
        self.intercept_checkbox.toggled.connect(self.toggle_intercept)
        self.intercept_checkbox.setEnabled(False)  # Disabled until proxy starts
        control_layout.addWidget(self.intercept_checkbox)
        
        control_layout.addStretch()
        layout.addWidget(control_frame)
        
        # Connect proxy signals
        self.request_handler.proxy_engine.proxy_started.connect(self.on_proxy_started)
        self.request_handler.proxy_engine.proxy_stopped.connect(self.on_proxy_stopped)
        
        self.proxy_running = False
        
        # Tab widget for different views
        main_tabs = QTabWidget()
        
        # Repeater tab
        repeater_tab = self.create_repeater_tab()
        main_tabs.addTab(repeater_tab, "Repeater")
        
        # History tab
        history_tab = self.create_history_tab()
        main_tabs.addTab(history_tab, "History")
        
        # Scanner tab
        scanner_tab = self.create_scanner_tab()
        main_tabs.addTab(scanner_tab, "Scanner")
        
        # Decoder tab
        decoder_tab = self.create_decoder_tab()
        main_tabs.addTab(decoder_tab, "Decoder")
        
        layout.addWidget(main_tabs)
    
    def create_repeater_tab(self):
        """Create the main repeater tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Request builder
        left_panel = self.create_request_builder()
        
        # Right panel - Response and controls
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        # Response area
        right_layout.addWidget(QLabel("Response:"))
        self.curl_response = QTextEdit()
        self.curl_response.setReadOnly(True)
        self.curl_response.setPlaceholderText("Response will appear here...")
        right_layout.addWidget(self.curl_response)
        
        # Paused requests
        right_layout.addWidget(QLabel("Paused Requests:"))
        self.paused_requests_list = QListWidget()
        self.paused_requests_list.setMaximumHeight(100)
        self.paused_requests_list.itemDoubleClicked.connect(self.edit_paused_request)
        right_layout.addWidget(self.paused_requests_list)
        
        paused_controls = QHBoxLayout()
        forward_btn = QPushButton("Forward")
        forward_btn.clicked.connect(self.forward_paused_request)
        drop_btn = QPushButton("Drop")
        drop_btn.clicked.connect(self.drop_paused_request)
        paused_controls.addWidget(forward_btn)
        paused_controls.addWidget(drop_btn)
        right_layout.addLayout(paused_controls)
        
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([500, 700])
        
        layout.addWidget(splitter)
        return tab
    
    def create_request_builder(self):
        """Create the GUI request builder"""
        frame = QFrame()
        layout = QVBoxLayout(frame)
        
        # Basic request info
        basic_frame = QFrame()
        basic_layout = QGridLayout(basic_frame)
        
        # Method
        basic_layout.addWidget(QLabel("Method:"), 0, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        basic_layout.addWidget(self.method_combo, 0, 1)
        
        # URL
        basic_layout.addWidget(QLabel("URL:"), 1, 0)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://api.example.com/endpoint")
        basic_layout.addWidget(self.url_input, 1, 1)
        
        layout.addWidget(basic_frame)
        
        # Tabs for different sections
        tabs = QTabWidget()
        
        # Headers tab
        headers_tab = QWidget()
        headers_layout = QVBoxLayout(headers_tab)
        
        headers_layout.addWidget(QLabel("Headers (one per line, format: Key: Value):"))
        self.headers_text = QTextEdit()
        self.headers_text.setMaximumHeight(100)
        self.headers_text.setPlaceholderText("Content-Type: application/json\nAuthorization: Bearer token123")
        headers_layout.addWidget(self.headers_text)
        
        # Common headers buttons
        common_headers = QHBoxLayout()
        self.json_btn = QPushButton("JSON")
        self.json_btn.setCheckable(True)
        self.json_btn.clicked.connect(lambda: self.toggle_header("Content-Type: application/json", self.json_btn))
        
        self.form_btn = QPushButton("Form")
        self.form_btn.setCheckable(True)
        self.form_btn.clicked.connect(lambda: self.toggle_header("Content-Type: application/x-www-form-urlencoded", self.form_btn))
        
        self.auth_btn = QPushButton("Auth")
        self.auth_btn.setCheckable(True)
        self.auth_btn.clicked.connect(lambda: self.toggle_header("Authorization: Bearer ", self.auth_btn))
        
        common_headers.addWidget(self.json_btn)
        common_headers.addWidget(self.form_btn)
        common_headers.addWidget(self.auth_btn)
        common_headers.addStretch()
        headers_layout.addLayout(common_headers)
        
        tabs.addTab(headers_tab, "Headers")
        
        # Body tab
        body_tab = QWidget()
        body_layout = QVBoxLayout(body_tab)
        
        body_layout.addWidget(QLabel("Request Body:"))
        self.body_text = QTextEdit()
        self.body_text.setMaximumHeight(120)
        self.body_text.setPlaceholderText('{"key": "value"}')
        body_layout.addWidget(self.body_text)
        
        # Body format buttons
        body_formats = QHBoxLayout()
        json_format_btn = QPushButton("JSON Format")
        json_format_btn.clicked.connect(self.format_json)
        url_encode_btn = QPushButton("URL Encode")
        url_encode_btn.clicked.connect(self.url_encode_body)
        
        body_formats.addWidget(json_format_btn)
        body_formats.addWidget(url_encode_btn)
        body_formats.addStretch()
        body_layout.addLayout(body_formats)
        
        tabs.addTab(body_tab, "Body")
        
        # Auth tab
        auth_tab = QWidget()
        auth_layout = QGridLayout(auth_tab)
        
        auth_layout.addWidget(QLabel("Username:"), 0, 0)
        self.username_input = QLineEdit()
        auth_layout.addWidget(self.username_input, 0, 1)
        
        auth_layout.addWidget(QLabel("Password:"), 1, 0)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        auth_layout.addWidget(self.password_input, 1, 1)
        
        tabs.addTab(auth_tab, "Auth")
        
        # Options tab
        options_tab = QWidget()
        options_layout = QGridLayout(options_tab)
        
        options_layout.addWidget(QLabel("Timeout (seconds):"), 0, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(30)
        options_layout.addWidget(self.timeout_spin, 0, 1)
        
        self.follow_redirects_cb = QCheckBox("Follow redirects")
        self.follow_redirects_cb.setChecked(True)
        options_layout.addWidget(self.follow_redirects_cb, 1, 0, 1, 2)
        
        self.verify_ssl_cb = QCheckBox("Verify SSL certificates")
        self.verify_ssl_cb.setChecked(True)
        options_layout.addWidget(self.verify_ssl_cb, 2, 0, 1, 2)
        
        tabs.addTab(options_tab, "Options")
        
        layout.addWidget(tabs)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        send_btn = QPushButton("Send Request")
        send_btn.clicked.connect(self.send_request)
        button_layout.addWidget(send_btn)
        
        pause_send_btn = QPushButton("Send with Pause")
        pause_send_btn.clicked.connect(self.send_with_pause)
        button_layout.addWidget(pause_send_btn)
        
        # Intruder functionality
        repeat_btn = QPushButton("Repeat 5x")
        repeat_btn.clicked.connect(lambda: self.repeat_request(5))
        button_layout.addWidget(repeat_btn)
        
        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(clear_btn)
        
        layout.addLayout(button_layout)
        
        # Generated curl command preview
        layout.addWidget(QLabel("Generated curl command:"))
        self.curl_preview = QTextEdit()
        self.curl_preview.setMaximumHeight(60)
        self.curl_preview.setReadOnly(True)
        layout.addWidget(self.curl_preview)
        
        # Update preview when inputs change
        self.method_combo.currentTextChanged.connect(self.update_curl_preview)
        self.url_input.textChanged.connect(self.update_curl_preview)
        self.headers_text.textChanged.connect(self.update_curl_preview)
        self.body_text.textChanged.connect(self.update_curl_preview)
        
        return frame
    
    def toggle_header(self, header, button):
        current = self.headers_text.toPlainText()
        lines = current.split('\n') if current else []
        header_key = header.split(':')[0]
        
        if button.isChecked():
            # Add header if not present
            if not any(line.startswith(header_key + ':') for line in lines):
                if current:
                    self.headers_text.setPlainText(current + '\n' + header)
                else:
                    self.headers_text.setPlainText(header)
        else:
            # Remove header
            filtered_lines = [line for line in lines if not line.startswith(header_key + ':')]
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
        self.method_combo.setCurrentText("GET")
        self.timeout_spin.setValue(30)
        self.follow_redirects_cb.setChecked(True)
        self.verify_ssl_cb.setChecked(True)
    
    def toggle_proxy(self):
        """Start or stop the proxy server"""
        if not self.proxy_running:
            if self.request_handler.start_proxy(8080):
                self.curl_response.append("\n[INFO] Starting proxy server on port 8080...")
            else:
                self.curl_response.append("\n[ERROR] Failed to start proxy - install mitmproxy: pip install mitmproxy")
        else:
            self.request_handler.stop_proxy()
            self.curl_response.append("\n[INFO] Stopping proxy server...")
    
    def on_proxy_started(self, port):
        """Handle proxy started event"""
        self.proxy_running = True
        self.start_proxy_btn.setText("Stop Proxy")
        self.proxy_status.setText(f"Proxy: Running on port {port}")
        self.proxy_status.setStyleSheet("color: #00FF41;")
        self.intercept_checkbox.setEnabled(True)
        self.curl_response.append(f"\n[SUCCESS] Proxy started on port {port}")
        self.curl_response.append(f"\n[INFO] Configure browser proxy: 127.0.0.1:{port}")
    
    def on_proxy_stopped(self):
        """Handle proxy stopped event"""
        self.proxy_running = False
        self.start_proxy_btn.setText("Start Proxy")
        self.proxy_status.setText("Proxy: Stopped")
        self.proxy_status.setStyleSheet("color: #FF4500;")
        self.intercept_checkbox.setEnabled(False)
        self.intercept_checkbox.setChecked(False)
        self.curl_response.append("\n[INFO] Proxy stopped")
    
    def toggle_intercept(self, enabled):
        if self.proxy_running and self.request_handler.proxy_available:
            self.request_handler.enable_intercept(enabled)
            status = "enabled" if enabled else "disabled"
            self.curl_response.append(f"\n[INFO] Request interception {status}")
        else:
            self.intercept_checkbox.setChecked(False)
            if not self.proxy_running:
                self.curl_response.append("\n[WARNING] Start proxy first to enable interception")
            else:
                self.curl_response.append("\n[WARNING] Proxy not available - install mitmproxy for interception")
    
    def on_request_intercepted(self, flow_id, http_request):
        """Handle intercepted request"""
        item_text = f"{http_request.method} {http_request.url}"
        self.paused_requests[flow_id] = http_request
        self.paused_requests_list.addItem(f"[{flow_id}] {item_text}")
        self.curl_response.append(f"\n[INTERCEPTED] {item_text}")
    
    def on_request_sent(self, request, response):
        """Handle request sent and response received"""
        self.curl_response.append(f"\n[REQUEST] {request.method} {request.url}")
        self.curl_response.append(f"[STATUS] {response.status_code}")
        self.curl_response.append(f"[TIME] {response.elapsed_time*1000:.2f}ms")
        self.curl_response.append(f"\n[RESPONSE]\n{response.text[:1000]}{'...' if len(response.text) > 1000 else ''}")
        self.curl_response.append("\n" + "="*50)
    
    def forward_paused_request(self):
        current_row = self.paused_requests_list.currentRow()
        if current_row >= 0:
            item_text = self.paused_requests_list.item(current_row).text()
            flow_id = int(item_text.split(']')[0][1:])  # Extract flow_id from [ID] format
            
            if self.request_handler.forward_request(flow_id):
                self.paused_requests_list.takeItem(current_row)
                del self.paused_requests[flow_id]
                self.curl_response.append(f"\n[INFO] Forwarded request {flow_id}")
    
    def drop_paused_request(self):
        current_row = self.paused_requests_list.currentRow()
        if current_row >= 0:
            item_text = self.paused_requests_list.item(current_row).text()
            flow_id = int(item_text.split(']')[0][1:])  # Extract flow_id from [ID] format
            
            if self.request_handler.drop_request(flow_id):
                self.paused_requests_list.takeItem(current_row)
                del self.paused_requests[flow_id]
                self.curl_response.append(f"\n[INFO] Dropped request {flow_id}")
    
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
        """Create request history tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Create stacked widget to switch between history table and details view
        self.history_stack = QStackedWidget()
        
        # History table page
        history_page = QWidget()
        history_layout = QVBoxLayout(history_page)
        
        # Controls
        controls = QHBoxLayout()
        clear_history_btn = QPushButton("Clear History")
        clear_history_btn.clicked.connect(self.clear_history)
        controls.addWidget(clear_history_btn)
        controls.addStretch()
        history_layout.addLayout(controls)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels(["Time", "Method", "URL", "Status", "Timing", "Size(bytes)"])
        # Set custom column widths
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)  # Time
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)  # Method
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch) # URL (stretches)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)  # Status
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)  # Timing
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)  # Size
        
        # Set fixed column widths
        self.history_table.setColumnWidth(0, 260)  # Time
        self.history_table.setColumnWidth(1, 100)   # Method
        self.history_table.setColumnWidth(3, 85)   # Status
        self.history_table.setColumnWidth(4, 130)  # Timing
        self.history_table.setColumnWidth(5, 200)  # Size
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.itemDoubleClicked.connect(self.view_request_details)
        
        # Context menu for history table
        self.history_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self.show_history_context_menu)
        
        history_layout.addWidget(self.history_table)
        
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
        self.back_btn.setFixedWidth(150)
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
        body_text.setFont(QFont("Consolas", 10))
        
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
        body_text.setFont(QFont("Consolas", 10))
        
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
    
    def refresh_history_table(self, request_id=None):
        """Refresh the history table from database"""
        try:
            history = self.request_handler.proxy_engine.get_history(limit=1000)
            self.history_table.setRowCount(len(history))
            
            for i, entry in enumerate(history):
                # Store request ID in first column for reference
                id_item = QTableWidgetItem(entry['formatted_time'])
                id_item.setData(Qt.ItemDataRole.UserRole, entry['id'])  # Store ID
                self.history_table.setItem(i, 0, id_item)
                
                self.history_table.setItem(i, 1, QTableWidgetItem(entry['method']))
                
                # Truncate long URLs
                url = entry['url']
                if len(url) > 80:
                    url = url[:77] + "..."
                self.history_table.setItem(i, 2, QTableWidgetItem(url))
                
                # Color-code status
                status_item = QTableWidgetItem(str(entry['status_code']) if entry['status_code'] else 'N/A')
                if entry['status_code']:
                    if 200 <= entry['status_code'] < 300:
                        status_item.setForeground(Qt.GlobalColor.green)
                    elif entry['status_code'] >= 400:
                        status_item.setForeground(Qt.GlobalColor.red)
                    else:
                        status_item.setForeground(Qt.GlobalColor.yellow)
                self.history_table.setItem(i, 3, status_item)
                
                self.history_table.setItem(i, 4, QTableWidgetItem(f"{entry['response_time']*1000:.0f}ms"))
                self.history_table.setItem(i, 5, QTableWidgetItem(f"{entry['response_size']} bytes"))
        except Exception as e:
            print(f"Error refreshing history: {e}")
    
    def view_request_details(self, item):
        """View detailed request information within the History tab"""
        try:
            # Get request ID from the first column
            row = item.row()
            id_item = self.history_table.item(row, 0)
            if id_item:
                request_id = id_item.data(Qt.ItemDataRole.UserRole)
                if request_id:
                    request_data = self.request_handler.proxy_engine.get_request_details(request_id)
                    if request_data:
                        self.show_request_details_inline(request_data)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not load request details: {e}")
    
    def show_history_context_menu(self, position):
        """Show context menu for history table"""
        from PyQt6.QtWidgets import QMenu
        from PyQt6.QtGui import QAction
        
        item = self.history_table.itemAt(position)
        if item:
            menu = QMenu(self)
            
            view_action = QAction("View Details", self)
            view_action.triggered.connect(lambda: self.view_request_details(item))
            menu.addAction(view_action)
            
            send_to_repeater_action = QAction("Send to Repeater", self)
            send_to_repeater_action.triggered.connect(lambda: self.send_to_repeater(item))
            menu.addAction(send_to_repeater_action)
            
            menu.exec(self.history_table.mapToGlobal(position))
    
    def send_to_repeater(self, item):
        """Send request from history to repeater"""
        try:
            row = item.row()
            id_item = self.history_table.item(row, 0)
            if id_item:
                request_id = id_item.data(Qt.ItemDataRole.UserRole)
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
                        parent_tabs = self.parent()
                        while parent_tabs and not isinstance(parent_tabs, QTabWidget):
                            parent_tabs = parent_tabs.parent()
                        if parent_tabs:
                            parent_tabs.setCurrentIndex(0)  # Repeater tab
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not load request: {e}")
    
    def clear_history(self):
        """Clear request history"""
        self.request_handler.proxy_engine.clear_history()
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