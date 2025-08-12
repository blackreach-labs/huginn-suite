# app/widgets/request_viewer.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QTextEdit, QLabel, QPushButton, QTableWidget, 
                            QTableWidgetItem, QHeaderView, QSplitter, QWidget)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
import json

class RequestViewerDialog(QDialog):
    def __init__(self, request_data, parent=None):
        super().__init__(parent)
        self.request_data = request_data
        self.setWindowTitle(f"Request Details - {request_data.get('method', 'GET')} {request_data.get('url', '')}")
        self.setMinimumSize(800, 600)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header info
        header_layout = QHBoxLayout()
        
        method_label = QLabel(f"Method: {self.request_data.get('method', 'N/A')}")
        method_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(method_label)
        
        status_code = self.request_data.get('status_code')
        if status_code:
            color = "#00FF41" if 200 <= status_code < 300 else "#FF4500" if status_code >= 400 else "#FFAA00"
            status_label = QLabel(f"Status: {status_code}")
            status_label.setStyleSheet(f"font-weight: bold; color: {color};")
            header_layout.addWidget(status_label)
        
        response_time = self.request_data.get('response_time', 0)
        time_label = QLabel(f"Time: {response_time*1000:.2f}ms")
        time_label.setStyleSheet("font-weight: bold; color: #DCDCDC;")
        header_layout.addWidget(time_label)
        
        header_layout.addStretch()
        layout.addLayout(header_layout)
        
        # URL
        url_label = QLabel(f"URL: {self.request_data.get('url', 'N/A')}")
        url_label.setStyleSheet("color: #DCDCDC; margin: 5px 0;")
        url_label.setWordWrap(True)
        layout.addWidget(url_label)
        
        # Main content tabs
        tab_widget = QTabWidget()
        
        # Request tab
        request_tab = self.create_request_tab()
        tab_widget.addTab(request_tab, "Request")
        
        # Response tab
        response_tab = self.create_response_tab()
        tab_widget.addTab(response_tab, "Response")
        
        # Headers tab
        headers_tab = self.create_headers_tab()
        tab_widget.addTab(headers_tab, "Headers")
        
        layout.addWidget(tab_widget)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setFixedWidth(100)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)
        
        self.apply_theme()
    
    def create_request_tab(self):
        """Create request details tab"""
        widget = QSplitter(Qt.Orientation.Vertical)
        
        # Request info
        info_text = QTextEdit()
        info_text.setMaximumHeight(100)
        info_text.setReadOnly(True)
        
        info_content = f"""Method: {self.request_data.get('method', 'N/A')}
URL: {self.request_data.get('url', 'N/A')}
Host: {self.request_data.get('host', 'N/A')}
Path: {self.request_data.get('path', 'N/A')}
Size: {self.request_data.get('request_size', 0)} bytes"""
        
        info_text.setPlainText(info_content)
        widget.addWidget(info_text)
        
        # Request body
        body_label = QLabel("Request Body:")
        body_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        
        body_text = QTextEdit()
        body_text.setReadOnly(True)
        body_text.setFont(QFont("Consolas", 10))
        
        request_body = self.request_data.get('request_body', '')
        if request_body:
            # Try to format JSON
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
    
    def create_response_tab(self):
        """Create response details tab"""
        widget = QSplitter(Qt.Orientation.Vertical)
        
        # Response info
        info_text = QTextEdit()
        info_text.setMaximumHeight(100)
        info_text.setReadOnly(True)
        
        status_code = self.request_data.get('status_code', 'N/A')
        content_type = self.request_data.get('content_type', 'N/A')
        response_size = self.request_data.get('response_size', 0)
        
        info_content = f"""Status Code: {status_code}
Content-Type: {content_type}
Response Size: {response_size} bytes
Response Time: {self.request_data.get('response_time', 0)*1000:.2f}ms"""
        
        info_text.setPlainText(info_content)
        widget.addWidget(info_text)
        
        # Response body
        body_label = QLabel("Response Body:")
        body_label.setStyleSheet("font-weight: bold; color: #64C8FF;")
        
        body_text = QTextEdit()
        body_text.setReadOnly(True)
        body_text.setFont(QFont("Consolas", 10))
        
        response_body = self.request_data.get('response_body', '')
        if response_body:
            # Try to format JSON/HTML
            try:
                if response_body.strip().startswith(('{', '[')):
                    formatted_body = json.dumps(json.loads(response_body), indent=2)
                    body_text.setPlainText(formatted_body)
                else:
                    # Limit display for large responses
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
    
    def create_headers_tab(self):
        """Create headers tab with request and response headers"""
        widget = QSplitter(Qt.Orientation.Horizontal)
        
        # Request headers
        req_headers_widget = QWidget()
        req_layout = QVBoxLayout(req_headers_widget)
        req_layout.addWidget(QLabel("Request Headers:"))
        
        req_headers_table = QTableWidget()
        req_headers_table.setColumnCount(2)
        req_headers_table.setHorizontalHeaderLabels(["Header", "Value"])
        req_headers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        request_headers = self.request_data.get('request_headers', {})
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
        
        response_headers = self.request_data.get('response_headers', {})
        resp_headers_table.setRowCount(len(response_headers))
        
        for i, (key, value) in enumerate(response_headers.items()):
            resp_headers_table.setItem(i, 0, QTableWidgetItem(str(key)))
            resp_headers_table.setItem(i, 1, QTableWidgetItem(str(value)))
        
        resp_layout.addWidget(resp_headers_table)
        widget.addWidget(resp_headers_widget)
        
        return widget
    
    def apply_theme(self):
        """Apply dark theme to the dialog"""
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
                color: #DCDCDC;
            }
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: #DCDCDC;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #555;
                color: #64C8FF;
            }
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #555;
                color: #DCDCDC;
                padding: 5px;
            }
            QTableWidget {
                background-color: #1e1e1e;
                border: 1px solid #555;
                gridline-color: #555;
            }
            QTableWidget::item {
                color: #DCDCDC;
                padding: 5px;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #64C8FF;
                padding: 5px;
                border: 1px solid #555;
            }
            QPushButton {
                background-color: #3c3c3c;
                border: 2px solid #64C8FF;
                border-radius: 5px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #555;
            }
        """)