# app/widgets/cert_transparency_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QTextEdit, QProgressBar, 
                            QGroupBox, QTableWidget, QTableWidgetItem, QTabWidget)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from app.core.cert_transparency import cert_transparency
import json

class CertTransparencyWorker(QThread):
    """Worker thread for certificate transparency search"""
    
    progress_update = pyqtSignal(str)
    search_completed = pyqtSignal(dict)
    
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
    
    def run(self):
        """Execute certificate transparency search"""
        try:
            results = cert_transparency.search_certificates(
                self.domain,
                progress_callback=self.progress_update.emit
            )
            self.search_completed.emit(results)
        except Exception as e:
            self.search_completed.emit({'error': str(e)})

class CertTransparencyWidget(QWidget):
    """Widget for Certificate Transparency log searches"""
    
    search_completed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main group
        main_group = QGroupBox("🔍 Certificate Transparency Search")
        main_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        main_layout = QVBoxLayout(main_group)
        
        # Search input
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Domain:"))
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.domain_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
        """)
        
        self.search_button = QPushButton("🔍 Search CT Logs")
        self.search_button.clicked.connect(self.start_search)
        self.search_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 255, 100, 150);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-size: 11pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(100, 255, 100, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                color: #888;
            }
        """)
        
        search_layout.addWidget(self.domain_input)
        search_layout.addWidget(self.search_button)
        
        # Progress section
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #555;
                border-radius: 4px;
                text-align: center;
                color: white;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: rgba(100, 200, 255, 150);
                border-radius: 3px;
            }
        """)
        
        self.status_label = QLabel("Enter domain to search Certificate Transparency logs")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: rgba(0, 0, 0, 100);
            }
            QTabBar::tab {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                padding: 8px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(100, 200, 255, 150);
                color: #000;
            }
        """)
        
        # Subdomains tab
        self.subdomains_text = QTextEdit()
        self.subdomains_text.setReadOnly(True)
        self.subdomains_text.setStyleSheet(self._get_text_style())
        self.results_tabs.addTab(self.subdomains_text, "📋 Subdomains")
        
        # Certificates tab
        self.certificates_table = QTableWidget()
        self.certificates_table.setColumnCount(5)
        self.certificates_table.setHorizontalHeaderLabels([
            "ID", "Issuer", "Common Name", "Valid From", "Valid To"
        ])
        self.certificates_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                gridline-color: #555;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                padding: 4px;
                border: none;
                font-weight: bold;
            }
        """)
        self.results_tabs.addTab(self.certificates_table, "📜 Certificates")
        
        # Statistics tab
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setStyleSheet(self._get_text_style())
        self.results_tabs.addTab(self.stats_text, "📊 Statistics")
        
        # Add to main layout
        main_layout.addLayout(search_layout)
        main_layout.addLayout(progress_layout)
        main_layout.addWidget(self.results_tabs)
        
        layout.addWidget(main_group)
        
    def _get_text_style(self):
        return """
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
        """
    
    def start_search(self):
        """Start certificate transparency search"""
        domain = self.domain_input.text().strip()
        if not domain:
            self.status_label.setText("❌ Please enter a domain")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        # Start worker thread
        self.worker = CertTransparencyWorker(domain)
        self.worker.progress_update.connect(self.on_progress_update)
        self.worker.search_completed.connect(self.on_search_completed)
        self.worker.start()
        
        # Update UI
        self.search_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.clear_results()
        
        self.status_label.setText("🔍 Searching Certificate Transparency logs...")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
    
    def on_progress_update(self, message):
        """Handle progress updates"""
        self.status_label.setText(message)
    
    def on_search_completed(self, results):
        """Handle search completion"""
        self.search_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if 'error' in results:
            self.status_label.setText(f"❌ Error: {results['error']}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        # Display results
        self.display_subdomains(results.get('subdomains', []))
        self.display_certificates(results.get('certificates', []))
        self.display_statistics(results.get('stats', {}), results.get('sources', {}))
        
        # Update status
        subdomain_count = len(results.get('subdomains', []))
        cert_count = len(results.get('certificates', []))
        
        self.status_label.setText(f"✅ Found {subdomain_count} subdomains from {cert_count} certificates")
        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
        
        # Emit completion signal
        self.search_completed.emit(results)
    
    def display_subdomains(self, subdomains):
        """Display discovered subdomains"""
        if not subdomains:
            self.subdomains_text.setPlainText("No subdomains found")
            return
        
        # Format subdomains with numbering
        formatted_text = f"Found {len(subdomains)} subdomains:\n\n"
        
        for i, subdomain in enumerate(subdomains, 1):
            formatted_text += f"{i:3d}. {subdomain}\n"
        
        self.subdomains_text.setPlainText(formatted_text)
    
    def display_certificates(self, certificates):
        """Display certificate information"""
        self.certificates_table.setRowCount(len(certificates))
        
        for row, cert in enumerate(certificates):
            # Certificate ID
            id_item = QTableWidgetItem(str(cert.get('id', 'N/A')))
            self.certificates_table.setItem(row, 0, id_item)
            
            # Issuer
            issuer = cert.get('issuer', 'N/A')
            if len(issuer) > 30:
                issuer = issuer[:27] + "..."
            issuer_item = QTableWidgetItem(issuer)
            self.certificates_table.setItem(row, 1, issuer_item)
            
            # Common Name
            cn = cert.get('common_name', cert.get('name_value', 'N/A'))
            if len(cn) > 30:
                cn = cn[:27] + "..."
            cn_item = QTableWidgetItem(cn)
            self.certificates_table.setItem(row, 2, cn_item)
            
            # Valid From
            not_before = cert.get('not_before', 'N/A')
            if 'T' in not_before:
                not_before = not_before.split('T')[0]
            from_item = QTableWidgetItem(not_before)
            self.certificates_table.setItem(row, 3, from_item)
            
            # Valid To
            not_after = cert.get('not_after', 'N/A')
            if 'T' in not_after:
                not_after = not_after.split('T')[0]
            to_item = QTableWidgetItem(not_after)
            self.certificates_table.setItem(row, 4, to_item)
        
        self.certificates_table.resizeColumnsToContents()
    
    def display_statistics(self, stats, sources):
        """Display search statistics"""
        stats_text = "Certificate Transparency Search Statistics\n"
        stats_text += "=" * 45 + "\n\n"
        
        # General stats
        stats_text += f"Total Subdomains Found: {stats.get('total_subdomains', 0)}\n"
        stats_text += f"Total Certificates: {stats.get('total_certificates', 0)}\n"
        stats_text += f"Sources Used: {stats.get('sources_used', 0)}\n\n"
        
        # Source breakdown
        stats_text += "Results by Source:\n"
        stats_text += "-" * 20 + "\n"
        
        for source, count in sources.items():
            stats_text += f"{source}: {count} certificates\n"
        
        if not sources:
            stats_text += "No source data available\n"
        
        # Additional info
        stats_text += "\nCertificate Transparency Logs:\n"
        stats_text += "-" * 30 + "\n"
        stats_text += "• crt.sh - Certificate search database\n"
        stats_text += "• Certspotter - Real-time CT monitoring\n"
        stats_text += "\nNote: Results may include expired certificates\n"
        
        self.stats_text.setPlainText(stats_text)
    
    def clear_results(self):
        """Clear all result displays"""
        self.subdomains_text.clear()
        self.certificates_table.setRowCount(0)
        self.stats_text.clear()