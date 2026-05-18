from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextBrowser, QFrame, QGroupBox,
                            QProgressBar)
from PyQt6.QtCore import pyqtSignal, QThreadPool

from app.core.people_intel_engine import (
    SocialProfilesWorker,
    ProfessionalNetworksWorker,
    PublicRecordsWorker,
    ContactDiscoveryWorker,
    UsernameSearchWorker,
    EmailEnumerationWorker,
    PhoneLookupWorker,
    FullPersonIntelWorker,
)


class PeopleSearchComponent(QWidget):
    search_started = pyqtSignal(str, str)
    search_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_worker = None
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup people search UI"""
        layout = QHBoxLayout(self)
        
        # Left panel - controls
        left_panel = self.create_controls_panel()
        layout.addWidget(left_panel)
        
        # Right panel - output
        right_panel = self.create_output_panel()
        layout.addWidget(right_panel, 2)

    def create_controls_panel(self):
        """Create controls panel"""
        panel = QFrame()
        panel.setFixedWidth(300)
        layout = QVBoxLayout(panel)
        
        # Target input
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("Person/Username:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("johndoe or John Doe")
        target_layout.addWidget(self.target_input)

        target_layout.addWidget(QLabel("Domain (optional):"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("company.com")
        target_layout.addWidget(self.domain_input)
        
        layout.addWidget(target_group)
        
        # Search modules
        modules_group = QGroupBox("People Search Tools")
        modules_layout = QVBoxLayout(modules_group)
        
        buttons = [
            ("Social Profiles", self.run_social_profiles),
            ("Professional Networks", self.run_professional_networks),
            ("Public Records", self.run_public_records),
            ("Contact Discovery", self.run_contact_discovery),
            ("Username Search", self.run_username_search),
            ("Email Enumeration", self.run_email_enumeration),
            ("Phone Lookup", self.run_phone_lookup),
            ("Full Person Intel", self.run_full_person_intel),
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            modules_layout.addWidget(btn)

        # Stop button
        self.stop_btn = QPushButton("\u25a0 Stop")
        self.stop_btn.setMinimumHeight(35)
        self.stop_btn.clicked.connect(self.stop_search)
        self.stop_btn.setEnabled(False)
        modules_layout.addWidget(self.stop_btn)
        
        layout.addWidget(modules_group)
        layout.addStretch()
        
        return panel

    def create_output_panel(self):
        """Create output panel"""
        panel = QFrame()
        layout = QVBoxLayout(panel)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        layout.addWidget(self.progress_bar)
        
        self.output_text = QTextBrowser()
        self.output_text.setReadOnly(True)
        self.output_text.setOpenExternalLinks(True)
        self.output_text.setPlaceholderText("People search results will appear here...")
        layout.addWidget(self.output_text)
        
        return panel

    # ------------------------------------------------------------------
    # Worker management
    # ------------------------------------------------------------------
    def _start_worker(self, worker):
        """Start a worker on the thread pool"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.setHtml(
                "<p style='color: #FFA500;'>\u26a0 Please enter a target</p>"
            )
            return

        if self.current_worker:
            self.current_worker.stop()

        self.output_text.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Searching...")
        self.stop_btn.setEnabled(True)

        worker.signals.output.connect(self.append_output)
        worker.signals.error.connect(self.append_output)
        worker.signals.progress.connect(self._on_progress)
        worker.signals.finished.connect(self._on_finished)
        self.current_worker = worker

        QThreadPool.globalInstance().start(worker)

    def _on_progress(self, value: int):
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"Progress: {value}%")

    def _on_finished(self):
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete")
        self.stop_btn.setEnabled(False)

        if self.current_worker and hasattr(self.current_worker, 'results'):
            self.search_completed.emit(self.current_worker.results)
        self.current_worker = None

    def stop_search(self):
        """Stop the running search"""
        if self.current_worker:
            self.current_worker.stop()
            self.append_output(
                "<p style='color: #FFA500;'>\u26a0 Search stopped by user</p>"
            )
        self.stop_btn.setEnabled(False)

    def append_output(self, html: str):
        """Append HTML output to the text widget"""
        self.output_text.append(html)
        scrollbar = self.output_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    # ------------------------------------------------------------------
    # Tool launchers
    # ------------------------------------------------------------------
    def run_social_profiles(self):
        target = self.target_input.text().strip()
        if not target:
            return
        self.search_started.emit(target, "Social Profiles")
        worker = SocialProfilesWorker(target)
        self._start_worker(worker)

    def run_professional_networks(self):
        target = self.target_input.text().strip()
        if not target:
            return
        self.search_started.emit(target, "Professional Networks")
        worker = ProfessionalNetworksWorker(target)
        self._start_worker(worker)

    def run_public_records(self):
        target = self.target_input.text().strip()
        if not target:
            return
        self.search_started.emit(target, "Public Records")
        worker = PublicRecordsWorker(target)
        self._start_worker(worker)

    def run_contact_discovery(self):
        target = self.target_input.text().strip()
        domain = self.domain_input.text().strip()
        if not target:
            return
        self.search_started.emit(target, "Contact Discovery")
        worker = ContactDiscoveryWorker(target, domain=domain)
        self._start_worker(worker)

    def run_username_search(self):
        target = self.target_input.text().strip()
        if not target:
            return
        self.search_started.emit(target, "Username Search")
        worker = UsernameSearchWorker(target)
        self._start_worker(worker)

    def run_email_enumeration(self):
        target = self.target_input.text().strip()
        if not target:
            return
        self.search_started.emit(target, "Email Enumeration")
        worker = EmailEnumerationWorker(target)
        self._start_worker(worker)

    def run_phone_lookup(self):
        target = self.target_input.text().strip()
        if not target:
            return
        self.search_started.emit(target, "Phone Lookup")
        worker = PhoneLookupWorker(target)
        self._start_worker(worker)

    def run_full_person_intel(self):
        target = self.target_input.text().strip()
        domain = self.domain_input.text().strip()
        if not target:
            return
        self.search_started.emit(target, "Full Person Intel")
        worker = FullPersonIntelWorker(target, domain=domain)
        self._start_worker(worker)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------
    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 10px;
                border: 1px solid rgba(100, 200, 255, 50);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton:disabled {
                background-color: rgba(20, 20, 20, 100);
                border: 1px solid rgba(80, 80, 80, 100);
                color: #666;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QTextBrowser {
                background-color: rgba(0, 0, 0, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                font-family: 'Courier New', monospace;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                margin-top: 10px;
                color: #64C8FF;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QProgressBar {
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                text-align: center;
                color: #DCDCDC;
                background-color: rgba(0, 0, 0, 150);
            }
            QProgressBar::chunk {
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #64C8FF, stop:1 #00FF41
                );
                border-radius: 4px;
            }
        """)
