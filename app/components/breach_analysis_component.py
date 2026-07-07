from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFrame, QGroupBox,
                            QProgressBar, QCheckBox)
from PyQt6.QtCore import pyqtSignal, QThreadPool
from PyQt6.QtGui import QFont

from app.core.breach_intel_engine import BreachIntelWorker


class BreachAnalysisComponent(QWidget):
    analysis_started = pyqtSignal(str, str)
    analysis_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_worker = None
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup breach analysis UI"""
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
        
        target_layout.addWidget(QLabel("Email/Domain:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("email@domain.com")
        target_layout.addWidget(self.target_input)
        
        layout.addWidget(target_group)

        # Phase selection
        phases_group = QGroupBox("Analysis Phases")
        phases_layout = QVBoxLayout(phases_group)

        self.phase_checks = {}
        phase_options = [
            ("hibp", "Have I Been Pwned"),
            ("dehashed", "DeHashed Search"),
            ("local_db", "Local Breach DB"),
            ("dark_web", "Dark Web Monitor"),
            ("doc_exposure", "Document Exposure"),
        ]
        for key, label in phase_options:
            cb = QCheckBox(label)
            cb.setChecked(True)
            self.phase_checks[key] = cb
            phases_layout.addWidget(cb)

        layout.addWidget(phases_group)
        
        # Breach intelligence modules
        modules_group = QGroupBox("Breach Intelligence")
        modules_layout = QVBoxLayout(modules_group)
        
        buttons = [
            ("Have I Been Pwned", self.run_hibp_check),
            ("DeHashed Search", self.run_dehashed),
            ("Local Breach DB", self.run_local_breach_db),
            ("Dark Web Monitor", self.run_dark_web_monitor),
            ("Leaked Documents", self.run_leaked_docs),
            ("Full Breach Intel", self.run_full_breach_intel),
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            modules_layout.addWidget(btn)

        # Stop button
        self.stop_btn = QPushButton("⬛ Stop Analysis")
        self.stop_btn.setMinimumHeight(35)
        self.stop_btn.clicked.connect(self.stop_analysis)
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
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Neuropol X", 9))
        self.output_text.setPlaceholderText("Breach analysis results will appear here...")
        layout.addWidget(self.output_text)
        
        return panel

    # ------------------------------------------------------------------
    # Worker management
    # ------------------------------------------------------------------
    def _start_worker(self, phases: list):
        """Start a breach intel worker with the given phases"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.setHtml(
                "<p style='color: #FFA500;'>⚠ Please enter a target email or domain</p>"
            )
            return

        # Stop any running worker
        if self.current_worker:
            self.current_worker.stop()

        self.output_text.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Analyzing...")
        self.stop_btn.setEnabled(True)

        self.analysis_started.emit(target, ", ".join(phases))

        worker = BreachIntelWorker(target, phases)
        worker.signals.output.connect(self.append_output)
        worker.signals.error.connect(self.append_output)
        worker.signals.progress.connect(self._on_progress)
        worker.signals.finished.connect(self._on_finished)
        self.current_worker = worker

        QThreadPool.globalInstance().start(worker)

    def _on_progress(self, value: int):
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"Phase progress: {value}%")

    def _on_finished(self):
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete")
        self.stop_btn.setEnabled(False)

        if self.current_worker:
            self.analysis_completed.emit(self.current_worker.results)
        self.current_worker = None

    def stop_analysis(self):
        """Stop the running analysis"""
        if self.current_worker:
            self.current_worker.stop()
            self.append_output(
                "<p style='color: #FFA500;'>⚠ Analysis stopped by user</p>"
            )
        self.stop_btn.setEnabled(False)

    def append_output(self, html: str):
        """Append HTML output to the text widget"""
        self.output_text.append(html)
        # Auto-scroll to bottom
        scrollbar = self.output_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    # ------------------------------------------------------------------
    # Individual phase launchers
    # ------------------------------------------------------------------
    def run_hibp_check(self):
        self._start_worker(["hibp"])

    def run_dehashed(self):
        self._start_worker(["dehashed"])

    def run_local_breach_db(self):
        self._start_worker(["local_db"])

    def run_dark_web_monitor(self):
        self._start_worker(["dark_web"])

    def run_leaked_docs(self):
        self._start_worker(["doc_exposure"])

    def run_full_breach_intel(self):
        """Run all selected phases"""
        selected = [key for key, cb in self.phase_checks.items() if cb.isChecked()]
        if not selected:
            selected = ["hibp", "dehashed", "local_db", "dark_web", "doc_exposure"]
        self._start_worker(selected)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------
    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass
