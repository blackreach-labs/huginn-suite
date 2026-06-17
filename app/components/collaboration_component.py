# app/components/collaboration_component.py
"""Collaboration UI Component.

Provides a team collaboration interface for exporting and importing
encrypted engagement packages (.huginn files). Integrated as a File menu dialog.

Features:
- Export dialog with passphrase input, finding/evidence selector checkboxes
- Import dialog with file picker and passphrase input
- Progress bars for export/import operations
- Integrity validation status display

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
"""

from typing import List, Optional

from PyQt6.QtCore import Qt, pyqtSignal, QThread
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.core.collaboration_manager import CollaborationManager


# ---------------------------------------------------------------------------
# Stylesheet constants
# ---------------------------------------------------------------------------

DIALOG_STYLE = """
    QDialog {
        background-color: #1e1e2e;
    }
    QLabel {
        color: #e0e0e0;
        font-size: 10pt;
    }
    QLineEdit {
        background-color: #2b2b3d;
        border: 1px solid #555;
        border-radius: 4px;
        padding: 6px;
        color: #e0e0e0;
        font-size: 10pt;
    }
    QLineEdit:focus {
        border: 2px solid #64C8FF;
    }
    QPushButton {
        background-color: #2b2b3d;
        border: 1px solid #555;
        border-radius: 4px;
        padding: 8px 16px;
        color: #e0e0e0;
        font-size: 10pt;
    }
    QPushButton:hover {
        background-color: #3a3a4d;
        border: 1px solid #64C8FF;
    }
    QPushButton:pressed {
        background-color: #64C8FF;
        color: #000000;
    }
    QPushButton#primaryBtn {
        background-color: rgba(100, 200, 255, 150);
        border: 1px solid #64C8FF;
        color: #000000;
        font-weight: bold;
    }
    QPushButton#primaryBtn:hover {
        background-color: rgba(100, 200, 255, 200);
    }
    QPushButton#primaryBtn:disabled {
        background-color: #3a3a4d;
        border: 1px solid #555;
        color: #888;
    }
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
        padding: 0 5px;
        color: #64C8FF;
    }
    QCheckBox {
        color: #e0e0e0;
        font-size: 10pt;
        spacing: 6px;
    }
    QCheckBox::indicator {
        width: 16px;
        height: 16px;
        border: 2px solid #555;
        border-radius: 3px;
        background-color: #2b2b3d;
    }
    QCheckBox::indicator:checked {
        border: 2px solid #64C8FF;
        background-color: #64C8FF;
    }
    QProgressBar {
        border: 1px solid #555;
        border-radius: 4px;
        background-color: #2b2b3d;
        text-align: center;
        color: #e0e0e0;
        font-size: 9pt;
        min-height: 20px;
    }
    QProgressBar::chunk {
        background-color: #64C8FF;
        border-radius: 3px;
    }
    QScrollArea {
        border: none;
        background-color: transparent;
    }
"""


# ---------------------------------------------------------------------------
# Export Worker Thread
# ---------------------------------------------------------------------------

class _ExportWorker(QThread):
    """Background thread for export operations."""

    finished = pyqtSignal(bool)

    def __init__(
        self,
        manager: CollaborationManager,
        engagement_id: str,
        passphrase: str,
        output_path: str,
        engagement_base_path: str,
        selected_findings: Optional[List[int]],
        selected_evidence: Optional[List[int]],
    ):
        super().__init__()
        self._manager = manager
        self._engagement_id = engagement_id
        self._passphrase = passphrase
        self._output_path = output_path
        self._engagement_base_path = engagement_base_path
        self._selected_findings = selected_findings
        self._selected_evidence = selected_evidence

    def run(self):
        result = self._manager.export_engagement(
            engagement_id=self._engagement_id,
            passphrase=self._passphrase,
            output_path=self._output_path,
            engagement_base_path=self._engagement_base_path,
            selected_findings=self._selected_findings,
            selected_evidence=self._selected_evidence,
        )
        self.finished.emit(result)


# ---------------------------------------------------------------------------
# Import Worker Thread
# ---------------------------------------------------------------------------

class _ImportWorker(QThread):
    """Background thread for import operations."""

    finished = pyqtSignal(str)  # new_engagement_id or empty on failure

    def __init__(
        self,
        manager: CollaborationManager,
        package_path: str,
        passphrase: str,
        engagements_base_path: str,
    ):
        super().__init__()
        self._manager = manager
        self._package_path = package_path
        self._passphrase = passphrase
        self._engagements_base_path = engagements_base_path

    def run(self):
        result = self._manager.import_engagement(
            package_path=self._package_path,
            passphrase=self._passphrase,
            engagements_base_path=self._engagements_base_path,
        )
        self.finished.emit(result or "")


# ---------------------------------------------------------------------------
# Export Dialog
# ---------------------------------------------------------------------------

class ExportDialog(QDialog):
    """Dialog for exporting an engagement as an encrypted package.

    Provides passphrase input, finding/evidence selector checkboxes,
    output file picker, and a progress bar during export.
    """

    export_started = pyqtSignal()
    export_completed = pyqtSignal(bool)

    def __init__(
        self,
        collaboration_manager: CollaborationManager,
        engagement_id: str,
        engagement_base_path: str,
        findings: Optional[List[dict]] = None,
        evidence: Optional[List[dict]] = None,
        parent=None,
    ):
        """Initialize the ExportDialog.

        Args:
            collaboration_manager: CollaborationManager instance.
            engagement_id: UUID of the engagement to export.
            engagement_base_path: Filesystem path to engagement directory.
            findings: List of finding dicts with 'id' and 'title' keys.
            evidence: List of evidence dicts with 'id' and 'title' keys.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self._manager = collaboration_manager
        self._engagement_id = engagement_id
        self._engagement_base_path = engagement_base_path
        self._findings = findings or []
        self._evidence = evidence or []
        self._worker: Optional[_ExportWorker] = None

        self.setWindowTitle("Export Engagement Package")
        self.setMinimumWidth(500)
        self.setMinimumHeight(450)
        self.setStyleSheet(DIALOG_STYLE)
        self._build_ui()
        self._connect_signals()

    def _build_ui(self):
        """Construct the dialog layout."""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Title
        title = QLabel("Export Engagement Package")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Passphrase group
        passphrase_group = QGroupBox("Encryption")
        passphrase_layout = QFormLayout(passphrase_group)
        self._passphrase_input = QLineEdit()
        self._passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._passphrase_input.setPlaceholderText("Enter passphrase (AES-256-GCM)")
        passphrase_layout.addRow("Passphrase:", self._passphrase_input)
        self._passphrase_confirm = QLineEdit()
        self._passphrase_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._passphrase_confirm.setPlaceholderText("Confirm passphrase")
        passphrase_layout.addRow("Confirm:", self._passphrase_confirm)
        layout.addWidget(passphrase_group)

        # Selective export - Findings
        if self._findings:
            findings_group = QGroupBox("Select Findings to Export")
            findings_layout = QVBoxLayout(findings_group)
            self._select_all_findings = QCheckBox("Select All")
            self._select_all_findings.setChecked(True)
            findings_layout.addWidget(self._select_all_findings)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setMaximumHeight(120)
            scroll_widget = QWidget()
            scroll_inner = QVBoxLayout(scroll_widget)
            scroll_inner.setSpacing(4)
            self._finding_checkboxes: List[QCheckBox] = []
            for finding in self._findings:
                cb = QCheckBox(f"[{finding.get('id', '?')}] {finding.get('title', 'Untitled')}")
                cb.setChecked(True)
                self._finding_checkboxes.append(cb)
                scroll_inner.addWidget(cb)
            scroll_inner.addStretch()
            scroll.setWidget(scroll_widget)
            findings_layout.addWidget(scroll)
            layout.addWidget(findings_group)

            self._select_all_findings.toggled.connect(self._toggle_all_findings)

        # Selective export - Evidence
        if self._evidence:
            evidence_group = QGroupBox("Select Evidence to Export")
            evidence_layout = QVBoxLayout(evidence_group)
            self._select_all_evidence = QCheckBox("Select All")
            self._select_all_evidence.setChecked(True)
            evidence_layout.addWidget(self._select_all_evidence)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setMaximumHeight(120)
            scroll_widget = QWidget()
            scroll_inner = QVBoxLayout(scroll_widget)
            scroll_inner.setSpacing(4)
            self._evidence_checkboxes: List[QCheckBox] = []
            for ev in self._evidence:
                cb = QCheckBox(f"[{ev.get('id', '?')}] {ev.get('title', 'Untitled')}")
                cb.setChecked(True)
                self._evidence_checkboxes.append(cb)
                scroll_inner.addWidget(cb)
            scroll_inner.addStretch()
            scroll.setWidget(scroll_widget)
            evidence_layout.addWidget(scroll)
            layout.addWidget(evidence_group)

            self._select_all_evidence.toggled.connect(self._toggle_all_evidence)

        # Output path
        output_group = QGroupBox("Output File")
        output_layout = QHBoxLayout(output_group)
        self._output_path_input = QLineEdit()
        self._output_path_input.setPlaceholderText("Select output file path...")
        self._output_path_input.setReadOnly(True)
        output_layout.addWidget(self._output_path_input)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_output)
        output_layout.addWidget(browse_btn)
        layout.addWidget(output_group)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setVisible(False)
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        layout.addWidget(self._progress_bar)

        # Status label
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_label)

        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self._export_btn = QPushButton("Export")
        self._export_btn.setObjectName("primaryBtn")
        self._export_btn.clicked.connect(self._start_export)
        btn_layout.addWidget(self._export_btn)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        layout.addWidget(self._create_button_frame(btn_layout))

    def _create_button_frame(self, layout: QHBoxLayout) -> QFrame:
        """Wrap button layout in a QFrame."""
        frame = QFrame()
        frame.setLayout(layout)
        return frame

    def _connect_signals(self):
        """Connect collaboration manager progress signals."""
        self._manager.export_progress.connect(self._on_export_progress)

    def _toggle_all_findings(self, checked: bool):
        """Toggle all finding checkboxes."""
        if hasattr(self, "_finding_checkboxes"):
            for cb in self._finding_checkboxes:
                cb.setChecked(checked)

    def _toggle_all_evidence(self, checked: bool):
        """Toggle all evidence checkboxes."""
        if hasattr(self, "_evidence_checkboxes"):
            for cb in self._evidence_checkboxes:
                cb.setChecked(checked)

    def _browse_output(self):
        """Open file dialog to select output path."""
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Engagement Package",
            "",
            "Huginn Package (*.huginn);;All Files (*)",
        )
        if path:
            if not path.endswith(".huginn"):
                path += ".huginn"
            self._output_path_input.setText(path)

    def _start_export(self):
        """Validate inputs and start the export operation."""
        passphrase = self._passphrase_input.text().strip()
        confirm = self._passphrase_confirm.text().strip()
        output_path = self._output_path_input.text().strip()

        if not passphrase:
            self._show_error("Please enter a passphrase.")
            return
        if passphrase != confirm:
            self._show_error("Passphrases do not match.")
            return
        if len(passphrase) < 8:
            self._show_error("Passphrase must be at least 8 characters.")
            return
        if not output_path:
            self._show_error("Please select an output file path.")
            return

        # Gather selected findings/evidence
        selected_findings = self._get_selected_findings()
        selected_evidence = self._get_selected_evidence()

        # Disable controls and show progress
        self._export_btn.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._status_label.setText("Exporting...")
        self._status_label.setStyleSheet("color: #64C8FF;")
        self.export_started.emit()

        # Run export in background thread
        self._worker = _ExportWorker(
            manager=self._manager,
            engagement_id=self._engagement_id,
            passphrase=passphrase,
            output_path=output_path,
            engagement_base_path=self._engagement_base_path,
            selected_findings=selected_findings,
            selected_evidence=selected_evidence,
        )
        self._worker.finished.connect(self._on_export_finished)
        self._worker.start()

    def _get_selected_findings(self) -> Optional[List[int]]:
        """Get list of selected finding IDs, or None for all."""
        if not self._findings:
            return None
        if hasattr(self, "_select_all_findings") and self._select_all_findings.isChecked():
            return None
        selected = []
        for i, cb in enumerate(self._finding_checkboxes):
            if cb.isChecked():
                selected.append(self._findings[i].get("id", i))
        return selected if selected else None

    def _get_selected_evidence(self) -> Optional[List[int]]:
        """Get list of selected evidence IDs, or None for all."""
        if not self._evidence:
            return None
        if hasattr(self, "_select_all_evidence") and self._select_all_evidence.isChecked():
            return None
        selected = []
        for i, cb in enumerate(self._evidence_checkboxes):
            if cb.isChecked():
                selected.append(self._evidence[i].get("id", i))
        return selected if selected else None

    def _on_export_progress(self, current: int, total: int):
        """Update progress bar from manager signal."""
        if total > 0:
            pct = int((current / total) * 100)
            self._progress_bar.setValue(pct)
            self._status_label.setText(f"Exporting... ({current}/{total} files)")

    def _on_export_finished(self, success: bool):
        """Handle export completion."""
        self._worker = None
        self._export_btn.setEnabled(True)
        if success:
            self._progress_bar.setValue(100)
            self._status_label.setText("✓ Export completed successfully")
            self._status_label.setStyleSheet("color: #00FF41; font-weight: bold;")
            self.export_completed.emit(True)
        else:
            self._status_label.setText("✗ Export failed")
            self._status_label.setStyleSheet("color: #FF5555; font-weight: bold;")
            self.export_completed.emit(False)

    def _show_error(self, message: str):
        """Display a validation error to the user."""
        self._status_label.setText(f"⚠ {message}")
        self._status_label.setStyleSheet("color: #FFD700;")


# ---------------------------------------------------------------------------
# Import Dialog
# ---------------------------------------------------------------------------

class ImportDialog(QDialog):
    """Dialog for importing an encrypted engagement package.

    Provides file picker, passphrase input, progress bar,
    and integrity validation status display.
    """

    import_started = pyqtSignal()
    import_completed = pyqtSignal(str)  # new_engagement_id or empty

    def __init__(
        self,
        collaboration_manager: CollaborationManager,
        engagements_base_path: str,
        parent=None,
    ):
        """Initialize the ImportDialog.

        Args:
            collaboration_manager: CollaborationManager instance.
            engagements_base_path: Base directory where engagements are stored.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self._manager = collaboration_manager
        self._engagements_base_path = engagements_base_path
        self._worker: Optional[_ImportWorker] = None

        self.setWindowTitle("Import Engagement Package")
        self.setMinimumWidth(480)
        self.setMinimumHeight(350)
        self.setStyleSheet(DIALOG_STYLE)
        self._build_ui()
        self._connect_signals()

    def _build_ui(self):
        """Construct the dialog layout."""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Title
        title = QLabel("Import Engagement Package")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # File picker
        file_group = QGroupBox("Package File")
        file_layout = QHBoxLayout(file_group)
        self._file_path_input = QLineEdit()
        self._file_path_input.setPlaceholderText("Select .huginn package file...")
        self._file_path_input.setReadOnly(True)
        file_layout.addWidget(self._file_path_input)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_file)
        file_layout.addWidget(browse_btn)
        layout.addWidget(file_group)

        # Passphrase
        passphrase_group = QGroupBox("Decryption")
        passphrase_layout = QFormLayout(passphrase_group)
        self._passphrase_input = QLineEdit()
        self._passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._passphrase_input.setPlaceholderText("Enter passphrase to decrypt")
        passphrase_layout.addRow("Passphrase:", self._passphrase_input)
        layout.addWidget(passphrase_group)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setVisible(False)
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        layout.addWidget(self._progress_bar)

        # Integrity validation status
        self._validation_frame = QFrame()
        self._validation_frame.setVisible(False)
        val_layout = QVBoxLayout(self._validation_frame)
        val_layout.setContentsMargins(8, 8, 8, 8)
        self._validation_title = QLabel("Integrity Validation")
        self._validation_title.setStyleSheet(
            "font-size: 11pt; font-weight: bold; color: #64C8FF;"
        )
        val_layout.addWidget(self._validation_title)
        self._validation_status = QLabel("")
        val_layout.addWidget(self._validation_status)
        layout.addWidget(self._validation_frame)

        # Status label
        self._status_label = QLabel("")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._status_label)

        # Spacer
        layout.addStretch()

        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self._import_btn = QPushButton("Import")
        self._import_btn.setObjectName("primaryBtn")
        self._import_btn.clicked.connect(self._start_import)
        btn_layout.addWidget(self._import_btn)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        frame = QFrame()
        frame.setLayout(btn_layout)
        layout.addWidget(frame)

    def _connect_signals(self):
        """Connect collaboration manager progress signals."""
        self._manager.import_progress.connect(self._on_import_progress)

    def _browse_file(self):
        """Open file dialog to select a .huginn package file."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Engagement Package",
            "",
            "Huginn Package (*.huginn);;All Files (*)",
        )
        if path:
            self._file_path_input.setText(path)

    def _start_import(self):
        """Validate inputs and start the import operation."""
        file_path = self._file_path_input.text().strip()
        passphrase = self._passphrase_input.text().strip()

        if not file_path:
            self._show_error("Please select a package file.")
            return
        if not passphrase:
            self._show_error("Please enter the decryption passphrase.")
            return

        # Disable controls and show progress
        self._import_btn.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._validation_frame.setVisible(True)
        self._validation_status.setText("Decrypting and validating...")
        self._validation_status.setStyleSheet("color: #64C8FF;")
        self._status_label.setText("Importing...")
        self._status_label.setStyleSheet("color: #64C8FF;")
        self.import_started.emit()

        # Run import in background thread
        self._worker = _ImportWorker(
            manager=self._manager,
            package_path=file_path,
            passphrase=passphrase,
            engagements_base_path=self._engagements_base_path,
        )
        self._worker.finished.connect(self._on_import_finished)
        self._worker.start()

    def _on_import_progress(self, current: int, total: int):
        """Update progress bar and validation status from manager signal."""
        if total > 0:
            pct = int((current / total) * 100)
            self._progress_bar.setValue(pct)

        # Update validation status based on import stages
        stage_labels = {
            1: "Decryption successful ✓",
            2: "Manifest loaded ✓",
            3: "Integrity checksums validated ✓",
            4: "Files extracted and registered ✓",
        }
        if current in stage_labels:
            self._validation_status.setText(stage_labels[current])
            self._validation_status.setStyleSheet("color: #00FF41;")

    def _on_import_finished(self, new_engagement_id: str):
        """Handle import completion."""
        self._worker = None
        self._import_btn.setEnabled(True)
        if new_engagement_id:
            self._progress_bar.setValue(100)
            self._status_label.setText(
                f"✓ Import successful — New ID: {new_engagement_id[:8]}..."
            )
            self._status_label.setStyleSheet("color: #00FF41; font-weight: bold;")
            self._validation_status.setText(
                "All integrity checks passed ✓\nEngagement registered in master index."
            )
            self._validation_status.setStyleSheet("color: #00FF41;")
            self.import_completed.emit(new_engagement_id)
        else:
            self._status_label.setText("✗ Import failed — check passphrase or file integrity")
            self._status_label.setStyleSheet("color: #FF5555; font-weight: bold;")
            self._validation_status.setText(
                "Validation failed — incorrect passphrase or corrupted package."
            )
            self._validation_status.setStyleSheet("color: #FF5555;")
            self.import_completed.emit("")

    def _show_error(self, message: str):
        """Display a validation error to the user."""
        self._status_label.setText(f"⚠ {message}")
        self._status_label.setStyleSheet("color: #FFD700;")


# ---------------------------------------------------------------------------
# Main Collaboration Component
# ---------------------------------------------------------------------------

class CollaborationComponent(QWidget):
    """Main collaboration widget providing export/import functionality.

    Integrated as a File menu dialog. Accepts a CollaborationManager instance
    and provides buttons to launch export and import dialogs.

    Signals:
        export_completed(bool): Emitted when an export operation finishes.
        import_completed(str): Emitted with new engagement ID on successful import.
    """

    export_completed = pyqtSignal(bool)
    import_completed = pyqtSignal(str)

    def __init__(
        self,
        collaboration_manager: CollaborationManager,
        parent=None,
    ):
        """Initialize the CollaborationComponent.

        Args:
            collaboration_manager: CollaborationManager instance for operations.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self._manager = collaboration_manager
        self._engagement_id: Optional[str] = None
        self._engagement_base_path: Optional[str] = None
        self._engagements_base_path: str = "resources/engagements"
        self._findings: List[dict] = []
        self._evidence: List[dict] = []

        self._build_ui()

    def _build_ui(self):
        """Build the main component layout."""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Team Collaboration")
        title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel(
            "Share engagement data with teammates via encrypted packages."
        )
        subtitle.setStyleSheet("color: #aaa; font-size: 10pt;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        layout.addSpacing(10)

        # Export section
        export_group = QGroupBox("Export Engagement")
        export_group.setStyleSheet(
            "QGroupBox { font-weight: bold; color: #64C8FF; "
            "border: 2px solid #555; border-radius: 5px; margin-top: 10px; padding-top: 10px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; "
            "padding: 0 5px; color: #64C8FF; }"
        )
        export_layout = QVBoxLayout(export_group)
        export_desc = QLabel(
            "Create an AES-256-GCM encrypted package of the active engagement.\n"
            "Teammates can import using the shared passphrase."
        )
        export_desc.setStyleSheet("color: #ccc; font-size: 9pt;")
        export_desc.setWordWrap(True)
        export_layout.addWidget(export_desc)
        self._export_btn = QPushButton("Export Engagement...")
        self._export_btn.setObjectName("primaryBtn")
        self._export_btn.setStyleSheet(
            "QPushButton#primaryBtn { background-color: rgba(100, 200, 255, 150); "
            "border: 1px solid #64C8FF; color: #000; font-weight: bold; "
            "padding: 10px 20px; font-size: 11pt; }"
            "QPushButton#primaryBtn:hover { background-color: rgba(100, 200, 255, 200); }"
            "QPushButton#primaryBtn:disabled { background-color: #3a3a4d; "
            "border: 1px solid #555; color: #888; }"
        )
        self._export_btn.clicked.connect(self._open_export_dialog)
        export_layout.addWidget(self._export_btn)

        # Export status
        self._export_status = QLabel("")
        self._export_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        export_layout.addWidget(self._export_status)
        layout.addWidget(export_group)

        # Import section
        import_group = QGroupBox("Import Engagement")
        import_group.setStyleSheet(
            "QGroupBox { font-weight: bold; color: #64C8FF; "
            "border: 2px solid #555; border-radius: 5px; margin-top: 10px; padding-top: 10px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; "
            "padding: 0 5px; color: #64C8FF; }"
        )
        import_layout = QVBoxLayout(import_group)
        import_desc = QLabel(
            "Import a .huginn encrypted package from a teammate.\n"
            "A new engagement ID is assigned to avoid conflicts."
        )
        import_desc.setStyleSheet("color: #ccc; font-size: 9pt;")
        import_desc.setWordWrap(True)
        import_layout.addWidget(import_desc)
        self._import_btn = QPushButton("Import Package...")
        self._import_btn.setObjectName("primaryBtn")
        self._import_btn.setStyleSheet(
            "QPushButton#primaryBtn { background-color: rgba(100, 200, 255, 150); "
            "border: 1px solid #64C8FF; color: #000; font-weight: bold; "
            "padding: 10px 20px; font-size: 11pt; }"
            "QPushButton#primaryBtn:hover { background-color: rgba(100, 200, 255, 200); }"
        )
        self._import_btn.clicked.connect(self._open_import_dialog)
        import_layout.addWidget(self._import_btn)

        # Import status
        self._import_status = QLabel("")
        self._import_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        import_layout.addWidget(self._import_status)
        layout.addWidget(import_group)

        layout.addStretch()

    # ------------------------------------------------------------------
    # Public API for setting engagement context
    # ------------------------------------------------------------------

    def set_engagement_context(
        self,
        engagement_id: str,
        engagement_base_path: str,
        findings: Optional[List[dict]] = None,
        evidence: Optional[List[dict]] = None,
    ):
        """Set the active engagement context for export operations.

        Args:
            engagement_id: UUID of the active engagement.
            engagement_base_path: Path to the engagement directory.
            findings: List of finding dicts with 'id' and 'title'.
            evidence: List of evidence dicts with 'id' and 'title'.
        """
        self._engagement_id = engagement_id
        self._engagement_base_path = engagement_base_path
        self._findings = findings or []
        self._evidence = evidence or []
        self._export_btn.setEnabled(True)

    def set_engagements_base_path(self, path: str):
        """Set the base engagements directory for import operations.

        Args:
            path: Filesystem path to the engagements root directory.
        """
        self._engagements_base_path = path

    # ------------------------------------------------------------------
    # Dialog Launchers
    # ------------------------------------------------------------------

    def _open_export_dialog(self):
        """Open the export dialog."""
        if not self._engagement_id or not self._engagement_base_path:
            self._export_status.setText("⚠ No active engagement selected")
            self._export_status.setStyleSheet("color: #FFD700;")
            return

        dialog = ExportDialog(
            collaboration_manager=self._manager,
            engagement_id=self._engagement_id,
            engagement_base_path=self._engagement_base_path,
            findings=self._findings,
            evidence=self._evidence,
            parent=self,
        )
        dialog.export_completed.connect(self._on_export_completed)
        dialog.exec()

    def _open_import_dialog(self):
        """Open the import dialog."""
        dialog = ImportDialog(
            collaboration_manager=self._manager,
            engagements_base_path=self._engagements_base_path,
            parent=self,
        )
        dialog.import_completed.connect(self._on_import_completed)
        dialog.exec()

    # ------------------------------------------------------------------
    # Signal Handlers
    # ------------------------------------------------------------------

    def _on_export_completed(self, success: bool):
        """Handle export dialog completion."""
        if success:
            self._export_status.setText("✓ Last export successful")
            self._export_status.setStyleSheet("color: #00FF41; font-weight: bold;")
        else:
            self._export_status.setText("✗ Last export failed")
            self._export_status.setStyleSheet("color: #FF5555;")
        self.export_completed.emit(success)

    def _on_import_completed(self, new_engagement_id: str):
        """Handle import dialog completion."""
        if new_engagement_id:
            self._import_status.setText(
                f"✓ Imported: {new_engagement_id[:8]}..."
            )
            self._import_status.setStyleSheet("color: #00FF41; font-weight: bold;")
        else:
            self._import_status.setText("✗ Last import failed")
            self._import_status.setStyleSheet("color: #FF5555;")
        self.import_completed.emit(new_engagement_id)
