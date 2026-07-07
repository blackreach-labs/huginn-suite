# app/components/import_export_component.py
"""Import/Export UI Component.

Provides a comprehensive import/export dialog accessible from the Tools menu with:
- Format selector (Nessus XML, Burp XML, SARIF, CSV)
- File picker with drag-and-drop support
- CSV column mapping configuration dialog
- Import preview table showing parsed records before commit
- Progress bar with warning log during import
- Export format selector and output path chooser

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.7
"""

import os
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QMimeData
from PyQt6.QtGui import QDragEnterEvent, QDropEvent
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.import_export_engine import ImportExportEngine, ImportRecord


# ---------------------------------------------------------------------------
# Format Definitions
# ---------------------------------------------------------------------------

IMPORT_FORMATS = {
    "Nessus XML (.nessus)": {
        "key": "nessus",
        "extensions": "Nessus Files (*.nessus *.xml);;All Files (*)",
    },
    "Burp Suite XML (.xml)": {
        "key": "burp",
        "extensions": "Burp XML Files (*.xml);;All Files (*)",
    },
    "SARIF (.sarif, .json)": {
        "key": "sarif",
        "extensions": "SARIF Files (*.sarif *.json);;All Files (*)",
    },
    "CSV (.csv)": {
        "key": "csv",
        "extensions": "CSV Files (*.csv);;All Files (*)",
    },
}

EXPORT_FORMATS = {
    "Nessus XML (.nessus)": "nessus",
    "Burp Suite XML (.xml)": "burp",
    "SARIF (.sarif)": "sarif",
    "CSV (.csv)": "csv",
    "JSON (.json)": "json",
}

# ImportRecord fields available for CSV column mapping
IMPORT_RECORD_FIELDS = [
    "(skip)",
    "host",
    "port",
    "vulnerability_name",
    "severity",
    "description",
    "evidence",
]


# ---------------------------------------------------------------------------
# Import Worker Thread
# ---------------------------------------------------------------------------


class ImportWorker(QThread):
    """Background thread for parsing import files."""

    finished = pyqtSignal(list, list)  # records, warnings
    progress = pyqtSignal(int, int)  # current, total
    warning = pyqtSignal(str)

    def __init__(
        self,
        engine: ImportExportEngine,
        file_path: str,
        format_key: str,
        column_mapping: Optional[Dict[str, str]] = None,
        parent=None,
    ):
        super().__init__(parent)
        self._engine = engine
        self._file_path = file_path
        self._format_key = format_key
        self._column_mapping = column_mapping or {}

    def run(self):
        """Execute the import parsing on a background thread."""
        # Connect engine signals to our relay signals
        self._engine.import_progress.connect(self.progress.emit)
        self._engine.import_warning.connect(self.warning.emit)

        records: List[ImportRecord] = []
        warnings: List[str] = []

        try:
            if self._format_key == "nessus":
                records, warnings = self._engine.parse_nessus_xml(self._file_path)
            elif self._format_key == "burp":
                records, warnings = self._engine.parse_burp_xml(self._file_path)
            elif self._format_key == "sarif":
                records, warnings = self._engine.parse_sarif(self._file_path)
            elif self._format_key == "csv":
                records, warnings = self._engine.parse_csv(
                    self._file_path, self._column_mapping
                )
        except Exception as e:
            warnings.append(f"Import failed: {e}")

        self.finished.emit(records, warnings)


# ---------------------------------------------------------------------------
# CSV Column Mapping Dialog
# ---------------------------------------------------------------------------


class CSVColumnMappingDialog(QDialog):
    """Dialog for configuring CSV column-to-field mapping.

    Reads the first row of the CSV to get column headers and lets the user
    assign each column to an ImportRecord field.
    """

    def __init__(self, csv_headers: List[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("CSV Column Mapping")
        self.setMinimumWidth(500)
        self.setMinimumHeight(300)
        self._csv_headers = csv_headers
        self._mapping_combos: Dict[str, QComboBox] = {}
        self._result_mapping: Dict[str, str] = {}

        self._setup_ui()
        self._apply_theme()

    def _setup_ui(self):
        """Build the column mapping layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Title
        title = QLabel("Map CSV Columns to Fields")
        title.setStyleSheet(
            "font-size: 13pt; font-weight: bold; color: #64C8FF;"
        )
        layout.addWidget(title)

        description = QLabel(
            "Assign each CSV column to an import field. "
            "Columns mapped to '(skip)' will be ignored."
        )
        description.setWordWrap(True)
        description.setStyleSheet("color: #A0A0A0; font-size: 9pt;")
        layout.addWidget(description)

        # Form layout for column mappings
        form_group = QGroupBox("Column Assignments")
        form_layout = QFormLayout(form_group)
        form_layout.setSpacing(8)

        for header in self._csv_headers:
            combo = QComboBox()
            combo.addItems(IMPORT_RECORD_FIELDS)
            # Auto-guess mapping based on header name
            self._auto_guess_mapping(header, combo)
            self._mapping_combos[header] = combo
            form_layout.addRow(QLabel(header), combo)

        layout.addWidget(form_group)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setMinimumHeight(32)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        apply_btn = QPushButton("Apply Mapping")
        apply_btn.setObjectName("applyBtn")
        apply_btn.setMinimumHeight(32)
        apply_btn.clicked.connect(self._accept_mapping)
        btn_layout.addWidget(apply_btn)

        layout.addLayout(btn_layout)

    def _auto_guess_mapping(self, header: str, combo: QComboBox):
        """Attempt to auto-guess the field mapping from the header name."""
        header_lower = header.lower().strip()
        guess_map = {
            "host": "host",
            "ip": "host",
            "ip address": "host",
            "target": "host",
            "port": "port",
            "vulnerability": "vulnerability_name",
            "vuln": "vulnerability_name",
            "finding": "vulnerability_name",
            "title": "vulnerability_name",
            "name": "vulnerability_name",
            "severity": "severity",
            "risk": "severity",
            "description": "description",
            "detail": "description",
            "evidence": "evidence",
            "proof": "evidence",
            "output": "evidence",
        }

        for keyword, field in guess_map.items():
            if keyword in header_lower:
                idx = combo.findText(field)
                if idx >= 0:
                    combo.setCurrentIndex(idx)
                    return

    def _accept_mapping(self):
        """Build the result mapping and accept the dialog."""
        self._result_mapping = {}
        for header, combo in self._mapping_combos.items():
            field = combo.currentText()
            if field != "(skip)":
                self._result_mapping[header] = field
        self.accept()

    def get_mapping(self) -> Dict[str, str]:
        """Return the configured column mapping."""
        return self._result_mapping

    def _apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass


# ---------------------------------------------------------------------------
# Drop-Enabled File Picker Widget
# ---------------------------------------------------------------------------


class FileDropArea(QFrame):
    """A file picker area that supports drag-and-drop."""

    file_selected = pyqtSignal(str)  # file_path

    def __init__(self, file_filter: str = "All Files (*)", parent=None):
        super().__init__(parent)
        self._file_filter = file_filter
        self._file_path: str = ""
        self.setAcceptDrops(True)
        self.setMinimumHeight(80)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self._setup_ui()

    def _setup_ui(self):
        """Build the drop area layout."""
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(6)

        self._icon_label = QLabel("📂")
        self._icon_label.setStyleSheet("font-size: 24pt;")
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._icon_label)

        self._text_label = QLabel("Drag & drop a file here, or click Browse")
        self._text_label.setStyleSheet("color: #A0A0A0; font-size: 9pt;")
        self._text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._text_label)

        self._path_label = QLabel("")
        self._path_label.setStyleSheet("color: #64C8FF; font-size: 9pt;")
        self._path_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._path_label.setWordWrap(True)
        layout.addWidget(self._path_label)

        browse_btn = QPushButton("Browse...")
        browse_btn.setMaximumWidth(100)
        browse_btn.clicked.connect(self._browse_file)
        layout.addWidget(browse_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def set_file_filter(self, file_filter: str):
        """Update the file dialog filter."""
        self._file_filter = file_filter

    def get_file_path(self) -> str:
        """Return the currently selected file path."""
        return self._file_path

    def _browse_file(self):
        """Open a file dialog to select the import file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Import File", "", self._file_filter
        )
        if file_path:
            self._set_file(file_path)

    def _set_file(self, file_path: str):
        """Set the selected file and update display."""
        self._file_path = file_path
        filename = os.path.basename(file_path)
        self._path_label.setText(filename)
        self._text_label.setText("File selected:")
        self.file_selected.emit(file_path)

    def clear(self):
        """Clear the selected file."""
        self._file_path = ""
        self._path_label.setText("")
        self._text_label.setText("Drag & drop a file here, or click Browse")

    # -- Drag and Drop --

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Accept drag events with file URLs."""
        if event.mimeData() and event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet(self.styleSheet() + """
                FileDropArea {
                    border: 2px dashed #64C8FF;
                }
            """)
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        """Reset style when drag leaves."""
        self._apply_default_style()

    def dropEvent(self, event: QDropEvent):
        """Handle file drop."""
        self._apply_default_style()
        if event.mimeData() and event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if file_path and os.path.isfile(file_path):
                    self._set_file(file_path)
                    event.acceptProposedAction()
                    return
        event.ignore()

    def _apply_default_style(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass


# ---------------------------------------------------------------------------
# Main Import/Export Component
# ---------------------------------------------------------------------------


class ImportExportComponent(QWidget):
    """Import/Export UI component integrated as a Tools menu dialog.

    Provides full import workflow (format selection, file pick, preview, commit)
    and export workflow (format selection, output path) in a tabbed/stacked layout.

    Signals:
        import_committed(list): Emitted when user confirms import with list of ImportRecord.
        export_completed(str): Emitted when export finishes with the output path.
    """

    import_committed = pyqtSignal(list)  # List[ImportRecord]
    export_completed = pyqtSignal(str)  # output_path

    def __init__(self, engine: ImportExportEngine, parent=None):
        super().__init__(parent)
        self._engine = engine
        self._parsed_records: List[ImportRecord] = []
        self._import_warnings: List[str] = []
        self._worker: Optional[ImportWorker] = None
        self._column_mapping: Dict[str, str] = {}

        self._setup_ui()
        self._apply_theme()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the main component layout with Import and Export sections."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Title
        title = QLabel("Import / Export")
        title.setStyleSheet(
            "font-size: 16pt; font-weight: bold; color: #64C8FF; margin-bottom: 4px;"
        )
        layout.addWidget(title)

        # ---- Import Section ----
        import_group = QGroupBox("Import Findings")
        import_layout = QVBoxLayout(import_group)
        import_layout.setSpacing(10)

        # Format selector row
        format_row = QHBoxLayout()
        format_label = QLabel("Format:")
        format_label.setStyleSheet("color: #DCDCDC; font-size: 10pt;")
        format_row.addWidget(format_label)

        self._import_format_combo = QComboBox()
        self._import_format_combo.addItems(IMPORT_FORMATS.keys())
        self._import_format_combo.currentTextChanged.connect(self._on_import_format_changed)
        self._import_format_combo.setMinimumWidth(200)
        format_row.addWidget(self._import_format_combo)

        # CSV column mapping button (only visible for CSV)
        self._csv_mapping_btn = QPushButton("Configure Columns...")
        self._csv_mapping_btn.setObjectName("csvMappingBtn")
        self._csv_mapping_btn.setVisible(False)
        self._csv_mapping_btn.clicked.connect(self._open_csv_mapping_dialog)
        format_row.addWidget(self._csv_mapping_btn)

        format_row.addStretch()
        import_layout.addLayout(format_row)

        # File picker with drag-and-drop
        self._file_drop = FileDropArea(
            file_filter=self._get_current_import_filter()
        )
        self._file_drop._apply_default_style()
        self._file_drop.file_selected.connect(self._on_file_selected)
        import_layout.addWidget(self._file_drop)

        # Parse / Preview button
        parse_row = QHBoxLayout()
        parse_row.addStretch()

        self._parse_btn = QPushButton("Parse && Preview")
        self._parse_btn.setObjectName("parseBtn")
        self._parse_btn.setMinimumHeight(32)
        self._parse_btn.setEnabled(False)
        self._parse_btn.clicked.connect(self._start_import_parse)
        parse_row.addWidget(self._parse_btn)
        import_layout.addLayout(parse_row)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setVisible(False)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setMinimumHeight(20)
        import_layout.addWidget(self._progress_bar)

        # Preview table
        self._preview_table = QTableWidget()
        self._preview_table.setColumnCount(5)
        self._preview_table.setHorizontalHeaderLabels(
            ["Host", "Port", "Vulnerability", "Severity", "Description"]
        )
        self._preview_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self._preview_table.setMinimumHeight(180)
        self._preview_table.setVisible(False)
        import_layout.addWidget(self._preview_table)

        # Warning log
        self._warning_log = QTextEdit()
        self._warning_log.setReadOnly(True)
        self._warning_log.setMaximumHeight(80)
        self._warning_log.setPlaceholderText("Warnings will appear here...")
        self._warning_log.setVisible(False)
        import_layout.addWidget(self._warning_log)

        # Commit button
        commit_row = QHBoxLayout()
        commit_row.addStretch()

        self._record_count_label = QLabel("")
        self._record_count_label.setStyleSheet("color: #A0A0A0; font-size: 9pt;")
        commit_row.addWidget(self._record_count_label)

        self._commit_btn = QPushButton("Commit Import")
        self._commit_btn.setObjectName("commitBtn")
        self._commit_btn.setMinimumHeight(32)
        self._commit_btn.setEnabled(False)
        self._commit_btn.clicked.connect(self._commit_import)
        commit_row.addWidget(self._commit_btn)
        import_layout.addLayout(commit_row)

        layout.addWidget(import_group)

        # ---- Export Section ----
        export_group = QGroupBox("Export Findings")
        export_layout = QVBoxLayout(export_group)
        export_layout.setSpacing(10)

        # Export format selector
        export_format_row = QHBoxLayout()
        export_format_label = QLabel("Format:")
        export_format_label.setStyleSheet("color: #DCDCDC; font-size: 10pt;")
        export_format_row.addWidget(export_format_label)

        self._export_format_combo = QComboBox()
        self._export_format_combo.addItems(EXPORT_FORMATS.keys())
        self._export_format_combo.setMinimumWidth(200)
        export_format_row.addWidget(self._export_format_combo)
        export_format_row.addStretch()
        export_layout.addLayout(export_format_row)

        # Output path row
        path_row = QHBoxLayout()
        path_label = QLabel("Output:")
        path_label.setStyleSheet("color: #DCDCDC; font-size: 10pt;")
        path_row.addWidget(path_label)

        self._export_path_input = QLineEdit()
        self._export_path_input.setPlaceholderText("Select output file path...")
        self._export_path_input.setReadOnly(True)
        path_row.addWidget(self._export_path_input, 1)

        self._export_browse_btn = QPushButton("Browse...")
        self._export_browse_btn.clicked.connect(self._browse_export_path)
        path_row.addWidget(self._export_browse_btn)
        export_layout.addLayout(path_row)

        # Export button
        export_btn_row = QHBoxLayout()
        export_btn_row.addStretch()

        self._export_btn = QPushButton("Export")
        self._export_btn.setObjectName("exportBtn")
        self._export_btn.setMinimumHeight(32)
        self._export_btn.setEnabled(False)
        self._export_btn.clicked.connect(self._execute_export)
        export_btn_row.addWidget(self._export_btn)
        export_layout.addLayout(export_btn_row)

        layout.addWidget(export_group)
        layout.addStretch()

    # ------------------------------------------------------------------
    # Import Logic
    # ------------------------------------------------------------------

    def _get_current_import_filter(self) -> str:
        """Get the file filter for the currently selected format."""
        format_name = self._import_format_combo.currentText()
        return IMPORT_FORMATS.get(format_name, {}).get(
            "extensions", "All Files (*)"
        )

    def _get_current_import_key(self) -> str:
        """Get the format key for the currently selected format."""
        format_name = self._import_format_combo.currentText()
        return IMPORT_FORMATS.get(format_name, {}).get("key", "")

    def _on_import_format_changed(self, format_name: str):
        """Handle import format selection change."""
        fmt_info = IMPORT_FORMATS.get(format_name, {})
        is_csv = fmt_info.get("key") == "csv"
        self._csv_mapping_btn.setVisible(is_csv)
        self._file_drop.set_file_filter(
            fmt_info.get("extensions", "All Files (*)")
        )
        # Reset state
        self._file_drop.clear()
        self._clear_preview()
        self._parse_btn.setEnabled(False)

    def _on_file_selected(self, file_path: str):
        """Handle file selection from drop area."""
        self._clear_preview()
        self._parse_btn.setEnabled(bool(file_path))

    def _open_csv_mapping_dialog(self):
        """Open the CSV column mapping configuration dialog."""
        file_path = self._file_drop.get_file_path()
        if not file_path:
            QMessageBox.warning(
                self,
                "No File Selected",
                "Please select a CSV file first before configuring columns.",
            )
            return

        # Read CSV headers
        import csv as csv_module

        try:
            with open(file_path, "r", encoding="utf-8-sig") as f:
                reader = csv_module.reader(f)
                headers = next(reader, [])
        except Exception as e:
            QMessageBox.critical(
                self, "Error", f"Could not read CSV headers: {e}"
            )
            return

        if not headers:
            QMessageBox.warning(
                self, "Empty CSV", "The CSV file has no header row."
            )
            return

        dialog = CSVColumnMappingDialog(headers, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._column_mapping = dialog.get_mapping()

    def _start_import_parse(self):
        """Start the import parsing process in a background thread."""
        file_path = self._file_drop.get_file_path()
        if not file_path:
            return

        format_key = self._get_current_import_key()

        # For CSV, require column mapping
        if format_key == "csv" and not self._column_mapping:
            self._open_csv_mapping_dialog()
            if not self._column_mapping:
                return

        # Reset UI state
        self._clear_preview()
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._warning_log.setVisible(True)
        self._warning_log.clear()
        self._parse_btn.setEnabled(False)

        # Start worker
        self._worker = ImportWorker(
            engine=self._engine,
            file_path=file_path,
            format_key=format_key,
            column_mapping=self._column_mapping,
            parent=self,
        )
        self._worker.progress.connect(self._on_import_progress)
        self._worker.warning.connect(self._on_import_warning)
        self._worker.finished.connect(self._on_import_finished)
        self._worker.start()

    def _on_import_progress(self, current: int, total: int):
        """Update progress bar during import."""
        if total > 0:
            self._progress_bar.setMaximum(total)
            self._progress_bar.setValue(current)
            self._progress_bar.setFormat(f"{current}/{total} records")

    def _on_import_warning(self, message: str):
        """Append a warning to the warning log."""
        self._warning_log.append(f"⚠ {message}")

    def _on_import_finished(self, records: List[ImportRecord], warnings: List[str]):
        """Handle import parsing completion."""
        self._parsed_records = records
        self._import_warnings = warnings
        self._parse_btn.setEnabled(True)

        # Show any warnings not already displayed
        for w in warnings:
            if w not in self._warning_log.toPlainText():
                self._warning_log.append(f"⚠ {w}")

        if not self._warning_log.toPlainText().strip():
            self._warning_log.setVisible(False)

        # Populate preview table
        self._populate_preview_table(records)

        # Update commit button
        self._commit_btn.setEnabled(len(records) > 0)
        self._record_count_label.setText(
            f"{len(records)} records parsed"
            + (f", {len(warnings)} warnings" if warnings else "")
        )

    def _populate_preview_table(self, records: List[ImportRecord]):
        """Fill the preview table with parsed records."""
        self._preview_table.setVisible(True)
        self._preview_table.setRowCount(min(len(records), 200))  # Cap at 200 for performance

        for row_idx, record in enumerate(records[:200]):
            self._preview_table.setItem(
                row_idx, 0, QTableWidgetItem(record.host)
            )
            self._preview_table.setItem(
                row_idx, 1, QTableWidgetItem(str(record.port))
            )
            self._preview_table.setItem(
                row_idx, 2, QTableWidgetItem(record.vulnerability_name)
            )

            severity_item = QTableWidgetItem(record.severity)
            severity_item.setForeground(
                self._severity_color(record.severity)
            )
            self._preview_table.setItem(row_idx, 3, severity_item)

            # Truncate long descriptions for preview
            desc = record.description[:120] + "..." if len(record.description) > 120 else record.description
            self._preview_table.setItem(
                row_idx, 4, QTableWidgetItem(desc)
            )

    def _severity_color(self, severity: str):
        """Return a QColor for the given severity level."""
        from PyQt6.QtGui import QColor

        colors = {
            "critical": QColor("#D0021B"),
            "high": QColor("#E57320"),
            "medium": QColor("#F5A623"),
            "low": QColor("#4A90D9"),
            "info": QColor("#808080"),
        }
        return colors.get(severity.lower(), QColor("#DCDCDC"))

    def _commit_import(self):
        """Confirm and emit the import records for database commit."""
        if not self._parsed_records:
            return

        reply = QMessageBox.question(
            self,
            "Confirm Import",
            f"Import {len(self._parsed_records)} records into the active engagement?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.import_committed.emit(self._parsed_records)
            QMessageBox.information(
                self,
                "Import Complete",
                f"Successfully queued {len(self._parsed_records)} records for import.",
            )
            self._clear_preview()

    def _clear_preview(self):
        """Reset the preview state."""
        self._parsed_records = []
        self._import_warnings = []
        self._preview_table.setRowCount(0)
        self._preview_table.setVisible(False)
        self._progress_bar.setVisible(False)
        self._warning_log.setVisible(False)
        self._warning_log.clear()
        self._commit_btn.setEnabled(False)
        self._record_count_label.setText("")

    # ------------------------------------------------------------------
    # Export Logic
    # ------------------------------------------------------------------

    def _browse_export_path(self):
        """Open a save file dialog for export output."""
        format_name = self._export_format_combo.currentText()
        format_key = EXPORT_FORMATS.get(format_name, "json")

        ext_map = {
            "nessus": "Nessus Files (*.nessus);;All Files (*)",
            "burp": "XML Files (*.xml);;All Files (*)",
            "sarif": "SARIF Files (*.sarif);;All Files (*)",
            "csv": "CSV Files (*.csv);;All Files (*)",
            "json": "JSON Files (*.json);;All Files (*)",
        }
        file_filter = ext_map.get(format_key, "All Files (*)")

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Select Export Output Path", "", file_filter
        )
        if file_path:
            self._export_path_input.setText(file_path)
            self._export_btn.setEnabled(True)

    def _execute_export(self):
        """Execute the export operation."""
        output_path = self._export_path_input.text()
        if not output_path:
            return

        format_name = self._export_format_combo.currentText()
        format_key = EXPORT_FORMATS.get(format_name, "json")

        # Emit signal with format info - the parent dialog/window
        # is responsible for supplying findings data
        self.export_completed.emit(output_path)

    def export_findings(self, findings: List[Dict], output_path: str = None):
        """Execute export with provided findings data.

        This is called externally when the parent supplies findings.

        Args:
            findings: List of finding dicts to export.
            output_path: Optional override for output path.
        """
        if output_path is None:
            output_path = self._export_path_input.text()
        if not output_path:
            return

        format_name = self._export_format_combo.currentText()
        format_key = EXPORT_FORMATS.get(format_name, "json")

        success = self._engine.export_findings(findings, format_key, output_path)
        if success:
            QMessageBox.information(
                self,
                "Export Complete",
                f"Findings exported successfully to:\n{output_path}",
            )
        else:
            QMessageBox.critical(
                self,
                "Export Failed",
                "Failed to export findings. Check the log for details.",
            )

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass
