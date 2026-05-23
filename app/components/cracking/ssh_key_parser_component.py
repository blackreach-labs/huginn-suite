"""SSH Key Parser UI component for the Cracking page."""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QFileDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont
from pathlib import Path


class SSHScanWorker(QThread):
    """Worker thread for recursive SSH key scanning."""
    output_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int, int)  # current, total
    finished_signal = pyqtSignal(int)  # total found

    def __init__(self, path, recursive=True):
        super().__init__()
        self.path = path
        self.recursive = recursive

    def run(self):
        try:
            from modules.ssh_parser import SSHKeyParser
            from modules.ssh_parser.scanner import SSHKeyScanner

            self.output_signal.emit(f"[SCAN] Scanning: {self.path}")
            scanner = SSHKeyScanner()
            results = scanner.scan(self.path, recursive=self.recursive)

            total = len(results)
            self.output_signal.emit(f"[INFO] Found {total} candidate key files")

            for i, result in enumerate(results, 1):
                self.progress_signal.emit(i, total)
                entry = result.to_dict()
                self.result_signal.emit(entry)

                if result.success:
                    state = "ENCRYPTED" if result.info.is_encrypted else "UNENCRYPTED"
                    cipher = result.info.cipher or "n/a"
                    self.output_signal.emit(
                        f"[KEY {i}/{total}] {result.filepath.name} — {state} ({cipher})"
                    )
                else:
                    self.output_signal.emit(
                        f"[ERR {i}/{total}] {result.filepath.name} — {result.error}"
                    )

            self.finished_signal.emit(total)

        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
            self.finished_signal.emit(0)


class SSHParseWorker(QThread):
    """Worker thread for parsing a single SSH key file."""
    output_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal()

    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath

    def run(self):
        try:
            from modules.ssh_parser import SSHKeyParser

            parser = SSHKeyParser()
            self.output_signal.emit(f"[PARSE] Parsing: {self.filepath}")

            info = parser.parse_file(self.filepath)
            result = {"file": str(self.filepath), **info.to_dict()}
            self.result_signal.emit(result)

            self.output_signal.emit(f"[OK] Format: {info.format.value}, State: {info.state.value}")
            if info.cipher:
                self.output_signal.emit(f"     Cipher: {info.cipher}")
            if info.kdf:
                self.output_signal.emit(f"     KDF: {info.kdf}")
            if info.rounds:
                self.output_signal.emit(f"     Rounds: {info.rounds}")
            if info.salt_hex:
                self.output_signal.emit(f"     Salt: {info.salt_hex}")
            if info.iv_hex:
                self.output_signal.emit(f"     IV: {info.iv_hex}")
            if info.hash_line:
                self.output_signal.emit(f"[HASH] {info.hash_line}")

        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
        finally:
            self.finished_signal.emit()


class SSHKeyParserComponent(QWidget):
    """UI component for SSH private key parsing and scanning."""

    def __init__(self):
        super().__init__()
        self.worker = None
        self._scan_results = []  # Store full result dicts keyed by row
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(4)

        # --- Single file parse section ---
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Key File:"))
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Path to SSH private key file...")
        file_layout.addWidget(self.file_input)

        self.browse_file_btn = QPushButton("Browse")
        self.browse_file_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_file_btn)

        self.parse_btn = QPushButton("Parse Key")
        self.parse_btn.clicked.connect(self.parse_single_key)
        file_layout.addWidget(self.parse_btn)
        layout.addLayout(file_layout)

        # --- Directory scan section ---
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("Scan Dir:"))
        self.dir_input = QLineEdit()
        self.dir_input.setPlaceholderText("Directory to scan for SSH keys (recursive)...")
        dir_layout.addWidget(self.dir_input)

        self.browse_dir_btn = QPushButton("Browse")
        self.browse_dir_btn.clicked.connect(self.browse_directory)
        dir_layout.addWidget(self.browse_dir_btn)

        self.scan_btn = QPushButton("Scan Directory")
        self.scan_btn.clicked.connect(self.scan_directory)
        dir_layout.addWidget(self.scan_btn)
        layout.addLayout(dir_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "File", "Format", "State", "Cipher", "KDF", "Severity"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.results_table.setFont(QFont("Neuropol X", 9))
        self.results_table.currentCellChanged.connect(self._on_row_selected)
        layout.addWidget(self.results_table, 1)

        # Output log
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Neuropol X", 9))
        self.output_text.setPlaceholderText("Output...")
        layout.addWidget(self.output_text, 1)

        # Export button
        export_layout = QHBoxLayout()
        export_layout.addStretch()
        self.export_btn = QPushButton("Export Results (JSON)")
        self.export_btn.clicked.connect(self.export_results)
        export_layout.addWidget(self.export_btn)
        layout.addLayout(export_layout)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select SSH Private Key", "", "All Files (*)"
        )
        if file_path:
            self.file_input.setText(file_path)

    def browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Directory to Scan"
        )
        if dir_path:
            self.dir_input.setText(dir_path)

    def parse_single_key(self):
        filepath = self.file_input.text().strip()
        if not filepath:
            self.output_text.append("[!] Please specify a key file path")
            return

        self.parse_btn.setEnabled(False)
        self.output_text.clear()

        self.worker = SSHParseWorker(filepath)
        self.worker.output_signal.connect(self.output_text.append)
        self.worker.result_signal.connect(self._add_table_row)
        self.worker.finished_signal.connect(lambda: self.parse_btn.setEnabled(True))
        self.worker.start()

    def scan_directory(self):
        dir_path = self.dir_input.text().strip()
        if not dir_path:
            self.output_text.append("[!] Please specify a directory to scan")
            return

        self.scan_btn.setEnabled(False)
        self.output_text.clear()
        self.results_table.setRowCount(0)
        self._scan_results.clear()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        self.worker = SSHScanWorker(dir_path)
        self.worker.output_signal.connect(self.output_text.append)
        self.worker.result_signal.connect(self._add_table_row)
        self.worker.progress_signal.connect(self._update_progress)
        self.worker.finished_signal.connect(self._scan_finished)
        self.worker.start()

    def _update_progress(self, current, total):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)

    def _scan_finished(self, total):
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.output_text.append(f"\n[DONE] Scan complete — {total} files processed")

    def _on_row_selected(self, current_row, current_col, prev_row, prev_col):
        """When a table row is selected, populate the Key File field and show details."""
        if current_row < 0 or current_row >= len(self._scan_results):
            return

        result = self._scan_results[current_row]
        filepath = result.get("file", "")

        # Populate the Key File input
        self.file_input.setText(filepath)

        # Show the stored parse details in the output
        self.output_text.clear()
        data = result.get("data", result)

        self.output_text.append(f"[SELECTED] {filepath}")
        fmt = data.get("format", "?")
        state = data.get("state", "?")
        self.output_text.append(f"  Format: {fmt}")
        self.output_text.append(f"  State:  {state}")

        cipher = data.get("cipher")
        if cipher:
            self.output_text.append(f"  Cipher: {cipher}")

        kdf = data.get("kdf")
        if kdf:
            self.output_text.append(f"  KDF:    {kdf}")

        rounds = data.get("rounds")
        if rounds:
            self.output_text.append(f"  Rounds: {rounds}")

        salt = data.get("salt")
        if salt:
            self.output_text.append(f"  Salt:   {salt}")

        iv = data.get("iv")
        if iv:
            self.output_text.append(f"  IV:     {iv}")

        key_type = data.get("key_type")
        if key_type:
            self.output_text.append(f"  Type:   {key_type}")

        hash_line = data.get("hash_line")
        if hash_line:
            self.output_text.append(f"\n[HASH] {hash_line}")

    def _add_table_row(self, result: dict):
        """Add a parsed result to the results table and store it."""
        if "error" in result and "data" not in result:
            return  # Skip pure errors for the table

        data = result.get("data", result)
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        filepath = result.get("file", "")
        filename = Path(filepath).name if filepath else "?"

        self.results_table.setItem(row, 0, QTableWidgetItem(filename))
        self.results_table.setItem(row, 1, QTableWidgetItem(data.get("format", "?")))
        self.results_table.setItem(row, 2, QTableWidgetItem(data.get("state", "?")))
        self.results_table.setItem(row, 3, QTableWidgetItem(data.get("cipher", "") or "—"))
        self.results_table.setItem(row, 4, QTableWidgetItem(data.get("kdf", "") or "—"))
        self.results_table.setItem(row, 5, QTableWidgetItem(result.get("severity", "—")))

        # Color-code severity
        severity = result.get("severity", "")
        if severity == "critical":
            self.results_table.item(row, 5).setForeground(Qt.GlobalColor.red)
        elif severity == "high":
            self.results_table.item(row, 5).setForeground(Qt.GlobalColor.yellow)

        # Store the full result for selection lookup
        self._scan_results.append(result)

    def export_results(self):
        """Export results table to JSON."""
        if self.results_table.rowCount() == 0:
            self.output_text.append("[!] No results to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export SSH Key Results", "ssh_keys_report.json", "JSON Files (*.json)"
        )
        if not file_path:
            return

        import json
        try:
            with open(file_path, "w") as f:
                json.dump(self._scan_results, f, indent=2)
            self.output_text.append(f"[OK] Exported {len(self._scan_results)} results to {file_path}")
        except Exception as e:
            self.output_text.append(f"[ERROR] Export failed: {e}")
