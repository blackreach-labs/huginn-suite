# app/components/cracking/results_management_component.py
"""Cracked results table with export and credential storage."""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QPushButton, QTableWidget, QTableWidgetItem,
                            QHeaderView, QMessageBox)
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QFont


class ResultsManagementComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.cracked_results = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Hash", "Password", "Type"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setFont(QFont("Neuropol X", 9))
        self.results_table.setAlternatingRowColors(True)
        layout.addWidget(self.results_table)

        # Controls
        controls_layout = QHBoxLayout()

        self.save_cred_btn = QPushButton("💾 Save to Credentials")
        self.save_cred_btn.setToolTip("Save selected result to Stored Credentials for the active profile")
        self.save_cred_btn.clicked.connect(self.save_to_credentials)
        controls_layout.addWidget(self.save_cred_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_results)
        controls_layout.addWidget(self.clear_btn)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

    def add_result(self, hash_val, password, hash_type, _time_unused=None):
        """Add a cracked result to the table."""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        # Truncate hash for display
        display_hash = hash_val[:24] + "..." if len(hash_val) > 24 else hash_val

        self.results_table.setItem(row, 0, QTableWidgetItem(display_hash))
        self.results_table.setItem(row, 1, QTableWidgetItem(password))
        self.results_table.setItem(row, 2, QTableWidgetItem(hash_type))

        # Store full result
        self.cracked_results.append({
            'hash': hash_val,
            'password': password,
            'type': hash_type,
        })

    def save_to_credentials(self):
        """Save selected (or all) cracked results to the active profile's credentials."""
        if not self.cracked_results:
            QMessageBox.information(self, "No Results", "No cracked results to save.")
            return

        try:
            from app.core.credential_manager import credential_manager

            if not credential_manager.current_profile:
                QMessageBox.warning(
                    self, "No Active Profile",
                    "No profile is currently active.\n\n"
                    "Load or create a profile first via Engagement Setup."
                )
                return

            # Get selected rows, or save all if none selected
            selected_rows = set(idx.row() for idx in self.results_table.selectedIndexes())
            if not selected_rows:
                selected_rows = set(range(len(self.cracked_results)))

            saved_count = 0
            for row_idx in sorted(selected_rows):
                if row_idx >= len(self.cracked_results):
                    continue
                result = self.cracked_results[row_idx]
                credential_manager.add_credential(
                    username="",
                    password=result['password'],
                    service=result['type'],
                    notes=f"Cracked from hash: {result['hash'][:32]}...",
                    source="exploitation",
                    credential_type="Username/Password",
                )
                saved_count += 1

            QMessageBox.information(
                self, "Saved",
                f"Saved {saved_count} credential(s) to profile: {credential_manager.current_profile}"
            )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save credentials: {e}")

    def clear_results(self):
        self.results_table.setRowCount(0)
        self.cracked_results.clear()
