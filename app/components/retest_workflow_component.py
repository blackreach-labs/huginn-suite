# app/components/retest_workflow_component.py
"""Retest Workflow UI Component.

Provides a comprehensive retest management interface with:
- Top metrics bar: Total, retested, remaining, regressed + pass rate progress bar
- Left panel: Findings checklist with status indicators
- Right panel: Retest result form + cycle history selector

Layout: Top metrics bar | Left: findings checklist | Right: result form + cycle history

Integrates as a new tab within the Reporting page.

Requirements: 6.2, 6.3, 6.4, 6.5, 6.6, 6.7
"""

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# Retest status definitions with corresponding colors
RETEST_STATUSES = [
    "not_tested",
    "fixed",
    "partially_fixed",
    "not_fixed",
    "regressed",
]

STATUS_DISPLAY_NAMES = {
    "not_tested": "Not Tested",
    "fixed": "Fixed",
    "partially_fixed": "Partially Fixed",
    "not_fixed": "Not Fixed",
    "regressed": "Regressed",
}

STATUS_COLORS = {
    "not_tested": "#808080",
    "fixed": "#00D68F",
    "partially_fixed": "#FFD700",
    "not_fixed": "#FF8C00",
    "regressed": "#FF4444",
}


class RetestWorkflowComponent(QWidget):
    """Main retest workflow component with metrics, checklist, and result form.

    Signals:
        finding_selected(int): Emitted when a finding is selected in the checklist.
        retest_recorded(int, str): Emitted when a retest result is recorded (finding_id, status).
        cycle_changed(int): Emitted when the active cycle changes.
    """

    finding_selected = pyqtSignal(int)
    retest_recorded = pyqtSignal(int, str)
    cycle_changed = pyqtSignal(int)

    def __init__(self, retest_workflow, parent=None):
        """Initialize the RetestWorkflowComponent.

        Args:
            retest_workflow: A RetestWorkflow instance providing cycle/finding data.
            parent: Optional QWidget parent.
        """
        super().__init__(parent)
        self.workflow = retest_workflow
        self._selected_finding_id: Optional[int] = None
        self._active_cycle_id: Optional[int] = None
        self._evidence_path: Optional[str] = None

        self.setup_ui()
        self.apply_theme()
        self._connect_signals()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def setup_ui(self):
        """Build the main layout: metrics bar on top, splitter below."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Top: Cycle controls bar
        layout.addWidget(self._create_cycle_controls_bar())

        # Top: Metrics dashboard bar
        layout.addWidget(self._create_metrics_bar())

        # Bottom: Splitter with findings checklist (left) and result form (right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._create_findings_checklist())
        splitter.addWidget(self._create_right_panel())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)

    # ------------------------------------------------------------------
    # Cycle Controls Bar
    # ------------------------------------------------------------------

    def _create_cycle_controls_bar(self) -> QWidget:
        """Create the cycle selector and action buttons bar."""
        bar = QFrame()
        bar.setObjectName("cycleControlsBar")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 8, 12, 8)

        # Cycle selector
        bar_layout.addWidget(QLabel("Retest Cycle:"))
        self.cycle_selector = QComboBox()
        self.cycle_selector.setMinimumWidth(200)
        self.cycle_selector.currentIndexChanged.connect(self._on_cycle_changed)
        bar_layout.addWidget(self.cycle_selector)

        bar_layout.addSpacing(16)

        # New Cycle button
        self.new_cycle_btn = QPushButton("New Retest Cycle")
        self.new_cycle_btn.setMinimumHeight(35)
        self.new_cycle_btn.clicked.connect(self._on_new_cycle)
        bar_layout.addWidget(self.new_cycle_btn)

        # Complete Cycle button
        self.complete_cycle_btn = QPushButton("Complete Cycle")
        self.complete_cycle_btn.setMinimumHeight(35)
        self.complete_cycle_btn.clicked.connect(self._on_complete_cycle)
        bar_layout.addWidget(self.complete_cycle_btn)

        bar_layout.addStretch()

        return bar

    # ------------------------------------------------------------------
    # Metrics Dashboard Bar
    # ------------------------------------------------------------------

    def _create_metrics_bar(self) -> QWidget:
        """Create the metrics dashboard bar with counts and progress bar."""
        bar = QFrame()
        bar.setObjectName("metricsBar")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(12, 10, 12, 10)

        # Total findings
        self.total_label = QLabel("Total: 0")
        self.total_label.setObjectName("metricLabel")
        bar_layout.addWidget(self.total_label)

        bar_layout.addSpacing(20)

        # Retested count
        self.retested_label = QLabel("Retested: 0")
        self.retested_label.setObjectName("metricLabel")
        bar_layout.addWidget(self.retested_label)

        bar_layout.addSpacing(20)

        # Remaining count
        self.remaining_label = QLabel("Remaining: 0")
        self.remaining_label.setObjectName("metricLabel")
        bar_layout.addWidget(self.remaining_label)

        bar_layout.addSpacing(20)

        # Regressed count (highlighted)
        self.regressed_label = QLabel("Regressed: 0")
        self.regressed_label.setObjectName("regressedMetricLabel")
        bar_layout.addWidget(self.regressed_label)

        bar_layout.addSpacing(30)

        # Pass rate progress bar
        bar_layout.addWidget(QLabel("Pass Rate:"))
        self.pass_rate_bar = QProgressBar()
        self.pass_rate_bar.setMinimum(0)
        self.pass_rate_bar.setMaximum(100)
        self.pass_rate_bar.setValue(0)
        self.pass_rate_bar.setTextVisible(True)
        self.pass_rate_bar.setFormat("%v%")
        self.pass_rate_bar.setMinimumWidth(200)
        self.pass_rate_bar.setMaximumHeight(22)
        bar_layout.addWidget(self.pass_rate_bar)

        bar_layout.addStretch()

        return bar

    # ------------------------------------------------------------------
    # Findings Checklist (Left Panel)
    # ------------------------------------------------------------------

    def _create_findings_checklist(self) -> QWidget:
        """Create the findings checklist table with status indicators."""
        panel = QFrame()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(8, 8, 8, 8)

        header_label = QLabel("Findings Checklist")
        header_label.setObjectName("sectionLabel")
        panel_layout.addWidget(header_label)

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(4)
        self.findings_table.setHorizontalHeaderLabels([
            "Title", "Severity", "Original Status", "Retest Status",
        ])
        self.findings_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.findings_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.findings_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.findings_table.horizontalHeader().setStretchLastSection(True)
        self.findings_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.findings_table.itemSelectionChanged.connect(
            self._on_finding_selected
        )
        panel_layout.addWidget(self.findings_table)

        return panel

    # ------------------------------------------------------------------
    # Right Panel: Result Form + Cycle History
    # ------------------------------------------------------------------

    def _create_right_panel(self) -> QWidget:
        """Create the right panel with retest result form and cycle history."""
        panel = QFrame()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(8, 8, 8, 8)

        # --- Retest Result Form ---
        form_label = QLabel("Record Retest Result")
        form_label.setObjectName("sectionLabel")
        panel_layout.addWidget(form_label)

        self.selected_finding_label = QLabel("No finding selected")
        self.selected_finding_label.setObjectName("stateIndicator")
        panel_layout.addWidget(self.selected_finding_label)

        # Status dropdown
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.status_combo = QComboBox()
        for status in RETEST_STATUSES:
            self.status_combo.addItem(STATUS_DISPLAY_NAMES[status], status)
        status_layout.addWidget(self.status_combo)
        panel_layout.addLayout(status_layout)

        # Notes text area
        panel_layout.addWidget(QLabel("Retester Notes:"))
        self.notes_text = QTextEdit()
        self.notes_text.setPlaceholderText(
            "Enter retest observations, steps taken, and findings..."
        )
        self.notes_text.setMaximumHeight(120)
        panel_layout.addWidget(self.notes_text)

        # Evidence attachment
        evidence_layout = QHBoxLayout()
        self.evidence_label = QLabel("No evidence attached")
        self.evidence_label.setObjectName("evidenceLabel")
        evidence_layout.addWidget(self.evidence_label, 1)

        self.attach_evidence_btn = QPushButton("Attach Evidence")
        self.attach_evidence_btn.setMinimumHeight(35)
        self.attach_evidence_btn.clicked.connect(self._on_attach_evidence)
        evidence_layout.addWidget(self.attach_evidence_btn)
        panel_layout.addLayout(evidence_layout)

        # Record button
        self.record_btn = QPushButton("Record Retest Result")
        self.record_btn.setMinimumHeight(40)
        self.record_btn.setObjectName("recordButton")
        self.record_btn.clicked.connect(self._on_record_result)
        panel_layout.addWidget(self.record_btn)

        panel_layout.addSpacing(20)

        # --- Cycle History ---
        history_label = QLabel("Cycle History & Comparison")
        history_label.setObjectName("sectionLabel")
        panel_layout.addWidget(history_label)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels([
            "Cycle", "Start Date", "Status", "Pass Rate",
        ])
        self.history_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.history_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.history_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.history_table.setMaximumHeight(180)
        panel_layout.addWidget(self.history_table)

        panel_layout.addStretch()

        return panel

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect to RetestWorkflow signals if available."""
        # The workflow may emit signals when results change; connect if present
        if hasattr(self.workflow, "result_recorded"):
            self.workflow.result_recorded.connect(self._on_result_recorded_signal)
        if hasattr(self.workflow, "cycle_completed"):
            self.workflow.cycle_completed.connect(self._on_cycle_completed_signal)

    def _on_result_recorded_signal(self, *args):
        """Handle result_recorded signal — refresh data."""
        self.refresh_data()

    def _on_cycle_completed_signal(self, *args):
        """Handle cycle_completed signal — refresh cycles and data."""
        self._refresh_cycle_selector()
        self.refresh_data()

    # ------------------------------------------------------------------
    # Data Refresh
    # ------------------------------------------------------------------

    def refresh_data(self):
        """Refresh all UI components from the workflow data."""
        self._refresh_cycle_selector()
        self._refresh_findings_checklist()
        self._refresh_metrics()
        self._refresh_cycle_history()

    def _refresh_cycle_selector(self):
        """Refresh the cycle selector combo box."""
        self.cycle_selector.blockSignals(True)
        current_cycle_id = self._active_cycle_id
        self.cycle_selector.clear()

        try:
            cycles = self.workflow.get_cycles()
            if not cycles:
                self.cycle_selector.addItem("No cycles available", None)
                self._active_cycle_id = None
            else:
                for cycle in cycles:
                    cycle_id = cycle.get("id")
                    cycle_num = cycle.get("cycle_number", "?")
                    start_date = cycle.get("start_date", "")[:10]
                    status = cycle.get("status", "in_progress")
                    display = f"Cycle #{cycle_num} ({start_date}) - {status}"
                    self.cycle_selector.addItem(display, cycle_id)

                # Restore selection or select latest
                if current_cycle_id is not None:
                    for i in range(self.cycle_selector.count()):
                        if self.cycle_selector.itemData(i) == current_cycle_id:
                            self.cycle_selector.setCurrentIndex(i)
                            break
                    else:
                        # Select latest cycle (last in list)
                        self.cycle_selector.setCurrentIndex(
                            self.cycle_selector.count() - 1
                        )
                else:
                    self.cycle_selector.setCurrentIndex(
                        self.cycle_selector.count() - 1
                    )

                self._active_cycle_id = self.cycle_selector.currentData()
        except Exception:
            self.cycle_selector.addItem("Error loading cycles", None)
            self._active_cycle_id = None

        self.cycle_selector.blockSignals(False)

    def _refresh_findings_checklist(self):
        """Refresh the findings checklist table for the active cycle."""
        self.findings_table.setRowCount(0)

        if self._active_cycle_id is None:
            return

        try:
            checklist = self.workflow.get_findings_checklist(self._active_cycle_id)
            for item in checklist:
                row = self.findings_table.rowCount()
                self.findings_table.insertRow(row)

                # Title
                title_item = QTableWidgetItem(item.get("title", "Unknown"))
                title_item.setData(
                    Qt.ItemDataRole.UserRole, item.get("finding_id")
                )
                self.findings_table.setItem(row, 0, title_item)

                # Severity
                severity = item.get("severity", "info")
                severity_item = QTableWidgetItem(severity.capitalize())
                severity_item.setForeground(
                    QColor(self._severity_color(severity))
                )
                self.findings_table.setItem(row, 1, severity_item)

                # Original Status
                original_status = item.get("original_status", "open")
                original_item = QTableWidgetItem(original_status.capitalize())
                self.findings_table.setItem(row, 2, original_item)

                # Retest Status with color indicator
                retest_status = item.get("retest_status", "not_tested")
                display_name = STATUS_DISPLAY_NAMES.get(
                    retest_status, retest_status
                )
                status_item = QTableWidgetItem(display_name)
                status_color = STATUS_COLORS.get(retest_status, "#808080")
                status_item.setForeground(QColor(status_color))

                # Bold font for regressed items
                if retest_status == "regressed":
                    font = QFont()
                    font.setBold(True)
                    status_item.setFont(font)
                    # Highlight the entire row for regressed findings
                    for col in range(4):
                        existing = self.findings_table.item(row, col)
                        if existing:
                            existing.setBackground(
                                QColor(255, 68, 68, 40)
                            )
                    status_item.setBackground(QColor(255, 68, 68, 40))

                self.findings_table.setItem(row, 3, status_item)

        except Exception:
            pass

    def _refresh_metrics(self):
        """Refresh the metrics dashboard from workflow data."""
        if self._active_cycle_id is None:
            self.total_label.setText("Total: 0")
            self.retested_label.setText("Retested: 0")
            self.remaining_label.setText("Remaining: 0")
            self.regressed_label.setText("Regressed: 0")
            self.pass_rate_bar.setValue(0)
            return

        try:
            metrics = self.workflow.get_metrics(self._active_cycle_id)
            total = metrics.get("total", 0)
            retested = metrics.get("retested", 0)
            remaining = metrics.get("remaining", 0)
            regressed = metrics.get("regressed", 0)
            pass_rate = metrics.get("pass_rate", 0.0)

            self.total_label.setText(f"Total: {total}")
            self.retested_label.setText(f"Retested: {retested}")
            self.remaining_label.setText(f"Remaining: {remaining}")
            self.regressed_label.setText(f"Regressed: {regressed}")

            # Pass rate as percentage (0-100)
            pass_pct = int(pass_rate * 100) if pass_rate <= 1.0 else int(pass_rate)
            self.pass_rate_bar.setValue(pass_pct)

        except Exception:
            pass

    def _refresh_cycle_history(self):
        """Refresh the cycle history table."""
        self.history_table.setRowCount(0)

        try:
            cycles = self.workflow.get_cycles()
            for cycle in cycles:
                row = self.history_table.rowCount()
                self.history_table.insertRow(row)

                # Cycle number
                cycle_num = cycle.get("cycle_number", "?")
                num_item = QTableWidgetItem(f"Cycle #{cycle_num}")
                num_item.setData(Qt.ItemDataRole.UserRole, cycle.get("id"))
                self.history_table.setItem(row, 0, num_item)

                # Start date
                start_date = cycle.get("start_date", "")[:10]
                self.history_table.setItem(
                    row, 1, QTableWidgetItem(start_date)
                )

                # Status
                status = cycle.get("status", "in_progress")
                status_item = QTableWidgetItem(status.replace("_", " ").title())
                if status == "completed":
                    status_item.setForeground(QColor("#00D68F"))
                else:
                    status_item.setForeground(QColor("#64C8FF"))
                self.history_table.setItem(row, 2, status_item)

                # Pass rate (from metrics if available)
                cycle_pass_rate = cycle.get("pass_rate", "—")
                if isinstance(cycle_pass_rate, (int, float)):
                    rate_pct = int(cycle_pass_rate * 100) if cycle_pass_rate <= 1.0 else int(cycle_pass_rate)
                    rate_text = f"{rate_pct}%"
                else:
                    rate_text = str(cycle_pass_rate)
                self.history_table.setItem(
                    row, 3, QTableWidgetItem(rate_text)
                )

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_cycle_changed(self, index: int):
        """Handle cycle selector change."""
        cycle_id = self.cycle_selector.itemData(index)
        if cycle_id is not None:
            self._active_cycle_id = cycle_id
            self.cycle_changed.emit(cycle_id)
            self._refresh_findings_checklist()
            self._refresh_metrics()

    def _on_new_cycle(self):
        """Handle New Retest Cycle button click."""
        try:
            cycle_id = self.workflow.create_retest_cycle()
            if cycle_id:
                self._active_cycle_id = cycle_id
                self.refresh_data()
        except Exception as e:
            self._show_error(f"Failed to create retest cycle: {e}")

    def _on_complete_cycle(self):
        """Handle Complete Cycle button click."""
        if self._active_cycle_id is None:
            self._show_error("No active cycle to complete.")
            return

        reply = QMessageBox.question(
            self,
            "Complete Retest Cycle",
            "Are you sure you want to complete this retest cycle?\n"
            "This will generate a retest summary report.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.workflow.complete_cycle(self._active_cycle_id)
                self.refresh_data()
            except Exception as e:
                self._show_error(f"Failed to complete cycle: {e}")

    def _on_finding_selected(self):
        """Handle finding selection in the checklist table."""
        selected = self.findings_table.selectedItems()
        if not selected:
            self._selected_finding_id = None
            self.selected_finding_label.setText("No finding selected")
            return

        row = self.findings_table.currentRow()
        title_item = self.findings_table.item(row, 0)
        if title_item:
            self._selected_finding_id = title_item.data(
                Qt.ItemDataRole.UserRole
            )
            title = title_item.text()
            self.selected_finding_label.setText(f"Finding: {title}")
            self.finding_selected.emit(self._selected_finding_id)

    def _on_attach_evidence(self):
        """Handle Attach Evidence button click."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Attach Evidence",
            "",
            "All Files (*);;Images (*.png *.jpg *.jpeg);;Text (*.txt *.log)",
        )
        if file_path:
            self._evidence_path = file_path
            # Show just the filename
            import os
            filename = os.path.basename(file_path)
            self.evidence_label.setText(f"📎 {filename}")

    def _on_record_result(self):
        """Handle Record Retest Result button click."""
        if self._selected_finding_id is None:
            self._show_error(
                "No finding selected. Select a finding from the checklist."
            )
            return

        if self._active_cycle_id is None:
            self._show_error(
                "No active retest cycle. Create a new cycle first."
            )
            return

        status = self.status_combo.currentData()
        notes = self.notes_text.toPlainText().strip()

        if not notes:
            reply = QMessageBox.question(
                self,
                "No Notes",
                "No retester notes provided. Continue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                return

        try:
            self.workflow.record_retest_result(
                cycle_id=self._active_cycle_id,
                finding_id=self._selected_finding_id,
                retest_status=status,
                retester_notes=notes,
                evidence_path=self._evidence_path,
            )

            self.retest_recorded.emit(self._selected_finding_id, status)

            # Clear the form
            self.notes_text.clear()
            self._evidence_path = None
            self.evidence_label.setText("No evidence attached")

            # Refresh data
            self._refresh_findings_checklist()
            self._refresh_metrics()

        except Exception as e:
            self._show_error(f"Failed to record retest result: {e}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _severity_color(self, severity: str) -> str:
        """Return a color for finding severity."""
        colors = {
            "critical": "#FF4444",
            "high": "#FF8C00",
            "medium": "#FFD700",
            "low": "#00D68F",
            "info": "#64C8FF",
        }
        return colors.get(severity.lower(), "#DCDCDC")

    def _show_error(self, message: str):
        """Show an error message box."""
        QMessageBox.warning(self, "Retest Workflow", message)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass
