# app/components/attack_matrix_component.py
"""ATT&CK Matrix UI Component.

Provides an interactive MITRE ATT&CK coverage matrix with:
- Top: Filter controls (tactic, platform, data source)
- Left: Scrollable matrix grid (tactics as columns, techniques as rows)
- Right: Technique detail panel with linked findings, evidence, and procedures
- Mapping interface for assigning techniques to findings
- Suggested mappings panel with accept/reject actions

Integrates as a new tab within the Reporting page.

Requirements: 5.3, 5.4, 5.5, 5.7
"""

from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


# Cell color constants for coverage status
COLOR_SUCCESSFUL = "#00D68F"  # tested/successful - green
COLOR_TESTED_FAILED = "#FFD700"  # tested/failed - yellow
COLOR_NOT_TESTED = "#404040"  # not_tested - gray


class ATTACKMatrixComponent(QWidget):
    """ATT&CK Matrix coverage visualization and mapping component.

    Provides a full interactive MITRE ATT&CK coverage matrix with filtering,
    technique details, and mapping capabilities.

    Signals:
        technique_selected(str): Emitted with technique ID when a cell is clicked.
        mapping_created(int, str): Emitted with (finding_id, technique_id) on mapping.
    """

    technique_selected = pyqtSignal(str)
    mapping_created = pyqtSignal(int, str)

    def __init__(self, attack_mapper, engagement_db=None, parent=None):
        """Initialize the ATTACKMatrixComponent.

        Args:
            attack_mapper: The ATTACKMapper instance for data operations.
            engagement_db: Optional EngagementDatabase instance for finding queries.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.mapper = attack_mapper
        self.engagement_db = engagement_db
        self._selected_technique_id: Optional[str] = None
        self._current_tactic_filter: Optional[str] = None
        self._current_platform_filter: Optional[str] = None
        self._current_datasource_filter: Optional[str] = None

        self.setup_ui()
        self.apply_theme()
        self._connect_signals()
        self.refresh_matrix()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def setup_ui(self):
        """Build the layout: top filter bar, left matrix grid, right detail panel."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Top filter bar
        layout.addWidget(self._create_filter_bar())

        # Main content: matrix grid (left) + detail panel (right)
        content_layout = QHBoxLayout()
        content_layout.setSpacing(8)

        # Left: scrollable matrix grid
        content_layout.addWidget(self._create_matrix_panel(), 3)

        # Right: detail panel + suggested mappings
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(8, 8, 8, 8)
        right_layout.setSpacing(6)

        right_layout.addWidget(self._create_detail_panel(), 2)
        right_layout.addWidget(self._create_suggested_mappings_panel(), 1)

        content_layout.addWidget(right_panel, 2)
        layout.addLayout(content_layout, 1)

    # ------------------------------------------------------------------
    # Filter Bar
    # ------------------------------------------------------------------

    def _create_filter_bar(self) -> QWidget:
        """Create the top filter controls bar."""
        container = QFrame()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(12)

        # Title
        title_label = QLabel("ATT&CK Coverage Matrix")
        title_label.setObjectName("sectionLabel")
        layout.addWidget(title_label)

        layout.addSpacing(16)

        # Tactic filter
        layout.addWidget(QLabel("Tactic:"))
        self.tactic_filter_combo = QComboBox()
        self.tactic_filter_combo.addItem("All Tactics", None)
        self.tactic_filter_combo.setMinimumWidth(160)
        layout.addWidget(self.tactic_filter_combo)

        # Platform filter
        layout.addWidget(QLabel("Platform:"))
        self.platform_filter_combo = QComboBox()
        self.platform_filter_combo.addItem("All Platforms", None)
        self.platform_filter_combo.addItems([
            "Windows", "Linux", "macOS", "Cloud", "Network",
            "Containers", "SaaS", "IaaS", "Office 365", "Azure AD",
            "Google Workspace",
        ])
        self.platform_filter_combo.setMinimumWidth(140)
        layout.addWidget(self.platform_filter_combo)

        # Data source filter
        layout.addWidget(QLabel("Data Source:"))
        self.datasource_filter_combo = QComboBox()
        self.datasource_filter_combo.addItem("All Data Sources", None)
        self.datasource_filter_combo.addItems([
            "Process", "Network Traffic", "File", "Command",
            "User Account", "Logon Session", "Windows Registry",
            "Scheduled Job", "Service", "Firmware",
        ])
        self.datasource_filter_combo.setMinimumWidth(150)
        layout.addWidget(self.datasource_filter_combo)

        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setMinimumHeight(30)
        layout.addWidget(self.refresh_btn)

        layout.addStretch()

        # Coverage summary stats
        self.stats_label = QLabel("Coverage: --")
        self.stats_label.setObjectName("countLabel")
        layout.addWidget(self.stats_label)

        return container

    # ------------------------------------------------------------------
    # Matrix Grid Panel
    # ------------------------------------------------------------------

    def _create_matrix_panel(self) -> QWidget:
        """Create the scrollable ATT&CK matrix grid."""
        container = QFrame()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(8, 8, 8, 8)
        container_layout.setSpacing(4)

        matrix_label = QLabel("Coverage Matrix")
        matrix_label.setObjectName("sectionLabel")
        container_layout.addWidget(matrix_label)

        # Legend
        legend = self._create_legend()
        container_layout.addWidget(legend)

        # Scrollable matrix table
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)

        self.matrix_table = QTableWidget()
        self.matrix_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.matrix_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.matrix_table.setAlternatingRowColors(False)
        self.matrix_table.verticalHeader().setDefaultSectionSize(28)
        self.matrix_table.horizontalHeader().setDefaultSectionSize(120)
        self.matrix_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )

        scroll_area.setWidget(self.matrix_table)
        container_layout.addWidget(scroll_area, 1)

        return container

    def _create_legend(self) -> QWidget:
        """Create the color-coded legend for the matrix."""
        legend_widget = QWidget()
        legend_layout = QHBoxLayout(legend_widget)
        legend_layout.setContentsMargins(0, 2, 0, 2)
        legend_layout.setSpacing(16)

        # Successful/Tested
        success_dot = QLabel("●")
        success_dot.setStyleSheet(f"color: {COLOR_SUCCESSFUL}; font-size: 14px; border: none; background: transparent;")
        legend_layout.addWidget(success_dot)
        legend_layout.addWidget(QLabel("Tested/Successful"))

        # Tested/Failed
        failed_dot = QLabel("●")
        failed_dot.setStyleSheet(f"color: {COLOR_TESTED_FAILED}; font-size: 14px; border: none; background: transparent;")
        legend_layout.addWidget(failed_dot)
        legend_layout.addWidget(QLabel("Tested/Failed"))

        # Not Tested
        not_tested_dot = QLabel("●")
        not_tested_dot.setStyleSheet(f"color: {COLOR_NOT_TESTED}; font-size: 14px; border: none; background: transparent;")
        legend_layout.addWidget(not_tested_dot)
        legend_layout.addWidget(QLabel("Not Tested"))

        legend_layout.addStretch()
        return legend_widget

    # ------------------------------------------------------------------
    # Detail Panel
    # ------------------------------------------------------------------

    def _create_detail_panel(self) -> QWidget:
        """Create the technique detail panel (right side)."""
        container = QFrame()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(8, 8, 8, 8)
        container_layout.setSpacing(6)

        detail_label = QLabel("Technique Details")
        detail_label.setObjectName("sectionLabel")
        container_layout.addWidget(detail_label)

        # Technique info
        self.technique_name_label = QLabel("Select a technique from the matrix")
        self.technique_name_label.setWordWrap(True)
        self.technique_name_label.setObjectName("techniqueNameLabel")
        container_layout.addWidget(self.technique_name_label)

        self.technique_id_label = QLabel("")
        self.technique_id_label.setObjectName("countLabel")
        container_layout.addWidget(self.technique_id_label)

        self.technique_tactic_label = QLabel("")
        container_layout.addWidget(self.technique_tactic_label)

        self.technique_description_label = QLabel("")
        self.technique_description_label.setWordWrap(True)
        self.technique_description_label.setMaximumHeight(80)
        container_layout.addWidget(self.technique_description_label)

        # Linked findings section
        container_layout.addSpacing(8)
        findings_label = QLabel("Linked Findings")
        findings_label.setObjectName("sectionLabel")
        container_layout.addWidget(findings_label)

        self.findings_list = QListWidget()
        self.findings_list.setMaximumHeight(120)
        container_layout.addWidget(self.findings_list)

        # Evidence section
        evidence_label = QLabel("Evidence")
        evidence_label.setObjectName("sectionLabel")
        container_layout.addWidget(evidence_label)

        self.evidence_list = QListWidget()
        self.evidence_list.setMaximumHeight(80)
        container_layout.addWidget(self.evidence_list)

        # Procedures section
        procedures_label = QLabel("Procedures")
        procedures_label.setObjectName("sectionLabel")
        container_layout.addWidget(procedures_label)

        self.procedures_list = QListWidget()
        self.procedures_list.setMaximumHeight(80)
        container_layout.addWidget(self.procedures_list)

        # Action buttons
        btn_layout = QHBoxLayout()
        self.link_finding_btn = QPushButton("Link to Finding")
        self.link_finding_btn.setMinimumHeight(32)
        self.link_finding_btn.setEnabled(False)
        btn_layout.addWidget(self.link_finding_btn)

        self.unlink_btn = QPushButton("Unlink Selected")
        self.unlink_btn.setMinimumHeight(32)
        self.unlink_btn.setEnabled(False)
        btn_layout.addWidget(self.unlink_btn)

        container_layout.addLayout(btn_layout)
        container_layout.addStretch()

        return container

    # ------------------------------------------------------------------
    # Suggested Mappings Panel
    # ------------------------------------------------------------------

    def _create_suggested_mappings_panel(self) -> QWidget:
        """Create the suggested mappings panel with accept/reject actions."""
        container = QFrame()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(8, 8, 8, 8)
        container_layout.setSpacing(6)

        suggested_label = QLabel("Suggested Mappings")
        suggested_label.setObjectName("sectionLabel")
        container_layout.addWidget(suggested_label)

        self.suggestions_list = QListWidget()
        self.suggestions_list.setMaximumHeight(120)
        container_layout.addWidget(self.suggestions_list)

        # Accept/Reject buttons
        btn_layout = QHBoxLayout()
        self.accept_suggestion_btn = QPushButton("Accept")
        self.accept_suggestion_btn.setMinimumHeight(30)
        self.accept_suggestion_btn.setEnabled(False)
        btn_layout.addWidget(self.accept_suggestion_btn)

        self.reject_suggestion_btn = QPushButton("Reject")
        self.reject_suggestion_btn.setMinimumHeight(30)
        self.reject_suggestion_btn.setEnabled(False)
        btn_layout.addWidget(self.reject_suggestion_btn)

        self.refresh_suggestions_btn = QPushButton("Get Suggestions")
        self.refresh_suggestions_btn.setMinimumHeight(30)
        btn_layout.addWidget(self.refresh_suggestions_btn)

        container_layout.addLayout(btn_layout)

        return container

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect widget signals to handler methods."""
        # Filter controls
        self.tactic_filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        self.platform_filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        self.datasource_filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        self.refresh_btn.clicked.connect(self.refresh_matrix)

        # Matrix cell selection
        self.matrix_table.cellClicked.connect(self._on_cell_clicked)

        # Mapping actions
        self.link_finding_btn.clicked.connect(self._on_link_finding)
        self.unlink_btn.clicked.connect(self._on_unlink_finding)

        # Suggestions
        self.accept_suggestion_btn.clicked.connect(self._on_accept_suggestion)
        self.reject_suggestion_btn.clicked.connect(self._on_reject_suggestion)
        self.refresh_suggestions_btn.clicked.connect(self._on_refresh_suggestions)
        self.suggestions_list.currentItemChanged.connect(self._on_suggestion_selected)

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_filter_changed(self):
        """Handle filter combo box changes."""
        self._current_tactic_filter = self.tactic_filter_combo.currentData()
        self._current_platform_filter = self.platform_filter_combo.currentText()
        if self._current_platform_filter == "All Platforms":
            self._current_platform_filter = None
        self._current_datasource_filter = self.datasource_filter_combo.currentText()
        if self._current_datasource_filter == "All Data Sources":
            self._current_datasource_filter = None
        self.refresh_matrix()

    def _on_cell_clicked(self, row: int, col: int):
        """Handle matrix cell click - show technique details."""
        item = self.matrix_table.item(row, col)
        if item is None:
            return

        technique_id = item.data(Qt.ItemDataRole.UserRole)
        if technique_id:
            self._selected_technique_id = technique_id
            self.technique_selected.emit(technique_id)
            self._load_technique_details(technique_id)
            self.link_finding_btn.setEnabled(True)

    def _on_link_finding(self):
        """Open dialog to link a finding to the selected technique."""
        if not self._selected_technique_id:
            self._show_validation_error("No technique selected. Click a cell in the matrix first.")
            return

        dialog = LinkFindingDialog(self.mapper, self._selected_technique_id, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            finding_id = dialog.get_selected_finding_id()
            if finding_id is not None:
                try:
                    self.mapper.map_finding_to_technique(
                        finding_id=finding_id,
                        technique_id=self._selected_technique_id,
                    )
                    self.mapping_created.emit(finding_id, self._selected_technique_id)
                    self._load_technique_details(self._selected_technique_id)
                    self.refresh_matrix()
                except Exception as e:
                    self._show_validation_error(f"Failed to create mapping: {e}")

    def _on_unlink_finding(self):
        """Unlink the selected finding from the current technique."""
        if not self._selected_technique_id:
            return

        selected = self.findings_list.currentItem()
        if not selected:
            self._show_validation_error("No finding selected to unlink.")
            return

        finding_id = selected.data(Qt.ItemDataRole.UserRole)
        if finding_id is not None:
            try:
                self.mapper.unmap_finding_from_technique(
                    finding_id=finding_id,
                    technique_id=self._selected_technique_id,
                )
                self._load_technique_details(self._selected_technique_id)
                self.refresh_matrix()
            except Exception as e:
                self._show_validation_error(f"Failed to unlink finding: {e}")

    def _on_accept_suggestion(self):
        """Accept the selected suggested mapping."""
        selected = self.suggestions_list.currentItem()
        if not selected:
            return

        suggestion_data = selected.data(Qt.ItemDataRole.UserRole)
        if suggestion_data:
            finding_id = suggestion_data.get("finding_id")
            technique_id = suggestion_data.get("technique_id")
            if finding_id is not None and technique_id:
                try:
                    self.mapper.map_finding_to_technique(
                        finding_id=finding_id,
                        technique_id=technique_id,
                    )
                    self.mapping_created.emit(finding_id, technique_id)
                    # Remove accepted suggestion from list
                    row = self.suggestions_list.row(selected)
                    self.suggestions_list.takeItem(row)
                    self.refresh_matrix()
                    if self._selected_technique_id == technique_id:
                        self._load_technique_details(technique_id)
                except Exception as e:
                    self._show_validation_error(f"Failed to apply mapping: {e}")

    def _on_reject_suggestion(self):
        """Reject (remove) the selected suggested mapping."""
        selected = self.suggestions_list.currentItem()
        if not selected:
            return

        row = self.suggestions_list.row(selected)
        self.suggestions_list.takeItem(row)

        if self.suggestions_list.count() == 0:
            self.accept_suggestion_btn.setEnabled(False)
            self.reject_suggestion_btn.setEnabled(False)

    def _on_suggestion_selected(self, current: QListWidgetItem, previous: QListWidgetItem):
        """Handle suggestion list selection change."""
        has_selection = current is not None
        self.accept_suggestion_btn.setEnabled(has_selection)
        self.reject_suggestion_btn.setEnabled(has_selection)

    def _on_refresh_suggestions(self):
        """Refresh the suggested mappings from the ATT&CK mapper."""
        self.suggestions_list.clear()

        try:
            suggestions = self.mapper.suggest_techniques()
        except Exception:
            suggestions = []

        for suggestion in suggestions:
            technique_id = suggestion.get("technique_id", "")
            technique_name = suggestion.get("technique_name", "Unknown")
            finding_title = suggestion.get("finding_title", "Unknown finding")
            confidence = suggestion.get("confidence", 0.0)

            display_text = (
                f"[{confidence:.0%}] {technique_id} → {finding_title}"
            )
            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, suggestion)
            item.setToolTip(
                f"Technique: {technique_name} ({technique_id})\n"
                f"Finding: {finding_title}\n"
                f"Confidence: {confidence:.0%}"
            )
            self.suggestions_list.addItem(item)

        if self.suggestions_list.count() == 0:
            placeholder = QListWidgetItem("No suggestions available")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.suggestions_list.addItem(placeholder)

    # ------------------------------------------------------------------
    # Data Loading
    # ------------------------------------------------------------------

    def refresh_matrix(self):
        """Refresh the coverage matrix grid from the ATT&CK mapper."""
        try:
            coverage_data = self.mapper.get_coverage_matrix()
        except Exception:
            coverage_data = {}

        # Get tactics list
        try:
            tactics = self.mapper.get_tactics()
        except Exception:
            tactics = []

        # Populate tactic filter combo if not yet done
        if self.tactic_filter_combo.count() <= 1:
            for tactic in tactics:
                tactic_name = tactic.get("name", tactic) if isinstance(tactic, dict) else str(tactic)
                tactic_id = tactic.get("id", tactic) if isinstance(tactic, dict) else str(tactic)
                self.tactic_filter_combo.addItem(tactic_name, tactic_id)

        # Apply tactic filter if active
        display_tactics = tactics
        if self._current_tactic_filter:
            display_tactics = [
                t for t in tactics
                if (t.get("id") if isinstance(t, dict) else str(t)) == self._current_tactic_filter
            ]

        # Build column headers (tactics)
        tactic_names = []
        tactic_ids = []
        for tactic in display_tactics:
            if isinstance(tactic, dict):
                tactic_names.append(tactic.get("name", "Unknown"))
                tactic_ids.append(tactic.get("id", ""))
            else:
                tactic_names.append(str(tactic))
                tactic_ids.append(str(tactic))

        # Collect all techniques across displayed tactics
        all_techniques: Dict[str, Dict] = {}
        tactic_technique_map: Dict[str, List[str]] = {}

        for tactic_id in tactic_ids:
            try:
                techniques = self.mapper.get_techniques_for_tactic(tactic_id)
            except Exception:
                techniques = []

            # Apply platform and datasource filters
            filtered_techniques = self._apply_technique_filters(techniques)
            tactic_technique_map[tactic_id] = []
            for tech in filtered_techniques:
                tech_id = tech.get("id", "") if isinstance(tech, dict) else str(tech)
                if tech_id not in all_techniques:
                    all_techniques[tech_id] = tech if isinstance(tech, dict) else {"id": tech_id, "name": str(tech)}
                tactic_technique_map[tactic_id].append(tech_id)

        # Setup table
        technique_ids_sorted = sorted(all_techniques.keys())
        self.matrix_table.setColumnCount(len(tactic_names))
        self.matrix_table.setRowCount(len(technique_ids_sorted))
        self.matrix_table.setHorizontalHeaderLabels(tactic_names)

        # Set row headers (technique names)
        row_labels = []
        for tech_id in technique_ids_sorted:
            tech_info = all_techniques[tech_id]
            tech_name = tech_info.get("name", tech_id) if isinstance(tech_info, dict) else str(tech_info)
            row_labels.append(f"{tech_id}: {tech_name}")
        self.matrix_table.setVerticalHeaderLabels(row_labels)

        # Populate cells
        tested_count = 0
        total_cells = 0

        for row_idx, tech_id in enumerate(technique_ids_sorted):
            for col_idx, tactic_id in enumerate(tactic_ids):
                total_cells += 1
                # Determine status for this technique under this tactic
                status = self._get_technique_status(tech_id, tactic_id, coverage_data)

                item = QTableWidgetItem()
                item.setData(Qt.ItemDataRole.UserRole, tech_id)
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                if tech_id in tactic_technique_map.get(tactic_id, []):
                    if status == "successful":
                        item.setBackground(QColor(COLOR_SUCCESSFUL))
                        item.setText("✓")
                        tested_count += 1
                    elif status == "tested":
                        item.setBackground(QColor(COLOR_TESTED_FAILED))
                        item.setText("~")
                        tested_count += 1
                    else:
                        item.setBackground(QColor(COLOR_NOT_TESTED))
                        item.setText("")
                    item.setToolTip(f"{tech_id} | {tactic_id} | Status: {status}")
                else:
                    # Technique not applicable to this tactic
                    item.setBackground(QColor("#1A1A1A"))
                    item.setFlags(Qt.ItemFlag.NoItemFlags)

                self.matrix_table.setItem(row_idx, col_idx, item)

        # Update coverage stats
        if total_cells > 0:
            coverage_pct = (tested_count / total_cells) * 100
            self.stats_label.setText(
                f"Coverage: {tested_count}/{total_cells} ({coverage_pct:.1f}%)"
            )
        else:
            self.stats_label.setText("Coverage: --")

    def _apply_technique_filters(self, techniques: List) -> List:
        """Apply platform and data source filters to a technique list."""
        if not self._current_platform_filter and not self._current_datasource_filter:
            return techniques

        filtered = []
        for tech in techniques:
            if not isinstance(tech, dict):
                filtered.append(tech)
                continue

            # Platform filter
            if self._current_platform_filter:
                platforms = tech.get("platforms", [])
                if isinstance(platforms, list) and self._current_platform_filter not in platforms:
                    continue

            # Data source filter
            if self._current_datasource_filter:
                data_sources = tech.get("data_sources", [])
                if isinstance(data_sources, list) and self._current_datasource_filter not in data_sources:
                    continue

            filtered.append(tech)

        return filtered

    def _get_technique_status(
        self, technique_id: str, tactic_id: str, coverage_data: Dict
    ) -> str:
        """Determine the status of a technique for a given tactic.

        Returns:
            One of 'successful', 'tested', or 'not_tested'.
        """
        # coverage_data structure depends on ATTACKMapper implementation
        # Expected format: {technique_id: {"status": "successful"|"tested"|"not_tested", ...}}
        if not coverage_data:
            return "not_tested"

        tech_data = coverage_data.get(technique_id)
        if tech_data is None:
            return "not_tested"

        if isinstance(tech_data, dict):
            return tech_data.get("status", "not_tested")
        elif isinstance(tech_data, str):
            return tech_data

        return "not_tested"

    def _load_technique_details(self, technique_id: str):
        """Load and display detailed information for a technique."""
        self.findings_list.clear()
        self.evidence_list.clear()
        self.procedures_list.clear()

        # Get technique info from mapper
        try:
            details = self.mapper.get_findings_for_technique(technique_id)
        except Exception:
            details = {}

        # Update technique info labels
        if isinstance(details, dict):
            self.technique_name_label.setText(
                details.get("technique_name", technique_id)
            )
            self.technique_id_label.setText(
                f"ID: {details.get('technique_id', technique_id)}"
            )
            self.technique_tactic_label.setText(
                f"Tactic: {details.get('tactic', 'N/A')}"
            )
            self.technique_description_label.setText(
                details.get("description", "No description available.")
            )

            # Populate linked findings
            findings = details.get("findings", [])
            for finding in findings:
                if isinstance(finding, dict):
                    display = f"[{finding.get('severity', '?')}] {finding.get('title', 'Untitled')}"
                    item = QListWidgetItem(display)
                    item.setData(Qt.ItemDataRole.UserRole, finding.get("id"))
                    item.setToolTip(
                        f"Finding #{finding.get('id')}: {finding.get('title', '')}\n"
                        f"Severity: {finding.get('severity', 'Unknown')}"
                    )
                    self.findings_list.addItem(item)

            # Populate evidence
            evidence_items = details.get("evidence", [])
            for ev in evidence_items:
                if isinstance(ev, dict):
                    display = f"[{ev.get('type', '?')}] {ev.get('title', 'Untitled')}"
                    item = QListWidgetItem(display)
                    item.setData(Qt.ItemDataRole.UserRole, ev.get("id"))
                    self.evidence_list.addItem(item)

            # Populate procedures
            procedures = details.get("procedures", [])
            for proc in procedures:
                if isinstance(proc, dict):
                    display = proc.get("description", "No description")
                    item = QListWidgetItem(display)
                    self.procedures_list.addItem(item)
                elif isinstance(proc, str):
                    self.procedures_list.addItem(QListWidgetItem(proc))
        else:
            self.technique_name_label.setText(technique_id)
            self.technique_id_label.setText(f"ID: {technique_id}")
            self.technique_tactic_label.setText("")
            self.technique_description_label.setText("No details available.")

        # Enable/disable unlink button
        self.unlink_btn.setEnabled(self.findings_list.count() > 0)

        # Show placeholder messages for empty lists
        if self.findings_list.count() == 0:
            placeholder = QListWidgetItem("No linked findings")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.findings_list.addItem(placeholder)

        if self.evidence_list.count() == 0:
            placeholder = QListWidgetItem("No evidence")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.evidence_list.addItem(placeholder)

        if self.procedures_list.count() == 0:
            placeholder = QListWidgetItem("No procedures documented")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.procedures_list.addItem(placeholder)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_engagement_db(self, engagement_db):
        """Set or update the engagement database reference.

        Args:
            engagement_db: An EngagementDatabase instance.
        """
        self.engagement_db = engagement_db

    def set_mapper(self, attack_mapper):
        """Set or update the ATT&CK mapper instance.

        Args:
            attack_mapper: An ATTACKMapper instance.
        """
        self.mapper = attack_mapper
        self.refresh_matrix()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _show_validation_error(self, message: str):
        """Show a validation error message box."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Validation Error")
        msg.setText(message)
        msg.setStyleSheet("""
            QMessageBox {
                background-color: rgba(20, 30, 40, 240);
                color: #DCDCDC;
            }
            QLabel { color: #DCDCDC; }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px 15px;
            }
        """)
        msg.exec()

    def _show_info(self, title: str, message: str):
        """Show an informational message box."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.setStyleSheet("""
            QMessageBox {
                background-color: rgba(20, 30, 40, 240);
                color: #DCDCDC;
            }
            QLabel { color: #DCDCDC; }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px 15px;
            }
        """)
        msg.exec()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def apply_theme(self):
        """Apply the dark theme with cyan accents matching project conventions."""
        self.setStyleSheet("""
            QWidget {
                background-color: transparent;
                color: #DCDCDC;
            }
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
                padding: 6px 10px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton:disabled {
                background-color: rgba(20, 25, 30, 100);
                border: 1px solid rgba(100, 200, 255, 30);
                color: rgba(220, 220, 220, 80);
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox QAbstractItemView {
                background-color: rgba(20, 30, 40, 240);
                border: 1px solid rgba(100, 200, 255, 100);
                color: #DCDCDC;
                selection-background-color: rgba(100, 200, 255, 80);
            }
            QListWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
            }
            QListWidget::item {
                padding: 4px 4px;
                border-bottom: 1px solid rgba(100, 200, 255, 20);
            }
            QListWidget::item:selected {
                background-color: rgba(100, 200, 255, 60);
            }
            QListWidget::item:hover {
                background-color: rgba(100, 200, 255, 30);
            }
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                gridline-color: rgba(100, 200, 255, 30);
            }
            QTableWidget::item {
                padding: 2px;
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 80);
            }
            QHeaderView::section {
                background-color: rgba(20, 30, 40, 200);
                color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 50);
                padding: 4px;
                font-weight: bold;
                font-size: 11px;
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
            QLabel {
                color: #DCDCDC;
                border: none;
                background: transparent;
            }
            QLabel#sectionLabel {
                color: #64C8FF;
                font-weight: bold;
                font-size: 14px;
                border: none;
                background: transparent;
            }
            QLabel#countLabel {
                color: #A0A0A0;
                font-size: 11px;
                border: none;
                background: transparent;
            }
            QLabel#techniqueNameLabel {
                color: #FFFFFF;
                font-weight: bold;
                font-size: 13px;
                border: none;
                background: transparent;
            }
        """)


# ---------------------------------------------------------------------------
# Link Finding Dialog
# ---------------------------------------------------------------------------


class LinkFindingDialog(QDialog):
    """Dialog for selecting a finding to link to an ATT&CK technique."""

    def __init__(self, attack_mapper, technique_id: str, parent=None):
        """Initialize the LinkFindingDialog.

        Args:
            attack_mapper: The ATTACKMapper instance for querying available findings.
            technique_id: The technique ID being linked to.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.mapper = attack_mapper
        self.technique_id = technique_id
        self._selected_finding_id: Optional[int] = None

        self.setWindowTitle(f"Link Finding to {technique_id}")
        self.setMinimumSize(450, 400)
        self.setup_ui()
        self.apply_theme()
        self._load_findings()

    def setup_ui(self):
        """Build the dialog layout."""
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Instructions
        instructions = QLabel(
            f"Select a finding to link to technique {self.technique_id}:"
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        # Search filter
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter findings...")
        self.search_input.textChanged.connect(self._on_search_changed)
        layout.addWidget(self.search_input)

        # Findings list
        self.findings_list = QListWidget()
        self.findings_list.currentItemChanged.connect(self._on_finding_selected)
        layout.addWidget(self.findings_list, 1)

        # Dialog buttons
        self.button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        layout.addWidget(self.button_box)

    def _load_findings(self, filter_text: str = ""):
        """Load available findings into the list."""
        self.findings_list.clear()
        self._all_findings = []

        try:
            # Try to get findings from engagement database via mapper
            if hasattr(self.mapper, 'get_available_findings'):
                self._all_findings = self.mapper.get_available_findings()
            elif hasattr(self.mapper, 'engagement_db') and self.mapper.engagement_db:
                # Fallback: query engagement DB directly
                db = self.mapper.engagement_db
                if hasattr(db, 'execute_query'):
                    results = db.execute_query(
                        "SELECT id, title, severity FROM findings ORDER BY severity, title"
                    )
                    self._all_findings = [
                        {"id": r[0], "title": r[1], "severity": r[2]}
                        for r in results
                    ]
        except Exception:
            self._all_findings = []

        # Apply filter
        for finding in self._all_findings:
            title = finding.get("title", "Untitled")
            severity = finding.get("severity", "Unknown")

            if filter_text and filter_text.lower() not in title.lower():
                continue

            display = f"[{severity}] {title}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, finding.get("id"))
            item.setToolTip(f"Finding #{finding.get('id')}: {title}")
            self.findings_list.addItem(item)

        if self.findings_list.count() == 0:
            placeholder = QListWidgetItem("No findings available")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.findings_list.addItem(placeholder)

    def _on_search_changed(self, text: str):
        """Handle search input text change."""
        self._load_findings(text)

    def _on_finding_selected(self, current: QListWidgetItem, previous: QListWidgetItem):
        """Handle finding selection."""
        if current and current.data(Qt.ItemDataRole.UserRole) is not None:
            self._selected_finding_id = current.data(Qt.ItemDataRole.UserRole)
            self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        else:
            self._selected_finding_id = None
            self.button_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)

    def get_selected_finding_id(self) -> Optional[int]:
        """Return the ID of the selected finding.

        Returns:
            The finding ID, or None if no selection.
        """
        return self._selected_finding_id

    def apply_theme(self):
        """Apply dark theme to the dialog."""
        self.setStyleSheet("""
            QDialog {
                background-color: rgba(20, 30, 40, 240);
                color: #DCDCDC;
            }
            QLabel {
                color: #DCDCDC;
                background: transparent;
                border: none;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
            QListWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
            }
            QListWidget::item {
                padding: 6px 4px;
                border-bottom: 1px solid rgba(100, 200, 255, 20);
            }
            QListWidget::item:selected {
                background-color: rgba(100, 200, 255, 60);
            }
            QListWidget::item:hover {
                background-color: rgba(100, 200, 255, 30);
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px 15px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton:disabled {
                background-color: rgba(20, 25, 30, 100);
                border: 1px solid rgba(100, 200, 255, 30);
                color: rgba(220, 220, 220, 80);
            }
        """)
