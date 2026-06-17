# app/components/engagement_setup_component.py
"""Engagement Setup UI Component.

Provides a comprehensive engagement management interface with tabs for:
- Overview: Engagement creation form and list view with state transitions
- Documents: Scoping document upload/view panel
- RoE: Rules of Engagement structured input form
- Contacts: Client contacts CRUD interface
- Milestones: Timeline milestones view

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8
"""

import os
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QDateEdit,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.engagement_manager import (
    EngagementManager,
    EngagementState,
    VALID_TRANSITIONS,
)
from app.core.timeline_logger import TimelineLogger


class EngagementSetupComponent(QWidget):
    """Main engagement setup component with tabbed interface.

    Signals:
        engagement_selected(str): Emitted when an engagement is selected from the list.
    """

    engagement_selected = pyqtSignal(str)

    def __init__(self, engagement_manager: EngagementManager, parent=None):
        super().__init__(parent)
        self.manager = engagement_manager
        self._selected_engagement_id: Optional[str] = None
        self._timeline_logger: Optional[TimelineLogger] = None

        self.setup_ui()
        self.apply_theme()
        self._connect_signals()
        self.refresh_engagement_list()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def setup_ui(self):
        """Build the tabbed layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Create each tab
        self.tabs.addTab(self._create_overview_tab(), "Overview")
        self.tabs.addTab(self._create_documents_tab(), "Documents")
        self.tabs.addTab(self._create_roe_tab(), "Rules of Engagement")
        self.tabs.addTab(self._create_contacts_tab(), "Contacts")
        self.tabs.addTab(self._create_milestones_tab(), "Milestones")
        self.tabs.addTab(self._create_timeline_tab(), "Timeline")

    # ------------------------------------------------------------------
    # Overview Tab
    # ------------------------------------------------------------------

    def _create_overview_tab(self) -> QWidget:
        """Create the overview tab with creation form, list, and state controls."""
        tab = QWidget()
        layout = QHBoxLayout(tab)

        # Left panel: creation form + state controls
        left_panel = QFrame()
        left_panel.setFixedWidth(320)
        left_layout = QVBoxLayout(left_panel)

        # --- Creation Form ---
        form_label = QLabel("Create Engagement")
        form_label.setObjectName("sectionLabel")
        left_layout.addWidget(form_label)

        form = QFormLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Engagement name")
        form.addRow("Name:", self.name_input)

        self.client_input = QLineEdit()
        self.client_input.setPlaceholderText("Client organization")
        form.addRow("Client:", self.client_input)

        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "internal", "external", "web", "mobile", "physical", "cloud"
        ])
        form.addRow("Type:", self.type_combo)

        self.start_date_input = QDateEdit()
        self.start_date_input.setCalendarPopup(True)
        self.start_date_input.setDate(datetime.now().date())
        form.addRow("Start:", self.start_date_input)

        self.end_date_input = QDateEdit()
        self.end_date_input.setCalendarPopup(True)
        self.end_date_input.setDate(datetime.now().date())
        form.addRow("End:", self.end_date_input)

        left_layout.addLayout(form)

        self.create_btn = QPushButton("Create Engagement")
        self.create_btn.setMinimumHeight(35)
        self.create_btn.clicked.connect(self._on_create_engagement)
        left_layout.addWidget(self.create_btn)

        # --- State Transition Controls ---
        left_layout.addSpacing(16)
        state_label = QLabel("State Transition")
        state_label.setObjectName("sectionLabel")
        left_layout.addWidget(state_label)

        self.state_indicator = QLabel("No engagement selected")
        self.state_indicator.setObjectName("stateIndicator")
        left_layout.addWidget(self.state_indicator)

        self.transition_combo = QComboBox()
        left_layout.addWidget(self.transition_combo)

        self.transition_btn = QPushButton("Transition State")
        self.transition_btn.setMinimumHeight(35)
        self.transition_btn.clicked.connect(self._on_transition_state)
        self.transition_btn.setEnabled(False)
        left_layout.addWidget(self.transition_btn)

        # Open engagement button
        self.open_btn = QPushButton("Open Engagement")
        self.open_btn.setMinimumHeight(35)
        self.open_btn.clicked.connect(self._on_open_engagement)
        self.open_btn.setEnabled(False)
        left_layout.addWidget(self.open_btn)

        left_layout.addStretch()
        layout.addWidget(left_panel)

        # Right panel: engagement list with search/filter
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)

        # Search and filter bar
        filter_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search engagements...")
        self.search_input.textChanged.connect(self._on_search_changed)
        filter_layout.addWidget(self.search_input)

        self.status_filter_combo = QComboBox()
        self.status_filter_combo.addItem("All Statuses", "")
        for state in EngagementState:
            self.status_filter_combo.addItem(state.value.capitalize(), state.value)
        self.status_filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self.status_filter_combo)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh_engagement_list)
        filter_layout.addWidget(self.refresh_btn)

        right_layout.addLayout(filter_layout)

        # Engagement table
        self.engagement_table = QTableWidget()
        self.engagement_table.setColumnCount(6)
        self.engagement_table.setHorizontalHeaderLabels([
            "Name", "Client", "Type", "Status", "Start", "End"
        ])
        self.engagement_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.engagement_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.engagement_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.engagement_table.horizontalHeader().setStretchLastSection(True)
        self.engagement_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.engagement_table.itemSelectionChanged.connect(self._on_engagement_selected)
        right_layout.addWidget(self.engagement_table)

        layout.addWidget(right_panel, 1)
        return tab

    # ------------------------------------------------------------------
    # Documents Tab
    # ------------------------------------------------------------------

    def _create_documents_tab(self) -> QWidget:
        """Create the documents upload/view panel."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Top controls
        controls = QHBoxLayout()
        self.doc_type_combo = QComboBox()
        self.doc_type_combo.addItems(["scope", "roe", "sow", "nda", "other"])
        controls.addWidget(QLabel("Type:"))
        controls.addWidget(self.doc_type_combo)

        self.upload_btn = QPushButton("Upload Document")
        self.upload_btn.setMinimumHeight(35)
        self.upload_btn.clicked.connect(self._on_upload_document)
        controls.addWidget(self.upload_btn)

        self.delete_doc_btn = QPushButton("Delete Selected")
        self.delete_doc_btn.setMinimumHeight(35)
        self.delete_doc_btn.clicked.connect(self._on_delete_document)
        controls.addWidget(self.delete_doc_btn)

        controls.addStretch()
        layout.addLayout(controls)

        # Documents table
        self.documents_table = QTableWidget()
        self.documents_table.setColumnCount(4)
        self.documents_table.setHorizontalHeaderLabels([
            "Filename", "Type", "MIME Type", "Upload Date"
        ])
        self.documents_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.documents_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.documents_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.documents_table.horizontalHeader().setStretchLastSection(True)
        self.documents_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.documents_table)

        return tab

    # ------------------------------------------------------------------
    # Rules of Engagement Tab
    # ------------------------------------------------------------------

    def _create_roe_tab(self) -> QWidget:
        """Create the RoE structured input form."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        form_label = QLabel("Rules of Engagement")
        form_label.setObjectName("sectionLabel")
        layout.addWidget(form_label)

        form = QFormLayout()

        self.roe_ip_ranges = QTextEdit()
        self.roe_ip_ranges.setPlaceholderText(
            "One IP range per line (e.g., 192.168.1.0/24)"
        )
        self.roe_ip_ranges.setMaximumHeight(80)
        form.addRow("Authorized IP Ranges:", self.roe_ip_ranges)

        self.roe_excluded = QTextEdit()
        self.roe_excluded.setPlaceholderText(
            "One system per line (e.g., dc01.corp.local)"
        )
        self.roe_excluded.setMaximumHeight(80)
        form.addRow("Excluded Systems:", self.roe_excluded)

        # Testing hours
        hours_layout = QHBoxLayout()
        self.roe_hours_start = QLineEdit()
        self.roe_hours_start.setPlaceholderText("08:00")
        hours_layout.addWidget(QLabel("Start:"))
        hours_layout.addWidget(self.roe_hours_start)
        self.roe_hours_end = QLineEdit()
        self.roe_hours_end.setPlaceholderText("18:00")
        hours_layout.addWidget(QLabel("End:"))
        hours_layout.addWidget(self.roe_hours_end)
        self.roe_hours_tz = QLineEdit()
        self.roe_hours_tz.setPlaceholderText("UTC")
        hours_layout.addWidget(QLabel("TZ:"))
        hours_layout.addWidget(self.roe_hours_tz)
        hours_widget = QWidget()
        hours_widget.setLayout(hours_layout)
        form.addRow("Testing Hours:", hours_widget)

        # Emergency contacts (simple text for now)
        self.roe_contacts = QTextEdit()
        self.roe_contacts.setPlaceholderText(
            "One per line: Name, Phone, Email\n"
            "e.g., John Smith, +1-555-0100, john@corp.com"
        )
        self.roe_contacts.setMaximumHeight(80)
        form.addRow("Emergency Contacts:", self.roe_contacts)

        self.roe_escalation = QTextEdit()
        self.roe_escalation.setPlaceholderText("Escalation procedures...")
        self.roe_escalation.setMaximumHeight(80)
        form.addRow("Escalation:", self.roe_escalation)

        self.roe_custom = QTextEdit()
        self.roe_custom.setPlaceholderText("Additional rules or constraints...")
        self.roe_custom.setMaximumHeight(80)
        form.addRow("Custom Rules:", self.roe_custom)

        layout.addLayout(form)

        # Save / Load buttons
        btn_layout = QHBoxLayout()
        self.roe_save_btn = QPushButton("Save RoE")
        self.roe_save_btn.setMinimumHeight(35)
        self.roe_save_btn.clicked.connect(self._on_save_roe)
        btn_layout.addWidget(self.roe_save_btn)

        self.roe_load_btn = QPushButton("Load RoE")
        self.roe_load_btn.setMinimumHeight(35)
        self.roe_load_btn.clicked.connect(self._on_load_roe)
        btn_layout.addWidget(self.roe_load_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        layout.addStretch()

        return tab

    # ------------------------------------------------------------------
    # Contacts Tab
    # ------------------------------------------------------------------

    def _create_contacts_tab(self) -> QWidget:
        """Create the client contacts CRUD interface."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Form for adding/editing contacts
        form_frame = QFrame()
        form_layout = QFormLayout(form_frame)

        self.contact_name_input = QLineEdit()
        self.contact_name_input.setPlaceholderText("Contact name")
        form_layout.addRow("Name:", self.contact_name_input)

        self.contact_role_input = QLineEdit()
        self.contact_role_input.setPlaceholderText("Role (e.g., CISO, IT Manager)")
        form_layout.addRow("Role:", self.contact_role_input)

        self.contact_email_input = QLineEdit()
        self.contact_email_input.setPlaceholderText("email@example.com")
        form_layout.addRow("Email:", self.contact_email_input)

        self.contact_phone_input = QLineEdit()
        self.contact_phone_input.setPlaceholderText("+1-555-0100")
        form_layout.addRow("Phone:", self.contact_phone_input)

        self.contact_avail_input = QLineEdit()
        self.contact_avail_input.setPlaceholderText("e.g., Mon-Fri 9am-5pm EST")
        form_layout.addRow("Availability:", self.contact_avail_input)

        layout.addWidget(form_frame)

        # Buttons
        btn_layout = QHBoxLayout()
        self.add_contact_btn = QPushButton("Add Contact")
        self.add_contact_btn.setMinimumHeight(35)
        self.add_contact_btn.clicked.connect(self._on_add_contact)
        btn_layout.addWidget(self.add_contact_btn)

        self.update_contact_btn = QPushButton("Update Selected")
        self.update_contact_btn.setMinimumHeight(35)
        self.update_contact_btn.clicked.connect(self._on_update_contact)
        btn_layout.addWidget(self.update_contact_btn)

        self.delete_contact_btn = QPushButton("Delete Selected")
        self.delete_contact_btn.setMinimumHeight(35)
        self.delete_contact_btn.clicked.connect(self._on_delete_contact)
        btn_layout.addWidget(self.delete_contact_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Contacts table
        self.contacts_table = QTableWidget()
        self.contacts_table.setColumnCount(5)
        self.contacts_table.setHorizontalHeaderLabels([
            "Name", "Role", "Email", "Phone", "Availability"
        ])
        self.contacts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.contacts_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.contacts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.contacts_table.horizontalHeader().setStretchLastSection(True)
        self.contacts_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.contacts_table.itemSelectionChanged.connect(self._on_contact_selected)
        layout.addWidget(self.contacts_table)

        return tab

    # ------------------------------------------------------------------
    # Milestones Tab
    # ------------------------------------------------------------------

    def _create_milestones_tab(self) -> QWidget:
        """Create the timeline milestones view."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Form for adding milestones
        form_frame = QFrame()
        form_layout = QFormLayout(form_frame)

        self.milestone_name_input = QLineEdit()
        self.milestone_name_input.setPlaceholderText("Milestone name")
        form_layout.addRow("Name:", self.milestone_name_input)

        self.milestone_type_combo = QComboBox()
        self.milestone_type_combo.addItems([
            "planned_start", "actual_start", "planned_end",
            "actual_end", "checkpoint"
        ])
        form_layout.addRow("Type:", self.milestone_type_combo)

        self.milestone_date_input = QDateEdit()
        self.milestone_date_input.setCalendarPopup(True)
        self.milestone_date_input.setDate(datetime.now().date())
        form_layout.addRow("Date:", self.milestone_date_input)

        self.milestone_notes_input = QLineEdit()
        self.milestone_notes_input.setPlaceholderText("Optional notes")
        form_layout.addRow("Notes:", self.milestone_notes_input)

        layout.addWidget(form_frame)

        # Buttons
        btn_layout = QHBoxLayout()
        self.add_milestone_btn = QPushButton("Add Milestone")
        self.add_milestone_btn.setMinimumHeight(35)
        self.add_milestone_btn.clicked.connect(self._on_add_milestone)
        btn_layout.addWidget(self.add_milestone_btn)

        self.delete_milestone_btn = QPushButton("Delete Selected")
        self.delete_milestone_btn.setMinimumHeight(35)
        self.delete_milestone_btn.clicked.connect(self._on_delete_milestone)
        btn_layout.addWidget(self.delete_milestone_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Milestones table
        self.milestones_table = QTableWidget()
        self.milestones_table.setColumnCount(4)
        self.milestones_table.setHorizontalHeaderLabels([
            "Name", "Type", "Date", "Notes"
        ])
        self.milestones_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.milestones_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.milestones_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.milestones_table.horizontalHeader().setStretchLastSection(True)
        self.milestones_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        layout.addWidget(self.milestones_table)

        return tab

    # ------------------------------------------------------------------
    # Timeline Tab
    # ------------------------------------------------------------------

    def _create_timeline_tab(self) -> QWidget:
        """Create the timeline activity log tab using TimelineComponent."""
        from app.components.timeline_component import TimelineComponent

        # Create a TimelineLogger instance for this tab
        self._timeline_logger = TimelineLogger()
        self.timeline_widget = TimelineComponent(self._timeline_logger)
        return self.timeline_widget

    def set_timeline_logger(self, timeline_logger: TimelineLogger):
        """Set an external TimelineLogger instance for the timeline tab.

        Call this after initialization to wire up a shared TimelineLogger
        (e.g., one connected to the engagement manager signals).

        Args:
            timeline_logger: A configured TimelineLogger instance.
        """
        self._timeline_logger = timeline_logger
        self.timeline_widget._logger = timeline_logger
        self.timeline_widget._connect_signals()
        self.timeline_widget.refresh_timeline()

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect to EngagementManager signals for real-time updates."""
        self.manager.engagement_created.connect(self._on_engagement_created_signal)
        self.manager.state_changed.connect(self._on_state_changed_signal)

    def _on_engagement_created_signal(self, engagement_id: str):
        """Handle the engagement_created signal from the manager."""
        self.refresh_engagement_list()

    def _on_state_changed_signal(self, engagement_id: str, old_state: str, new_state: str):
        """Handle the state_changed signal from the manager."""
        self.refresh_engagement_list()
        if engagement_id == self._selected_engagement_id:
            self._update_state_controls(new_state)

    # ------------------------------------------------------------------
    # Overview Tab Handlers
    # ------------------------------------------------------------------

    def _on_create_engagement(self):
        """Handle engagement creation button click."""
        name = self.name_input.text().strip()
        client = self.client_input.text().strip()

        if not name:
            self._show_validation_error("Engagement name is required.")
            return
        if not client:
            self._show_validation_error("Client name is required.")
            return

        eng_type = self.type_combo.currentText()
        start_date = self.start_date_input.date().toString("yyyy-MM-dd")
        end_date = self.end_date_input.date().toString("yyyy-MM-dd")

        try:
            engagement_id = self.manager.create_engagement(
                name=name,
                client_name=client,
                engagement_type=eng_type,
                start_date=start_date,
                end_date=end_date,
            )
            # Clear inputs on success
            self.name_input.clear()
            self.client_input.clear()
            self.refresh_engagement_list()
        except Exception as e:
            self._show_validation_error(f"Failed to create engagement: {e}")

    def _on_transition_state(self):
        """Handle state transition button click."""
        if not self._selected_engagement_id:
            return

        target_state_value = self.transition_combo.currentData()
        if not target_state_value:
            return

        try:
            new_state = EngagementState(target_state_value)
            success = self.manager.transition_state(
                self._selected_engagement_id, new_state
            )
            if not success:
                self._show_validation_error(
                    f"Invalid transition to '{new_state.value}'. "
                    "Check allowed transitions for the current state."
                )
            else:
                self.refresh_engagement_list()
        except Exception as e:
            self._show_validation_error(f"State transition failed: {e}")

    def _on_open_engagement(self):
        """Handle open engagement button click."""
        if not self._selected_engagement_id:
            return

        success = self.manager.open_engagement(self._selected_engagement_id)
        if success:
            self._refresh_engagement_data_tabs()
        else:
            self._show_validation_error("Failed to open engagement.")

    def _on_engagement_selected(self):
        """Handle engagement selection in the table."""
        selected = self.engagement_table.selectedItems()
        if not selected:
            self._selected_engagement_id = None
            self.state_indicator.setText("No engagement selected")
            self.transition_combo.clear()
            self.transition_btn.setEnabled(False)
            self.open_btn.setEnabled(False)
            return

        row = self.engagement_table.currentRow()
        # Engagement ID stored in first column's data role
        id_item = self.engagement_table.item(row, 0)
        if id_item:
            self._selected_engagement_id = id_item.data(Qt.ItemDataRole.UserRole)
            engagement = self.manager.get_engagement(self._selected_engagement_id)
            if engagement:
                self._update_state_controls(engagement["status"])
                self.open_btn.setEnabled(True)
                self.engagement_selected.emit(self._selected_engagement_id)

    def _update_state_controls(self, current_status: str):
        """Update the state indicator and transition combo for the selected engagement."""
        self.state_indicator.setText(f"Current State: {current_status.upper()}")
        self.state_indicator.setStyleSheet(
            f"color: {self._state_color(current_status)}; font-weight: bold; font-size: 13px;"
        )

        # Populate valid transitions
        self.transition_combo.clear()
        try:
            current_state = EngagementState(current_status)
            allowed = VALID_TRANSITIONS.get(current_state, [])
            for state in allowed:
                self.transition_combo.addItem(state.value.capitalize(), state.value)
            self.transition_btn.setEnabled(len(allowed) > 0)
        except ValueError:
            self.transition_btn.setEnabled(False)

    def _state_color(self, status: str) -> str:
        """Return a color for the given engagement state."""
        colors = {
            "draft": "#A0A0A0",
            "scoping": "#64C8FF",
            "active": "#00FF88",
            "paused": "#FFD700",
            "retest": "#FF8C00",
            "reporting": "#DA70D6",
            "closed": "#FF4500",
        }
        return colors.get(status, "#DCDCDC")

    def _on_search_changed(self):
        """Handle search input change."""
        self.refresh_engagement_list()

    def _on_filter_changed(self):
        """Handle status filter change."""
        self.refresh_engagement_list()

    def refresh_engagement_list(self):
        """Refresh the engagement list table from the manager."""
        search_text = self.search_input.text().strip() if hasattr(self, 'search_input') else ""
        status_filter = ""
        if hasattr(self, 'status_filter_combo'):
            status_filter = self.status_filter_combo.currentData() or ""

        engagements = self.manager.list_engagements(
            status_filter=status_filter if status_filter else None,
            search_query=search_text if search_text else None,
        )

        self.engagement_table.setRowCount(0)
        for eng in engagements:
            row = self.engagement_table.rowCount()
            self.engagement_table.insertRow(row)

            name_item = QTableWidgetItem(eng["name"])
            name_item.setData(Qt.ItemDataRole.UserRole, eng["id"])
            self.engagement_table.setItem(row, 0, name_item)
            self.engagement_table.setItem(row, 1, QTableWidgetItem(eng["client_name"]))
            self.engagement_table.setItem(row, 2, QTableWidgetItem(eng["engagement_type"]))

            status_item = QTableWidgetItem(eng["status"].capitalize())
            status_item.setForeground(QColor(self._state_color(eng["status"])))
            self.engagement_table.setItem(row, 3, status_item)
            self.engagement_table.setItem(row, 4, QTableWidgetItem(eng.get("start_date", "") or ""))
            self.engagement_table.setItem(row, 5, QTableWidgetItem(eng.get("end_date", "") or ""))

    # ------------------------------------------------------------------
    # Documents Tab Handlers
    # ------------------------------------------------------------------

    def _on_upload_document(self):
        """Handle document upload button."""
        if self.manager.active_db is None:
            self._show_validation_error(
                "No engagement is open. Select and open an engagement first."
            )
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Document", "",
            "All Files (*);;PDF (*.pdf);;Word (*.docx);;Text (*.txt)"
        )
        if not file_path:
            return

        try:
            filename = os.path.basename(file_path)
            with open(file_path, "rb") as f:
                content = f.read()

            # Determine MIME type from extension
            ext = os.path.splitext(filename)[1].lower()
            mime_map = {
                ".pdf": "application/pdf",
                ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ".doc": "application/msword",
                ".txt": "text/plain",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
            }
            mime_type = mime_map.get(ext, "application/octet-stream")
            doc_type = self.doc_type_combo.currentText()

            self.manager.add_document(
                filename=filename,
                document_type=doc_type,
                content=content,
                mime_type=mime_type,
            )
            self._refresh_documents_table()
        except Exception as e:
            self._show_validation_error(f"Failed to upload document: {e}")

    def _on_delete_document(self):
        """Handle document deletion."""
        if self.manager.active_db is None:
            return

        selected = self.documents_table.selectedItems()
        if not selected:
            return

        row = self.documents_table.currentRow()
        doc_id_item = self.documents_table.item(row, 0)
        if doc_id_item:
            doc_id = doc_id_item.data(Qt.ItemDataRole.UserRole)
            if doc_id is not None:
                self.manager.delete_document(doc_id)
                self._refresh_documents_table()

    def _refresh_documents_table(self):
        """Refresh the documents table from the active engagement."""
        self.documents_table.setRowCount(0)
        if self.manager.active_db is None:
            return

        try:
            docs = self.manager.get_documents()
            for doc in docs:
                row = self.documents_table.rowCount()
                self.documents_table.insertRow(row)

                filename_item = QTableWidgetItem(doc["filename"])
                filename_item.setData(Qt.ItemDataRole.UserRole, doc["id"])
                self.documents_table.setItem(row, 0, filename_item)
                self.documents_table.setItem(row, 1, QTableWidgetItem(doc["document_type"]))
                self.documents_table.setItem(row, 2, QTableWidgetItem(doc.get("mime_type", "") or ""))
                self.documents_table.setItem(row, 3, QTableWidgetItem(doc.get("upload_date", "") or ""))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # RoE Tab Handlers
    # ------------------------------------------------------------------

    def _on_save_roe(self):
        """Save Rules of Engagement to the active engagement."""
        if self.manager.active_db is None:
            self._show_validation_error(
                "No engagement is open. Select and open an engagement first."
            )
            return

        # Parse IP ranges
        ip_text = self.roe_ip_ranges.toPlainText().strip()
        ip_ranges = [line.strip() for line in ip_text.splitlines() if line.strip()] if ip_text else None

        # Parse excluded systems
        excluded_text = self.roe_excluded.toPlainText().strip()
        excluded = [line.strip() for line in excluded_text.splitlines() if line.strip()] if excluded_text else None

        # Parse testing hours
        hours_start = self.roe_hours_start.text().strip()
        hours_end = self.roe_hours_end.text().strip()
        hours_tz = self.roe_hours_tz.text().strip()
        testing_hours = None
        if hours_start or hours_end:
            testing_hours = {
                "start": hours_start,
                "end": hours_end,
                "timezone": hours_tz or "UTC",
            }

        # Parse emergency contacts
        contacts_text = self.roe_contacts.toPlainText().strip()
        emergency_contacts = None
        if contacts_text:
            emergency_contacts = []
            for line in contacts_text.splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 1:
                    contact = {"name": parts[0]}
                    if len(parts) >= 2:
                        contact["phone"] = parts[1]
                    if len(parts) >= 3:
                        contact["email"] = parts[2]
                    emergency_contacts.append(contact)

        escalation = self.roe_escalation.toPlainText().strip() or None
        custom_rules = self.roe_custom.toPlainText().strip() or None

        try:
            self.manager.set_rules_of_engagement(
                authorized_ip_ranges=ip_ranges,
                excluded_systems=excluded,
                testing_hours=testing_hours,
                emergency_contacts=emergency_contacts,
                escalation_procedures=escalation,
                custom_rules=custom_rules,
            )
        except Exception as e:
            self._show_validation_error(f"Failed to save RoE: {e}")

    def _on_load_roe(self):
        """Load Rules of Engagement from the active engagement into the form."""
        if self.manager.active_db is None:
            self._show_validation_error(
                "No engagement is open. Select and open an engagement first."
            )
            return

        try:
            roe = self.manager.get_rules_of_engagement()
            if roe is None:
                self._show_validation_error("No Rules of Engagement found for this engagement.")
                return

            # Populate IP ranges
            ip_ranges = roe.get("authorized_ip_ranges")
            self.roe_ip_ranges.setPlainText(
                "\n".join(ip_ranges) if ip_ranges else ""
            )

            # Populate excluded systems
            excluded = roe.get("excluded_systems")
            self.roe_excluded.setPlainText(
                "\n".join(excluded) if excluded else ""
            )

            # Populate testing hours
            hours = roe.get("testing_hours")
            if hours:
                self.roe_hours_start.setText(hours.get("start", ""))
                self.roe_hours_end.setText(hours.get("end", ""))
                self.roe_hours_tz.setText(hours.get("timezone", ""))
            else:
                self.roe_hours_start.clear()
                self.roe_hours_end.clear()
                self.roe_hours_tz.clear()

            # Populate emergency contacts
            contacts = roe.get("emergency_contacts")
            if contacts:
                lines = []
                for c in contacts:
                    parts = [c.get("name", "")]
                    if c.get("phone"):
                        parts.append(c["phone"])
                    if c.get("email"):
                        parts.append(c["email"])
                    lines.append(", ".join(parts))
                self.roe_contacts.setPlainText("\n".join(lines))
            else:
                self.roe_contacts.clear()

            # Populate escalation and custom rules
            self.roe_escalation.setPlainText(roe.get("escalation_procedures", "") or "")
            self.roe_custom.setPlainText(roe.get("custom_rules", "") or "")
        except Exception as e:
            self._show_validation_error(f"Failed to load RoE: {e}")

    # ------------------------------------------------------------------
    # Contacts Tab Handlers
    # ------------------------------------------------------------------

    def _on_add_contact(self):
        """Add a new client contact."""
        if self.manager.active_db is None:
            self._show_validation_error(
                "No engagement is open. Select and open an engagement first."
            )
            return

        name = self.contact_name_input.text().strip()
        if not name:
            self._show_validation_error("Contact name is required.")
            return

        role = self.contact_role_input.text().strip() or None
        email = self.contact_email_input.text().strip() or None
        phone = self.contact_phone_input.text().strip() or None
        avail_text = self.contact_avail_input.text().strip()
        availability = {"window": avail_text} if avail_text else None

        try:
            self.manager.add_contact(
                name=name,
                role=role,
                email=email,
                phone=phone,
                availability_window=availability,
            )
            self._clear_contact_form()
            self._refresh_contacts_table()
        except Exception as e:
            self._show_validation_error(f"Failed to add contact: {e}")

    def _on_update_contact(self):
        """Update the selected contact."""
        if self.manager.active_db is None:
            return

        selected = self.contacts_table.selectedItems()
        if not selected:
            self._show_validation_error("No contact selected.")
            return

        row = self.contacts_table.currentRow()
        contact_id_item = self.contacts_table.item(row, 0)
        if not contact_id_item:
            return
        contact_id = contact_id_item.data(Qt.ItemDataRole.UserRole)

        name = self.contact_name_input.text().strip()
        if not name:
            self._show_validation_error("Contact name is required.")
            return

        role = self.contact_role_input.text().strip() or None
        email = self.contact_email_input.text().strip() or None
        phone = self.contact_phone_input.text().strip() or None
        avail_text = self.contact_avail_input.text().strip()
        availability = {"window": avail_text} if avail_text else None

        try:
            self.manager.update_contact(
                contact_id,
                name=name,
                role=role,
                email=email,
                phone=phone,
                availability_window=availability,
            )
            self._refresh_contacts_table()
        except Exception as e:
            self._show_validation_error(f"Failed to update contact: {e}")

    def _on_delete_contact(self):
        """Delete the selected contact."""
        if self.manager.active_db is None:
            return

        selected = self.contacts_table.selectedItems()
        if not selected:
            return

        row = self.contacts_table.currentRow()
        contact_id_item = self.contacts_table.item(row, 0)
        if contact_id_item:
            contact_id = contact_id_item.data(Qt.ItemDataRole.UserRole)
            if contact_id is not None:
                self.manager.delete_contact(contact_id)
                self._clear_contact_form()
                self._refresh_contacts_table()

    def _on_contact_selected(self):
        """Populate form when a contact is selected in the table."""
        selected = self.contacts_table.selectedItems()
        if not selected:
            return

        row = self.contacts_table.currentRow()
        self.contact_name_input.setText(
            self.contacts_table.item(row, 0).text() if self.contacts_table.item(row, 0) else ""
        )
        self.contact_role_input.setText(
            self.contacts_table.item(row, 1).text() if self.contacts_table.item(row, 1) else ""
        )
        self.contact_email_input.setText(
            self.contacts_table.item(row, 2).text() if self.contacts_table.item(row, 2) else ""
        )
        self.contact_phone_input.setText(
            self.contacts_table.item(row, 3).text() if self.contacts_table.item(row, 3) else ""
        )
        self.contact_avail_input.setText(
            self.contacts_table.item(row, 4).text() if self.contacts_table.item(row, 4) else ""
        )

    def _clear_contact_form(self):
        """Clear the contact form inputs."""
        self.contact_name_input.clear()
        self.contact_role_input.clear()
        self.contact_email_input.clear()
        self.contact_phone_input.clear()
        self.contact_avail_input.clear()

    def _refresh_contacts_table(self):
        """Refresh the contacts table from the active engagement."""
        self.contacts_table.setRowCount(0)
        if self.manager.active_db is None:
            return

        try:
            contacts = self.manager.get_contacts()
            for contact in contacts:
                row = self.contacts_table.rowCount()
                self.contacts_table.insertRow(row)

                name_item = QTableWidgetItem(contact["name"])
                name_item.setData(Qt.ItemDataRole.UserRole, contact["id"])
                self.contacts_table.setItem(row, 0, name_item)
                self.contacts_table.setItem(row, 1, QTableWidgetItem(contact.get("role", "") or ""))
                self.contacts_table.setItem(row, 2, QTableWidgetItem(contact.get("email", "") or ""))
                self.contacts_table.setItem(row, 3, QTableWidgetItem(contact.get("phone", "") or ""))

                # Display availability window
                avail = contact.get("availability_window")
                avail_text = ""
                if avail and isinstance(avail, dict):
                    avail_text = avail.get("window", str(avail))
                self.contacts_table.setItem(row, 4, QTableWidgetItem(avail_text))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Milestones Tab Handlers
    # ------------------------------------------------------------------

    def _on_add_milestone(self):
        """Add a new milestone to the active engagement."""
        if self.manager.active_db is None:
            self._show_validation_error(
                "No engagement is open. Select and open an engagement first."
            )
            return

        name = self.milestone_name_input.text().strip()
        if not name:
            self._show_validation_error("Milestone name is required.")
            return

        milestone_type = self.milestone_type_combo.currentText()
        date = self.milestone_date_input.date().toString("yyyy-MM-dd")
        notes = self.milestone_notes_input.text().strip() or None

        try:
            self.manager.add_milestone(
                name=name,
                milestone_type=milestone_type,
                date=date,
                notes=notes,
            )
            self.milestone_name_input.clear()
            self.milestone_notes_input.clear()
            self._refresh_milestones_table()
        except Exception as e:
            self._show_validation_error(f"Failed to add milestone: {e}")

    def _on_delete_milestone(self):
        """Delete the selected milestone."""
        if self.manager.active_db is None:
            return

        selected = self.milestones_table.selectedItems()
        if not selected:
            return

        row = self.milestones_table.currentRow()
        name_item = self.milestones_table.item(row, 0)
        if name_item:
            milestone_id = name_item.data(Qt.ItemDataRole.UserRole)
            if milestone_id is not None:
                self.manager.delete_milestone(milestone_id)
                self._refresh_milestones_table()

    def _refresh_milestones_table(self):
        """Refresh the milestones table from the active engagement."""
        self.milestones_table.setRowCount(0)
        if self.manager.active_db is None:
            return

        try:
            milestones = self.manager.get_milestones()
            for ms in milestones:
                row = self.milestones_table.rowCount()
                self.milestones_table.insertRow(row)

                name_item = QTableWidgetItem(ms["name"])
                name_item.setData(Qt.ItemDataRole.UserRole, ms["id"])
                self.milestones_table.setItem(row, 0, name_item)
                self.milestones_table.setItem(row, 1, QTableWidgetItem(ms.get("milestone_type", "")))
                self.milestones_table.setItem(row, 2, QTableWidgetItem(ms.get("date", "")))
                self.milestones_table.setItem(row, 3, QTableWidgetItem(ms.get("notes", "") or ""))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _refresh_engagement_data_tabs(self):
        """Refresh all data tabs after opening an engagement."""
        self._refresh_documents_table()
        self._refresh_contacts_table()
        self._refresh_milestones_table()
        # Try loading RoE if available
        try:
            self._on_load_roe()
        except Exception:
            pass

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
            QTabWidget::pane {
                background-color: rgba(0, 0, 0, 100);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: rgba(30, 40, 50, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                padding: 8px 16px;
                color: #DCDCDC;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
                border-bottom: none;
                color: #64C8FF;
            }
            QTabBar::tab:hover {
                background-color: rgba(50, 70, 90, 200);
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
            QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QTextEdit:focus {
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
            QDateEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                gridline-color: rgba(100, 200, 255, 30);
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 60);
            }
            QHeaderView::section {
                background-color: rgba(30, 40, 50, 200);
                border: 1px solid rgba(100, 200, 255, 50);
                color: #64C8FF;
                font-weight: bold;
                padding: 6px;
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
            QLabel#stateIndicator {
                color: #64C8FF;
                font-weight: bold;
                font-size: 13px;
                border: none;
                background: transparent;
            }
        """)
