# app/components/physical_security_component.py
"""Physical Security Assessment UI Component.

Provides physical security assessment interface with:
- Attempt logging form (location, time, method dropdown, outcome dropdown, evidence link, notes)
- Attempt history table with filtering (by location, method)
- Floor plan viewer with annotation overlay (QLabel with image + annotation list)
- Control effectiveness rating interface per location (1-5 rating + control type + notes)
- Physical assessment summary view for report inclusion

Integrates as a sub-tab within the Engagement Setup page.

Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QComboBox,
    QDateTimeEdit,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.physical_security_engine import (
    VALID_ANNOTATION_TYPES,
    VALID_METHODS,
    VALID_OUTCOMES,
    PhysicalSecurityEngine,
)


class PhysicalSecurityComponent(QWidget):
    """Physical security assessment UI component.

    Provides physical access attempt logging, site annotation viewing,
    control effectiveness rating, and assessment summary for report
    inclusion.

    Signals:
        attempt_logged(dict): Emitted when an attempt is successfully logged.
        summary_generated(dict): Emitted when a summary is generated.
    """

    attempt_logged = pyqtSignal(dict)
    summary_generated = pyqtSignal(dict)

    def __init__(self, engine: PhysicalSecurityEngine, parent=None):
        """Initialize the PhysicalSecurityComponent.

        Args:
            engine: The PhysicalSecurityEngine instance providing data logic.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.engine = engine
        self._attempts: List[Dict] = []
        self._annotations: List[Dict] = []
        self._ratings: List[Dict] = []
        self._floor_plan_pixmap: Optional[QPixmap] = None

        self._setup_ui()
        self._apply_theme()
        self._connect_signals()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the main layout with sub-tabs for each assessment area."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Header
        header = QLabel("Physical Security Assessment")
        header.setObjectName("sectionLabel")
        layout.addWidget(header)

        # Tab widget for different areas
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_attempt_log_tab(), "Log Attempt")
        self.tabs.addTab(self._create_attempt_history_tab(), "Attempt History")
        self.tabs.addTab(self._create_floor_plan_tab(), "Floor Plan")
        self.tabs.addTab(self._create_control_rating_tab(), "Control Ratings")
        self.tabs.addTab(self._create_summary_tab(), "Summary")
        layout.addWidget(self.tabs, 1)

    # ------------------------------------------------------------------
    # Attempt Logging Tab
    # ------------------------------------------------------------------

    def _create_attempt_log_tab(self) -> QWidget:
        """Build the attempt logging form."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        form_group = QGroupBox("Log Physical Access Attempt")
        form_layout = QVBoxLayout(form_group)

        # Location
        loc_row = QHBoxLayout()
        loc_row.addWidget(QLabel("Location:"))
        self.attempt_location_input = QLineEdit()
        self.attempt_location_input.setPlaceholderText("e.g., Main Entrance, Server Room B2")
        loc_row.addWidget(self.attempt_location_input)
        form_layout.addLayout(loc_row)

        # Time
        time_row = QHBoxLayout()
        time_row.addWidget(QLabel("Time:"))
        self.attempt_time_edit = QDateTimeEdit()
        self.attempt_time_edit.setCalendarPopup(True)
        self.attempt_time_edit.setDateTime(self.attempt_time_edit.dateTime().currentDateTime())
        self.attempt_time_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        time_row.addWidget(self.attempt_time_edit)
        form_layout.addLayout(time_row)

        # Method dropdown
        method_row = QHBoxLayout()
        method_row.addWidget(QLabel("Method:"))
        self.attempt_method_combo = QComboBox()
        for method in VALID_METHODS:
            self.attempt_method_combo.addItem(method.replace("_", " ").title(), method)
        method_row.addWidget(self.attempt_method_combo)
        form_layout.addLayout(method_row)

        # Outcome dropdown
        outcome_row = QHBoxLayout()
        outcome_row.addWidget(QLabel("Outcome:"))
        self.attempt_outcome_combo = QComboBox()
        for outcome in VALID_OUTCOMES:
            self.attempt_outcome_combo.addItem(outcome.title(), outcome)
        outcome_row.addWidget(self.attempt_outcome_combo)
        form_layout.addLayout(outcome_row)

        # Evidence link
        evidence_row = QHBoxLayout()
        evidence_row.addWidget(QLabel("Evidence ID:"))
        self.attempt_evidence_input = QLineEdit()
        self.attempt_evidence_input.setPlaceholderText("Optional evidence record ID")
        evidence_row.addWidget(self.attempt_evidence_input)
        form_layout.addLayout(evidence_row)

        # Notes
        notes_label = QLabel("Notes:")
        form_layout.addWidget(notes_label)
        self.attempt_notes_input = QTextEdit()
        self.attempt_notes_input.setPlaceholderText("Additional details about the attempt...")
        self.attempt_notes_input.setMaximumHeight(100)
        form_layout.addWidget(self.attempt_notes_input)

        layout.addWidget(form_group)

        # Submit button
        btn_row = QHBoxLayout()
        self.log_attempt_btn = QPushButton("Log Attempt")
        self.log_attempt_btn.setMinimumHeight(34)
        btn_row.addWidget(self.log_attempt_btn)

        self.clear_form_btn = QPushButton("Clear Form")
        self.clear_form_btn.setMinimumHeight(34)
        btn_row.addWidget(self.clear_form_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Status label
        self.attempt_status_label = QLabel("")
        self.attempt_status_label.setObjectName("countLabel")
        layout.addWidget(self.attempt_status_label)

        layout.addStretch()
        return container

    # ------------------------------------------------------------------
    # Attempt History Tab
    # ------------------------------------------------------------------

    def _create_attempt_history_tab(self) -> QWidget:
        """Build the attempt history table with filtering."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Filter row
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout(filter_group)

        filter_layout.addWidget(QLabel("Location:"))
        self.history_location_filter = QLineEdit()
        self.history_location_filter.setPlaceholderText("Filter by location...")
        filter_layout.addWidget(self.history_location_filter)

        filter_layout.addWidget(QLabel("Method:"))
        self.history_method_filter = QComboBox()
        self.history_method_filter.addItem("All Methods", "")
        for method in VALID_METHODS:
            self.history_method_filter.addItem(method.replace("_", " ").title(), method)
        filter_layout.addWidget(self.history_method_filter)

        self.history_filter_btn = QPushButton("Apply")
        self.history_filter_btn.setMinimumHeight(30)
        filter_layout.addWidget(self.history_filter_btn)

        self.history_refresh_btn = QPushButton("Refresh")
        self.history_refresh_btn.setMinimumHeight(30)
        filter_layout.addWidget(self.history_refresh_btn)

        layout.addWidget(filter_group)

        # Summary label
        self.history_count_label = QLabel("No attempts logged")
        self.history_count_label.setObjectName("countLabel")
        layout.addWidget(self.history_count_label)

        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels(
            ["Location", "Time", "Method", "Outcome", "Evidence", "Notes"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.ResizeToContents
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        self.history_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.history_table.setAlternatingRowColors(True)
        self.history_table.verticalHeader().setVisible(False)
        layout.addWidget(self.history_table, 1)

        return container

    # ------------------------------------------------------------------
    # Floor Plan Viewer Tab
    # ------------------------------------------------------------------

    def _create_floor_plan_tab(self) -> QWidget:
        """Build floor plan viewer with annotation overlay."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Image load controls
        load_group = QGroupBox("Floor Plan Image")
        load_layout = QHBoxLayout(load_group)

        self.floor_plan_path_input = QLineEdit()
        self.floor_plan_path_input.setPlaceholderText("Path to floor plan image...")
        self.floor_plan_path_input.setReadOnly(True)
        load_layout.addWidget(self.floor_plan_path_input)

        self.floor_plan_browse_btn = QPushButton("Browse...")
        self.floor_plan_browse_btn.setFixedWidth(90)
        load_layout.addWidget(self.floor_plan_browse_btn)

        self.floor_plan_evidence_id_input = QLineEdit()
        self.floor_plan_evidence_id_input.setPlaceholderText("Evidence ID")
        self.floor_plan_evidence_id_input.setFixedWidth(100)
        load_layout.addWidget(self.floor_plan_evidence_id_input)

        layout.addWidget(load_group)

        # Splitter: image on left, annotations on right
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Floor plan image display
        image_frame = QFrame()
        image_layout = QVBoxLayout(image_frame)
        image_layout.setContentsMargins(4, 4, 4, 4)

        self.floor_plan_label = QLabel("No floor plan loaded")
        self.floor_plan_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.floor_plan_label.setMinimumSize(400, 300)
        self.floor_plan_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.floor_plan_label.setScaledContents(False)
        image_layout.addWidget(self.floor_plan_label)
        splitter.addWidget(image_frame)

        # Annotation list panel
        annotation_panel = QFrame()
        ann_layout = QVBoxLayout(annotation_panel)
        ann_layout.setContentsMargins(8, 8, 8, 8)
        ann_layout.setSpacing(6)

        ann_header = QLabel("Annotations")
        ann_header.setObjectName("sectionLabel")
        ann_layout.addWidget(ann_header)

        self.annotation_list = QListWidget()
        ann_layout.addWidget(self.annotation_list, 1)

        # Add annotation controls
        ann_add_group = QGroupBox("Add Annotation")
        ann_add_layout = QVBoxLayout(ann_add_group)

        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Type:"))
        self.annotation_type_combo = QComboBox()
        for ann_type in VALID_ANNOTATION_TYPES:
            self.annotation_type_combo.addItem(ann_type.replace("_", " ").title(), ann_type)
        type_row.addWidget(self.annotation_type_combo)
        ann_add_layout.addLayout(type_row)

        label_row = QHBoxLayout()
        label_row.addWidget(QLabel("Label:"))
        self.annotation_label_input = QLineEdit()
        self.annotation_label_input.setPlaceholderText("Annotation label")
        label_row.addWidget(self.annotation_label_input)
        ann_add_layout.addLayout(label_row)

        coords_row = QHBoxLayout()
        coords_row.addWidget(QLabel("X:"))
        self.annotation_x_input = QLineEdit()
        self.annotation_x_input.setFixedWidth(50)
        self.annotation_x_input.setPlaceholderText("0")
        coords_row.addWidget(self.annotation_x_input)
        coords_row.addWidget(QLabel("Y:"))
        self.annotation_y_input = QLineEdit()
        self.annotation_y_input.setFixedWidth(50)
        self.annotation_y_input.setPlaceholderText("0")
        coords_row.addWidget(self.annotation_y_input)
        coords_row.addWidget(QLabel("W:"))
        self.annotation_w_input = QLineEdit()
        self.annotation_w_input.setFixedWidth(50)
        self.annotation_w_input.setPlaceholderText("50")
        coords_row.addWidget(self.annotation_w_input)
        coords_row.addWidget(QLabel("H:"))
        self.annotation_h_input = QLineEdit()
        self.annotation_h_input.setFixedWidth(50)
        self.annotation_h_input.setPlaceholderText("50")
        coords_row.addWidget(self.annotation_h_input)
        ann_add_layout.addLayout(coords_row)

        self.annotation_notes_input = QLineEdit()
        self.annotation_notes_input.setPlaceholderText("Notes (optional)")
        ann_add_layout.addWidget(self.annotation_notes_input)

        self.add_annotation_btn = QPushButton("Add Annotation")
        self.add_annotation_btn.setMinimumHeight(30)
        ann_add_layout.addWidget(self.add_annotation_btn)

        ann_layout.addWidget(ann_add_group)
        splitter.addWidget(annotation_panel)

        splitter.setSizes([600, 350])
        layout.addWidget(splitter, 1)

        return container

    # ------------------------------------------------------------------
    # Control Effectiveness Rating Tab
    # ------------------------------------------------------------------

    def _create_control_rating_tab(self) -> QWidget:
        """Build control effectiveness rating interface per location."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Rating form
        rating_group = QGroupBox("Rate Physical Security Control")
        rating_layout = QVBoxLayout(rating_group)

        # Location
        loc_row = QHBoxLayout()
        loc_row.addWidget(QLabel("Location:"))
        self.rating_location_input = QLineEdit()
        self.rating_location_input.setPlaceholderText("e.g., Main Lobby, Data Center")
        loc_row.addWidget(self.rating_location_input)
        rating_layout.addLayout(loc_row)

        # Control type
        ctrl_row = QHBoxLayout()
        ctrl_row.addWidget(QLabel("Control Type:"))
        self.rating_control_type_input = QLineEdit()
        self.rating_control_type_input.setPlaceholderText("e.g., CCTV, Access Badge, Guard, Lock")
        ctrl_row.addWidget(self.rating_control_type_input)
        rating_layout.addLayout(ctrl_row)

        # Rating 1-5
        rate_row = QHBoxLayout()
        rate_row.addWidget(QLabel("Effectiveness (1-5):"))
        self.rating_spin = QSpinBox()
        self.rating_spin.setMinimum(1)
        self.rating_spin.setMaximum(5)
        self.rating_spin.setValue(3)
        rate_row.addWidget(self.rating_spin)

        self.rating_display_label = QLabel("3 / 5")
        self.rating_display_label.setObjectName("countLabel")
        rate_row.addWidget(self.rating_display_label)
        rate_row.addStretch()
        rating_layout.addLayout(rate_row)

        # Notes
        self.rating_notes_input = QTextEdit()
        self.rating_notes_input.setPlaceholderText("Notes about the control effectiveness...")
        self.rating_notes_input.setMaximumHeight(80)
        rating_layout.addWidget(self.rating_notes_input)

        layout.addWidget(rating_group)

        # Submit button
        btn_row = QHBoxLayout()
        self.submit_rating_btn = QPushButton("Submit Rating")
        self.submit_rating_btn.setMinimumHeight(34)
        btn_row.addWidget(self.submit_rating_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # Status
        self.rating_status_label = QLabel("")
        self.rating_status_label.setObjectName("countLabel")
        layout.addWidget(self.rating_status_label)

        # Existing ratings table
        ratings_header = QLabel("Existing Ratings")
        ratings_header.setObjectName("sectionLabel")
        layout.addWidget(ratings_header)

        self.ratings_table = QTableWidget()
        self.ratings_table.setColumnCount(5)
        self.ratings_table.setHorizontalHeaderLabels(
            ["Location", "Control Type", "Rating", "Notes", "Assessed At"]
        )
        self.ratings_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self.ratings_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.ratings_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self.ratings_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self.ratings_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.ResizeToContents
        )
        self.ratings_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.ratings_table.setAlternatingRowColors(True)
        self.ratings_table.verticalHeader().setVisible(False)
        layout.addWidget(self.ratings_table, 1)

        return container

    # ------------------------------------------------------------------
    # Summary Tab
    # ------------------------------------------------------------------

    def _create_summary_tab(self) -> QWidget:
        """Build physical assessment summary view for report inclusion."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Header
        header_row = QHBoxLayout()
        header_label = QLabel("Physical Assessment Summary")
        header_label.setObjectName("sectionLabel")
        header_row.addWidget(header_label)
        header_row.addStretch()

        self.generate_summary_btn = QPushButton("Generate Summary")
        self.generate_summary_btn.setMinimumHeight(34)
        header_row.addWidget(self.generate_summary_btn)
        layout.addLayout(header_row)

        # Summary content area (scrollable)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.summary_content = QWidget()
        self.summary_layout = QVBoxLayout(self.summary_content)
        self.summary_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.summary_layout.setSpacing(10)

        # Placeholder
        self.summary_placeholder = QLabel(
            "Click 'Generate Summary' to produce the assessment overview."
        )
        self.summary_placeholder.setObjectName("countLabel")
        self.summary_placeholder.setWordWrap(True)
        self.summary_layout.addWidget(self.summary_placeholder)

        scroll.setWidget(self.summary_content)
        layout.addWidget(scroll, 1)

        return container

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect UI signals to handler slots."""
        # Attempt logging tab
        self.log_attempt_btn.clicked.connect(self._on_log_attempt)
        self.clear_form_btn.clicked.connect(self._on_clear_form)

        # History tab
        self.history_filter_btn.clicked.connect(self._on_refresh_history)
        self.history_refresh_btn.clicked.connect(self._on_refresh_history)

        # Floor plan tab
        self.floor_plan_browse_btn.clicked.connect(self._on_browse_floor_plan)
        self.add_annotation_btn.clicked.connect(self._on_add_annotation)

        # Control rating tab
        self.submit_rating_btn.clicked.connect(self._on_submit_rating)
        self.rating_spin.valueChanged.connect(self._on_rating_value_changed)

        # Summary tab
        self.generate_summary_btn.clicked.connect(self._on_generate_summary)

        # Engine signals
        self.engine.attempt_logged.connect(self._on_engine_attempt_logged)
        self.engine.annotation_added.connect(self._on_engine_annotation_added)

    # ------------------------------------------------------------------
    # Action Handlers — Attempt Logging
    # ------------------------------------------------------------------

    def _on_log_attempt(self):
        """Log the physical access attempt from form data."""
        location = self.attempt_location_input.text().strip()
        if not location:
            self.attempt_status_label.setText("Error: Location is required.")
            return

        attempt_time = self.attempt_time_edit.dateTime().toString(Qt.DateFormat.ISODate)
        method = self.attempt_method_combo.currentData()
        outcome = self.attempt_outcome_combo.currentData()

        evidence_text = self.attempt_evidence_input.text().strip()
        evidence_id = int(evidence_text) if evidence_text.isdigit() else None
        notes = self.attempt_notes_input.toPlainText().strip() or None

        try:
            attempt_id = self.engine.log_attempt(
                location=location,
                attempt_time=attempt_time,
                method=method,
                outcome=outcome,
                evidence_id=evidence_id,
                notes=notes,
            )
            self.attempt_status_label.setText(
                f"Attempt logged successfully (ID: {attempt_id})"
            )
            self._on_clear_form()
        except (RuntimeError, ValueError) as e:
            self.attempt_status_label.setText(f"Error: {e}")

    def _on_clear_form(self):
        """Clear the attempt logging form."""
        self.attempt_location_input.clear()
        self.attempt_time_edit.setDateTime(
            self.attempt_time_edit.dateTime().currentDateTime()
        )
        self.attempt_method_combo.setCurrentIndex(0)
        self.attempt_outcome_combo.setCurrentIndex(0)
        self.attempt_evidence_input.clear()
        self.attempt_notes_input.clear()

    # ------------------------------------------------------------------
    # Action Handlers — Attempt History
    # ------------------------------------------------------------------

    def _on_refresh_history(self):
        """Refresh the attempt history table with optional filters."""
        location_filter = self.history_location_filter.text().strip() or None
        method_filter = self.history_method_filter.currentData() or None

        try:
            self._attempts = self.engine.get_attempts(
                location=location_filter, method=method_filter
            )
            self._populate_history_table()
        except (RuntimeError, ValueError) as e:
            self.history_count_label.setText(f"Error: {e}")

    def _populate_history_table(self):
        """Populate the history table from self._attempts."""
        self.history_table.setRowCount(len(self._attempts))

        for row, attempt in enumerate(self._attempts):
            self.history_table.setItem(
                row, 0, QTableWidgetItem(attempt.get("location", ""))
            )
            self.history_table.setItem(
                row, 1, QTableWidgetItem(attempt.get("attempt_time", ""))
            )

            method_item = QTableWidgetItem(
                attempt.get("method", "").replace("_", " ").title()
            )
            self.history_table.setItem(row, 2, method_item)

            outcome = attempt.get("outcome", "")
            outcome_item = QTableWidgetItem(outcome.title())
            if outcome == "success":
                outcome_item.setForeground(Qt.GlobalColor.green)
            elif outcome == "failure":
                outcome_item.setForeground(Qt.GlobalColor.red)
            else:
                outcome_item.setForeground(Qt.GlobalColor.yellow)
            self.history_table.setItem(row, 3, outcome_item)

            evidence_id = attempt.get("evidence_id")
            evidence_text = str(evidence_id) if evidence_id else "—"
            self.history_table.setItem(row, 4, QTableWidgetItem(evidence_text))

            self.history_table.setItem(
                row, 5, QTableWidgetItem(attempt.get("notes", "") or "")
            )

        self.history_count_label.setText(f"{len(self._attempts)} attempt(s) found")

    # ------------------------------------------------------------------
    # Action Handlers — Floor Plan
    # ------------------------------------------------------------------

    def _on_browse_floor_plan(self):
        """Open file dialog to select a floor plan image."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Floor Plan Image",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif);;All Files (*.*)",
        )
        if path:
            self.floor_plan_path_input.setText(path)
            self._load_floor_plan_image(path)

    def _load_floor_plan_image(self, path: str):
        """Load and display a floor plan image in the label."""
        pixmap = QPixmap(path)
        if pixmap.isNull():
            self.floor_plan_label.setText("Failed to load image")
            self._floor_plan_pixmap = None
            return

        self._floor_plan_pixmap = pixmap
        scaled = pixmap.scaled(
            self.floor_plan_label.size(),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.floor_plan_label.setPixmap(scaled)
        self._refresh_annotations()

    def _on_add_annotation(self):
        """Add a site annotation to the current floor plan."""
        evidence_id_text = self.floor_plan_evidence_id_input.text().strip()
        if not evidence_id_text.isdigit():
            return

        floor_plan_evidence_id = int(evidence_id_text)
        annotation_type = self.annotation_type_combo.currentData()
        label = self.annotation_label_input.text().strip() or None
        notes = self.annotation_notes_input.text().strip() or None

        # Parse coordinates
        try:
            x = int(self.annotation_x_input.text() or "0")
            y = int(self.annotation_y_input.text() or "0")
            w = int(self.annotation_w_input.text() or "50")
            h = int(self.annotation_h_input.text() or "50")
        except ValueError:
            return

        coordinates = {"x": x, "y": y, "width": w, "height": h}

        try:
            self.engine.add_site_annotation(
                floor_plan_evidence_id=floor_plan_evidence_id,
                annotation_type=annotation_type,
                coordinates=coordinates,
                label=label,
                notes=notes,
            )
            self._refresh_annotations()
            # Clear input fields
            self.annotation_label_input.clear()
            self.annotation_notes_input.clear()
            self.annotation_x_input.clear()
            self.annotation_y_input.clear()
            self.annotation_w_input.clear()
            self.annotation_h_input.clear()
        except (RuntimeError, ValueError):
            pass

    def _refresh_annotations(self):
        """Refresh the annotation list from the engine."""
        self.annotation_list.clear()
        evidence_id_text = self.floor_plan_evidence_id_input.text().strip()
        floor_plan_id = int(evidence_id_text) if evidence_id_text.isdigit() else None

        try:
            self._annotations = self.engine.get_annotations(
                floor_plan_evidence_id=floor_plan_id
            )
        except RuntimeError:
            self._annotations = []

        for ann in self._annotations:
            ann_type = ann.get("annotation_type", "").replace("_", " ").title()
            label = ann.get("label", "") or ""
            coords = ann.get("coordinates", {})
            coord_str = f"({coords.get('x', 0)}, {coords.get('y', 0)})"
            text = f"[{ann_type}] {label} @ {coord_str}"
            item = QListWidgetItem(text)
            # Color by annotation type
            ann_type_raw = ann.get("annotation_type", "")
            if ann_type_raw == "entry_point":
                item.setForeground(Qt.GlobalColor.green)
            elif ann_type_raw == "camera":
                item.setForeground(Qt.GlobalColor.yellow)
            elif ann_type_raw == "access_control_zone":
                item.setForeground(Qt.GlobalColor.cyan)
            item.setData(Qt.ItemDataRole.UserRole, ann)
            self.annotation_list.addItem(item)

    # ------------------------------------------------------------------
    # Action Handlers — Control Ratings
    # ------------------------------------------------------------------

    def _on_rating_value_changed(self, value: int):
        """Update the rating display label."""
        self.rating_display_label.setText(f"{value} / 5")

    def _on_submit_rating(self):
        """Submit a control effectiveness rating."""
        location = self.rating_location_input.text().strip()
        control_type = self.rating_control_type_input.text().strip()

        if not location:
            self.rating_status_label.setText("Error: Location is required.")
            return
        if not control_type:
            self.rating_status_label.setText("Error: Control type is required.")
            return

        rating_value = self.rating_spin.value()
        notes = self.rating_notes_input.toPlainText().strip() or None

        try:
            rating_id = self.engine.rate_control(
                location=location,
                control_type=control_type,
                effectiveness_rating=rating_value,
                notes=notes,
            )
            self.rating_status_label.setText(
                f"Rating submitted (ID: {rating_id})"
            )
            # Clear form
            self.rating_location_input.clear()
            self.rating_control_type_input.clear()
            self.rating_spin.setValue(3)
            self.rating_notes_input.clear()
            # Refresh table
            self._refresh_ratings_table()
        except (RuntimeError, ValueError) as e:
            self.rating_status_label.setText(f"Error: {e}")

    def _refresh_ratings_table(self):
        """Refresh the ratings table from the engine."""
        try:
            self._ratings = self.engine.get_ratings()
        except RuntimeError:
            self._ratings = []

        self.ratings_table.setRowCount(len(self._ratings))
        for row, rating in enumerate(self._ratings):
            self.ratings_table.setItem(
                row, 0, QTableWidgetItem(rating.get("location", ""))
            )
            self.ratings_table.setItem(
                row, 1, QTableWidgetItem(rating.get("control_type", ""))
            )

            effectiveness = rating.get("effectiveness_rating", 0)
            rating_item = QTableWidgetItem(f"{'★' * effectiveness}{'☆' * (5 - effectiveness)}")
            if effectiveness <= 2:
                rating_item.setForeground(Qt.GlobalColor.red)
            elif effectiveness <= 3:
                rating_item.setForeground(Qt.GlobalColor.yellow)
            else:
                rating_item.setForeground(Qt.GlobalColor.green)
            self.ratings_table.setItem(row, 2, rating_item)

            self.ratings_table.setItem(
                row, 3, QTableWidgetItem(rating.get("notes", "") or "")
            )
            self.ratings_table.setItem(
                row, 4, QTableWidgetItem(rating.get("assessed_at", ""))
            )

    # ------------------------------------------------------------------
    # Action Handlers — Summary
    # ------------------------------------------------------------------

    def _on_generate_summary(self):
        """Generate and display the physical assessment summary."""
        try:
            summary = self.engine.generate_summary()
        except RuntimeError as e:
            self._clear_summary_layout()
            error_label = QLabel(f"Error generating summary: {e}")
            error_label.setWordWrap(True)
            self.summary_layout.addWidget(error_label)
            return

        self._clear_summary_layout()
        self._populate_summary(summary)
        self.summary_generated.emit(summary)

    def _clear_summary_layout(self):
        """Remove all widgets from the summary layout."""
        while self.summary_layout.count():
            child = self.summary_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def _populate_summary(self, summary: Dict):
        """Populate the summary tab with structured data."""
        # Total attempts
        total = summary.get("total_attempts", 0)
        total_label = QLabel(f"Total Attempts: {total}")
        total_label.setObjectName("sectionLabel")
        self.summary_layout.addWidget(total_label)

        # Attempts by method
        attempts_by_method = summary.get("attempts_by_method", {})
        if attempts_by_method:
            method_header = QLabel("Attempts by Method & Outcome")
            method_header.setObjectName("sectionLabel")
            self.summary_layout.addWidget(method_header)

            for method, outcomes in attempts_by_method.items():
                method_text = method.replace("_", " ").title()
                outcome_parts = [
                    f"{outcome}: {count}" for outcome, count in outcomes.items()
                ]
                line = QLabel(f"  • {method_text} — {', '.join(outcome_parts)}")
                line.setWordWrap(True)
                self.summary_layout.addWidget(line)

        # Successful access points
        access_points = summary.get("successful_access_points", [])
        if access_points:
            access_header = QLabel("Successful Access Points")
            access_header.setObjectName("sectionLabel")
            self.summary_layout.addWidget(access_header)

            for ap in access_points:
                loc = ap.get("location", "Unknown")
                method = ap.get("method", "").replace("_", " ").title()
                time = ap.get("time", "")
                line = QLabel(f"  • {loc} via {method} at {time}")
                line.setForeground(Qt.GlobalColor.green) if hasattr(line, "setForeground") else None
                line.setStyleSheet("color: #A8E6CF; border: none; background: transparent;")
                line.setWordWrap(True)
                self.summary_layout.addWidget(line)

        # Average ratings by location
        avg_ratings = summary.get("average_ratings_by_location", {})
        if avg_ratings:
            rating_header = QLabel("Control Effectiveness by Location")
            rating_header.setObjectName("sectionLabel")
            self.summary_layout.addWidget(rating_header)

            for loc, avg in avg_ratings.items():
                line = QLabel(f"  • {loc}: {avg:.1f} / 5.0")
                if avg <= 2.0:
                    line.setStyleSheet("color: #FF6B6B; border: none; background: transparent;")
                elif avg <= 3.5:
                    line.setStyleSheet("color: #FFD93D; border: none; background: transparent;")
                else:
                    line.setStyleSheet("color: #A8E6CF; border: none; background: transparent;")
                self.summary_layout.addWidget(line)

        # Annotations overview
        annotations_by_plan = summary.get("annotations_by_floor_plan", {})
        if annotations_by_plan:
            ann_header = QLabel("Site Annotations Overview")
            ann_header.setObjectName("sectionLabel")
            self.summary_layout.addWidget(ann_header)

            for plan_id, types in annotations_by_plan.items():
                type_parts = [
                    f"{t.replace('_', ' ').title()}: {c}"
                    for t, c in types.items()
                ]
                line = QLabel(f"  • Floor Plan #{plan_id} — {', '.join(type_parts)}")
                line.setWordWrap(True)
                self.summary_layout.addWidget(line)

        # Generated timestamp
        generated_at = summary.get("generated_at", "")
        if generated_at:
            ts_label = QLabel(f"Generated: {generated_at}")
            ts_label.setObjectName("countLabel")
            self.summary_layout.addWidget(ts_label)

    # ------------------------------------------------------------------
    # Engine Signal Handlers
    # ------------------------------------------------------------------

    def _on_engine_attempt_logged(self, attempt_data: dict):
        """Handle attempt_logged signal from engine."""
        self.attempt_logged.emit(attempt_data)

    def _on_engine_annotation_added(self, annotation_id: int):
        """Handle annotation_added signal from engine."""
        self._refresh_annotations()

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
        """Apply dark theme with cyan accents matching project conventions."""
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
            QGroupBox {
                background-color: rgba(0, 0, 0, 80);
                border: 1px solid rgba(100, 200, 255, 60);
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 14px;
                color: #64C8FF;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
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
                min-width: 120px;
            }
            QComboBox:hover {
                border: 2px solid #64C8FF;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            QComboBox QAbstractItemView {
                background-color: rgba(20, 30, 40, 240);
                border: 1px solid rgba(100, 200, 255, 80);
                color: #DCDCDC;
                selection-background-color: rgba(100, 200, 255, 80);
            }
            QSpinBox {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
                min-width: 60px;
            }
            QSpinBox:focus {
                border: 2px solid #64C8FF;
            }
            QDateTimeEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px;
            }
            QDateTimeEdit:focus {
                border: 2px solid #64C8FF;
            }
            QTabWidget::pane {
                background-color: rgba(0, 0, 0, 80);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: rgba(30, 40, 50, 150);
                border: 1px solid rgba(100, 200, 255, 60);
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                color: #DCDCDC;
                padding: 6px 14px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(50, 70, 90, 200);
                border-color: #64C8FF;
                color: #64C8FF;
            }
            QTabBar::tab:hover {
                background-color: rgba(50, 70, 90, 150);
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
                color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 40);
                padding: 5px;
                font-weight: bold;
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
            QTextEdit {
                background-color: rgba(10, 15, 25, 200);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 12px;
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
            QSplitter::handle {
                background-color: rgba(100, 200, 255, 40);
                width: 3px;
            }
        """)
