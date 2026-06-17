# app/components/scan_scheduler_component.py
"""Scan Scheduler UI Component.

Provides a comprehensive scheduling interface with:
- Schedule creation form (name, scan config JSON, targets text area, recurrence pattern)
- Cron expression builder with human-readable preview
- Calendar/list view showing all scheduled scans with status indicators
- Schedule list with enable/disable toggles
- Failure log viewer per schedule
- Integrates within Tools menu and Engagement Setup page

Requirements: 19.1, 19.2, 19.6, 19.7
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.scheduling_engine import SchedulingEngine


# ---------------------------------------------------------------------------
# Cron Expression Builder Helpers
# ---------------------------------------------------------------------------

NAMED_RECURRENCE_OPTIONS = [
    ("Once (One-time)", "once"),
    ("Daily (Every day at midnight)", "daily"),
    ("Weekly (Every Monday at midnight)", "weekly"),
    ("Monthly (1st of every month at midnight)", "monthly"),
    ("Custom Cron Expression", "custom"),
]

WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def _cron_to_human_readable(pattern: str) -> str:
    """Convert a recurrence pattern to a human-readable description."""
    pattern_lower = pattern.strip().lower()

    if pattern_lower == "once":
        return "One-time execution"
    if pattern_lower == "daily":
        return "Every day at midnight"
    if pattern_lower == "weekly":
        return "Every Monday at midnight"
    if pattern_lower == "monthly":
        return "1st of every month at midnight"

    # Parse custom cron expression
    fields = pattern.strip().split()
    if len(fields) != 5:
        return f"Custom: {pattern}"

    minute, hour, dom, month, dow = fields

    parts = []

    # Time description
    if minute == "0" and hour == "0":
        parts.append("At midnight")
    elif minute == "0":
        parts.append(f"At {hour}:00")
    elif hour == "*":
        if minute.startswith("*/"):
            parts.append(f"Every {minute[2:]} minutes")
        else:
            parts.append(f"At minute {minute} of every hour")
    else:
        parts.append(f"At {hour}:{minute.zfill(2)}")

    # Day of week
    if dow != "*":
        if dow.isdigit():
            idx = int(dow)
            if 0 <= idx < 7:
                parts.append(f"on {WEEKDAY_NAMES[idx]}")
        elif "," in dow:
            days = []
            for d in dow.split(","):
                if d.isdigit() and 0 <= int(d) < 7:
                    days.append(WEEKDAY_NAMES[int(d)])
            if days:
                parts.append(f"on {', '.join(days)}")
        elif "-" in dow:
            start, end = dow.split("-", 1)
            if start.isdigit() and end.isdigit():
                s, e = int(start), int(end)
                if 0 <= s < 7 and 0 <= e < 7:
                    parts.append(f"on {WEEKDAY_NAMES[s]} through {WEEKDAY_NAMES[e]}")

    # Day of month
    if dom != "*" and dow == "*":
        if dom.isdigit():
            parts.append(f"on day {dom}")
        elif "," in dom:
            parts.append(f"on days {dom}")
        elif dom.startswith("*/"):
            parts.append(f"every {dom[2:]} days")

    # Month
    if month != "*":
        month_names = [
            "", "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December"
        ]
        if month.isdigit() and 1 <= int(month) <= 12:
            parts.append(f"in {month_names[int(month)]}")
        elif "," in month:
            months = []
            for m in month.split(","):
                if m.isdigit() and 1 <= int(m) <= 12:
                    months.append(month_names[int(m)])
            if months:
                parts.append(f"in {', '.join(months)}")

    return " ".join(parts) if parts else f"Custom: {pattern}"


def _status_color(status: str) -> str:
    """Return a display color for a schedule status."""
    colors = {
        "active": "#66BB6A",
        "disabled": "#FF9800",
        "completed": "#78909C",
        "failed": "#FF5252",
    }
    return colors.get(status, "#AAAAAA")


def _status_icon(status: str) -> str:
    """Return a status indicator character."""
    icons = {
        "active": "●",
        "disabled": "○",
        "completed": "✓",
        "failed": "✗",
    }
    return icons.get(status, "?")


# ---------------------------------------------------------------------------
# Cron Builder Widget
# ---------------------------------------------------------------------------

class CronBuilderWidget(QWidget):
    """Interactive cron expression builder with human-readable preview."""

    cron_changed = pyqtSignal(str)  # Emits the full recurrence pattern string

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._connect_signals()
        self._update_preview()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Recurrence type selector
        type_layout = QHBoxLayout()
        type_label = QLabel("Recurrence:")
        type_label.setStyleSheet("color: #00E5FF; font-size: 11px; font-weight: bold;")
        type_layout.addWidget(type_label)

        self.recurrence_combo = QComboBox()
        for display, _value in NAMED_RECURRENCE_OPTIONS:
            self.recurrence_combo.addItem(display)
        type_layout.addWidget(self.recurrence_combo, 1)
        layout.addLayout(type_layout)

        # Custom cron fields (shown only when "Custom" is selected)
        self.custom_frame = QFrame()
        self.custom_frame.setObjectName("cronFrame")
        custom_layout = QFormLayout(self.custom_frame)
        custom_layout.setContentsMargins(8, 8, 8, 8)
        custom_layout.setSpacing(6)

        self.minute_input = QLineEdit("0")
        self.minute_input.setPlaceholderText("0-59, */5, etc.")
        self.minute_input.setToolTip("Minute (0-59). Examples: 0, */5, 0,30")
        custom_layout.addRow("Minute:", self.minute_input)

        self.hour_input = QLineEdit("0")
        self.hour_input.setPlaceholderText("0-23, */2, etc.")
        self.hour_input.setToolTip("Hour (0-23). Examples: 0, 8, */6, 9-17")
        custom_layout.addRow("Hour:", self.hour_input)

        self.dom_input = QLineEdit("*")
        self.dom_input.setPlaceholderText("1-31, *, etc.")
        self.dom_input.setToolTip("Day of month (1-31). Examples: *, 1, 1,15")
        custom_layout.addRow("Day of Month:", self.dom_input)

        self.month_input = QLineEdit("*")
        self.month_input.setPlaceholderText("1-12, *, etc.")
        self.month_input.setToolTip("Month (1-12). Examples: *, 1,6, 3-9")
        custom_layout.addRow("Month:", self.month_input)

        self.dow_input = QLineEdit("*")
        self.dow_input.setPlaceholderText("0-6 (Mon=0), *, etc.")
        self.dow_input.setToolTip("Day of week (0=Monday, 6=Sunday). Examples: *, 0-4, 0,2,4")
        custom_layout.addRow("Day of Week:", self.dow_input)

        self.custom_frame.setVisible(False)
        layout.addWidget(self.custom_frame)

        # Preview label
        self.preview_label = QLabel("")
        self.preview_label.setWordWrap(True)
        self.preview_label.setStyleSheet(
            "color: #00E5FF; font-size: 12px; font-style: italic; "
            "padding: 4px 8px; background-color: #1A1A2A; "
            "border: 1px solid #3A3A5E; border-radius: 4px;"
        )
        layout.addWidget(self.preview_label)

    def _connect_signals(self):
        self.recurrence_combo.currentIndexChanged.connect(self._on_type_changed)
        self.minute_input.textChanged.connect(self._update_preview)
        self.hour_input.textChanged.connect(self._update_preview)
        self.dom_input.textChanged.connect(self._update_preview)
        self.month_input.textChanged.connect(self._update_preview)
        self.dow_input.textChanged.connect(self._update_preview)

    def _on_type_changed(self, index: int):
        is_custom = (index == len(NAMED_RECURRENCE_OPTIONS) - 1)
        self.custom_frame.setVisible(is_custom)
        self._update_preview()

    def _update_preview(self):
        pattern = self.get_pattern()
        human = _cron_to_human_readable(pattern)
        self.preview_label.setText(f"📅 {human}")
        self.cron_changed.emit(pattern)

    def get_pattern(self) -> str:
        """Return the current recurrence pattern string."""
        index = self.recurrence_combo.currentIndex()
        if index < len(NAMED_RECURRENCE_OPTIONS) - 1:
            return NAMED_RECURRENCE_OPTIONS[index][1]
        # Custom cron
        minute = self.minute_input.text().strip() or "0"
        hour = self.hour_input.text().strip() or "0"
        dom = self.dom_input.text().strip() or "*"
        month = self.month_input.text().strip() or "*"
        dow = self.dow_input.text().strip() or "*"
        return f"{minute} {hour} {dom} {month} {dow}"

    def set_pattern(self, pattern: str):
        """Set the builder to display a given pattern."""
        pattern_lower = pattern.strip().lower()
        for i, (_, value) in enumerate(NAMED_RECURRENCE_OPTIONS[:-1]):
            if pattern_lower == value:
                self.recurrence_combo.setCurrentIndex(i)
                return

        # Custom cron
        self.recurrence_combo.setCurrentIndex(len(NAMED_RECURRENCE_OPTIONS) - 1)
        fields = pattern.strip().split()
        if len(fields) == 5:
            self.minute_input.setText(fields[0])
            self.hour_input.setText(fields[1])
            self.dom_input.setText(fields[2])
            self.month_input.setText(fields[3])
            self.dow_input.setText(fields[4])


# ---------------------------------------------------------------------------
# Schedule List Item Widget
# ---------------------------------------------------------------------------

class ScheduleListItemWidget(QWidget):
    """Custom widget for a schedule list item with status and toggle."""

    toggle_clicked = pyqtSignal(str, bool)  # schedule_id, enabled

    def __init__(self, schedule: Dict, parent=None):
        super().__init__(parent)
        self.schedule_id = schedule["id"]
        self.status = schedule.get("status", "active")
        self._setup_ui(schedule)

    def _setup_ui(self, schedule: Dict):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(8)

        # Status indicator
        status_label = QLabel(_status_icon(self.status))
        status_label.setFixedWidth(16)
        status_label.setStyleSheet(f"color: {_status_color(self.status)}; font-size: 14px;")
        status_label.setToolTip(f"Status: {self.status}")
        layout.addWidget(status_label)

        # Name and recurrence info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(1)
        info_layout.setContentsMargins(0, 0, 0, 0)

        name_label = QLabel(schedule.get("name", "Unnamed"))
        name_label.setStyleSheet("color: #E0E0E0; font-size: 12px; font-weight: bold;")
        info_layout.addWidget(name_label)

        recurrence = schedule.get("recurrence_pattern", "")
        human_pattern = _cron_to_human_readable(recurrence)
        next_exec = schedule.get("next_execution", "")
        if next_exec:
            try:
                dt = datetime.fromisoformat(next_exec)
                next_str = dt.strftime("%Y-%m-%d %H:%M UTC")
            except (ValueError, TypeError):
                next_str = next_exec
        else:
            next_str = "N/A"

        meta_label = QLabel(f"{human_pattern} • Next: {next_str}")
        meta_label.setStyleSheet("color: #808080; font-size: 10px;")
        info_layout.addWidget(meta_label)

        layout.addLayout(info_layout, 1)

        # Failure count badge
        failure_count = schedule.get("failure_count", 0)
        if failure_count > 0:
            fail_badge = QLabel(f"⚠ {failure_count}")
            fail_badge.setStyleSheet(
                "color: #FF5252; font-size: 10px; "
                "background-color: #2A1A1A; padding: 2px 4px; "
                "border-radius: 3px;"
            )
            fail_badge.setToolTip(f"{failure_count} failure(s)")
            layout.addWidget(fail_badge)

        # Enable/Disable toggle
        self.toggle_check = QCheckBox()
        self.toggle_check.setChecked(self.status == "active")
        self.toggle_check.setToolTip("Enable/Disable schedule")
        self.toggle_check.setEnabled(self.status in ("active", "disabled"))
        self.toggle_check.stateChanged.connect(self._on_toggle)
        layout.addWidget(self.toggle_check)

    def _on_toggle(self, state):
        enabled = state == Qt.CheckState.Checked.value
        self.toggle_clicked.emit(self.schedule_id, enabled)


# ---------------------------------------------------------------------------
# Scan Scheduler Component
# ---------------------------------------------------------------------------

class ScanSchedulerComponent(QWidget):
    """Main scan scheduler UI component.

    Layout: Left (schedule list with toggles) | Right (stacked: creation form / detail view)

    Signals:
        schedule_created(str): Emitted when a new schedule is created (schedule_id).
        schedule_toggled(str, bool): Emitted when a schedule is enabled/disabled.
        schedule_deleted(str): Emitted when a schedule is deleted.
    """

    schedule_created = pyqtSignal(str)
    schedule_toggled = pyqtSignal(str, bool)
    schedule_deleted = pyqtSignal(str)

    def __init__(self, scheduling_engine: SchedulingEngine, parent=None):
        super().__init__(parent)
        self.engine = scheduling_engine
        self._schedules_cache: List[Dict] = []
        self._selected_schedule_id: Optional[str] = None

        self._setup_ui()
        self._apply_theme()
        self._connect_signals()

        # Initial load
        QTimer.singleShot(0, self._load_schedules)

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the two-panel layout with splitter."""
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # --- LEFT PANEL: Schedule List ---
        self.left_panel = QWidget()
        left_layout = QVBoxLayout(self.left_panel)
        left_layout.setContentsMargins(8, 8, 4, 8)
        left_layout.setSpacing(6)

        # Title
        title_label = QLabel("Scheduled Scans")
        title_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #00E5FF;")
        left_layout.addWidget(title_label)

        # Filter bar
        filter_layout = QHBoxLayout()
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Active", "Disabled", "Completed"])
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.filter_combo, 1)
        left_layout.addLayout(filter_layout)

        # Schedule list
        self.schedule_list = QListWidget()
        left_layout.addWidget(self.schedule_list, 1)

        # Action buttons
        btn_layout = QHBoxLayout()
        self.new_schedule_btn = QPushButton("+ New Schedule")
        self.new_schedule_btn.setMinimumHeight(28)
        btn_layout.addWidget(self.new_schedule_btn)

        self.refresh_btn = QPushButton("⟳ Refresh")
        self.refresh_btn.setMinimumHeight(28)
        btn_layout.addWidget(self.refresh_btn)
        left_layout.addLayout(btn_layout)

        self.left_panel.setMinimumWidth(300)
        self.left_panel.setMaximumWidth(450)
        self.main_splitter.addWidget(self.left_panel)

        # --- RIGHT PANEL: Stacked (Form / Detail View) ---
        self.right_panel = QWidget()
        right_layout = QVBoxLayout(self.right_panel)
        right_layout.setContentsMargins(4, 8, 8, 8)
        right_layout.setSpacing(6)

        self.right_stack = QStackedWidget()

        # Page 0: Empty state / Calendar overview
        self.overview_page = self._build_overview_page()
        self.right_stack.addWidget(self.overview_page)

        # Page 1: Schedule creation form
        self.creation_page = self._build_creation_form()
        self.right_stack.addWidget(self.creation_page)

        # Page 2: Schedule detail view with failure log
        self.detail_page = self._build_detail_page()
        self.right_stack.addWidget(self.detail_page)

        right_layout.addWidget(self.right_stack, 1)
        self.right_panel.setMinimumWidth(450)
        self.main_splitter.addWidget(self.right_panel)

        # Splitter proportions
        self.main_splitter.setStretchFactor(0, 2)
        self.main_splitter.setStretchFactor(1, 3)

        main_layout.addWidget(self.main_splitter)

    def _build_overview_page(self) -> QWidget:
        """Build the calendar/overview page showing all scheduled scans."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        header = QLabel("Schedule Overview")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: #00E5FF;")
        layout.addWidget(header)

        desc = QLabel(
            "View all scheduled scans at a glance. Select a schedule from the "
            "list or create a new one."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #AAAAAA; font-size: 11px;")
        layout.addWidget(desc)

        # Calendar-style table showing upcoming scans
        self.calendar_table = QTableWidget()
        self.calendar_table.setColumnCount(5)
        self.calendar_table.setHorizontalHeaderLabels(
            ["Name", "Recurrence", "Next Execution", "Status", "Failures"]
        )
        self.calendar_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.calendar_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.calendar_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.calendar_table.setAlternatingRowColors(True)
        layout.addWidget(self.calendar_table, 1)

        return page

    def _build_creation_form(self) -> QWidget:
        """Build the schedule creation form."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        header = QLabel("Create New Schedule")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: #00E5FF;")
        layout.addWidget(header)

        # Form fields
        form_frame = QFrame()
        form_frame.setObjectName("formFrame")
        form_layout = QFormLayout(form_frame)
        form_layout.setContentsMargins(12, 12, 12, 12)
        form_layout.setSpacing(8)

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g., Weekly Network Scan")
        form_layout.addRow("Schedule Name:", self.name_input)

        # Scan configuration JSON editor
        config_label = QLabel("Scan Configuration (JSON):")
        config_label.setStyleSheet("color: #E0E0E0;")
        self.config_editor = QTextEdit()
        self.config_editor.setPlaceholderText(
            '{\n    "scan_type": "full",\n    "ports": "1-1000",\n    "intensity": "normal"\n}'
        )
        self.config_editor.setFont(QFont("Neuropol X", 10))
        self.config_editor.setMaximumHeight(120)
        form_layout.addRow(config_label, self.config_editor)

        # Targets text area
        targets_label = QLabel("Targets (one per line):")
        targets_label.setStyleSheet("color: #E0E0E0;")
        self.targets_editor = QTextEdit()
        self.targets_editor.setPlaceholderText(
            "192.168.1.0/24\nexample.com\n10.0.0.1-10.0.0.50"
        )
        self.targets_editor.setMaximumHeight(100)
        form_layout.addRow(targets_label, self.targets_editor)

        # Engagement ID (optional)
        self.engagement_input = QLineEdit()
        self.engagement_input.setPlaceholderText("(Optional) Engagement UUID")
        form_layout.addRow("Engagement:", self.engagement_input)

        layout.addWidget(form_frame)

        # Cron builder
        cron_group = QGroupBox("Recurrence Pattern")
        cron_group.setStyleSheet(
            "QGroupBox { color: #00E5FF; font-weight: bold; "
            "border: 1px solid #3A3A5E; border-radius: 4px; "
            "margin-top: 8px; padding-top: 12px; } "
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; }"
        )
        cron_layout = QVBoxLayout(cron_group)
        self.cron_builder = CronBuilderWidget()
        cron_layout.addWidget(self.cron_builder)
        layout.addWidget(cron_group)

        # Action buttons
        action_layout = QHBoxLayout()
        self.create_btn = QPushButton("Create Schedule")
        self.create_btn.setMinimumHeight(32)
        self.create_btn.setStyleSheet(
            "QPushButton { background-color: #00695C; border: 1px solid #00E5FF; "
            "color: #FFFFFF; font-weight: bold; } "
            "QPushButton:hover { background-color: #00897B; } "
            "QPushButton:pressed { background-color: #00E5FF; color: #1E1E2E; }"
        )
        action_layout.addWidget(self.create_btn)

        self.cancel_create_btn = QPushButton("Cancel")
        self.cancel_create_btn.setMinimumHeight(32)
        action_layout.addWidget(self.cancel_create_btn)

        action_layout.addStretch()
        layout.addLayout(action_layout)

        layout.addStretch()
        return page

    def _build_detail_page(self) -> QWidget:
        """Build the schedule detail view with failure log."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Header with name and status
        header_layout = QHBoxLayout()
        self.detail_name_label = QLabel("Schedule Details")
        self.detail_name_label.setStyleSheet(
            "font-size: 14px; font-weight: bold; color: #00E5FF;"
        )
        header_layout.addWidget(self.detail_name_label)
        header_layout.addStretch()

        self.detail_status_label = QLabel("")
        self.detail_status_label.setStyleSheet("font-size: 12px;")
        header_layout.addWidget(self.detail_status_label)
        layout.addLayout(header_layout)

        # Detail info frame
        info_frame = QFrame()
        info_frame.setObjectName("detailFrame")
        info_layout = QFormLayout(info_frame)
        info_layout.setContentsMargins(12, 12, 12, 12)
        info_layout.setSpacing(6)

        self.detail_id_label = QLabel("")
        self.detail_id_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        info_layout.addRow("ID:", self.detail_id_label)

        self.detail_recurrence_label = QLabel("")
        info_layout.addRow("Recurrence:", self.detail_recurrence_label)

        self.detail_next_exec_label = QLabel("")
        info_layout.addRow("Next Execution:", self.detail_next_exec_label)

        self.detail_last_exec_label = QLabel("")
        info_layout.addRow("Last Execution:", self.detail_last_exec_label)

        self.detail_targets_label = QLabel("")
        self.detail_targets_label.setWordWrap(True)
        info_layout.addRow("Targets:", self.detail_targets_label)

        self.detail_engagement_label = QLabel("")
        info_layout.addRow("Engagement:", self.detail_engagement_label)

        self.detail_created_label = QLabel("")
        info_layout.addRow("Created:", self.detail_created_label)

        layout.addWidget(info_frame)

        # Scan config viewer
        config_group = QGroupBox("Scan Configuration")
        config_group.setStyleSheet(
            "QGroupBox { color: #00E5FF; font-weight: bold; "
            "border: 1px solid #3A3A5E; border-radius: 4px; "
            "margin-top: 8px; padding-top: 12px; } "
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; }"
        )
        config_layout = QVBoxLayout(config_group)
        self.detail_config_view = QTextEdit()
        self.detail_config_view.setReadOnly(True)
        self.detail_config_view.setFont(QFont("Neuropol X", 10))
        self.detail_config_view.setMaximumHeight(100)
        config_layout.addWidget(self.detail_config_view)
        layout.addWidget(config_group)

        # Failure log viewer
        fail_group = QGroupBox("Failure Log")
        fail_group.setStyleSheet(
            "QGroupBox { color: #FF5252; font-weight: bold; "
            "border: 1px solid #3A3A5E; border-radius: 4px; "
            "margin-top: 8px; padding-top: 12px; } "
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; }"
        )
        fail_layout = QVBoxLayout(fail_group)
        self.failure_log_view = QTextEdit()
        self.failure_log_view.setReadOnly(True)
        self.failure_log_view.setFont(QFont("Neuropol X", 10))
        self.failure_log_view.setMaximumHeight(120)
        self.failure_log_view.setPlaceholderText("No failures recorded.")
        fail_layout.addWidget(self.failure_log_view)
        layout.addWidget(fail_group)

        # Action buttons
        detail_actions = QHBoxLayout()

        self.enable_disable_btn = QPushButton("Disable")
        self.enable_disable_btn.setMinimumHeight(28)
        detail_actions.addWidget(self.enable_disable_btn)

        self.delete_schedule_btn = QPushButton("Delete")
        self.delete_schedule_btn.setMinimumHeight(28)
        self.delete_schedule_btn.setStyleSheet(
            "QPushButton { color: #FF5252; } "
            "QPushButton:hover { background-color: #FF5252; color: #FFFFFF; }"
        )
        detail_actions.addWidget(self.delete_schedule_btn)

        detail_actions.addStretch()

        self.back_to_overview_btn = QPushButton("← Back")
        self.back_to_overview_btn.setMinimumHeight(28)
        detail_actions.addWidget(self.back_to_overview_btn)

        layout.addLayout(detail_actions)
        layout.addStretch()

        return page

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
        """Apply dark theme with cyan accents."""
        self.setStyleSheet("""
            QWidget {
                background-color: #1E1E2E;
                color: #DCDCDC;
                font-family: "Neuropol X", sans-serif;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #2A2A3E;
                border: 1px solid #3A3A5E;
                border-radius: 4px;
                padding: 4px 8px;
                color: #E0E0E0;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border-color: #00E5FF;
            }
            QPushButton {
                background-color: #2A2A3E;
                border: 1px solid #3A3A5E;
                border-radius: 4px;
                padding: 4px 12px;
                color: #E0E0E0;
            }
            QPushButton:hover {
                background-color: #3A3A5E;
                border-color: #00E5FF;
            }
            QPushButton:pressed {
                background-color: #00E5FF;
                color: #1E1E2E;
            }
            QListWidget {
                background-color: #1A1A2A;
                border: 1px solid #3A3A5E;
                border-radius: 4px;
            }
            QListWidget::item {
                border-bottom: 1px solid #2A2A3E;
                padding: 2px;
            }
            QListWidget::item:selected {
                background-color: #2A3A5E;
            }
            QTableWidget {
                background-color: #1A1A2A;
                border: 1px solid #3A3A5E;
                border-radius: 4px;
                gridline-color: #2A2A3E;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: #2A3A5E;
            }
            QHeaderView::section {
                background-color: #2A2A3E;
                color: #00E5FF;
                border: 1px solid #3A3A5E;
                padding: 4px;
                font-weight: bold;
                font-size: 11px;
            }
            QFrame#formFrame, QFrame#detailFrame, QFrame#cronFrame {
                background-color: #222236;
                border: 1px solid #3A3A5E;
                border-radius: 4px;
            }
            QSplitter::handle {
                background-color: #3A3A5E;
                width: 2px;
            }
            QLabel {
                background-color: transparent;
                border: none;
            }
            QCheckBox {
                spacing: 4px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 3px;
                border: 1px solid #3A3A5E;
                background-color: #2A2A3E;
            }
            QCheckBox::indicator:checked {
                background-color: #00E5FF;
                border-color: #00E5FF;
            }
        """)

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect UI signals to handlers."""
        # Left panel
        self.filter_combo.currentTextChanged.connect(self._on_filter_changed)
        self.schedule_list.currentRowChanged.connect(self._on_schedule_selected)
        self.new_schedule_btn.clicked.connect(self._on_new_schedule)
        self.refresh_btn.clicked.connect(self._load_schedules)

        # Creation form
        self.create_btn.clicked.connect(self._on_create_schedule)
        self.cancel_create_btn.clicked.connect(self._on_cancel_create)

        # Detail view
        self.enable_disable_btn.clicked.connect(self._on_toggle_schedule)
        self.delete_schedule_btn.clicked.connect(self._on_delete_schedule)
        self.back_to_overview_btn.clicked.connect(self._on_back_to_overview)

        # Calendar table double-click
        self.calendar_table.cellDoubleClicked.connect(self._on_calendar_row_clicked)

        # Engine signals
        self.engine.scan_triggered.connect(self._on_scan_triggered)
        self.engine.scan_completed.connect(self._on_scan_completed)
        self.engine.scan_failed.connect(self._on_scan_failed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Reload all schedule data."""
        self._load_schedules()

    # ------------------------------------------------------------------
    # Data Loading
    # ------------------------------------------------------------------

    def _load_schedules(self):
        """Load schedules from the engine and populate UI."""
        status_filter = self._get_status_filter()
        try:
            self._schedules_cache = self.engine.list_schedules(
                status_filter=status_filter
            )
        except Exception:
            self._schedules_cache = []

        self._populate_schedule_list()
        self._populate_calendar_table()

    def _get_status_filter(self) -> Optional[str]:
        """Get the current filter selection as a status string."""
        text = self.filter_combo.currentText()
        if text == "All":
            return None
        return text.lower()

    def _populate_schedule_list(self):
        """Populate the left panel schedule list."""
        self.schedule_list.clear()
        for schedule in self._schedules_cache:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, schedule["id"])
            item.setSizeHint(ScheduleListItemWidget(schedule).sizeHint())

            widget = ScheduleListItemWidget(schedule)
            widget.toggle_clicked.connect(self._on_item_toggle)

            self.schedule_list.addItem(item)
            self.schedule_list.setItemWidget(item, widget)

    def _populate_calendar_table(self):
        """Populate the calendar overview table."""
        self.calendar_table.setRowCount(len(self._schedules_cache))

        for row, schedule in enumerate(self._schedules_cache):
            # Name
            name_item = QTableWidgetItem(schedule.get("name", ""))
            name_item.setData(Qt.ItemDataRole.UserRole, schedule["id"])
            self.calendar_table.setItem(row, 0, name_item)

            # Recurrence
            recurrence = schedule.get("recurrence_pattern", "")
            human = _cron_to_human_readable(recurrence)
            self.calendar_table.setItem(row, 1, QTableWidgetItem(human))

            # Next Execution
            next_exec = schedule.get("next_execution", "")
            if next_exec:
                try:
                    dt = datetime.fromisoformat(next_exec)
                    next_str = dt.strftime("%Y-%m-%d %H:%M")
                except (ValueError, TypeError):
                    next_str = next_exec
            else:
                next_str = "—"
            self.calendar_table.setItem(row, 2, QTableWidgetItem(next_str))

            # Status with color
            status = schedule.get("status", "")
            status_item = QTableWidgetItem(f"{_status_icon(status)} {status.capitalize()}")
            status_item.setForeground(
                Qt.GlobalColor.white  # fallback, styled via table
            )
            self.calendar_table.setItem(row, 3, status_item)

            # Failures
            failures = schedule.get("failure_count", 0)
            fail_item = QTableWidgetItem(str(failures))
            self.calendar_table.setItem(row, 4, fail_item)

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_filter_changed(self, _text: str):
        self._load_schedules()

    def _on_schedule_selected(self, row: int):
        if row < 0 or row >= len(self._schedules_cache):
            return
        schedule = self._schedules_cache[row]
        self._selected_schedule_id = schedule["id"]
        self._show_detail(schedule)

    def _on_new_schedule(self):
        """Switch to the creation form."""
        self._clear_creation_form()
        self.right_stack.setCurrentIndex(1)

    def _on_cancel_create(self):
        """Return to overview from creation form."""
        self.right_stack.setCurrentIndex(0)

    def _on_back_to_overview(self):
        """Return to overview from detail view."""
        self.right_stack.setCurrentIndex(0)

    def _on_calendar_row_clicked(self, row: int, _col: int):
        """Handle double-click on calendar table row."""
        if row < 0 or row >= len(self._schedules_cache):
            return
        schedule = self._schedules_cache[row]
        self._selected_schedule_id = schedule["id"]
        self._show_detail(schedule)

        # Also select in the list
        self.schedule_list.blockSignals(True)
        self.schedule_list.setCurrentRow(row)
        self.schedule_list.blockSignals(False)

    def _on_create_schedule(self):
        """Validate and create a new schedule."""
        name = self.name_input.text().strip()
        if not name:
            QMessageBox.warning(self, "Validation Error", "Schedule name is required.")
            return

        # Parse scan config JSON
        config_text = self.config_editor.toPlainText().strip()
        if not config_text:
            config_text = "{}"
        try:
            scan_config = json.loads(config_text)
        except json.JSONDecodeError as e:
            QMessageBox.warning(
                self, "Validation Error",
                f"Invalid JSON in scan configuration:\n{e}"
            )
            return

        # Parse targets
        targets_text = self.targets_editor.toPlainText().strip()
        if not targets_text:
            QMessageBox.warning(self, "Validation Error", "At least one target is required.")
            return
        target_list = [
            t.strip() for t in targets_text.splitlines() if t.strip()
        ]

        # Get recurrence pattern
        recurrence = self.cron_builder.get_pattern()

        # Optional engagement ID
        engagement_id = self.engagement_input.text().strip() or None

        # Create schedule via engine
        try:
            schedule_id = self.engine.create_schedule(
                name=name,
                scan_config=scan_config,
                target_list=target_list,
                recurrence=recurrence,
                engagement_id=engagement_id,
            )
        except ValueError as e:
            QMessageBox.warning(
                self, "Invalid Recurrence",
                f"Invalid recurrence pattern:\n{e}"
            )
            return
        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to create schedule:\n{e}"
            )
            return

        self.schedule_created.emit(schedule_id)
        self._load_schedules()
        self.right_stack.setCurrentIndex(0)

    def _on_item_toggle(self, schedule_id: str, enabled: bool):
        """Handle toggle from a list item widget."""
        self._toggle_schedule(schedule_id, enabled)

    def _on_toggle_schedule(self):
        """Handle enable/disable button in detail view."""
        if not self._selected_schedule_id:
            return
        schedule = self._get_selected_schedule()
        if not schedule:
            return

        enabled = schedule.get("status") != "active"
        self._toggle_schedule(self._selected_schedule_id, enabled)

    def _toggle_schedule(self, schedule_id: str, enable: bool):
        """Enable or disable a schedule."""
        try:
            if enable:
                self.engine.enable_schedule(schedule_id)
            else:
                self.engine.disable_schedule(schedule_id)
        except Exception as e:
            QMessageBox.critical(
                self, "Error",
                f"Failed to {'enable' if enable else 'disable'} schedule:\n{e}"
            )
            return

        self.schedule_toggled.emit(schedule_id, enable)
        self._load_schedules()

        # Refresh detail if viewing this schedule
        if self._selected_schedule_id == schedule_id:
            schedule = self._get_schedule_by_id(schedule_id)
            if schedule:
                self._show_detail(schedule)

    def _on_delete_schedule(self):
        """Delete the selected schedule."""
        if not self._selected_schedule_id:
            return

        schedule = self._get_selected_schedule()
        name = schedule.get("name", "this schedule") if schedule else "this schedule"

        reply = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to permanently delete '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            self.engine.delete_schedule(self._selected_schedule_id)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete schedule:\n{e}")
            return

        self.schedule_deleted.emit(self._selected_schedule_id)
        self._selected_schedule_id = None
        self._load_schedules()
        self.right_stack.setCurrentIndex(0)

    # ------------------------------------------------------------------
    # Engine Signal Handlers
    # ------------------------------------------------------------------

    def _on_scan_triggered(self, schedule_id: str):
        """Refresh when a scan is triggered."""
        self._load_schedules()

    def _on_scan_completed(self, schedule_id: str, results: dict):
        """Refresh when a scan completes."""
        self._load_schedules()

    def _on_scan_failed(self, schedule_id: str, error: str):
        """Refresh and update detail if viewing the failed schedule."""
        self._load_schedules()
        if self._selected_schedule_id == schedule_id:
            schedule = self._get_schedule_by_id(schedule_id)
            if schedule:
                self._show_detail(schedule)

    # ------------------------------------------------------------------
    # Detail View
    # ------------------------------------------------------------------

    def _show_detail(self, schedule: Dict):
        """Display schedule details in the detail page."""
        self.right_stack.setCurrentIndex(2)

        self.detail_name_label.setText(schedule.get("name", "Unnamed"))

        status = schedule.get("status", "")
        color = _status_color(status)
        self.detail_status_label.setText(
            f"{_status_icon(status)} {status.capitalize()}"
        )
        self.detail_status_label.setStyleSheet(f"color: {color}; font-size: 12px;")

        self.detail_id_label.setText(schedule.get("id", ""))

        recurrence = schedule.get("recurrence_pattern", "")
        human = _cron_to_human_readable(recurrence)
        self.detail_recurrence_label.setText(f"{recurrence}  ({human})")

        next_exec = schedule.get("next_execution", "")
        if next_exec:
            try:
                dt = datetime.fromisoformat(next_exec)
                next_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, TypeError):
                next_str = next_exec
        else:
            next_str = "—"
        self.detail_next_exec_label.setText(next_str)

        last_exec = schedule.get("last_execution", "")
        if last_exec:
            try:
                dt = datetime.fromisoformat(last_exec)
                last_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, TypeError):
                last_str = last_exec
        else:
            last_str = "Never"
        self.detail_last_exec_label.setText(last_str)

        targets = schedule.get("target_list", [])
        if isinstance(targets, list):
            targets_str = ", ".join(targets[:10])
            if len(targets) > 10:
                targets_str += f" (+{len(targets) - 10} more)"
        else:
            targets_str = str(targets)
        self.detail_targets_label.setText(targets_str)

        self.detail_engagement_label.setText(
            schedule.get("engagement_id") or "None"
        )

        created = schedule.get("created_at", "")
        if created:
            try:
                dt = datetime.fromisoformat(created)
                created_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                created_str = created
        else:
            created_str = "—"
        self.detail_created_label.setText(created_str)

        # Scan config
        config = schedule.get("scan_config", {})
        config_str = json.dumps(config, indent=2) if config else "{}"
        self.detail_config_view.setPlainText(config_str)

        # Failure log
        failure_count = schedule.get("failure_count", 0)
        last_failure = schedule.get("last_failure_reason", "")
        if failure_count > 0 and last_failure:
            fail_text = (
                f"Total failures: {failure_count}\n"
                f"Last failure reason:\n  {last_failure}"
            )
        elif failure_count > 0:
            fail_text = f"Total failures: {failure_count}\nNo failure details available."
        else:
            fail_text = ""
        self.failure_log_view.setPlainText(fail_text)

        # Update enable/disable button text
        if status == "active":
            self.enable_disable_btn.setText("Disable")
            self.enable_disable_btn.setEnabled(True)
        elif status == "disabled":
            self.enable_disable_btn.setText("Enable")
            self.enable_disable_btn.setEnabled(True)
        else:
            self.enable_disable_btn.setText("—")
            self.enable_disable_btn.setEnabled(False)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _clear_creation_form(self):
        """Reset the creation form fields."""
        self.name_input.clear()
        self.config_editor.clear()
        self.targets_editor.clear()
        self.engagement_input.clear()
        self.cron_builder.recurrence_combo.setCurrentIndex(0)

    def _get_selected_schedule(self) -> Optional[Dict]:
        """Get the currently selected schedule dict."""
        if not self._selected_schedule_id:
            return None
        return self._get_schedule_by_id(self._selected_schedule_id)

    def _get_schedule_by_id(self, schedule_id: str) -> Optional[Dict]:
        """Find a schedule in cache by ID."""
        for s in self._schedules_cache:
            if s["id"] == schedule_id:
                return s
        # Fallback: fetch directly from engine
        try:
            return self.engine.get_schedule(schedule_id)
        except Exception:
            return None
