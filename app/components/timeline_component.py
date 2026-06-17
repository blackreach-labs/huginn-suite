# app/components/timeline_component.py
"""Engagement Timeline UI Component.

Provides a chronological scrollable timeline view of all engagement activity
with filtering, manual entry creation, and detail popovers. Integrates as
a new tab within the Engagement Setup page.

- Chronological scrollable timeline with icons per action type
- Filter toolbar (date range picker, action type dropdown, actor filter)
- Manual entry creation form
- Timeline entry detail popover on click

Requirements: 8.3, 8.4, 8.6
"""

from datetime import datetime
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal, QPoint
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QDateEdit,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from app.core.timeline_logger import TimelineLogger, VALID_ACTION_TYPES


# Icons for each action type
ACTION_TYPE_ICONS: Dict[str, str] = {
    "scan_start": "🔍",
    "scan_complete": "✅",
    "finding_discovered": "🐛",
    "exploit_attempt": "🎯",
    "state_transition": "🔄",
    "evidence_captured": "📷",
    "note_added": "📝",
    "finding_modified": "✏️",
    "manual": "💬",
}

# Human-readable labels for action types
ACTION_TYPE_LABELS: Dict[str, str] = {
    "scan_start": "Scan Start",
    "scan_complete": "Scan Complete",
    "finding_discovered": "Finding Discovered",
    "exploit_attempt": "Exploit Attempt",
    "state_transition": "State Transition",
    "evidence_captured": "Evidence Captured",
    "note_added": "Note Added",
    "finding_modified": "Finding Modified",
    "manual": "Manual Entry",
}


class TimelineComponent(QWidget):
    """Timeline view component for engagement activity logging.

    Displays a chronological list of all recorded timeline events with
    filtering controls and manual entry creation.

    Signals:
        entry_selected(dict): Emitted when a timeline entry is clicked,
            containing the full entry dict.
    """

    entry_selected = pyqtSignal(dict)

    def __init__(self, timeline_logger: TimelineLogger, parent=None):
        """Initialize the TimelineComponent.

        Args:
            timeline_logger: The TimelineLogger instance to query and add entries.
            parent: Optional QWidget parent.
        """
        super().__init__(parent)
        self._logger = timeline_logger
        self._entries: List[Dict] = []

        self._setup_ui()
        self._apply_theme()
        self._connect_signals()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the timeline layout with filter toolbar, list, and entry form."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Section title
        title = QLabel("Activity Timeline")
        title.setObjectName("sectionLabel")
        layout.addWidget(title)

        # Filter toolbar
        layout.addWidget(self._create_filter_toolbar())

        # Timeline list view
        self.timeline_list = QListWidget()
        self.timeline_list.setSpacing(2)
        self.timeline_list.setWordWrap(True)
        self.timeline_list.setAlternatingRowColors(False)
        self.timeline_list.itemClicked.connect(self._on_entry_clicked)
        layout.addWidget(self.timeline_list, 1)

        # Manual entry form
        layout.addWidget(self._create_manual_entry_form())

    def _create_filter_toolbar(self) -> QFrame:
        """Create the filter toolbar with date range, action type, and actor filters."""
        toolbar = QFrame()
        toolbar.setObjectName("filterToolbar")
        h_layout = QHBoxLayout(toolbar)
        h_layout.setContentsMargins(8, 6, 8, 6)
        h_layout.setSpacing(10)

        # Date From
        from_label = QLabel("From:")
        h_layout.addWidget(from_label)

        self.date_from_input = QDateEdit()
        self.date_from_input.setCalendarPopup(True)
        self.date_from_input.setDisplayFormat("yyyy-MM-dd")
        # Default to 30 days ago
        from datetime import timedelta
        default_from = datetime.now().date() - timedelta(days=30)
        self.date_from_input.setDate(default_from)
        self.date_from_input.setFixedWidth(130)
        h_layout.addWidget(self.date_from_input)

        # Date To
        to_label = QLabel("To:")
        h_layout.addWidget(to_label)

        self.date_to_input = QDateEdit()
        self.date_to_input.setCalendarPopup(True)
        self.date_to_input.setDisplayFormat("yyyy-MM-dd")
        self.date_to_input.setDate(datetime.now().date())
        self.date_to_input.setFixedWidth(130)
        h_layout.addWidget(self.date_to_input)

        # Action Type filter
        type_label = QLabel("Type:")
        h_layout.addWidget(type_label)

        self.action_type_combo = QComboBox()
        self.action_type_combo.addItem("All", "")
        for action_type in sorted(VALID_ACTION_TYPES):
            icon = ACTION_TYPE_ICONS.get(action_type, "")
            label = ACTION_TYPE_LABELS.get(action_type, action_type)
            self.action_type_combo.addItem(f"{icon} {label}", action_type)
        self.action_type_combo.setFixedWidth(180)
        h_layout.addWidget(self.action_type_combo)

        # Actor filter
        actor_label = QLabel("Actor:")
        h_layout.addWidget(actor_label)

        self.actor_filter_input = QLineEdit()
        self.actor_filter_input.setPlaceholderText("Filter by actor...")
        self.actor_filter_input.setFixedWidth(150)
        h_layout.addWidget(self.actor_filter_input)

        # Apply filter button
        self.apply_filter_btn = QPushButton("Apply")
        self.apply_filter_btn.setFixedWidth(80)
        self.apply_filter_btn.setMinimumHeight(30)
        self.apply_filter_btn.clicked.connect(self.refresh_timeline)
        h_layout.addWidget(self.apply_filter_btn)

        # Refresh button (clear filters)
        self.clear_filter_btn = QPushButton("Clear")
        self.clear_filter_btn.setFixedWidth(70)
        self.clear_filter_btn.setMinimumHeight(30)
        self.clear_filter_btn.clicked.connect(self._clear_filters)
        h_layout.addWidget(self.clear_filter_btn)

        h_layout.addStretch()
        return toolbar

    def _create_manual_entry_form(self) -> QFrame:
        """Create the manual entry form for adding custom timeline entries."""
        form_frame = QFrame()
        form_frame.setObjectName("manualEntryFrame")
        v_layout = QVBoxLayout(form_frame)
        v_layout.setContentsMargins(8, 6, 8, 6)
        v_layout.setSpacing(6)

        form_label = QLabel("Add Manual Entry")
        form_label.setObjectName("sectionLabel")
        v_layout.addWidget(form_label)

        # Description text area and button row
        h_layout = QHBoxLayout()
        h_layout.setSpacing(8)

        self.manual_entry_input = QTextEdit()
        self.manual_entry_input.setPlaceholderText(
            "Enter a manual timeline note..."
        )
        self.manual_entry_input.setMaximumHeight(60)
        h_layout.addWidget(self.manual_entry_input, 1)

        self.add_entry_btn = QPushButton("Add Entry")
        self.add_entry_btn.setMinimumHeight(50)
        self.add_entry_btn.setFixedWidth(100)
        self.add_entry_btn.clicked.connect(self._on_add_manual_entry)
        h_layout.addWidget(self.add_entry_btn)

        v_layout.addLayout(h_layout)
        return form_frame

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect to TimelineLogger signals for live updates."""
        self._logger.event_logged.connect(self._on_event_logged)

    def _on_event_logged(self, entry: dict):
        """Handle new event from the logger — refresh the list."""
        self.refresh_timeline()

    # ------------------------------------------------------------------
    # Timeline Data Loading
    # ------------------------------------------------------------------

    def refresh_timeline(self):
        """Reload timeline entries from the logger with current filter settings."""
        self.timeline_list.clear()
        self._entries = []

        # Gather filter values
        date_from = self.date_from_input.date().toString("yyyy-MM-dd") + "T00:00:00"
        date_to = self.date_to_input.date().toString("yyyy-MM-dd") + "T23:59:59"

        action_type_filter = self.action_type_combo.currentData() or None
        actor_filter = self.actor_filter_input.text().strip() or None

        try:
            entries = self._logger.get_timeline(
                date_from=date_from,
                date_to=date_to,
                action_type=action_type_filter if action_type_filter else None,
                actor=actor_filter,
            )
        except (RuntimeError, ValueError):
            # No database set or invalid filter
            entries = []

        self._entries = entries

        # Populate list in reverse chronological order (newest first)
        for entry in reversed(entries):
            self._add_timeline_item(entry)

    def _add_timeline_item(self, entry: Dict):
        """Add a single timeline entry to the list widget."""
        action_type = entry.get("action_type", "manual")
        icon = ACTION_TYPE_ICONS.get(action_type, "💬")
        timestamp = entry.get("timestamp", "")
        description = entry.get("description", "")
        actor = entry.get("actor", "")

        # Format timestamp for display
        display_time = self._format_timestamp(timestamp)

        # Build display text
        actor_str = f" [{actor}]" if actor else ""
        label_text = f"{icon}  {display_time}{actor_str} — {description}"

        item = QListWidgetItem(label_text)
        item.setData(Qt.ItemDataRole.UserRole, entry)

        # Style based on action type
        font = QFont("Segoe UI", 9)
        item.setFont(font)

        self.timeline_list.addItem(item)

    def _format_timestamp(self, timestamp: str) -> str:
        """Format an ISO timestamp for display."""
        if not timestamp:
            return ""
        try:
            # Handle various ISO formats
            if "T" in timestamp:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return timestamp[:19] if len(timestamp) >= 19 else timestamp

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_entry_clicked(self, item: QListWidgetItem):
        """Show a detail popover when a timeline entry is clicked."""
        entry = item.data(Qt.ItemDataRole.UserRole)
        if not entry:
            return

        self.entry_selected.emit(entry)
        self._show_entry_detail(entry, item)

    def _show_entry_detail(self, entry: Dict, item: QListWidgetItem):
        """Display a tooltip-style detail popover for the clicked entry."""
        action_type = entry.get("action_type", "unknown")
        icon = ACTION_TYPE_ICONS.get(action_type, "💬")
        label = ACTION_TYPE_LABELS.get(action_type, action_type)
        timestamp = self._format_timestamp(entry.get("timestamp", ""))
        actor = entry.get("actor", "N/A")
        description = entry.get("description", "")
        entity_type = entry.get("affected_entity_type", "")
        entity_id = entry.get("affected_entity_id", "")
        metadata = entry.get("metadata", {})

        # Build rich detail text
        detail_lines = [
            f"<b>{icon} {label}</b>",
            f"<br/><b>Time:</b> {timestamp}",
            f"<br/><b>Actor:</b> {actor}",
            f"<br/><b>Description:</b> {description}",
        ]

        if entity_type:
            detail_lines.append(f"<br/><b>Entity Type:</b> {entity_type}")
        if entity_id:
            detail_lines.append(f"<br/><b>Entity ID:</b> {entity_id}")
        if metadata:
            meta_str = ", ".join(f"{k}: {v}" for k, v in metadata.items())
            detail_lines.append(f"<br/><b>Metadata:</b> {meta_str}")

        detail_html = "".join(detail_lines)

        # Show as QToolTip at the item's position
        item_rect = self.timeline_list.visualItemRect(item)
        global_pos = self.timeline_list.mapToGlobal(
            QPoint(item_rect.right(), item_rect.center().y())
        )
        QToolTip.showText(global_pos, detail_html, self.timeline_list)

    def _on_add_manual_entry(self):
        """Handle adding a manual timeline entry."""
        description = self.manual_entry_input.toPlainText().strip()
        if not description:
            return

        try:
            self._logger.add_manual_entry(
                description=description,
                actor="user",
            )
            self.manual_entry_input.clear()
            # Timeline will refresh via event_logged signal
        except RuntimeError:
            # No database set — show inline feedback
            pass

    def _clear_filters(self):
        """Reset all filters to defaults and refresh."""
        from datetime import timedelta
        self.date_from_input.setDate(
            datetime.now().date() - timedelta(days=30)
        )
        self.date_to_input.setDate(datetime.now().date())
        self.action_type_combo.setCurrentIndex(0)
        self.actor_filter_input.clear()
        self.refresh_timeline()

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
            QFrame#filterToolbar, QFrame#manualEntryFrame {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 8px;
                border: 1px solid rgba(100, 200, 255, 50);
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
            QListWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 9pt;
            }
            QListWidget::item {
                padding: 6px 8px;
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
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 6px;
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
        """)
