# app/components/notes_panel_component.py
"""Notes Panel UI Component.

Provides a floating/dockable notes panel accessible from all pages with:
- Note creation form with markdown editor and preview
- Note list with scope indicators (target/service/vulnerability)
- Revision history viewer
- Full-text search bar with results highlighting
- Pin/unpin toggle on note items
- Scope selector (scope_type and scope_id combo boxes)

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7
"""

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon, QTextCharFormat
from PyQt6.QtWidgets import (
    QComboBox,
    QDockWidget,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.note_system import NoteSystem


# Scope badge colors
SCOPE_COLORS = {
    "target": "#4A9EFF",          # Blue
    "service": "#00D68F",         # Green
    "vulnerability": "#FF5252",   # Red
}

SCOPE_LABELS = {
    "target": "TGT",
    "service": "SVC",
    "vulnerability": "VLN",
}


class NoteListItemWidget(QWidget):
    """Custom widget for a note list item with scope badge and pin toggle."""

    pin_toggled = pyqtSignal(int, bool)  # note_id, pinned

    def __init__(self, note: dict, parent=None):
        super().__init__(parent)
        self.note_id = note["id"]
        self.pinned = note["pinned"]
        self._setup_ui(note)

    def _setup_ui(self, note: dict):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(6)

        # Pin button
        self.pin_btn = QPushButton("★" if self.pinned else "☆")
        self.pin_btn.setFixedSize(24, 24)
        self.pin_btn.setToolTip("Unpin note" if self.pinned else "Pin note")
        self.pin_btn.setStyleSheet(self._pin_style())
        self.pin_btn.clicked.connect(self._on_pin_clicked)
        layout.addWidget(self.pin_btn)

        # Scope badge
        scope_type = note["scope_type"]
        badge_color = SCOPE_COLORS.get(scope_type, "#888888")
        badge_text = SCOPE_LABELS.get(scope_type, "???")

        self.scope_badge = QLabel(badge_text)
        self.scope_badge.setFixedWidth(36)
        self.scope_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.scope_badge.setStyleSheet(
            f"background-color: {badge_color}; color: #FFFFFF; "
            f"border-radius: 3px; font-size: 10px; font-weight: bold; "
            f"padding: 2px 4px; font-family: 'Neuropol X';"
        )
        layout.addWidget(self.scope_badge)

        # Content preview and metadata
        info_layout = QVBoxLayout()
        info_layout.setSpacing(1)
        info_layout.setContentsMargins(0, 0, 0, 0)

        # Truncated content preview
        content_preview = note["content"][:80].replace("\n", " ")
        if len(note["content"]) > 80:
            content_preview += "…"

        self.content_label = QLabel(content_preview)
        self.content_label.setStyleSheet("color: #E0E0E0; font-size: 12px; font-family: 'Neuropol X';")
        info_layout.addWidget(self.content_label)

        # Timestamp and scope info
        meta_text = f"{scope_type}:{note['scope_id']} • {note['created_at'][:16]}"
        self.meta_label = QLabel(meta_text)
        self.meta_label.setStyleSheet("color: #808080; font-size: 10px; font-family: 'Neuropol X';")
        info_layout.addWidget(self.meta_label)

        layout.addLayout(info_layout, 1)

    def _pin_style(self) -> str:
        if self.pinned:
            return (
                "QPushButton { background: transparent; color: #FFD700; "
                "border: none; font-size: 16px; } "
                "QPushButton:hover { color: #FFF8DC; }"
            )
        return (
            "QPushButton { background: transparent; color: #666666; "
            "border: none; font-size: 16px; } "
            "QPushButton:hover { color: #FFD700; }"
        )

    def _on_pin_clicked(self):
        self.pinned = not self.pinned
        self.pin_btn.setText("★" if self.pinned else "☆")
        self.pin_btn.setToolTip("Unpin note" if self.pinned else "Pin note")
        self.pin_btn.setStyleSheet(self._pin_style())
        self.pin_toggled.emit(self.note_id, self.pinned)


class NotesPanelComponent(QWidget):
    """Floating/dockable notes panel for all pages.

    Provides note creation, editing, search, revision history, and
    scope-based filtering with pin/unpin capabilities.

    Signals:
        note_selected(int): Emitted when a note is selected from the list.
    """

    note_selected = pyqtSignal(int)

    def __init__(self, note_system: NoteSystem, parent=None):
        super().__init__(parent)
        self.note_system = note_system
        self._current_note_id: Optional[int] = None
        self._editing = False
        self._scope_id = 1

        self._setup_ui()
        self._apply_theme()
        self._connect_signals()

    def showEvent(self, event):
        """Reload notes for the current scope each time the panel is shown."""
        super().showEvent(event)
        self._load_notes_for_current_scope(silent=True)

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the panel layout."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        # Header
        header_layout = QHBoxLayout()
        header_layout.addStretch()

        self.new_note_btn = QPushButton("+ New Note")
        self.new_note_btn.setMinimumHeight(28)
        self.new_note_btn.setToolTip("Create a new note")
        header_layout.addWidget(self.new_note_btn)

        main_layout.addLayout(header_layout)

        # Search bar
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search notes (full-text)...")
        self.search_input.setClearButtonEnabled(True)
        search_layout.addWidget(self.search_input)

        self.search_btn = QPushButton("Search")
        self.search_btn.setMinimumHeight(28)
        search_layout.addWidget(self.search_btn)

        self.clear_search_btn = QPushButton("Clear")
        self.clear_search_btn.setMinimumHeight(28)
        search_layout.addWidget(self.clear_search_btn)

        main_layout.addLayout(search_layout)

        # Scope selector
        scope_frame = QFrame()
        scope_frame.setObjectName("scopeFrame")
        scope_layout = QHBoxLayout(scope_frame)
        scope_layout.setContentsMargins(4, 4, 4, 4)

        scope_layout.addWidget(QLabel("Scope:"))
        self.scope_type_combo = QComboBox()
        self.scope_type_combo.addItems(["target", "service", "vulnerability"])
        scope_layout.addWidget(self.scope_type_combo)

        scope_layout.addStretch()
        main_layout.addWidget(scope_frame)

        # Splitter: Note list (top) / Editor+Preview (bottom)
        self.splitter = QSplitter(Qt.Orientation.Vertical)

        # Note list
        self.note_list = QListWidget()
        self.note_list.setMinimumHeight(120)
        self.splitter.addWidget(self.note_list)

        # Bottom panel: revision history + create form
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(4)

        # Editor toolbar (shown when a note is selected)
        editor_toolbar = QHBoxLayout()
        self.edit_btn = QPushButton("Edit")
        self.edit_btn.setMinimumHeight(28)
        self.edit_btn.setEnabled(False)
        editor_toolbar.addWidget(self.edit_btn)

        self.save_btn = QPushButton("Save")
        self.save_btn.setMinimumHeight(28)
        self.save_btn.setEnabled(False)
        self.save_btn.setVisible(False)
        editor_toolbar.addWidget(self.save_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(28)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setVisible(False)
        editor_toolbar.addWidget(self.cancel_btn)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setMinimumHeight(28)
        self.delete_btn.setEnabled(False)
        self.delete_btn.setStyleSheet(
            "QPushButton { color: #FF5252; } "
            "QPushButton:hover { background-color: #FF5252; color: #FFFFFF; }"
        )
        editor_toolbar.addWidget(self.delete_btn)

        self.history_btn = QPushButton("History")
        self.history_btn.setMinimumHeight(28)
        self.history_btn.setEnabled(False)
        self.history_btn.setToolTip("View revision history")
        editor_toolbar.addWidget(self.history_btn)

        editor_toolbar.addStretch()
        bottom_layout.addLayout(editor_toolbar)

        # Note content viewer (read-only, shown when a note is selected)
        self.content_viewer = QTextEdit()
        self.content_viewer.setReadOnly(True)
        self.content_viewer.setPlaceholderText("Select a note to view its contents...")
        self.content_viewer.setMinimumHeight(80)
        bottom_layout.addWidget(self.content_viewer)

        # Revision history panel (hidden by default)
        self.revision_frame = QFrame()
        self.revision_frame.setObjectName("revisionFrame")
        self.revision_frame.setVisible(False)
        revision_layout = QVBoxLayout(self.revision_frame)
        revision_layout.setContentsMargins(6, 6, 6, 6)
        revision_layout.setSpacing(4)

        rev_header = QHBoxLayout()
        rev_title = QLabel("Revision History")
        rev_title.setStyleSheet("font-weight: bold; color: #00E5FF; font-family: 'Neuropol X';")
        rev_header.addWidget(rev_title)
        rev_header.addStretch()
        self.close_history_btn = QPushButton("✕")
        self.close_history_btn.setFixedSize(24, 24)
        self.close_history_btn.setToolTip("Close history")
        rev_header.addWidget(self.close_history_btn)
        revision_layout.addLayout(rev_header)

        self.revision_list = QListWidget()
        self.revision_list.setMinimumHeight(60)
        revision_layout.addWidget(self.revision_list, 1)

        self.revision_content = QTextEdit()
        self.revision_content.setReadOnly(True)
        self.revision_content.setMinimumHeight(80)
        self.revision_content.setPlaceholderText("Select a revision to view...")
        revision_layout.addWidget(self.revision_content, 2)

        bottom_layout.addWidget(self.revision_frame)

        # Note creation form (hidden by default)
        self.create_frame = QFrame()
        self.create_frame.setObjectName("createFrame")
        self.create_frame.setVisible(False)
        create_layout = QVBoxLayout(self.create_frame)
        create_layout.setContentsMargins(4, 4, 4, 4)

        create_header = QLabel("Create New Note")
        create_header.setStyleSheet("font-weight: bold; color: #00E5FF; font-family: 'Neuropol X';")
        create_layout.addWidget(create_header)

        create_form = QFormLayout()
        self.create_scope_type = QComboBox()
        self.create_scope_type.addItems(["target", "service", "vulnerability"])
        create_form.addRow("Scope Type:", self.create_scope_type)

        self.create_author = QLineEdit()
        self.create_author.setPlaceholderText("Author (optional)")
        create_form.addRow("Author:", self.create_author)

        create_layout.addLayout(create_form)

        self.create_content = QTextEdit()
        self.create_content.setPlaceholderText(
            "Note content (Markdown supported)..."
        )
        self.create_content.setMinimumHeight(80)
        create_layout.addWidget(self.create_content)

        create_btn_layout = QHBoxLayout()
        self.submit_create_btn = QPushButton("Create Note")
        self.submit_create_btn.setMinimumHeight(30)
        create_btn_layout.addWidget(self.submit_create_btn)

        self.cancel_create_btn = QPushButton("Cancel")
        self.cancel_create_btn.setMinimumHeight(30)
        create_btn_layout.addWidget(self.cancel_create_btn)

        create_btn_layout.addStretch()
        create_layout.addLayout(create_btn_layout)

        bottom_layout.addWidget(self.create_frame)

        self.splitter.addWidget(bottom_widget)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 2)

        main_layout.addWidget(self.splitter, 1)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect UI signals to handlers."""
        # Search
        self.search_btn.clicked.connect(self._on_search)
        self.search_input.returnPressed.connect(self._on_search)
        self.clear_search_btn.clicked.connect(self._on_clear_search)

        # Scope loading — auto-load when dropdown changes
        self.scope_type_combo.currentTextChanged.connect(self._on_scope_changed)

        # Note list
        self.note_list.currentRowChanged.connect(self._on_note_selected)

        # Editor controls
        self.new_note_btn.clicked.connect(self._on_new_note)
        self.edit_btn.clicked.connect(self._on_edit)
        self.save_btn.clicked.connect(self._on_save)
        self.cancel_btn.clicked.connect(self._on_cancel_edit)
        self.delete_btn.clicked.connect(self._on_delete)

        # History
        self.history_btn.clicked.connect(self._on_show_history)
        self.close_history_btn.clicked.connect(self._on_close_history)
        self.revision_list.currentRowChanged.connect(self._on_revision_selected)

        # Create form
        self.submit_create_btn.clicked.connect(self._on_submit_create)
        self.cancel_create_btn.clicked.connect(self._on_cancel_create)

        # NoteSystem signals
        self.note_system.note_created.connect(self._on_note_system_changed)
        self.note_system.note_edited.connect(self._on_note_system_changed)
        self.note_system.note_pinned.connect(self._on_note_system_pin_changed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_scope(self, scope_type: str, scope_id: int) -> None:
        """Set the current scope and load notes.

        Args:
            scope_type: One of 'target', 'service', 'vulnerability'.
            scope_id: The entity ID (used internally).
        """
        idx = self.scope_type_combo.findText(scope_type)
        if idx >= 0:
            self.scope_type_combo.setCurrentIndex(idx)
        self._scope_id = scope_id
        self._load_notes_for_current_scope()

    def refresh(self) -> None:
        """Refresh the note list for the current scope."""
        self._load_notes_for_current_scope()

    # ------------------------------------------------------------------
    # Handlers: Search
    # ------------------------------------------------------------------

    def _on_search(self):
        """Handle search button click or Enter press in search bar."""
        query = self.search_input.text().strip()
        if not query:
            return

        try:
            results = self.note_system.search_notes(query)
            self._populate_note_list(results, highlight_query=query)
        except Exception as e:
            self._show_error(f"Search failed: {e}")

    def _on_clear_search(self):
        """Clear search and reload scope notes."""
        self.search_input.clear()
        self._load_notes_for_current_scope()

    # ------------------------------------------------------------------
    # Handlers: Scope
    # ------------------------------------------------------------------

    def _on_scope_changed(self, _text: str = ""):
        """Auto-load notes when scope dropdown changes."""
        self._load_notes_for_current_scope()

    def _load_notes_for_current_scope(self, silent: bool = False):
        """Load notes from NoteSystem for the current scope selector values.

        Args:
            silent: If True, suppress error dialogs (used during init).
        """
        scope_type = self.scope_type_combo.currentText()
        scope_id = getattr(self, "_scope_id", 1)

        try:
            notes = self.note_system.get_notes_for_scope(scope_type, scope_id)
            self._populate_note_list(notes)
        except Exception as e:
            if not silent:
                self._show_error(f"Failed to load notes: {e}")

    # ------------------------------------------------------------------
    # Handlers: Note Selection
    # ------------------------------------------------------------------

    def _on_note_selected(self, row: int):
        """Handle note selection in the list."""
        if row < 0:
            self._current_note_id = None
            self.content_viewer.clear()
            self._set_editor_controls(False)
            return

        item = self.note_list.item(row)
        if item is None:
            return

        note_id = item.data(Qt.ItemDataRole.UserRole)
        if note_id is None:
            return

        self._current_note_id = note_id
        self._set_editor_controls(True)

        # Load and display note content
        try:
            note = self.note_system.get_note(note_id)
            if note:
                self.content_viewer.setPlainText(note["content"])
        except Exception as e:
            self.content_viewer.setPlainText(f"(Error loading note: {e})")

        self.note_selected.emit(note_id)



    # ------------------------------------------------------------------
    # Handlers: Editor Controls
    # ------------------------------------------------------------------

    def _on_edit(self):
        """Enter edit mode for the current note — open content in create form for editing."""
        if self._current_note_id is None:
            return
        try:
            note = self.note_system.get_note(self._current_note_id)
            if note:
                self._editing = True
                self.create_content.setPlainText(note["content"])
                idx = self.create_scope_type.findText(note["scope_type"])
                if idx >= 0:
                    self.create_scope_type.setCurrentIndex(idx)
                self.create_frame.setVisible(True)
                self.create_content.setFocus()
                # Change button text to indicate save-edit mode
                self.submit_create_btn.setText("Save Changes")
        except Exception as e:
            self._show_error(f"Failed to load note for editing: {e}")

    def _on_save(self):
        """Save edited note content (delegates to the create form submit)."""
        self._on_submit_create()

    def _on_cancel_edit(self):
        """Cancel editing."""
        self._editing = False
        self.create_frame.setVisible(False)
        self.submit_create_btn.setText("Create Note")

    def _on_delete(self):
        """Delete the selected note."""
        if self._current_note_id is None:
            return

        reply = QMessageBox.question(
            self,
            "Delete Note",
            "Are you sure you want to delete this note and all its revisions?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.note_system.delete_note(self._current_note_id)
                self._current_note_id = None
                self._set_editor_controls(False)
                self._load_notes_for_current_scope()
            except Exception as e:
                self._show_error(f"Failed to delete note: {e}")

    # ------------------------------------------------------------------
    # Handlers: Note Creation
    # ------------------------------------------------------------------

    def _on_new_note(self):
        """Show the note creation form."""
        # Pre-fill scope from current selector
        scope_type = self.scope_type_combo.currentText()

        idx = self.create_scope_type.findText(scope_type)
        if idx >= 0:
            self.create_scope_type.setCurrentIndex(idx)
        self._editing = False
        self._current_note_id = None
        self.submit_create_btn.setText("Create Note")
        self.create_content.clear()
        self.create_frame.setVisible(True)
        self.create_content.setFocus()

    def _on_submit_create(self):
        """Submit the new note creation form, or save edits to existing note."""
        scope_type = self.create_scope_type.currentText()
        content = self.create_content.toPlainText().strip()
        author = self.create_author.text().strip() or None

        if not content:
            self._show_error("Note content cannot be empty.")
            return

        scope_id = getattr(self, "_scope_id", 1)

        try:
            if self._editing and self._current_note_id is not None:
                # Editing an existing note
                self.note_system.edit_note(self._current_note_id, content)
                self._editing = False
            else:
                # Creating a new note
                self.note_system.create_note(
                    scope_type=scope_type,
                    scope_id=scope_id,
                    content=content,
                    author=author,
                )
            self.create_frame.setVisible(False)
            self.submit_create_btn.setText("Create Note")
            # Sync scope selector and reload
            self.scope_type_combo.setCurrentText(scope_type)
            self._load_notes_for_current_scope()
        except Exception as e:
            self._show_error(f"Failed to save note: {e}")

    def _on_cancel_create(self):
        """Hide the note creation form."""
        self._editing = False
        self.submit_create_btn.setText("Create Note")
        self.create_frame.setVisible(False)

    # ------------------------------------------------------------------
    # Handlers: Pin Toggle
    # ------------------------------------------------------------------

    def _on_pin_toggled(self, note_id: int, pinned: bool):
        """Handle pin/unpin toggle from a note list item."""
        try:
            if pinned:
                self.note_system.pin_note(note_id)
            else:
                self.note_system.unpin_note(note_id)
        except Exception as e:
            self._show_error(f"Failed to toggle pin: {e}")

    # ------------------------------------------------------------------
    # Handlers: Revision History
    # ------------------------------------------------------------------

    def _on_show_history(self):
        """Show revision history for the current note."""
        if self._current_note_id is None:
            return

        try:
            revisions = self.note_system.get_revisions(self._current_note_id)
            self.revision_list.clear()
            self.revision_content.clear()

            if not revisions:
                self.revision_content.setPlainText("No revisions found.")
            else:
                for rev in revisions:
                    item = QListWidgetItem(f"Rev #{rev['id']} — {rev['revised_at'][:16]}")
                    item.setData(Qt.ItemDataRole.UserRole, rev["id"])
                    # Store content in a secondary role
                    item.setData(Qt.ItemDataRole.UserRole + 1, rev["content"])
                    self.revision_list.addItem(item)

            self.content_viewer.setVisible(False)
            self.revision_frame.setVisible(True)
        except Exception as e:
            self._show_error(f"Failed to load revisions: {e}")

    def _on_close_history(self):
        """Hide the revision history panel."""
        self.revision_frame.setVisible(False)
        self.content_viewer.setVisible(True)

    def _on_revision_selected(self, row: int):
        """Show the content of a selected revision."""
        if row < 0:
            self.revision_content.clear()
            return

        item = self.revision_list.item(row)
        if item:
            content = item.data(Qt.ItemDataRole.UserRole + 1)
            self.revision_content.setPlainText(content or "")

    # ------------------------------------------------------------------
    # Handlers: NoteSystem Signals
    # ------------------------------------------------------------------

    def _on_note_system_changed(self, note_id: int):
        """Handle note creation/edit signals from the system."""
        # Refresh if we're viewing the relevant scope
        self._load_notes_for_current_scope()

    def _on_note_system_pin_changed(self, note_id: int, pinned: bool):
        """Handle pin state change from the system."""
        self._load_notes_for_current_scope()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _populate_note_list(self, notes: list, highlight_query: str = ""):
        """Populate the note list widget with note items.

        Args:
            notes: List of note dicts from NoteSystem.
            highlight_query: Optional search query to highlight in previews.
        """
        self.note_list.clear()
        self._current_note_id = None
        self.content_viewer.clear()
        self._set_editor_controls(False)

        for note in notes:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, note["id"])
            item.setSizeHint(
                NoteListItemWidget(note).sizeHint()
            )

            widget = NoteListItemWidget(note)
            widget.pin_toggled.connect(self._on_pin_toggled)

            # Highlight search terms in content preview
            if highlight_query:
                label = widget.content_label
                text = label.text()
                lower_text = text.lower()
                lower_query = highlight_query.lower()
                if lower_query in lower_text:
                    idx = lower_text.index(lower_query)
                    highlighted = (
                        text[:idx]
                        + f'<span style="background-color: #FFD700; color: #000000;">'
                        + text[idx : idx + len(highlight_query)]
                        + "</span>"
                        + text[idx + len(highlight_query) :]
                    )
                    label.setText(highlighted)
                    label.setTextFormat(Qt.TextFormat.RichText)

            self.note_list.addItem(item)
            self.note_list.setItemWidget(item, widget)

    def _set_editor_controls(self, enabled: bool):
        """Enable/disable editor control buttons."""
        self.edit_btn.setEnabled(enabled)
        self.delete_btn.setEnabled(enabled)
        self.history_btn.setEnabled(enabled)
        self.save_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)

    def _show_error(self, message: str):
        """Show an error message dialog.

        If the error is due to no database being attached, show a friendly
        prompt asking the user to select an engagement first.
        """
        if "No database attached" in message or "set_database()" in message:
            QMessageBox.information(
                self,
                "Notes Panel",
                "No engagement is currently open.\n\n"
                "Please select and open an engagement before using Notes.",
            )
        else:
            QMessageBox.warning(self, "Notes Panel", message)


class NotesDockWidget(QDockWidget):
    """Dockable wrapper for the NotesPanelComponent.

    Provides a floating/dockable side panel that can be toggled
    from any page in the application.
    """

    def __init__(self, note_system: NoteSystem, parent=None):
        super().__init__("Notes", parent)
        self.setObjectName("notesDockWidget")

        # Configure docking behavior
        self.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea
            | Qt.DockWidgetArea.RightDockWidgetArea
        )
        self.setFeatures(
            QDockWidget.DockWidgetFeature.DockWidgetMovable
            | QDockWidget.DockWidgetFeature.DockWidgetFloatable
            | QDockWidget.DockWidgetFeature.DockWidgetClosable
        )

        # Set the panel as the dock widget content
        self.notes_panel = NotesPanelComponent(note_system)
        self.setWidget(self.notes_panel)

        # Minimum size for usability
        self.setMinimumWidth(320)


