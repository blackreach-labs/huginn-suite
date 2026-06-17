# app/components/evidence_manager_component.py
"""Evidence Manager UI Component.

Provides a comprehensive evidence management interface with tabs for:
- Gallery: Grid/list view with thumbnail previews, tag filtering, chronological sort
- Capture: Screenshot capture, clipboard paste, file import with drag-drop
- Link to Finding: Two-list interface for linking evidence to findings
- Details: Evidence metadata display (type, hash, size, tags, annotations)

Integrates as an enhancement to the existing Post-Exploitation page.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QPixmap
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.evidence_manager import EvidenceManager


class DropArea(QFrame):
    """A drag-and-drop area for importing evidence files."""

    file_dropped = pyqtSignal(str)  # file_path

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(100)
        self.setObjectName("dropArea")

        layout = QVBoxLayout(self)
        self._label = QLabel("Drag & Drop files here\nor use Import File button")
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._label.setObjectName("dropLabel")
        layout.addWidget(self._label)

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Accept drag events with file URLs."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet(
                "QFrame#dropArea { border: 2px dashed #64C8FF; "
                "background-color: rgba(100, 200, 255, 30); }"
            )

    def dragLeaveEvent(self, event):
        """Reset styling when drag leaves."""
        self.setStyleSheet("")

    def dropEvent(self, event: QDropEvent):
        """Handle file drop."""
        self.setStyleSheet("")
        urls = event.mimeData().urls()
        for url in urls:
            file_path = url.toLocalFile()
            if file_path and os.path.isfile(file_path):
                self.file_dropped.emit(file_path)


class EvidenceManagerComponent(QWidget):
    """Main evidence management component with tabbed interface.

    Signals:
        evidence_selected(int): Emitted when an evidence item is selected.
        evidence_linked(int, int): Emitted when evidence is linked to a finding.
    """

    evidence_selected = pyqtSignal(int)
    evidence_linked = pyqtSignal(int, int)

    def __init__(self, evidence_manager: EvidenceManager, parent=None):
        """Initialize the EvidenceManagerComponent.

        Args:
            evidence_manager: An EvidenceManager instance (with database set).
            parent: Optional QWidget parent.
        """
        super().__init__(parent)
        self.manager = evidence_manager
        self._selected_evidence_id: Optional[int] = None
        self._evidence_cache: List[Dict] = []

        self.setup_ui()
        self.apply_theme()
        self._connect_signals()

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
        self.tabs.addTab(self._create_gallery_tab(), "Gallery")
        self.tabs.addTab(self._create_capture_tab(), "Capture")
        self.tabs.addTab(self._create_link_tab(), "Link to Finding")
        self.tabs.addTab(self._create_details_tab(), "Details")

    # ------------------------------------------------------------------
    # Gallery Tab
    # ------------------------------------------------------------------

    def _create_gallery_tab(self) -> QWidget:
        """Create the gallery tab with thumbnail list, tag filtering, and sorting."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Filter and sort controls
        controls = QHBoxLayout()

        controls.addWidget(QLabel("Filter by Tag:"))
        self.tag_filter_combo = QComboBox()
        self.tag_filter_combo.addItem("All Tags", "")
        self.tag_filter_combo.currentIndexChanged.connect(self._on_tag_filter_changed)
        controls.addWidget(self.tag_filter_combo)

        controls.addWidget(QLabel("Sort:"))
        self.sort_combo = QComboBox()
        self.sort_combo.addItem("Newest First", "desc")
        self.sort_combo.addItem("Oldest First", "asc")
        self.sort_combo.currentIndexChanged.connect(self._on_sort_changed)
        controls.addWidget(self.sort_combo)

        self.refresh_gallery_btn = QPushButton("Refresh")
        self.refresh_gallery_btn.clicked.connect(self.refresh_gallery)
        controls.addWidget(self.refresh_gallery_btn)

        controls.addStretch()
        layout.addLayout(controls)

        # Evidence list (gallery view)
        self.gallery_list = QListWidget()
        self.gallery_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.gallery_list.currentItemChanged.connect(self._on_gallery_item_changed)
        layout.addWidget(self.gallery_list)

        return tab

    # ------------------------------------------------------------------
    # Capture Tab
    # ------------------------------------------------------------------

    def _create_capture_tab(self) -> QWidget:
        """Create the capture tab with screenshot, paste, and file import."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Section label
        capture_label = QLabel("Evidence Capture")
        capture_label.setObjectName("sectionLabel")
        layout.addWidget(capture_label)

        # Capture buttons row
        btn_layout = QHBoxLayout()

        self.capture_screenshot_btn = QPushButton("Capture Screenshot")
        self.capture_screenshot_btn.setMinimumHeight(40)
        self.capture_screenshot_btn.setToolTip(
            "Capture a screenshot of the primary screen"
        )
        self.capture_screenshot_btn.clicked.connect(self._on_capture_screenshot)
        btn_layout.addWidget(self.capture_screenshot_btn)

        self.paste_clipboard_btn = QPushButton("Paste from Clipboard")
        self.paste_clipboard_btn.setMinimumHeight(40)
        self.paste_clipboard_btn.setToolTip(
            "Paste image or text from the system clipboard"
        )
        self.paste_clipboard_btn.clicked.connect(self._on_paste_clipboard)
        btn_layout.addWidget(self.paste_clipboard_btn)

        self.import_file_btn = QPushButton("Import File")
        self.import_file_btn.setMinimumHeight(40)
        self.import_file_btn.setToolTip("Import a file as evidence")
        self.import_file_btn.clicked.connect(self._on_import_file)
        btn_layout.addWidget(self.import_file_btn)

        layout.addLayout(btn_layout)

        # Metadata inputs for capture
        form = QFormLayout()

        self.capture_title_input = QLineEdit()
        self.capture_title_input.setPlaceholderText("Evidence title (optional)")
        form.addRow("Title:", self.capture_title_input)

        self.capture_context_input = QLineEdit()
        self.capture_context_input.setPlaceholderText(
            "Source context (e.g., target IP, service)"
        )
        form.addRow("Context:", self.capture_context_input)

        self.capture_tags_input = QLineEdit()
        self.capture_tags_input.setPlaceholderText(
            "Tags, comma-separated (e.g., web, sqli, proof)"
        )
        form.addRow("Tags:", self.capture_tags_input)

        self.capture_type_combo = QComboBox()
        self.capture_type_combo.addItems([
            "screenshot", "text_snippet", "file",
            "http_pair", "terminal_output",
        ])
        form.addRow("Type:", self.capture_type_combo)

        layout.addLayout(form)

        # Drag-and-drop area
        layout.addSpacing(12)
        self.drop_area = DropArea()
        layout.addWidget(self.drop_area)

        # Annotation toolbar section
        layout.addSpacing(16)
        annotation_label = QLabel("Annotation Tools")
        annotation_label.setObjectName("sectionLabel")
        layout.addWidget(annotation_label)

        annotation_layout = QHBoxLayout()

        self.ann_rectangle_btn = QPushButton("Rectangle")
        self.ann_rectangle_btn.setMinimumHeight(35)
        self.ann_rectangle_btn.setToolTip("Add rectangle annotation")
        self.ann_rectangle_btn.clicked.connect(
            lambda: self._on_add_annotation("rectangle")
        )
        annotation_layout.addWidget(self.ann_rectangle_btn)

        self.ann_arrow_btn = QPushButton("Arrow")
        self.ann_arrow_btn.setMinimumHeight(35)
        self.ann_arrow_btn.setToolTip("Add arrow annotation")
        self.ann_arrow_btn.clicked.connect(
            lambda: self._on_add_annotation("arrow")
        )
        annotation_layout.addWidget(self.ann_arrow_btn)

        self.ann_text_btn = QPushButton("Text")
        self.ann_text_btn.setMinimumHeight(35)
        self.ann_text_btn.setToolTip("Add text label annotation")
        self.ann_text_btn.clicked.connect(
            lambda: self._on_add_annotation("text_label")
        )
        annotation_layout.addWidget(self.ann_text_btn)

        self.ann_redaction_btn = QPushButton("Redaction")
        self.ann_redaction_btn.setMinimumHeight(35)
        self.ann_redaction_btn.setToolTip("Add redaction box annotation")
        self.ann_redaction_btn.clicked.connect(
            lambda: self._on_add_annotation("redaction")
        )
        annotation_layout.addWidget(self.ann_redaction_btn)

        layout.addLayout(annotation_layout)
        layout.addStretch()

        return tab

    # ------------------------------------------------------------------
    # Link to Finding Tab
    # ------------------------------------------------------------------

    def _create_link_tab(self) -> QWidget:
        """Create the evidence-to-finding linking interface."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Info label
        link_label = QLabel("Link Evidence to Findings")
        link_label.setObjectName("sectionLabel")
        layout.addWidget(link_label)

        self.link_evidence_label = QLabel("No evidence selected")
        self.link_evidence_label.setObjectName("stateIndicator")
        layout.addWidget(self.link_evidence_label)

        # Two-list layout with add/remove buttons in the middle
        lists_layout = QHBoxLayout()

        # Available findings list (left)
        left_panel = QVBoxLayout()
        left_panel.addWidget(QLabel("Available Findings"))
        self.available_findings_list = QListWidget()
        self.available_findings_list.setSelectionMode(
            QListWidget.SelectionMode.SingleSelection
        )
        left_panel.addWidget(self.available_findings_list)
        lists_layout.addLayout(left_panel)

        # Add/Remove buttons (center)
        center_panel = QVBoxLayout()
        center_panel.addStretch()

        self.link_add_btn = QPushButton("→ Link")
        self.link_add_btn.setMinimumHeight(35)
        self.link_add_btn.setToolTip("Link selected finding to evidence")
        self.link_add_btn.clicked.connect(self._on_link_finding)
        center_panel.addWidget(self.link_add_btn)

        self.link_remove_btn = QPushButton("← Unlink")
        self.link_remove_btn.setMinimumHeight(35)
        self.link_remove_btn.setToolTip("Unlink selected finding from evidence")
        self.link_remove_btn.clicked.connect(self._on_unlink_finding)
        center_panel.addWidget(self.link_remove_btn)

        center_panel.addStretch()
        lists_layout.addLayout(center_panel)

        # Linked findings list (right)
        right_panel = QVBoxLayout()
        right_panel.addWidget(QLabel("Linked Findings"))
        self.linked_findings_list = QListWidget()
        self.linked_findings_list.setSelectionMode(
            QListWidget.SelectionMode.SingleSelection
        )
        right_panel.addWidget(self.linked_findings_list)
        lists_layout.addLayout(right_panel)

        layout.addLayout(lists_layout)

        # Refresh button
        self.refresh_links_btn = QPushButton("Refresh Findings")
        self.refresh_links_btn.setMinimumHeight(35)
        self.refresh_links_btn.clicked.connect(self._refresh_link_tab)
        layout.addWidget(self.refresh_links_btn)

        return tab

    # ------------------------------------------------------------------
    # Details Tab
    # ------------------------------------------------------------------

    def _create_details_tab(self) -> QWidget:
        """Create the evidence detail view with metadata."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        detail_label = QLabel("Evidence Details")
        detail_label.setObjectName("sectionLabel")
        layout.addWidget(detail_label)

        # Metadata form (read-only display)
        form = QFormLayout()

        self.detail_id_label = QLabel("—")
        form.addRow("ID:", self.detail_id_label)

        self.detail_type_label = QLabel("—")
        form.addRow("Type:", self.detail_type_label)

        self.detail_title_label = QLabel("—")
        form.addRow("Title:", self.detail_title_label)

        self.detail_hash_label = QLabel("—")
        self.detail_hash_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        form.addRow("SHA-256:", self.detail_hash_label)

        self.detail_compressed_label = QLabel("—")
        form.addRow("Compressed:", self.detail_compressed_label)

        self.detail_mime_label = QLabel("—")
        form.addRow("MIME Type:", self.detail_mime_label)

        self.detail_context_label = QLabel("—")
        form.addRow("Source Context:", self.detail_context_label)

        self.detail_tags_label = QLabel("—")
        form.addRow("Tags:", self.detail_tags_label)

        self.detail_target_label = QLabel("—")
        form.addRow("Target ID:", self.detail_target_label)

        self.detail_created_label = QLabel("—")
        form.addRow("Created At:", self.detail_created_label)

        layout.addLayout(form)

        # Annotations display
        layout.addSpacing(12)
        ann_label = QLabel("Annotations")
        ann_label.setObjectName("sectionLabel")
        layout.addWidget(ann_label)

        self.detail_annotations_text = QTextEdit()
        self.detail_annotations_text.setReadOnly(True)
        self.detail_annotations_text.setMaximumHeight(200)
        self.detail_annotations_text.setPlaceholderText("No annotations")
        layout.addWidget(self.detail_annotations_text)

        # Integrity verification button
        self.verify_integrity_btn = QPushButton("Verify Integrity (SHA-256)")
        self.verify_integrity_btn.setMinimumHeight(35)
        self.verify_integrity_btn.clicked.connect(self._on_verify_integrity)
        layout.addWidget(self.verify_integrity_btn)

        layout.addStretch()
        return tab

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect to EvidenceManager signals."""
        self.manager.evidence_stored.connect(self._on_evidence_stored_signal)
        self.manager.evidence_linked.connect(self._on_evidence_linked_signal)
        self.drop_area.file_dropped.connect(self._on_file_dropped)

    def _on_evidence_stored_signal(self, evidence_id: int):
        """Handle evidence_stored signal — refresh gallery."""
        self.refresh_gallery()

    def _on_evidence_linked_signal(self, evidence_id: int, finding_id: int):
        """Handle evidence_linked signal — refresh link tab."""
        self.evidence_linked.emit(evidence_id, finding_id)
        if evidence_id == self._selected_evidence_id:
            self._refresh_link_tab()

    # ------------------------------------------------------------------
    # Gallery Tab Handlers
    # ------------------------------------------------------------------

    def refresh_gallery(self):
        """Refresh the gallery list from the database."""
        self.gallery_list.clear()
        self._evidence_cache.clear()

        try:
            db = self.manager.database
            if db is None:
                return

            # Query all evidence (without blob data for performance)
            rows = db.execute_query(
                """SELECT id, evidence_type, title, sha256_hash,
                          mime_type, source_context, tags, created_at
                   FROM evidence
                   ORDER BY created_at DESC"""
            )

            all_tags = set()
            for row in rows:
                item_data = {
                    "id": row[0],
                    "evidence_type": row[1],
                    "title": row[2],
                    "sha256_hash": row[3],
                    "mime_type": row[4],
                    "source_context": row[5],
                    "tags": json.loads(row[6]) if row[6] else [],
                    "created_at": row[7],
                }
                self._evidence_cache.append(item_data)
                for tag in item_data["tags"]:
                    all_tags.add(tag)

            # Update tag filter combo
            current_filter = self.tag_filter_combo.currentData()
            self.tag_filter_combo.blockSignals(True)
            self.tag_filter_combo.clear()
            self.tag_filter_combo.addItem("All Tags", "")
            for tag in sorted(all_tags):
                self.tag_filter_combo.addItem(tag, tag)
            # Restore selection if possible
            if current_filter:
                idx = self.tag_filter_combo.findData(current_filter)
                if idx >= 0:
                    self.tag_filter_combo.setCurrentIndex(idx)
            self.tag_filter_combo.blockSignals(False)

            # Apply filter and sort
            self._populate_gallery()

        except Exception:
            pass

    def _populate_gallery(self):
        """Populate gallery list with current filter/sort settings."""
        self.gallery_list.clear()

        tag_filter = self.tag_filter_combo.currentData() or ""
        sort_order = self.sort_combo.currentData() or "desc"

        items = self._evidence_cache[:]

        # Apply tag filter
        if tag_filter:
            items = [i for i in items if tag_filter in i.get("tags", [])]

        # Apply sort (chronological)
        reverse = sort_order == "desc"
        items.sort(key=lambda x: x.get("created_at", ""), reverse=reverse)

        for item_data in items:
            title = item_data.get("title") or f"Evidence #{item_data['id']}"
            type_icon = self._type_icon(item_data["evidence_type"])
            display_text = (
                f"{type_icon} {title}\n"
                f"  Type: {item_data['evidence_type']} | "
                f"Created: {item_data.get('created_at', 'N/A')[:19]}"
            )
            if item_data.get("tags"):
                display_text += f"\n  Tags: {', '.join(item_data['tags'])}"

            list_item = QListWidgetItem(display_text)
            list_item.setData(Qt.ItemDataRole.UserRole, item_data["id"])
            self.gallery_list.addItem(list_item)

    def _type_icon(self, evidence_type: str) -> str:
        """Return a text icon for evidence type."""
        icons = {
            "screenshot": "📷",
            "text_snippet": "📝",
            "file": "📁",
            "http_pair": "🌐",
            "terminal_output": "💻",
        }
        return icons.get(evidence_type, "📄")

    def _on_tag_filter_changed(self):
        """Handle tag filter change."""
        self._populate_gallery()

    def _on_sort_changed(self):
        """Handle sort order change."""
        self._populate_gallery()

    def _on_gallery_item_changed(self, current: QListWidgetItem, previous):
        """Handle gallery item selection change."""
        if current is None:
            self._selected_evidence_id = None
            return

        evidence_id = current.data(Qt.ItemDataRole.UserRole)
        self._selected_evidence_id = evidence_id
        self.evidence_selected.emit(evidence_id)
        self._update_details_tab(evidence_id)
        self._update_link_tab_label(evidence_id)

    # ------------------------------------------------------------------
    # Capture Tab Handlers
    # ------------------------------------------------------------------

    def _on_capture_screenshot(self):
        """Capture a screenshot of the primary screen."""
        try:
            from PyQt6.QtGui import QGuiApplication

            screen = QGuiApplication.primaryScreen()
            if screen is None:
                self._show_error("No screen available for capture.")
                return

            pixmap = screen.grabWindow(0)
            if pixmap.isNull():
                self._show_error("Screenshot capture returned empty image.")
                return

            # Convert QPixmap to bytes (PNG format)
            from PyQt6.QtCore import QBuffer, QIODevice

            buffer = QBuffer()
            buffer.open(QIODevice.OpenModeFlag.WriteOnly)
            pixmap.save(buffer, "PNG")
            data = bytes(buffer.data())
            buffer.close()

            title = self.capture_title_input.text().strip() or "Screenshot"
            context = self.capture_context_input.text().strip()
            tags = self._parse_tags()

            self.manager.store_evidence(
                evidence_type="screenshot",
                data=data,
                title=title,
                source_context=context,
                tags=tags,
                mime_type="image/png",
            )

            self._show_info("Screenshot captured and stored successfully.")
            self._clear_capture_inputs()
            self.refresh_gallery()

        except RuntimeError as e:
            self._show_error(f"Cannot capture screenshot: {e}")
        except Exception as e:
            self._show_error(f"Screenshot capture failed: {e}")

    def _on_paste_clipboard(self):
        """Paste content from the system clipboard."""
        try:
            from PyQt6.QtWidgets import QApplication

            clipboard = QApplication.clipboard()
            if clipboard is None:
                self._show_error("Clipboard not available.")
                return

            mime_data = clipboard.mimeData()

            if mime_data.hasImage():
                # Paste image from clipboard
                from PyQt6.QtCore import QBuffer, QIODevice

                image = clipboard.image()
                if image.isNull():
                    self._show_error("Clipboard image is empty.")
                    return

                pixmap = QPixmap.fromImage(image)
                buffer = QBuffer()
                buffer.open(QIODevice.OpenModeFlag.WriteOnly)
                pixmap.save(buffer, "PNG")
                data = bytes(buffer.data())
                buffer.close()

                title = self.capture_title_input.text().strip() or "Clipboard Image"
                context = self.capture_context_input.text().strip()
                tags = self._parse_tags()

                self.manager.store_evidence(
                    evidence_type="screenshot",
                    data=data,
                    title=title,
                    source_context=context,
                    tags=tags,
                    mime_type="image/png",
                )
                self._show_info("Clipboard image stored as evidence.")

            elif mime_data.hasText():
                # Paste text from clipboard
                text = mime_data.text()
                if not text.strip():
                    self._show_error("Clipboard text is empty.")
                    return

                data = text.encode("utf-8")
                title = self.capture_title_input.text().strip() or "Clipboard Text"
                context = self.capture_context_input.text().strip()
                tags = self._parse_tags()
                ev_type = self.capture_type_combo.currentText()
                if ev_type == "screenshot":
                    ev_type = "text_snippet"

                self.manager.store_evidence(
                    evidence_type=ev_type,
                    data=data,
                    title=title,
                    source_context=context,
                    tags=tags,
                    mime_type="text/plain",
                )
                self._show_info("Clipboard text stored as evidence.")

            else:
                self._show_error("Clipboard contains no supported content.")
                return

            self._clear_capture_inputs()
            self.refresh_gallery()

        except RuntimeError as e:
            self._show_error(f"Cannot paste from clipboard: {e}")
        except Exception as e:
            self._show_error(f"Clipboard paste failed: {e}")

    def _on_import_file(self):
        """Import a file as evidence via file dialog."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Evidence File", "",
            "All Files (*);;Images (*.png *.jpg *.jpeg *.gif *.bmp);;"
            "Text (*.txt *.log *.md);;Documents (*.pdf *.docx)"
        )
        if file_path:
            self._import_file_path(file_path)

    def _on_file_dropped(self, file_path: str):
        """Handle file dropped into the drop area."""
        self._import_file_path(file_path)

    def _import_file_path(self, file_path: str):
        """Import a file from disk as evidence."""
        try:
            if not os.path.isfile(file_path):
                self._show_error(f"File not found: {file_path}")
                return

            with open(file_path, "rb") as f:
                data = f.read()

            filename = os.path.basename(file_path)
            ext = os.path.splitext(filename)[1].lower()

            # Determine MIME type
            mime_map = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".gif": "image/gif",
                ".bmp": "image/bmp",
                ".txt": "text/plain",
                ".log": "text/plain",
                ".md": "text/markdown",
                ".pdf": "application/pdf",
                ".docx": "application/vnd.openxmlformats-officedocument"
                         ".wordprocessingml.document",
                ".html": "text/html",
                ".xml": "application/xml",
                ".json": "application/json",
            }
            mime_type = mime_map.get(ext, "application/octet-stream")

            # Determine evidence type from extension
            image_exts = {".png", ".jpg", ".jpeg", ".gif", ".bmp"}
            text_exts = {".txt", ".log", ".md"}
            if ext in image_exts:
                ev_type = "screenshot"
            elif ext in text_exts:
                ev_type = "text_snippet"
            else:
                ev_type = self.capture_type_combo.currentText()

            title = self.capture_title_input.text().strip() or filename
            context = self.capture_context_input.text().strip()
            tags = self._parse_tags()

            self.manager.store_evidence(
                evidence_type=ev_type,
                data=data,
                title=title,
                source_context=context,
                tags=tags,
                mime_type=mime_type,
            )

            self._show_info(f"File imported: {filename}")
            self._clear_capture_inputs()
            self.refresh_gallery()

        except RuntimeError as e:
            self._show_error(f"Cannot import file: {e}")
        except Exception as e:
            self._show_error(f"File import failed: {e}")

    def _on_add_annotation(self, annotation_type: str):
        """Add an annotation to the currently selected evidence.

        Annotations are stored as metadata (not rendered on canvas yet).
        A default placeholder coordinate set is used since canvas rendering
        is not yet implemented.
        """
        if self._selected_evidence_id is None:
            self._show_error(
                "No evidence selected. Select an item from the Gallery first."
            )
            return

        # Default coordinates (placeholder — canvas rendering is future work)
        default_coords = {
            "rectangle": {"x": 10, "y": 10, "width": 100, "height": 50},
            "arrow": {"x1": 10, "y1": 10, "x2": 110, "y2": 60},
            "text_label": {"x": 50, "y": 50, "width": 200, "height": 30},
            "redaction": {"x": 10, "y": 10, "width": 150, "height": 80},
        }

        default_properties = {
            "rectangle": {"color": "#FF0000", "thickness": 2},
            "arrow": {"color": "#FF0000", "thickness": 2},
            "text_label": {"color": "#FFFFFF", "text": "Label", "font_size": 12},
            "redaction": {"color": "#000000", "fill": True},
        }

        coordinates = default_coords.get(
            annotation_type, {"x": 0, "y": 0, "width": 50, "height": 50}
        )
        properties = default_properties.get(annotation_type, {})

        try:
            self.manager.add_annotation(
                evidence_id=self._selected_evidence_id,
                annotation_type=annotation_type,
                coordinates=coordinates,
                properties=properties,
            )
            self._show_info(
                f"Annotation '{annotation_type}' added to evidence "
                f"#{self._selected_evidence_id}."
            )
            # Refresh details view
            self._update_details_tab(self._selected_evidence_id)
        except Exception as e:
            self._show_error(f"Failed to add annotation: {e}")

    # ------------------------------------------------------------------
    # Link to Finding Tab Handlers
    # ------------------------------------------------------------------

    def _refresh_link_tab(self):
        """Refresh the link tab lists."""
        self.available_findings_list.clear()
        self.linked_findings_list.clear()

        if self._selected_evidence_id is None:
            self.link_evidence_label.setText("No evidence selected")
            return

        try:
            db = self.manager.database
            if db is None:
                return

            # Get all findings
            all_findings = db.execute_query(
                """SELECT id, title, severity, status
                   FROM findings ORDER BY created_at DESC"""
            )

            # Get linked findings for this evidence
            linked = self.manager.get_findings_for_evidence(self._selected_evidence_id)
            linked_ids = {f["id"] for f in linked}

            # Populate available (not linked)
            for row in all_findings:
                finding_id = row[0]
                if finding_id not in linked_ids:
                    display = f"[{row[2].upper()}] {row[1]} (#{finding_id})"
                    item = QListWidgetItem(display)
                    item.setData(Qt.ItemDataRole.UserRole, finding_id)
                    self.available_findings_list.addItem(item)

            # Populate linked
            for finding in linked:
                display = (
                    f"[{finding['severity'].upper()}] "
                    f"{finding['title']} (#{finding['id']})"
                )
                item = QListWidgetItem(display)
                item.setData(Qt.ItemDataRole.UserRole, finding["id"])
                self.linked_findings_list.addItem(item)

        except Exception:
            pass

    def _on_link_finding(self):
        """Link the selected available finding to the current evidence."""
        if self._selected_evidence_id is None:
            self._show_error("No evidence selected.")
            return

        current_item = self.available_findings_list.currentItem()
        if current_item is None:
            self._show_error("No finding selected from the available list.")
            return

        finding_id = current_item.data(Qt.ItemDataRole.UserRole)
        try:
            self.manager.link_to_finding(self._selected_evidence_id, finding_id)
            self._refresh_link_tab()
        except Exception as e:
            self._show_error(f"Failed to link finding: {e}")

    def _on_unlink_finding(self):
        """Unlink the selected linked finding from the current evidence."""
        if self._selected_evidence_id is None:
            self._show_error("No evidence selected.")
            return

        current_item = self.linked_findings_list.currentItem()
        if current_item is None:
            self._show_error("No finding selected from the linked list.")
            return

        finding_id = current_item.data(Qt.ItemDataRole.UserRole)
        try:
            self.manager.unlink_from_finding(self._selected_evidence_id, finding_id)
            self._refresh_link_tab()
        except Exception as e:
            self._show_error(f"Failed to unlink finding: {e}")

    def _update_link_tab_label(self, evidence_id: int):
        """Update the link tab label to show selected evidence."""
        self.link_evidence_label.setText(
            f"Selected Evidence: #{evidence_id}"
        )
        self._refresh_link_tab()

    # ------------------------------------------------------------------
    # Details Tab Handlers
    # ------------------------------------------------------------------

    def _update_details_tab(self, evidence_id: int):
        """Update the details tab with metadata for the given evidence."""
        try:
            metadata = self.manager.get_evidence_metadata(evidence_id)

            self.detail_id_label.setText(str(metadata["id"]))
            self.detail_type_label.setText(metadata["evidence_type"])
            self.detail_title_label.setText(metadata.get("title") or "—")
            self.detail_hash_label.setText(metadata["sha256_hash"])
            self.detail_compressed_label.setText(
                "Yes" if metadata["compressed"] else "No"
            )
            self.detail_mime_label.setText(metadata.get("mime_type") or "—")
            self.detail_context_label.setText(
                metadata.get("source_context") or "—"
            )
            tags = metadata.get("tags", [])
            self.detail_tags_label.setText(
                ", ".join(tags) if tags else "—"
            )
            self.detail_target_label.setText(
                str(metadata["target_id"]) if metadata.get("target_id") else "—"
            )
            self.detail_created_label.setText(
                metadata.get("created_at", "—")
            )

            # Annotations JSON display
            annotations = metadata.get("annotations", [])
            if annotations:
                ann_text = json.dumps(annotations, indent=2)
            else:
                ann_text = "No annotations"
            self.detail_annotations_text.setPlainText(ann_text)

        except Exception:
            self._clear_details_tab()

    def _clear_details_tab(self):
        """Clear the details tab fields."""
        self.detail_id_label.setText("—")
        self.detail_type_label.setText("—")
        self.detail_title_label.setText("—")
        self.detail_hash_label.setText("—")
        self.detail_compressed_label.setText("—")
        self.detail_mime_label.setText("—")
        self.detail_context_label.setText("—")
        self.detail_tags_label.setText("—")
        self.detail_target_label.setText("—")
        self.detail_created_label.setText("—")
        self.detail_annotations_text.clear()

    def _on_verify_integrity(self):
        """Verify the integrity of the selected evidence."""
        if self._selected_evidence_id is None:
            self._show_error("No evidence selected.")
            return

        try:
            is_valid = self.manager.verify_integrity(self._selected_evidence_id)
            if is_valid:
                self._show_info(
                    f"Evidence #{self._selected_evidence_id} integrity verified. "
                    "SHA-256 hash matches."
                )
            else:
                self._show_error(
                    f"Evidence #{self._selected_evidence_id} INTEGRITY FAILURE! "
                    "Hash mismatch detected — data may be corrupted."
                )
        except Exception as e:
            self._show_error(f"Integrity verification failed: {e}")

    # ------------------------------------------------------------------
    # Utility Methods
    # ------------------------------------------------------------------

    def _parse_tags(self) -> List[str]:
        """Parse comma-separated tags from the capture tags input."""
        text = self.capture_tags_input.text().strip()
        if not text:
            return []
        return [t.strip() for t in text.split(",") if t.strip()]

    def _clear_capture_inputs(self):
        """Clear the capture form inputs."""
        self.capture_title_input.clear()
        self.capture_context_input.clear()
        self.capture_tags_input.clear()

    def _show_error(self, message: str):
        """Show an error message box."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("Evidence Manager")
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

    def _show_info(self, message: str):
        """Show an informational message box."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setWindowTitle("Evidence Manager")
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
            QFrame#dropArea {
                background-color: rgba(20, 30, 40, 100);
                border: 2px dashed rgba(100, 200, 255, 80);
                border-radius: 10px;
                min-height: 80px;
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
            QListWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
            }
            QListWidget::item {
                padding: 6px;
                border-bottom: 1px solid rgba(100, 200, 255, 20);
            }
            QListWidget::item:selected {
                background-color: rgba(100, 200, 255, 60);
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
            QLabel#dropLabel {
                color: rgba(100, 200, 255, 150);
                font-size: 12px;
                border: none;
                background: transparent;
            }
        """)
