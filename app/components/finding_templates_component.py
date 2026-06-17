# app/components/finding_templates_component.py
"""Finding Templates UI Component.

Provides a template library browser and editor interface with:
- Left panel: Category tabs, search bar, and template list
- Right panel: Template detail/edit form with all fields
- Actions: Save, Create Finding, Export, Import

Integrates as a new tab within the Reporting page.

Requirements: 2.1, 2.2, 2.3, 2.5, 2.7, 2.8
"""

from typing import List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
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
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.finding_template_library import (
    FindingTemplateLibrary,
    TEMPLATE_CATEGORIES,
    VALID_SEVERITIES,
)


class FindingTemplatesComponent(QWidget):
    """Finding Templates library browser and editor component.

    Provides a split-pane interface with category browsing, search,
    template list, and a detail/edit form for managing finding templates.

    Signals:
        finding_created(int): Emitted with the finding row ID when a finding
            is created from a template.
    """

    finding_created = pyqtSignal(int)

    def __init__(
        self,
        template_library: FindingTemplateLibrary,
        engagement_db=None,
        parent=None,
    ):
        """Initialize the FindingTemplatesComponent.

        Args:
            template_library: The FindingTemplateLibrary instance for CRUD operations.
            engagement_db: Optional EngagementDatabase instance for creating findings.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.library = template_library
        self.engagement_db = engagement_db
        self._selected_template_id: Optional[str] = None
        self._active_category: Optional[str] = None

        self.setup_ui()
        self.apply_theme()
        self._connect_signals()
        self._refresh_template_list()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def setup_ui(self):
        """Build the split-pane layout: left browser | right detail form."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Left panel: category tabs + search + template list
        left_panel = QFrame()
        left_panel.setFixedWidth(340)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.setSpacing(6)

        # Section label
        browser_label = QLabel("Template Library")
        browser_label.setObjectName("sectionLabel")
        left_layout.addWidget(browser_label)

        # Category tabs (using QPushButton group)
        left_layout.addWidget(self._create_category_tabs())

        # Search bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search templates...")
        left_layout.addWidget(self.search_input)

        # Template list
        self.template_list = QListWidget()
        self.template_list.setMinimumHeight(200)
        left_layout.addWidget(self.template_list, 1)

        # Template count indicator
        self.count_label = QLabel("0 templates")
        self.count_label.setObjectName("countLabel")
        left_layout.addWidget(self.count_label)

        # Bottom buttons: New Template, Delete Template
        btn_row = QHBoxLayout()
        self.new_template_btn = QPushButton("New Template")
        self.new_template_btn.setMinimumHeight(32)
        btn_row.addWidget(self.new_template_btn)

        self.delete_template_btn = QPushButton("Delete")
        self.delete_template_btn.setMinimumHeight(32)
        btn_row.addWidget(self.delete_template_btn)
        left_layout.addLayout(btn_row)

        layout.addWidget(left_panel)

        # Right panel: detail/edit form
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(8, 8, 8, 8)
        right_layout.setSpacing(6)

        # Section label
        detail_label = QLabel("Template Details")
        detail_label.setObjectName("sectionLabel")
        right_layout.addWidget(detail_label)

        # Scrollable form area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_content = QWidget()
        form_layout = QFormLayout(scroll_content)
        form_layout.setSpacing(8)

        # Title
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Finding template title")
        form_layout.addRow("Title:", self.title_input)

        # Severity
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(VALID_SEVERITIES)
        form_layout.addRow("Severity:", self.severity_combo)

        # Category
        self.category_combo = QComboBox()
        self.category_combo.addItems(TEMPLATE_CATEGORIES)
        form_layout.addRow("Category:", self.category_combo)

        # Description
        self.description_input = QTextEdit()
        self.description_input.setPlaceholderText("Vulnerability description...")
        self.description_input.setMaximumHeight(100)
        form_layout.addRow("Description:", self.description_input)

        # Impact
        self.impact_input = QTextEdit()
        self.impact_input.setPlaceholderText("Business/technical impact...")
        self.impact_input.setMaximumHeight(80)
        form_layout.addRow("Impact:", self.impact_input)

        # Remediation
        self.remediation_input = QTextEdit()
        self.remediation_input.setPlaceholderText("Remediation guidance...")
        self.remediation_input.setMaximumHeight(80)
        form_layout.addRow("Remediation:", self.remediation_input)

        # References
        self.references_input = QTextEdit()
        self.references_input.setPlaceholderText("One URL per line...")
        self.references_input.setMaximumHeight(60)
        form_layout.addRow("References:", self.references_input)

        # CVSS Vector
        self.cvss_input = QLineEdit()
        self.cvss_input.setPlaceholderText("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        form_layout.addRow("CVSS Vector:", self.cvss_input)

        # CWE ID
        self.cwe_input = QLineEdit()
        self.cwe_input.setPlaceholderText("CWE-79")
        form_layout.addRow("CWE ID:", self.cwe_input)

        # Tags
        self.tags_input = QLineEdit()
        self.tags_input.setPlaceholderText("Comma-separated tags (e.g., xss, injection, owasp)")
        form_layout.addRow("Tags:", self.tags_input)

        scroll_area.setWidget(scroll_content)
        right_layout.addWidget(scroll_area, 1)

        # Action buttons row
        actions_layout = QHBoxLayout()

        self.save_btn = QPushButton("Save Template")
        self.save_btn.setMinimumHeight(35)
        actions_layout.addWidget(self.save_btn)

        self.create_finding_btn = QPushButton("Create Finding")
        self.create_finding_btn.setMinimumHeight(35)
        actions_layout.addWidget(self.create_finding_btn)

        self.export_btn = QPushButton("Export Selected")
        self.export_btn.setMinimumHeight(35)
        actions_layout.addWidget(self.export_btn)

        self.import_btn = QPushButton("Import Templates")
        self.import_btn.setMinimumHeight(35)
        actions_layout.addWidget(self.import_btn)

        right_layout.addLayout(actions_layout)

        layout.addWidget(right_panel, 1)

    # ------------------------------------------------------------------
    # Category Tabs
    # ------------------------------------------------------------------

    def _create_category_tabs(self) -> QWidget:
        """Create the category filter button group."""
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self.category_buttons: List[QPushButton] = []

        # "All" button
        all_btn = QPushButton("All")
        all_btn.setCheckable(True)
        all_btn.setChecked(True)
        all_btn.setMinimumHeight(28)
        all_btn.setProperty("category", None)
        all_btn.clicked.connect(lambda: self._on_category_selected(None, all_btn))
        layout.addWidget(all_btn)
        self.category_buttons.append(all_btn)

        for cat in TEMPLATE_CATEGORIES:
            # Use short labels for compact display
            short_label = cat.split()[0] if len(cat) > 10 else cat
            btn = QPushButton(short_label)
            btn.setCheckable(True)
            btn.setMinimumHeight(28)
            btn.setProperty("category", cat)
            btn.setToolTip(cat)
            btn.clicked.connect(
                lambda checked, c=cat, b=btn: self._on_category_selected(c, b)
            )
            layout.addWidget(btn)
            self.category_buttons.append(btn)

        layout.addStretch()
        return container

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect widget signals to handler methods."""
        self.search_input.textChanged.connect(self._on_search_changed)
        self.template_list.currentItemChanged.connect(self._on_template_selected)
        self.save_btn.clicked.connect(self._on_save_template)
        self.create_finding_btn.clicked.connect(self._on_create_finding)
        self.export_btn.clicked.connect(self._on_export_templates)
        self.import_btn.clicked.connect(self._on_import_templates)
        self.new_template_btn.clicked.connect(self._on_new_template)
        self.delete_template_btn.clicked.connect(self._on_delete_template)

        # Connect library signals for live updates
        self.library.template_created.connect(self._on_library_changed)
        self.library.template_updated.connect(self._on_library_changed)
        self.library.template_deleted.connect(self._on_library_changed)

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_category_selected(self, category: Optional[str], clicked_btn: QPushButton):
        """Handle category tab selection."""
        # Uncheck all other buttons
        for btn in self.category_buttons:
            btn.setChecked(btn is clicked_btn)

        self._active_category = category
        self._refresh_template_list()

    def _on_search_changed(self, text: str):
        """Handle search input text change."""
        self._refresh_template_list()

    def _on_template_selected(self, current: QListWidgetItem, previous: QListWidgetItem):
        """Handle template selection in the list."""
        if current is None:
            self._selected_template_id = None
            self._clear_form()
            return

        template_id = current.data(Qt.ItemDataRole.UserRole)
        self._selected_template_id = template_id
        self._load_template_into_form(template_id)

    def _on_save_template(self):
        """Save or update the current template from form fields."""
        title = self.title_input.text().strip()
        if not title:
            self._show_validation_error("Template title is required.")
            return

        severity = self.severity_combo.currentText()
        category = self.category_combo.currentText()
        description = self.description_input.toPlainText().strip()
        impact = self.impact_input.toPlainText().strip()
        remediation = self.remediation_input.toPlainText().strip()

        if not description:
            self._show_validation_error("Description is required.")
            return
        if not impact:
            self._show_validation_error("Impact is required.")
            return
        if not remediation:
            self._show_validation_error("Remediation is required.")
            return

        # Parse references (one URL per line)
        refs_text = self.references_input.toPlainText().strip()
        references = (
            [line.strip() for line in refs_text.splitlines() if line.strip()]
            if refs_text
            else None
        )

        cvss_vector = self.cvss_input.text().strip() or None
        cwe_id = self.cwe_input.text().strip() or None

        # Parse tags (comma-separated)
        tags_text = self.tags_input.text().strip()
        tags = (
            [t.strip() for t in tags_text.split(",") if t.strip()]
            if tags_text
            else None
        )

        try:
            if self._selected_template_id:
                # Update existing template
                self.library.update_template(
                    self._selected_template_id,
                    title=title,
                    severity=severity,
                    category=category,
                    description=description,
                    impact=impact,
                    remediation=remediation,
                    references=references,
                    cvss_vector=cvss_vector,
                    cwe_id=cwe_id,
                    tags=tags,
                )
            else:
                # Create new template
                new_id = self.library.create_template(
                    title=title,
                    severity=severity,
                    category=category,
                    description=description,
                    impact=impact,
                    remediation=remediation,
                    references=references,
                    cvss_vector=cvss_vector,
                    cwe_id=cwe_id,
                    tags=tags,
                )
                self._selected_template_id = new_id
        except Exception as e:
            self._show_validation_error(f"Failed to save template: {e}")

    def _on_create_finding(self):
        """Open confirmation dialog and create a finding from selected template."""
        if not self._selected_template_id:
            self._show_validation_error("No template selected. Select a template first.")
            return

        if self.engagement_db is None:
            self._show_validation_error(
                "No engagement database available. Open an engagement first."
            )
            return

        template = self.library.get_template(self._selected_template_id)
        if template is None:
            self._show_validation_error("Selected template not found.")
            return

        # Show the confirmation/customization dialog
        dialog = CreateFindingDialog(template, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            overrides = dialog.get_overrides()
            try:
                finding_id = self.library.create_finding_from_template(
                    self._selected_template_id,
                    self.engagement_db,
                    overrides=overrides if overrides else None,
                )
                if finding_id is not None:
                    self.finding_created.emit(finding_id)
                    self._show_info("Finding Created", f"Finding #{finding_id} created from template.")
                else:
                    self._show_validation_error("Failed to create finding from template.")
            except Exception as e:
                self._show_validation_error(f"Failed to create finding: {e}")

    def _on_export_templates(self):
        """Export selected or all templates to a JSON file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Templates",
            "finding_templates_export.json",
            "JSON Files (*.json);;All Files (*)",
        )
        if not file_path:
            return

        # Export only the selected template, or all if none selected
        template_ids = [self._selected_template_id] if self._selected_template_id else None

        try:
            success = self.library.export_templates(file_path, template_ids=template_ids)
            if success:
                count = 1 if template_ids else self.library.get_template_count()
                self._show_info("Export Complete", f"Exported {count} template(s) to file.")
            else:
                self._show_validation_error("Failed to export templates.")
        except Exception as e:
            self._show_validation_error(f"Export error: {e}")

    def _on_import_templates(self):
        """Import templates from a JSON file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Templates",
            "",
            "JSON Files (*.json);;All Files (*)",
        )
        if not file_path:
            return

        try:
            imported, skipped, warnings = self.library.import_templates(
                file_path, overwrite_existing=False
            )
            msg = f"Imported: {imported}, Skipped: {skipped}"
            if warnings:
                msg += f"\nWarnings:\n" + "\n".join(warnings[:5])
            self._show_info("Import Complete", msg)
        except Exception as e:
            self._show_validation_error(f"Import error: {e}")

    def _on_new_template(self):
        """Clear form for creating a new template."""
        self._selected_template_id = None
        self.template_list.clearSelection()
        self._clear_form()
        self.title_input.setFocus()

    def _on_delete_template(self):
        """Delete the currently selected template."""
        if not self._selected_template_id:
            self._show_validation_error("No template selected.")
            return

        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Delete Template",
            "Are you sure you want to delete this template? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.library.delete_template(self._selected_template_id)
                self._selected_template_id = None
                self._clear_form()
            except Exception as e:
                self._show_validation_error(f"Failed to delete template: {e}")

    def _on_library_changed(self, template_id: str):
        """Handle library signal indicating a template was created/updated/deleted."""
        self._refresh_template_list()

    # ------------------------------------------------------------------
    # Data Loading
    # ------------------------------------------------------------------

    def _refresh_template_list(self):
        """Refresh the template list based on current filters."""
        search_text = self.search_input.text().strip()

        if search_text:
            templates = self.library.search_templates(search_text)
            # Apply category filter to search results if active
            if self._active_category:
                templates = [
                    t for t in templates if t["category"] == self._active_category
                ]
        else:
            templates = self.library.list_templates(category=self._active_category)

        self.template_list.blockSignals(True)
        self.template_list.clear()

        for tmpl in templates:
            item = QListWidgetItem()
            # Display title with severity badge
            display_text = f"[{tmpl['severity'][:4]}] {tmpl['title']}"
            item.setText(display_text)
            item.setData(Qt.ItemDataRole.UserRole, tmpl["id"])
            item.setToolTip(f"{tmpl['title']} ({tmpl['severity']} - {tmpl['category']})")

            # Color code by severity
            color = self._severity_color(tmpl["severity"])
            item.setForeground(QColor(color))

            self.template_list.addItem(item)

        self.template_list.blockSignals(False)
        self.count_label.setText(f"{len(templates)} template(s)")

        # Re-select the previously selected template if still in list
        if self._selected_template_id:
            for i in range(self.template_list.count()):
                item = self.template_list.item(i)
                if item and item.data(Qt.ItemDataRole.UserRole) == self._selected_template_id:
                    self.template_list.setCurrentItem(item)
                    break

    def _load_template_into_form(self, template_id: str):
        """Load a template's data into the edit form."""
        template = self.library.get_template(template_id)
        if template is None:
            self._clear_form()
            return

        self.title_input.setText(template["title"])

        # Set severity combo
        sev_idx = self.severity_combo.findText(template["severity"])
        if sev_idx >= 0:
            self.severity_combo.setCurrentIndex(sev_idx)

        # Set category combo
        cat_idx = self.category_combo.findText(template["category"])
        if cat_idx >= 0:
            self.category_combo.setCurrentIndex(cat_idx)

        self.description_input.setPlainText(template["description"] or "")
        self.impact_input.setPlainText(template["impact"] or "")
        self.remediation_input.setPlainText(template["remediation"] or "")

        # References (list -> newline-separated)
        refs = template.get("references")
        self.references_input.setPlainText("\n".join(refs) if refs else "")

        self.cvss_input.setText(template.get("cvss_vector") or "")
        self.cwe_input.setText(template.get("cwe_id") or "")

        # Tags (list -> comma-separated)
        tags = template.get("tags")
        self.tags_input.setText(", ".join(tags) if tags else "")

    def _clear_form(self):
        """Clear all form fields."""
        self.title_input.clear()
        self.severity_combo.setCurrentIndex(0)
        self.category_combo.setCurrentIndex(0)
        self.description_input.clear()
        self.impact_input.clear()
        self.remediation_input.clear()
        self.references_input.clear()
        self.cvss_input.clear()
        self.cwe_input.clear()
        self.tags_input.clear()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_engagement_db(self, engagement_db):
        """Set or update the engagement database for finding creation.

        Args:
            engagement_db: An EngagementDatabase instance.
        """
        self.engagement_db = engagement_db

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _severity_color(self, severity: str) -> str:
        """Return a display color for the given severity level."""
        colors = {
            "Critical": "#FF4444",
            "High": "#FF8C00",
            "Medium": "#FFD700",
            "Low": "#64C8FF",
            "Informational": "#A0A0A0",
        }
        return colors.get(severity, "#DCDCDC")

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
            QPushButton:checked {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
                color: #64C8FF;
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
                padding: 6px 4px;
                border-bottom: 1px solid rgba(100, 200, 255, 20);
            }
            QListWidget::item:selected {
                background-color: rgba(100, 200, 255, 60);
            }
            QListWidget::item:hover {
                background-color: rgba(100, 200, 255, 30);
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
        """)


# ---------------------------------------------------------------------------
# Create Finding Dialog
# ---------------------------------------------------------------------------


class CreateFindingDialog(QDialog):
    """Dialog for confirming and customizing a finding before creation from template.

    Shows all template fields with the option to override any value
    before creating the finding in the engagement database.
    """

    def __init__(self, template: dict, parent=None):
        super().__init__(parent)
        self.template = template
        self._overrides: dict = {}

        self.setWindowTitle("Create Finding from Template")
        self.setMinimumWidth(550)
        self.setMinimumHeight(500)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Build the dialog form with pre-populated template fields."""
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Instructions
        info_label = QLabel(
            "Review and customize fields before creating the finding. "
            "Changes here only apply to this finding instance."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Scrollable form
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_content = QWidget()
        form = QFormLayout(scroll_content)
        form.setSpacing(6)

        # Title
        self.dlg_title = QLineEdit(self.template["title"])
        form.addRow("Title:", self.dlg_title)

        # Severity
        self.dlg_severity = QComboBox()
        self.dlg_severity.addItems(VALID_SEVERITIES)
        sev_idx = self.dlg_severity.findText(self.template["severity"])
        if sev_idx >= 0:
            self.dlg_severity.setCurrentIndex(sev_idx)
        form.addRow("Severity:", self.dlg_severity)

        # Category
        self.dlg_category = QComboBox()
        self.dlg_category.addItems(TEMPLATE_CATEGORIES)
        cat_idx = self.dlg_category.findText(self.template["category"])
        if cat_idx >= 0:
            self.dlg_category.setCurrentIndex(cat_idx)
        form.addRow("Category:", self.dlg_category)

        # Description
        self.dlg_description = QTextEdit()
        self.dlg_description.setPlainText(self.template["description"] or "")
        self.dlg_description.setMaximumHeight(80)
        form.addRow("Description:", self.dlg_description)

        # Impact
        self.dlg_impact = QTextEdit()
        self.dlg_impact.setPlainText(self.template["impact"] or "")
        self.dlg_impact.setMaximumHeight(60)
        form.addRow("Impact:", self.dlg_impact)

        # Remediation
        self.dlg_remediation = QTextEdit()
        self.dlg_remediation.setPlainText(self.template["remediation"] or "")
        self.dlg_remediation.setMaximumHeight(60)
        form.addRow("Remediation:", self.dlg_remediation)

        # CVSS Vector
        self.dlg_cvss = QLineEdit(self.template.get("cvss_vector") or "")
        form.addRow("CVSS Vector:", self.dlg_cvss)

        # CWE ID
        self.dlg_cwe = QLineEdit(self.template.get("cwe_id") or "")
        form.addRow("CWE ID:", self.dlg_cwe)

        scroll_area.setWidget(scroll_content)
        layout.addWidget(scroll_area, 1)

        # Dialog buttons
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.button(QDialogButtonBox.StandardButton.Ok).setText("Create Finding")
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def get_overrides(self) -> dict:
        """Return a dict of field overrides (only fields that differ from template).

        Returns:
            Dict of field name -> new value for fields that were changed.
        """
        overrides = {}

        title = self.dlg_title.text().strip()
        if title and title != self.template["title"]:
            overrides["title"] = title

        severity = self.dlg_severity.currentText()
        if severity != self.template["severity"]:
            overrides["severity"] = severity

        category = self.dlg_category.currentText()
        if category != self.template["category"]:
            overrides["category"] = category

        description = self.dlg_description.toPlainText().strip()
        if description and description != (self.template["description"] or ""):
            overrides["description"] = description

        impact = self.dlg_impact.toPlainText().strip()
        if impact and impact != (self.template["impact"] or ""):
            overrides["impact"] = impact

        remediation = self.dlg_remediation.toPlainText().strip()
        if remediation and remediation != (self.template["remediation"] or ""):
            overrides["remediation"] = remediation

        cvss = self.dlg_cvss.text().strip()
        if cvss != (self.template.get("cvss_vector") or ""):
            overrides["cvss_vector"] = cvss or None

        cwe = self.dlg_cwe.text().strip()
        if cwe != (self.template.get("cwe_id") or ""):
            overrides["cwe_id"] = cwe or None

        return overrides

    def apply_theme(self):
        """Apply dark theme styling to the dialog."""
        self.setStyleSheet("""
            QDialog {
                background-color: rgba(20, 30, 40, 240);
                color: #DCDCDC;
            }
            QLabel {
                color: #DCDCDC;
                border: none;
                background: transparent;
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
            QScrollArea {
                border: none;
                background: transparent;
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QDialogButtonBox {
                border: none;
                background: transparent;
            }
        """)
