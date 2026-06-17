# app/components/report_designer_component.py
"""Report Designer UI Component.

Provides a full report template designer with:
- Drag-and-drop section list for report layout ordering
- Branding configuration panel (logo, colors, company name, header/footer)
- Output format selector (PDF, HTML, DOCX, Markdown)
- Severity filter dropdown
- Template save/load interface
- Report preview pane (read-only markdown preview)
- Generate Report button

Integrates as enhancement to the existing Reporting page.

Requirements: 12.1, 12.2, 12.3, 12.4, 12.6
"""

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QColorDialog,
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
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.report_customizer import (
    DEFAULT_SECTIONS,
    ReportCustomizer,
    ReportSection,
    ReportTemplate,
    SEVERITY_LEVELS,
)


class ReportDesignerComponent(QWidget):
    """Report Designer component for building and managing report templates.

    Provides drag-and-drop section ordering, branding configuration,
    output format selection, severity filtering, template management,
    and a markdown preview pane.

    Signals:
        report_generated(str): Emitted with the output path when a report is generated.
        template_saved(str): Emitted with the template name when saved.
    """

    report_generated = pyqtSignal(str)
    template_saved = pyqtSignal(str)

    def __init__(
        self,
        report_customizer: ReportCustomizer,
        engagement_db=None,
        parent=None,
    ):
        """Initialize the ReportDesignerComponent.

        Args:
            report_customizer: The ReportCustomizer engine instance.
            engagement_db: Optional EngagementDatabase instance for report generation.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.customizer = report_customizer
        self.engagement_db = engagement_db
        self._current_template: Optional[ReportTemplate] = None
        self._logo_path: str = ""
        self._primary_color: str = "#2c3e50"
        self._secondary_color: str = "#3498db"

        self._setup_ui()
        self._apply_theme()
        self._connect_signals()
        self._load_defaults()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the main layout with left config panel and right preview."""
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel: configuration
        left_panel = QFrame()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.setSpacing(6)

        # Template management section
        left_layout.addWidget(self._build_template_management())

        # Section ordering
        left_layout.addWidget(self._build_section_list())

        # Branding configuration
        left_layout.addWidget(self._build_branding_panel())

        # Output format & severity filter
        left_layout.addWidget(self._build_output_options())

        # Generate button
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.setMinimumHeight(40)
        self.generate_btn.setObjectName("generateBtn")
        left_layout.addWidget(self.generate_btn)

        splitter.addWidget(left_panel)

        # Right panel: preview pane
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(8, 8, 8, 8)
        right_layout.setSpacing(6)

        preview_label = QLabel("Report Preview")
        preview_label.setObjectName("sectionLabel")
        right_layout.addWidget(preview_label)

        self.preview_pane = QTextEdit()
        self.preview_pane.setReadOnly(True)
        self.preview_pane.setPlaceholderText(
            "Report preview will appear here after generation or template load..."
        )
        right_layout.addWidget(self.preview_pane, 1)

        # Refresh preview button
        self.refresh_preview_btn = QPushButton("Refresh Preview")
        self.refresh_preview_btn.setMinimumHeight(32)
        right_layout.addWidget(self.refresh_preview_btn)

        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        main_layout.addWidget(splitter)

    def _build_template_management(self) -> QWidget:
        """Build the template save/load/delete interface."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        label = QLabel("Template Management")
        label.setObjectName("sectionLabel")
        layout.addWidget(label)

        # Template name input
        name_row = QHBoxLayout()
        self.template_name_input = QLineEdit()
        self.template_name_input.setPlaceholderText("Template name...")
        name_row.addWidget(self.template_name_input, 1)
        layout.addLayout(name_row)

        # Existing templates combo
        templates_row = QHBoxLayout()
        self.templates_combo = QComboBox()
        self.templates_combo.setPlaceholderText("Select existing template...")
        templates_row.addWidget(self.templates_combo, 1)
        layout.addLayout(templates_row)

        # Action buttons: Save / Load / Delete
        btn_row = QHBoxLayout()
        self.save_template_btn = QPushButton("Save")
        self.save_template_btn.setMinimumHeight(30)
        btn_row.addWidget(self.save_template_btn)

        self.load_template_btn = QPushButton("Load")
        self.load_template_btn.setMinimumHeight(30)
        btn_row.addWidget(self.load_template_btn)

        self.delete_template_btn = QPushButton("Delete")
        self.delete_template_btn.setMinimumHeight(30)
        btn_row.addWidget(self.delete_template_btn)

        layout.addLayout(btn_row)

        return container

    def _build_section_list(self) -> QWidget:
        """Build the drag-and-drop section ordering list."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        label = QLabel("Report Sections (drag to reorder)")
        label.setObjectName("sectionLabel")
        layout.addWidget(label)

        self.section_list = QListWidget()
        self.section_list.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        self.section_list.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.section_list.setMinimumHeight(140)
        layout.addWidget(self.section_list)

        return container

    def _build_branding_panel(self) -> QWidget:
        """Build branding configuration panel."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        label = QLabel("Branding")
        label.setObjectName("sectionLabel")
        layout.addWidget(label)

        form = QFormLayout()
        form.setSpacing(6)

        # Company name
        self.company_name_input = QLineEdit()
        self.company_name_input.setPlaceholderText("Company name...")
        form.addRow("Company:", self.company_name_input)

        # Logo upload
        logo_row = QHBoxLayout()
        self.logo_path_label = QLabel("No logo selected")
        self.logo_path_label.setObjectName("countLabel")
        logo_row.addWidget(self.logo_path_label, 1)
        self.logo_browse_btn = QPushButton("Browse...")
        self.logo_browse_btn.setMaximumWidth(80)
        logo_row.addWidget(self.logo_browse_btn)
        form.addRow("Logo:", logo_row)

        # Primary color
        color_row = QHBoxLayout()
        self.primary_color_btn = QPushButton("Primary")
        self.primary_color_btn.setMaximumWidth(80)
        color_row.addWidget(self.primary_color_btn)
        self.secondary_color_btn = QPushButton("Secondary")
        self.secondary_color_btn.setMaximumWidth(80)
        color_row.addWidget(self.secondary_color_btn)
        self.color_preview_label = QLabel("■ ■")
        self.color_preview_label.setObjectName("colorPreview")
        color_row.addWidget(self.color_preview_label)
        form.addRow("Colors:", color_row)

        # Header text
        self.header_text_input = QLineEdit()
        self.header_text_input.setPlaceholderText("Header text...")
        form.addRow("Header:", self.header_text_input)

        # Footer text
        self.footer_text_input = QLineEdit()
        self.footer_text_input.setPlaceholderText("Footer text...")
        form.addRow("Footer:", self.footer_text_input)

        layout.addLayout(form)
        return container

    def _build_output_options(self) -> QWidget:
        """Build output format selector and severity filter."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        label = QLabel("Output Options")
        label.setObjectName("sectionLabel")
        layout.addWidget(label)

        form = QFormLayout()
        form.setSpacing(6)

        # Output format
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PDF", "HTML", "DOCX", "Markdown"])
        form.addRow("Format:", self.format_combo)

        # Severity filter
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(
            [s.capitalize() for s in SEVERITY_LEVELS]
        )
        form.addRow("Min Severity:", self.severity_combo)

        layout.addLayout(form)
        return container

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect all button and widget signals to handlers."""
        self.save_template_btn.clicked.connect(self._on_save_template)
        self.load_template_btn.clicked.connect(self._on_load_template)
        self.delete_template_btn.clicked.connect(self._on_delete_template)
        self.logo_browse_btn.clicked.connect(self._on_browse_logo)
        self.primary_color_btn.clicked.connect(self._on_pick_primary_color)
        self.secondary_color_btn.clicked.connect(self._on_pick_secondary_color)
        self.generate_btn.clicked.connect(self._on_generate_report)
        self.refresh_preview_btn.clicked.connect(self._on_refresh_preview)
        self.section_list.model().rowsMoved.connect(self._on_sections_reordered)

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _load_defaults(self):
        """Load default sections and refresh template list."""
        # Populate section list with defaults
        for section_data in DEFAULT_SECTIONS:
            item = QListWidgetItem(section_data["title"])
            item.setData(Qt.ItemDataRole.UserRole, section_data["id"])
            item.setCheckState(
                Qt.CheckState.Checked if section_data["enabled"] else Qt.CheckState.Unchecked
            )
            self.section_list.addItem(item)

        # Refresh available templates
        self._refresh_templates_combo()

        # Update color preview
        self._update_color_preview()

    def _refresh_templates_combo(self):
        """Refresh the templates combo box with saved templates."""
        self.templates_combo.clear()
        templates = self.customizer.list_templates()
        for name in templates:
            self.templates_combo.addItem(name)

    # ------------------------------------------------------------------
    # Template Management Handlers
    # ------------------------------------------------------------------

    def _on_save_template(self):
        """Save the current configuration as a template."""
        name = self.template_name_input.text().strip()
        if not name:
            QMessageBox.warning(
                self, "Save Template", "Please enter a template name."
            )
            return

        # Build sections from list
        sections = self._get_sections_from_list()

        # Build branding dict
        branding = self._get_branding_dict()

        # Get severity threshold
        severity = self.severity_combo.currentText().lower()

        try:
            template = self.customizer.create_template(
                name=name,
                sections=[s.to_dict() for s in sections],
                branding=branding,
                severity_threshold=severity,
            )
            self.customizer.save_template(template)
            self._current_template = template
            self._refresh_templates_combo()
            self.template_saved.emit(name)
            QMessageBox.information(
                self, "Save Template", f"Template '{name}' saved successfully."
            )
        except (ValueError, OSError) as e:
            QMessageBox.critical(
                self, "Save Error", f"Failed to save template: {e}"
            )

    def _on_load_template(self):
        """Load the selected template from the combo box."""
        name = self.templates_combo.currentText()
        if not name:
            QMessageBox.warning(
                self, "Load Template", "Please select a template to load."
            )
            return

        try:
            template = self.customizer.load_template(name)
            self._current_template = template
            self._apply_template_to_ui(template)
            QMessageBox.information(
                self, "Load Template", f"Template '{name}' loaded."
            )
        except (FileNotFoundError, ValueError) as e:
            QMessageBox.critical(
                self, "Load Error", f"Failed to load template: {e}"
            )

    def _on_delete_template(self):
        """Delete the selected template."""
        name = self.templates_combo.currentText()
        if not name:
            QMessageBox.warning(
                self, "Delete Template", "Please select a template to delete."
            )
            return

        reply = QMessageBox.question(
            self,
            "Delete Template",
            f"Are you sure you want to delete '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            deleted = self.customizer.delete_template(name)
            if deleted:
                self._refresh_templates_combo()
                QMessageBox.information(
                    self, "Deleted", f"Template '{name}' deleted."
                )
            else:
                QMessageBox.warning(
                    self, "Delete", f"Template '{name}' not found."
                )

    # ------------------------------------------------------------------
    # Branding Handlers
    # ------------------------------------------------------------------

    def _on_browse_logo(self):
        """Open file dialog to select a logo image."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Logo Image",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.svg);;All Files (*)",
        )
        if path:
            self._logo_path = path
            # Show just the filename
            filename = path.split("/")[-1].split("\\")[-1]
            self.logo_path_label.setText(filename)

    def _on_pick_primary_color(self):
        """Open color picker for primary color."""
        color = QColorDialog.getColor(
            QColor(self._primary_color), self, "Select Primary Color"
        )
        if color.isValid():
            self._primary_color = color.name()
            self._update_color_preview()

    def _on_pick_secondary_color(self):
        """Open color picker for secondary color."""
        color = QColorDialog.getColor(
            QColor(self._secondary_color), self, "Select Secondary Color"
        )
        if color.isValid():
            self._secondary_color = color.name()
            self._update_color_preview()

    def _update_color_preview(self):
        """Update the color preview label with current colors."""
        self.color_preview_label.setText(
            f'<span style="color:{self._primary_color};">■</span> '
            f'<span style="color:{self._secondary_color};">■</span>'
        )

    # ------------------------------------------------------------------
    # Report Generation
    # ------------------------------------------------------------------

    def _on_generate_report(self):
        """Generate a report using the current template configuration."""
        if self.engagement_db is None:
            QMessageBox.warning(
                self,
                "Generate Report",
                "No engagement database is connected. Open an engagement first.",
            )
            return

        # Ensure we have a saved template to use
        name = self.template_name_input.text().strip()
        if not name:
            name = self.templates_combo.currentText()
        if not name:
            QMessageBox.warning(
                self,
                "Generate Report",
                "Please enter or select a template name before generating.",
            )
            return

        # Save current state as template first
        sections = self._get_sections_from_list()
        branding = self._get_branding_dict()
        severity = self.severity_combo.currentText().lower()

        try:
            template = self.customizer.create_template(
                name=name,
                sections=[s.to_dict() for s in sections],
                branding=branding,
                severity_threshold=severity,
            )
            self.customizer.save_template(template)
        except (ValueError, OSError) as e:
            QMessageBox.critical(
                self, "Template Error", f"Failed to prepare template: {e}"
            )
            return

        # Ask for output path
        format_text = self.format_combo.currentText()
        format_map = {
            "PDF": ("pdf", "PDF Files (*.pdf)"),
            "HTML": ("html", "HTML Files (*.html)"),
            "DOCX": ("docx", "Word Documents (*.docx)"),
            "Markdown": ("markdown", "Markdown Files (*.md)"),
        }
        fmt, file_filter = format_map.get(format_text, ("markdown", "Markdown Files (*.md)"))

        output_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Report As",
            f"report.{fmt if fmt != 'markdown' else 'md'}",
            f"{file_filter};;All Files (*)",
        )
        if not output_path:
            return

        try:
            result_path = self.customizer.generate_report(
                template_name=name,
                engagement_db=self.engagement_db,
                output_path=output_path,
                output_format=fmt,
            )
            self.report_generated.emit(result_path)

            # Load preview if markdown
            if fmt in ("markdown", "md"):
                self._load_preview_from_file(result_path)

            QMessageBox.information(
                self,
                "Report Generated",
                f"Report saved to:\n{result_path}",
            )
        except (FileNotFoundError, ValueError, ImportError, OSError) as e:
            QMessageBox.critical(
                self, "Generation Error", f"Failed to generate report: {e}"
            )

    # ------------------------------------------------------------------
    # Preview
    # ------------------------------------------------------------------

    def _on_refresh_preview(self):
        """Refresh the preview pane with current template markdown output."""
        if self.engagement_db is None:
            self._show_template_structure_preview()
            return

        name = self.template_name_input.text().strip()
        if not name:
            name = self.templates_combo.currentText()
        if not name:
            self._show_template_structure_preview()
            return

        # Save temporary template and generate markdown preview
        sections = self._get_sections_from_list()
        branding = self._get_branding_dict()
        severity = self.severity_combo.currentText().lower()

        try:
            template = self.customizer.create_template(
                name=name,
                sections=[s.to_dict() for s in sections],
                branding=branding,
                severity_threshold=severity,
            )
            self.customizer.save_template(template)

            import tempfile
            import os

            temp_path = os.path.join(
                tempfile.gettempdir(), "huginn_report_preview.md"
            )
            self.customizer.generate_report(
                template_name=name,
                engagement_db=self.engagement_db,
                output_path=temp_path,
                output_format="markdown",
            )
            self._load_preview_from_file(temp_path)
        except Exception as e:
            self.preview_pane.setPlainText(f"Preview error: {e}")

    def _show_template_structure_preview(self):
        """Show a structural preview of enabled sections without engagement data."""
        lines = ["# Report Template Preview", ""]
        sections = self._get_sections_from_list()
        branding = self._get_branding_dict()

        if branding.get("company_name"):
            lines.append(f"**Company:** {branding['company_name']}")
            lines.append("")

        lines.append("## Enabled Sections:")
        lines.append("")
        for i, section in enumerate(sections, 1):
            status = "✓" if section.enabled else "✗"
            lines.append(f"{i}. [{status}] {section.title}")
        lines.append("")
        lines.append(f"**Severity Threshold:** {self.severity_combo.currentText()}")
        lines.append(f"**Output Format:** {self.format_combo.currentText()}")

        self.preview_pane.setPlainText("\n".join(lines))

    def _load_preview_from_file(self, path: str):
        """Load a file's contents into the preview pane."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.preview_pane.setPlainText(content)
        except OSError:
            self.preview_pane.setPlainText("Failed to load preview file.")

    # ------------------------------------------------------------------
    # Section Helpers
    # ------------------------------------------------------------------

    def _on_sections_reordered(self):
        """Handle section list reorder (triggered by drag-and-drop)."""
        # The list order is now the authoritative order
        # Update the current template if we have one
        if self._current_template:
            new_order = []
            for i in range(self.section_list.count()):
                item = self.section_list.item(i)
                section_id = item.data(Qt.ItemDataRole.UserRole)
                if section_id:
                    new_order.append(section_id)
            try:
                self.customizer.reorder_sections(self._current_template, new_order)
            except ValueError:
                pass

    def _get_sections_from_list(self) -> list:
        """Extract ReportSection objects from the section list widget."""
        sections = []
        for i in range(self.section_list.count()):
            item = self.section_list.item(i)
            section_id = item.data(Qt.ItemDataRole.UserRole)
            title = item.text()
            enabled = item.checkState() == Qt.CheckState.Checked

            # Try to preserve conditional info from defaults
            conditional = False
            condition_key = None
            for default in DEFAULT_SECTIONS:
                if default["id"] == section_id:
                    conditional = default.get("conditional", False)
                    condition_key = default.get("condition_key")
                    break

            sections.append(
                ReportSection(
                    id=section_id or title.lower().replace(" ", "_"),
                    title=title,
                    enabled=enabled,
                    conditional=conditional,
                    condition_key=condition_key,
                )
            )
        return sections

    def _get_branding_dict(self) -> dict:
        """Build the branding configuration dictionary from UI fields."""
        return {
            "logo_path": self._logo_path,
            "company_name": self.company_name_input.text().strip(),
            "primary_color": self._primary_color,
            "secondary_color": self._secondary_color,
            "header_text": self.header_text_input.text().strip(),
            "footer_text": self.footer_text_input.text().strip(),
            "cover_page": True,
        }

    def _apply_template_to_ui(self, template: ReportTemplate):
        """Apply a loaded template's configuration to the UI widgets."""
        # Template name
        self.template_name_input.setText(template.name)

        # Sections
        self.section_list.clear()
        for section in template.sections:
            item = QListWidgetItem(section.title)
            item.setData(Qt.ItemDataRole.UserRole, section.id)
            item.setCheckState(
                Qt.CheckState.Checked if section.enabled else Qt.CheckState.Unchecked
            )
            self.section_list.addItem(item)

        # Branding
        branding = template.branding
        self.company_name_input.setText(branding.get("company_name", ""))
        self._logo_path = branding.get("logo_path", "")
        if self._logo_path:
            filename = self._logo_path.split("/")[-1].split("\\")[-1]
            self.logo_path_label.setText(filename)
        else:
            self.logo_path_label.setText("No logo selected")

        self._primary_color = branding.get("primary_color", "#2c3e50")
        self._secondary_color = branding.get("secondary_color", "#3498db")
        self._update_color_preview()

        self.header_text_input.setText(branding.get("header_text", ""))
        self.footer_text_input.setText(branding.get("footer_text", ""))

        # Severity threshold
        threshold = template.severity_threshold or "low"
        index = self.severity_combo.findText(threshold.capitalize())
        if index >= 0:
            self.severity_combo.setCurrentIndex(index)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
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
            QPushButton:pressed {
                background-color: rgba(60, 90, 120, 200);
            }
            QPushButton#generateBtn {
                background-color: rgba(20, 80, 100, 180);
                border: 2px solid #64C8FF;
                font-size: 14px;
            }
            QPushButton#generateBtn:hover {
                background-color: rgba(30, 100, 130, 220);
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
                font-family: 'Consolas', 'Courier New', monospace;
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
            QLabel#colorPreview {
                font-size: 18px;
                border: none;
                background: transparent;
            }
            QSplitter::handle {
                background-color: rgba(100, 200, 255, 40);
                width: 3px;
            }
        """)
