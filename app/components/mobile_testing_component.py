# app/components/mobile_testing_component.py
"""Mobile Testing UI Component.

Provides OWASP Mobile Top 10 2024 penetration testing interface with:
- OWASP Mobile Top 10 category tabs (M1-M10)
- Platform selector (Android / iOS / Cross-platform) via QComboBox
- Interactive checklist per category with Pass/Fail/Skip buttons
- Progress bars per category and overall
- Finding creation form with mobile-specific fields (platform, OWASP Mobile category)
- Integrates as sub-tab within Exploitation page

Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6
"""

from __future__ import annotations

from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.mobile_testing_engine import (
    CheckStatus,
    MobileCheckItem,
    MobilePlatform,
    MobileTestingEngine,
    OWASPMobileCategory,
)


# Mapping for short tab labels
_CATEGORY_SHORT_LABELS = {
    OWASPMobileCategory.M1: "M1: Credentials",
    OWASPMobileCategory.M2: "M2: Supply Chain",
    OWASPMobileCategory.M3: "M3: Auth",
    OWASPMobileCategory.M4: "M4: Input/Output",
    OWASPMobileCategory.M5: "M5: Communication",
    OWASPMobileCategory.M6: "M6: Privacy",
    OWASPMobileCategory.M7: "M7: Binary",
    OWASPMobileCategory.M8: "M8: Misconfig",
    OWASPMobileCategory.M9: "M9: Data Storage",
    OWASPMobileCategory.M10: "M10: Crypto",
}


class MobileTestingComponent(QWidget):
    """OWASP Mobile Top 10 2024 testing UI component.

    Provides platform-specific checklist workflows, progress tracking,
    and finding creation for mobile application penetration testing.

    Signals:
        finding_created(dict): Emitted when a new finding is created.
        progress_updated(int): Emitted with overall completion percentage.
    """

    finding_created = pyqtSignal(dict)
    progress_updated = pyqtSignal(int)

    def __init__(self, engine: MobileTestingEngine, parent=None):
        """Initialize the MobileTestingComponent.

        Args:
            engine: The MobileTestingEngine instance providing testing logic.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self.engine = engine
        self._check_widgets: Dict[str, "_CheckItemWidget"] = {}
        self._category_progress_bars: Dict[OWASPMobileCategory, QProgressBar] = {}

        self._setup_ui()
        self._apply_theme()
        self._connect_signals()
        self._refresh_all_progress()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the main layout with platform selector, progress, and category tabs."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Header
        header = QLabel("OWASP Mobile Top 10 Testing")
        header.setObjectName("sectionLabel")
        layout.addWidget(header)

        # Top bar: platform selector + overall progress
        top_bar = QHBoxLayout()
        top_bar.setSpacing(12)

        # Platform selector
        platform_label = QLabel("Platform:")
        platform_label.setObjectName("countLabel")
        top_bar.addWidget(platform_label)

        self.platform_combo = QComboBox()
        self.platform_combo.addItem("Cross-platform", MobilePlatform.CROSS_PLATFORM)
        self.platform_combo.addItem("Android", MobilePlatform.ANDROID)
        self.platform_combo.addItem("iOS", MobilePlatform.IOS)
        self.platform_combo.setMinimumWidth(160)
        top_bar.addWidget(self.platform_combo)

        top_bar.addStretch()

        # Overall progress
        overall_label = QLabel("Overall Progress:")
        overall_label.setObjectName("countLabel")
        top_bar.addWidget(overall_label)

        self.overall_progress_bar = QProgressBar()
        self.overall_progress_bar.setMinimumWidth(200)
        self.overall_progress_bar.setMaximumHeight(20)
        self.overall_progress_bar.setTextVisible(True)
        self.overall_progress_bar.setFormat("%v/%m (%p%)")
        top_bar.addWidget(self.overall_progress_bar)

        layout.addLayout(top_bar)

        # Category tabs
        self.category_tabs = QTabWidget()
        self._build_category_tabs()
        layout.addWidget(self.category_tabs, 1)

        # Finding creation form at the bottom
        self._build_finding_form(layout)

    def _build_category_tabs(self):
        """Build one tab per OWASP Mobile category with checklist and progress."""
        for cat_enum in OWASPMobileCategory:
            tab_widget = self._create_category_tab(cat_enum)
            label = _CATEGORY_SHORT_LABELS.get(cat_enum, cat_enum.name)
            self.category_tabs.addTab(tab_widget, label)

    def _create_category_tab(self, category: OWASPMobileCategory) -> QWidget:
        """Create a single category tab with progress bar and checklist."""
        container = QFrame()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # Category header and progress bar
        header_row = QHBoxLayout()
        cat_label = QLabel(category.value)
        cat_label.setObjectName("sectionLabel")
        cat_label.setWordWrap(True)
        header_row.addWidget(cat_label, 1)

        progress_bar = QProgressBar()
        progress_bar.setMinimumWidth(150)
        progress_bar.setMaximumHeight(18)
        progress_bar.setTextVisible(True)
        progress_bar.setFormat("%v/%m (%p%)")
        header_row.addWidget(progress_bar)
        self._category_progress_bars[category] = progress_bar

        layout.addLayout(header_row)

        # Scrollable checklist area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)

        checklist_widget = QWidget()
        checklist_layout = QVBoxLayout(checklist_widget)
        checklist_layout.setContentsMargins(4, 4, 4, 4)
        checklist_layout.setSpacing(6)
        checklist_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Populate check items
        checks = self.engine.get_checks_for_category(category)
        for check_item in checks:
            item_widget = _CheckItemWidget(check_item, self)
            item_widget.status_changed.connect(self._on_check_status_changed)
            checklist_layout.addWidget(item_widget)
            self._check_widgets[check_item.id] = item_widget

        scroll_area.setWidget(checklist_widget)
        layout.addWidget(scroll_area, 1)

        return container

    def _build_finding_form(self, parent_layout: QVBoxLayout):
        """Build the finding creation form with mobile-specific fields."""
        form_group = QGroupBox("Create Finding")
        form_layout = QVBoxLayout(form_group)
        form_layout.setSpacing(8)

        # Row 1: Title
        title_row = QHBoxLayout()
        title_row.addWidget(QLabel("Title:"))
        self.finding_title_input = QLineEdit()
        self.finding_title_input.setPlaceholderText("Finding title...")
        title_row.addWidget(self.finding_title_input)
        form_layout.addLayout(title_row)

        # Row 2: Severity + Platform + OWASP Category
        row2 = QHBoxLayout()

        row2.addWidget(QLabel("Severity:"))
        self.finding_severity_combo = QComboBox()
        self.finding_severity_combo.addItems(
            ["critical", "high", "medium", "low", "info"]
        )
        self.finding_severity_combo.setCurrentIndex(2)
        row2.addWidget(self.finding_severity_combo)

        row2.addWidget(QLabel("Platform:"))
        self.finding_platform_combo = QComboBox()
        self.finding_platform_combo.addItem("Cross-platform", MobilePlatform.CROSS_PLATFORM)
        self.finding_platform_combo.addItem("Android", MobilePlatform.ANDROID)
        self.finding_platform_combo.addItem("iOS", MobilePlatform.IOS)
        row2.addWidget(self.finding_platform_combo)

        row2.addWidget(QLabel("OWASP Category:"))
        self.finding_category_combo = QComboBox()
        for cat in OWASPMobileCategory:
            self.finding_category_combo.addItem(cat.value, cat)
        row2.addWidget(self.finding_category_combo)

        form_layout.addLayout(row2)

        # Row 3: CWE ID
        cwe_row = QHBoxLayout()
        cwe_row.addWidget(QLabel("CWE ID:"))
        self.finding_cwe_input = QLineEdit()
        self.finding_cwe_input.setPlaceholderText("e.g., CWE-312")
        self.finding_cwe_input.setMaximumWidth(200)
        cwe_row.addWidget(self.finding_cwe_input)
        cwe_row.addStretch()
        form_layout.addLayout(cwe_row)

        # Row 4: Description
        form_layout.addWidget(QLabel("Description:"))
        self.finding_desc_input = QTextEdit()
        self.finding_desc_input.setPlaceholderText("Detailed description of the finding...")
        self.finding_desc_input.setMaximumHeight(60)
        form_layout.addWidget(self.finding_desc_input)

        # Row 5: Impact + Remediation side by side
        impact_rem_row = QHBoxLayout()

        impact_col = QVBoxLayout()
        impact_col.addWidget(QLabel("Impact:"))
        self.finding_impact_input = QTextEdit()
        self.finding_impact_input.setPlaceholderText("Business/security impact...")
        self.finding_impact_input.setMaximumHeight(50)
        impact_col.addWidget(self.finding_impact_input)
        impact_rem_row.addLayout(impact_col)

        rem_col = QVBoxLayout()
        rem_col.addWidget(QLabel("Remediation:"))
        self.finding_remediation_input = QTextEdit()
        self.finding_remediation_input.setPlaceholderText("Recommended fix...")
        self.finding_remediation_input.setMaximumHeight(50)
        rem_col.addWidget(self.finding_remediation_input)
        impact_rem_row.addLayout(rem_col)

        form_layout.addLayout(impact_rem_row)

        # Row 6: Evidence
        form_layout.addWidget(QLabel("Evidence:"))
        self.finding_evidence_input = QTextEdit()
        self.finding_evidence_input.setPlaceholderText("Supporting evidence...")
        self.finding_evidence_input.setMaximumHeight(50)
        form_layout.addWidget(self.finding_evidence_input)

        # Submit button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        self.create_finding_btn = QPushButton("Create Finding")
        self.create_finding_btn.setMinimumHeight(34)
        self.create_finding_btn.setMinimumWidth(140)
        btn_row.addWidget(self.create_finding_btn)
        form_layout.addLayout(btn_row)

        parent_layout.addWidget(form_group)

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect UI signals to handler slots."""
        self.platform_combo.currentIndexChanged.connect(self._on_platform_changed)
        self.create_finding_btn.clicked.connect(self._on_create_finding)
        self.engine.check_completed.connect(self._on_engine_check_completed)
        self.engine.finding_created.connect(self._on_engine_finding_created)

    # ------------------------------------------------------------------
    # Action Handlers
    # ------------------------------------------------------------------

    def _on_platform_changed(self, index: int):
        """Handle platform selection change — rebuild checklists."""
        platform = self.platform_combo.currentData()
        if platform is None:
            return
        self.engine.set_platform(platform)
        self._rebuild_category_tabs()
        self._refresh_all_progress()

    def _on_check_status_changed(self, check_id: str, new_status: str):
        """Handle a check item's status being changed by the user."""
        if new_status == "passed":
            self.engine.mark_complete(check_id)
        elif new_status == "failed":
            self.engine.mark_failed(check_id)
        elif new_status == "skipped":
            self.engine.mark_not_applicable(check_id)
        self._refresh_all_progress()

    def _on_create_finding(self):
        """Handle the Create Finding button click."""
        title = self.finding_title_input.text().strip()
        if not title:
            return

        severity = self.finding_severity_combo.currentText()
        platform = self.finding_platform_combo.currentData()
        owasp_cat = self.finding_category_combo.currentData()
        description = self.finding_desc_input.toPlainText().strip()
        impact = self.finding_impact_input.toPlainText().strip()
        remediation = self.finding_remediation_input.toPlainText().strip()
        evidence = self.finding_evidence_input.toPlainText().strip()
        cwe_id = self.finding_cwe_input.text().strip()

        self.engine.create_finding(
            title=title,
            severity=severity,
            owasp_category=owasp_cat,
            platform=platform,
            description=description,
            impact=impact,
            remediation=remediation,
            evidence=evidence,
            cwe_id=cwe_id,
        )

        # Clear form after successful creation
        self._clear_finding_form()

    def _on_engine_check_completed(self, category_name: str, check_id: str):
        """Handle engine signal when a check is marked complete."""
        self._refresh_all_progress()

    def _on_engine_finding_created(self, finding_data: dict):
        """Handle engine signal when a finding is created."""
        self.finding_created.emit(finding_data)

    # ------------------------------------------------------------------
    # Progress Updates
    # ------------------------------------------------------------------

    def _refresh_all_progress(self):
        """Refresh all progress bars from engine state."""
        # Overall progress
        overall = self.engine.get_progress()
        total = overall.get("total", 0)
        completed = overall.get("completed", 0)
        self.overall_progress_bar.setMaximum(max(total, 1))
        self.overall_progress_bar.setValue(completed)

        # Per-category progress
        cat_progress = self.engine.get_category_progress()
        for cat_enum, progress in cat_progress.items():
            bar = self._category_progress_bars.get(cat_enum)
            if bar:
                cat_total = progress.get("total", 0)
                cat_completed = progress.get("completed", 0)
                bar.setMaximum(max(cat_total, 1))
                bar.setValue(cat_completed)

        # Emit overall percentage
        pct = int((completed / total * 100) if total > 0 else 0)
        self.progress_updated.emit(pct)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _rebuild_category_tabs(self):
        """Rebuild all category tabs after platform change."""
        self._check_widgets.clear()
        self._category_progress_bars.clear()
        self.category_tabs.clear()
        self._build_category_tabs()

    def _clear_finding_form(self):
        """Clear all fields in the finding creation form."""
        self.finding_title_input.clear()
        self.finding_severity_combo.setCurrentIndex(2)
        self.finding_desc_input.clear()
        self.finding_impact_input.clear()
        self.finding_remediation_input.clear()
        self.finding_evidence_input.clear()
        self.finding_cwe_input.clear()

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
                padding: 4px 8px;
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
                padding: 5px 10px;
                margin-right: 2px;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background-color: rgba(50, 70, 90, 200);
                border-color: #64C8FF;
                color: #64C8FF;
            }
            QTabBar::tab:hover {
                background-color: rgba(50, 70, 90, 150);
            }
            QProgressBar {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 60);
                border-radius: 4px;
                text-align: center;
                color: #DCDCDC;
                font-size: 10px;
            }
            QProgressBar::chunk {
                background-color: rgba(100, 200, 255, 180);
                border-radius: 3px;
            }
            QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 4px;
            }
            QTextEdit:focus {
                border: 2px solid #64C8FF;
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
# Check Item Widget (internal helper)
# ---------------------------------------------------------------------------

class _CheckItemWidget(QFrame):
    """A single interactive checklist item with Pass/Fail/Skip buttons.

    Displays the check item name, description, platform tag, and action buttons.
    Emits status_changed(check_id, new_status) when the user clicks a button.
    """

    status_changed = pyqtSignal(str, str)  # check_item_id, new_status

    # Status colors
    _STATUS_COLORS = {
        CheckStatus.NOT_STARTED: "#A0A0A0",
        CheckStatus.PASSED: "#A8E6CF",
        CheckStatus.FAILED: "#FF6B6B",
        CheckStatus.SKIPPED: "#FFD93D",
    }

    _STATUS_LABELS = {
        CheckStatus.NOT_STARTED: "⊘ Pending",
        CheckStatus.PASSED: "✓ Pass",
        CheckStatus.FAILED: "✗ Fail",
        CheckStatus.SKIPPED: "⊘ Skip",
    }

    def __init__(self, check_item: MobileCheckItem, parent=None):
        """Initialize the check item widget.

        Args:
            check_item: The MobileCheckItem data model.
            parent: Optional parent widget.
        """
        super().__init__(parent)
        self._check_item = check_item
        self._setup_ui()

    @property
    def check_id(self) -> str:
        """Return the check item ID."""
        return self._check_item.id

    def _setup_ui(self):
        """Build the check item row layout."""
        self.setFrameShape(QFrame.Shape.Box)
        self.setMinimumHeight(48)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(8)

        # Status indicator
        self.status_label = QLabel(self._STATUS_LABELS[self._check_item.status])
        self.status_label.setFixedWidth(70)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._update_status_color()
        layout.addWidget(self.status_label)

        # Check item info (name + description)
        info_col = QVBoxLayout()
        info_col.setSpacing(2)

        name_label = QLabel(self._check_item.name)
        name_label.setStyleSheet(
            "font-weight: bold; color: #DCDCDC; border: none; background: transparent;"
        )
        info_col.addWidget(name_label)

        desc_label = QLabel(self._check_item.description)
        desc_label.setStyleSheet(
            "color: #A0A0A0; font-size: 11px; border: none; background: transparent;"
        )
        desc_label.setWordWrap(True)
        info_col.addWidget(desc_label)

        layout.addLayout(info_col, 1)

        # Platform tag
        platform_text = self._check_item.platform.value.replace("_", " ").title()
        platform_tag = QLabel(platform_text)
        platform_tag.setStyleSheet(
            "color: #64C8FF; font-size: 10px; border: 1px solid rgba(100,200,255,80); "
            "border-radius: 3px; padding: 2px 6px; background: rgba(100,200,255,20);"
        )
        platform_tag.setFixedHeight(20)
        layout.addWidget(platform_tag)

        # Action buttons
        self.pass_btn = QPushButton("Pass")
        self.pass_btn.setFixedSize(60, 26)
        self.pass_btn.setStyleSheet(
            "QPushButton { background: rgba(168,230,207,40); border: 1px solid #A8E6CF; "
            "border-radius: 4px; color: #A8E6CF; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: rgba(168,230,207,80); }"
        )
        self.pass_btn.clicked.connect(lambda: self._set_status("passed"))
        layout.addWidget(self.pass_btn)

        self.fail_btn = QPushButton("Fail")
        self.fail_btn.setFixedSize(60, 26)
        self.fail_btn.setStyleSheet(
            "QPushButton { background: rgba(255,107,107,40); border: 1px solid #FF6B6B; "
            "border-radius: 4px; color: #FF6B6B; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: rgba(255,107,107,80); }"
        )
        self.fail_btn.clicked.connect(lambda: self._set_status("failed"))
        layout.addWidget(self.fail_btn)

        self.skip_btn = QPushButton("Skip")
        self.skip_btn.setFixedSize(60, 26)
        self.skip_btn.setStyleSheet(
            "QPushButton { background: rgba(255,217,61,40); border: 1px solid #FFD93D; "
            "border-radius: 4px; color: #FFD93D; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: rgba(255,217,61,80); }"
        )
        self.skip_btn.clicked.connect(lambda: self._set_status("skipped"))
        layout.addWidget(self.skip_btn)

    def _set_status(self, status: str):
        """Handle a status button click."""
        self.status_changed.emit(self._check_item.id, status)
        # Update local display
        status_enum = {
            "passed": CheckStatus.PASSED,
            "failed": CheckStatus.FAILED,
            "skipped": CheckStatus.SKIPPED,
        }.get(status, CheckStatus.NOT_STARTED)
        self._check_item.status = status_enum
        self.status_label.setText(self._STATUS_LABELS[status_enum])
        self._update_status_color()

    def _update_status_color(self):
        """Update the status label color based on current status."""
        color = self._STATUS_COLORS.get(self._check_item.status, "#A0A0A0")
        self.status_label.setStyleSheet(
            f"color: {color}; font-weight: bold; font-size: 11px; "
            f"border: none; background: transparent;"
        )
