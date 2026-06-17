# app/components/cvss_calculator_component.py
"""CVSS Calculator UI Component.

Provides a CVSS v3.1 and v4.0 scoring calculator dialog/panel with:
- Version toggle (v3.1 / v4.0) switching metric panels
- Metric selection buttons with tooltip descriptions
- Real-time score display updating on each metric change
- Severity label badge with color coding
- Vector string display with copy button
- "Apply to Finding" button for findings integration

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6
"""

from typing import Dict, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from app.core.cvss_calculator import CVSSCalculator, CVSSVersion, SEVERITY_RANGES


# ---------------------------------------------------------------------------
# Metric Definitions (labels, values, and tooltip descriptions)
# ---------------------------------------------------------------------------

V31_METRIC_DEFINITIONS = {
    "AV": {
        "name": "Attack Vector",
        "values": {
            "N": ("Network", "The vulnerability is exploitable over the network."),
            "A": ("Adjacent", "The vulnerability is exploitable from an adjacent network."),
            "L": ("Local", "The vulnerability requires local access to the target."),
            "P": ("Physical", "The vulnerability requires physical access to the target."),
        },
    },
    "AC": {
        "name": "Attack Complexity",
        "values": {
            "L": ("Low", "No specialized conditions needed for exploitation."),
            "H": ("High", "Exploitation requires special conditions beyond attacker control."),
        },
    },
    "PR": {
        "name": "Privileges Required",
        "values": {
            "N": ("None", "No privileges are required to exploit the vulnerability."),
            "L": ("Low", "Low-level privileges (e.g., basic user) are required."),
            "H": ("High", "High-level privileges (e.g., admin) are required."),
        },
    },
    "UI": {
        "name": "User Interaction",
        "values": {
            "N": ("None", "No user interaction is needed for exploitation."),
            "R": ("Required", "A user must interact for successful exploitation."),
        },
    },
    "S": {
        "name": "Scope",
        "values": {
            "U": ("Unchanged", "Impact is limited to the vulnerable component."),
            "C": ("Changed", "Impact extends beyond the vulnerable component."),
        },
    },
    "C": {
        "name": "Confidentiality",
        "values": {
            "N": ("None", "No impact to confidentiality."),
            "L": ("Low", "Limited confidentiality impact."),
            "H": ("High", "Total loss of confidentiality."),
        },
    },
    "I": {
        "name": "Integrity",
        "values": {
            "N": ("None", "No impact to integrity."),
            "L": ("Low", "Limited integrity impact."),
            "H": ("High", "Total loss of integrity."),
        },
    },
    "A": {
        "name": "Availability",
        "values": {
            "N": ("None", "No impact to availability."),
            "L": ("Low", "Limited availability impact."),
            "H": ("High", "Total loss of availability."),
        },
    },
}

V31_TEMPORAL_DEFINITIONS = {
    "E": {
        "name": "Exploit Code Maturity",
        "values": {
            "X": ("Not Defined", "Not factored into the score."),
            "U": ("Unproven", "No exploit code is available."),
            "P": ("Proof-of-Concept", "Proof-of-concept exploit code exists."),
            "F": ("Functional", "Functional exploit code is available."),
            "H": ("High", "Exploitation is actively occurring."),
        },
    },
    "RL": {
        "name": "Remediation Level",
        "values": {
            "X": ("Not Defined", "Not factored into the score."),
            "O": ("Official Fix", "An official patch or upgrade is available."),
            "T": ("Temporary Fix", "A temporary fix is available."),
            "W": ("Workaround", "An unofficial workaround exists."),
            "U": ("Unavailable", "No remediation is available."),
        },
    },
    "RC": {
        "name": "Report Confidence",
        "values": {
            "X": ("Not Defined", "Not factored into the score."),
            "U": ("Unknown", "Unconfirmed reports exist."),
            "R": ("Reasonable", "Multiple non-official sources agree."),
            "C": ("Confirmed", "Vulnerability confirmed by vendor or researcher."),
        },
    },
}

V40_METRIC_DEFINITIONS = {
    "AV": {
        "name": "Attack Vector",
        "values": {
            "N": ("Network", "The vulnerability is exploitable over the network."),
            "A": ("Adjacent", "The vulnerability is exploitable from an adjacent network."),
            "L": ("Local", "The vulnerability requires local access to the target."),
            "P": ("Physical", "The vulnerability requires physical access to the target."),
        },
    },
    "AC": {
        "name": "Attack Complexity",
        "values": {
            "L": ("Low", "No specialized conditions needed for exploitation."),
            "H": ("High", "Exploitation requires special conditions beyond attacker control."),
        },
    },
    "AT": {
        "name": "Attack Requirements",
        "values": {
            "N": ("None", "No prerequisite deployment or execution conditions needed."),
            "P": ("Present", "Specific conditions must be present for exploitation."),
        },
    },
    "PR": {
        "name": "Privileges Required",
        "values": {
            "N": ("None", "No privileges are required to exploit the vulnerability."),
            "L": ("Low", "Low-level privileges (e.g., basic user) are required."),
            "H": ("High", "High-level privileges (e.g., admin) are required."),
        },
    },
    "UI": {
        "name": "User Interaction",
        "values": {
            "N": ("None", "No user interaction is needed for exploitation."),
            "P": ("Passive", "User interaction is needed but no active engagement."),
            "A": ("Active", "User must actively interact for exploitation."),
        },
    },
    "VC": {
        "name": "Vulnerable System Confidentiality",
        "values": {
            "H": ("High", "Total loss of confidentiality on the vulnerable system."),
            "L": ("Low", "Limited confidentiality impact on the vulnerable system."),
            "N": ("None", "No confidentiality impact on the vulnerable system."),
        },
    },
    "VI": {
        "name": "Vulnerable System Integrity",
        "values": {
            "H": ("High", "Total loss of integrity on the vulnerable system."),
            "L": ("Low", "Limited integrity impact on the vulnerable system."),
            "N": ("None", "No integrity impact on the vulnerable system."),
        },
    },
    "VA": {
        "name": "Vulnerable System Availability",
        "values": {
            "H": ("High", "Total loss of availability on the vulnerable system."),
            "L": ("Low", "Limited availability impact on the vulnerable system."),
            "N": ("None", "No availability impact on the vulnerable system."),
        },
    },
    "SC": {
        "name": "Subsequent System Confidentiality",
        "values": {
            "H": ("High", "Total loss of confidentiality on subsequent systems."),
            "L": ("Low", "Limited confidentiality impact on subsequent systems."),
            "N": ("None", "No confidentiality impact on subsequent systems."),
        },
    },
    "SI": {
        "name": "Subsequent System Integrity",
        "values": {
            "H": ("High", "Total loss of integrity on subsequent systems."),
            "L": ("Low", "Limited integrity impact on subsequent systems."),
            "N": ("None", "No integrity impact on subsequent systems."),
        },
    },
    "SA": {
        "name": "Subsequent System Availability",
        "values": {
            "H": ("High", "Total loss of availability on subsequent systems."),
            "L": ("Low", "Limited availability impact on subsequent systems."),
            "N": ("None", "No availability impact on subsequent systems."),
        },
    },
}

# Severity badge colors
SEVERITY_COLORS = {
    "None": "#808080",
    "Low": "#4A90D9",
    "Medium": "#F5A623",
    "High": "#E57320",
    "Critical": "#D0021B",
}


# ---------------------------------------------------------------------------
# CVSS Calculator Component
# ---------------------------------------------------------------------------

class CVSSCalculatorComponent(QWidget):
    """CVSS Calculator UI component for scoring vulnerabilities.

    Can be used as a standalone dialog or embedded panel. Provides real-time
    CVSS v3.1 and v4.0 score computation with metric selection buttons.

    Signals:
        apply_to_finding(float, str): Emitted when user clicks "Apply to Finding".
            Carries (score, vector_string).
        score_changed(float, str): Emitted on each metric selection change.
            Carries (current_score, current_vector).
    """

    apply_to_finding = pyqtSignal(float, str)
    score_changed = pyqtSignal(float, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._calculator = CVSSCalculator()
        self._current_version = CVSSVersion.V3_1
        self._metrics: Dict[str, str] = {}
        self._metric_buttons: Dict[str, Dict[str, QPushButton]] = {}

        self._setup_ui()
        self._apply_theme()
        self._reset_metrics()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the calculator layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Title
        title = QLabel("CVSS Calculator")
        title.setStyleSheet(
            "font-size: 16pt; font-weight: bold; color: #64C8FF; margin-bottom: 4px;"
        )
        layout.addWidget(title)

        # Version toggle row
        layout.addWidget(self._create_version_toggle())

        # Score display row
        layout.addWidget(self._create_score_display())

        # Vector string row
        layout.addWidget(self._create_vector_display())

        # Metrics scroll area
        self._metrics_scroll = QScrollArea()
        self._metrics_scroll.setWidgetResizable(True)
        self._metrics_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._metrics_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self._v31_panel = self._create_v31_metrics_panel()
        self._v40_panel = self._create_v40_metrics_panel()
        self._v40_panel.setVisible(False)

        # Container for metric panels
        self._metrics_container = QWidget()
        metrics_container_layout = QVBoxLayout(self._metrics_container)
        metrics_container_layout.setContentsMargins(0, 0, 0, 0)
        metrics_container_layout.addWidget(self._v31_panel)
        metrics_container_layout.addWidget(self._v40_panel)

        self._metrics_scroll.setWidget(self._metrics_container)
        layout.addWidget(self._metrics_scroll, 1)

        # Bottom buttons
        layout.addWidget(self._create_action_buttons())

    def _create_version_toggle(self) -> QWidget:
        """Create version toggle buttons (v3.1 / v4.0)."""
        container = QWidget()
        h_layout = QHBoxLayout(container)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(8)

        label = QLabel("Version:")
        label.setStyleSheet("color: #DCDCDC; font-size: 10pt;")
        h_layout.addWidget(label)

        self._version_group = QButtonGroup(self)
        self._version_group.setExclusive(True)

        self._v31_btn = QPushButton("CVSS v3.1")
        self._v31_btn.setCheckable(True)
        self._v31_btn.setChecked(True)
        self._v31_btn.setMinimumHeight(30)
        self._version_group.addButton(self._v31_btn, 0)
        h_layout.addWidget(self._v31_btn)

        self._v40_btn = QPushButton("CVSS v4.0")
        self._v40_btn.setCheckable(True)
        self._v40_btn.setMinimumHeight(30)
        self._version_group.addButton(self._v40_btn, 1)
        h_layout.addWidget(self._v40_btn)

        h_layout.addStretch()

        # Reset button
        self._reset_btn = QPushButton("Reset")
        self._reset_btn.setMinimumHeight(30)
        self._reset_btn.clicked.connect(self._reset_metrics)
        h_layout.addWidget(self._reset_btn)

        self._version_group.buttonClicked.connect(self._on_version_changed)
        return container

    def _create_score_display(self) -> QWidget:
        """Create the score and severity display row."""
        container = QFrame()
        container.setObjectName("scoreFrame")
        h_layout = QHBoxLayout(container)
        h_layout.setContentsMargins(12, 8, 12, 8)
        h_layout.setSpacing(16)

        # Score value
        score_label = QLabel("Score:")
        score_label.setStyleSheet("color: #DCDCDC; font-size: 11pt;")
        h_layout.addWidget(score_label)

        self._score_value = QLabel("0.0")
        self._score_value.setStyleSheet(
            "font-size: 24pt; font-weight: bold; color: #64C8FF;"
        )
        h_layout.addWidget(self._score_value)

        # Severity badge
        self._severity_badge = QLabel("None")
        self._severity_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._severity_badge.setMinimumWidth(90)
        self._severity_badge.setStyleSheet(self._severity_badge_style("None"))
        h_layout.addWidget(self._severity_badge)

        h_layout.addStretch()

        # Temporal / Environmental scores for v3.1
        self._temporal_label = QLabel("Temporal: —")
        self._temporal_label.setStyleSheet("color: #A0A0A0; font-size: 9pt;")
        h_layout.addWidget(self._temporal_label)

        self._env_label = QLabel("Environmental: —")
        self._env_label.setStyleSheet("color: #A0A0A0; font-size: 9pt;")
        h_layout.addWidget(self._env_label)

        return container

    def _create_vector_display(self) -> QWidget:
        """Create the vector string display with copy button."""
        container = QWidget()
        h_layout = QHBoxLayout(container)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(8)

        vec_label = QLabel("Vector:")
        vec_label.setStyleSheet("color: #DCDCDC; font-size: 10pt;")
        h_layout.addWidget(vec_label)

        self._vector_input = QLineEdit()
        self._vector_input.setReadOnly(True)
        self._vector_input.setPlaceholderText("Select metrics to generate vector string")
        h_layout.addWidget(self._vector_input, 1)

        self._copy_btn = QPushButton("Copy")
        self._copy_btn.setMinimumHeight(28)
        self._copy_btn.setMaximumWidth(70)
        self._copy_btn.clicked.connect(self._copy_vector_string)
        h_layout.addWidget(self._copy_btn)

        return container

    def _create_v31_metrics_panel(self) -> QWidget:
        """Create the v3.1 base + temporal metrics panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        # Base metrics section
        base_group = QGroupBox("Base Metrics")
        base_layout = QVBoxLayout(base_group)
        base_layout.setSpacing(4)

        for metric_key, metric_def in V31_METRIC_DEFINITIONS.items():
            base_layout.addWidget(
                self._create_metric_row(metric_key, metric_def, "v31")
            )

        layout.addWidget(base_group)

        # Temporal metrics section
        temporal_group = QGroupBox("Temporal Metrics (Optional)")
        temporal_layout = QVBoxLayout(temporal_group)
        temporal_layout.setSpacing(4)

        for metric_key, metric_def in V31_TEMPORAL_DEFINITIONS.items():
            temporal_layout.addWidget(
                self._create_metric_row(metric_key, metric_def, "v31")
            )

        layout.addWidget(temporal_group)
        layout.addStretch()
        return panel

    def _create_v40_metrics_panel(self) -> QWidget:
        """Create the v4.0 base metrics panel."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        base_group = QGroupBox("Base Metrics")
        base_layout = QVBoxLayout(base_group)
        base_layout.setSpacing(4)

        for metric_key, metric_def in V40_METRIC_DEFINITIONS.items():
            base_layout.addWidget(
                self._create_metric_row(metric_key, metric_def, "v40")
            )

        layout.addWidget(base_group)
        layout.addStretch()
        return panel

    def _create_metric_row(self, metric_key: str, metric_def: dict,
                           version_prefix: str) -> QWidget:
        """Create a single metric row with label and value buttons."""
        row = QWidget()
        h_layout = QHBoxLayout(row)
        h_layout.setContentsMargins(4, 2, 4, 2)
        h_layout.setSpacing(6)

        # Metric name label
        name_label = QLabel(f"{metric_def['name']} ({metric_key}):")
        name_label.setMinimumWidth(200)
        name_label.setMaximumWidth(200)
        name_label.setStyleSheet("color: #DCDCDC; font-size: 9pt;")
        h_layout.addWidget(name_label)

        # Button group for this metric
        btn_group = QButtonGroup(row)
        btn_group.setExclusive(True)

        full_key = f"{version_prefix}_{metric_key}"
        self._metric_buttons[full_key] = {}

        for value_code, (value_label, tooltip_text) in metric_def["values"].items():
            btn = QPushButton(value_label)
            btn.setCheckable(True)
            btn.setToolTip(f"{value_code}: {tooltip_text}")
            btn.setMinimumHeight(26)
            btn.setMinimumWidth(50)
            btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            btn.setProperty("metric_key", metric_key)
            btn.setProperty("metric_value", value_code)
            btn.setProperty("version_prefix", version_prefix)
            btn_group.addButton(btn)
            h_layout.addWidget(btn)
            self._metric_buttons[full_key][value_code] = btn

        btn_group.buttonClicked.connect(self._on_metric_button_clicked)
        h_layout.addStretch()
        return row

    def _create_action_buttons(self) -> QWidget:
        """Create the bottom action buttons."""
        container = QWidget()
        h_layout = QHBoxLayout(container)
        h_layout.setContentsMargins(0, 8, 0, 0)
        h_layout.setSpacing(10)

        h_layout.addStretch()

        self._apply_btn = QPushButton("Apply to Finding")
        self._apply_btn.setMinimumHeight(36)
        self._apply_btn.setMinimumWidth(150)
        self._apply_btn.clicked.connect(self._on_apply_to_finding)
        h_layout.addWidget(self._apply_btn)

        return container

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
        """Apply dark theme with cyan accent styling."""
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #DCDCDC;
            }
            QGroupBox {
                font-weight: bold;
                font-size: 10pt;
                border: 1px solid rgba(100, 200, 255, 80);
                border-radius: 5px;
                margin-top: 12px;
                padding-top: 14px;
            }
            QGroupBox::title {
                color: #64C8FF;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QFrame#scoreFrame {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 6px;
            }
            QLineEdit {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                padding: 5px 8px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 9pt;
            }
            QPushButton {
                background-color: rgba(40, 50, 60, 180);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 80);
                border-radius: 4px;
                padding: 4px 10px;
                font-size: 9pt;
            }
            QPushButton:hover {
                background-color: rgba(60, 80, 100, 200);
                border-color: rgba(100, 200, 255, 160);
            }
            QPushButton:checked {
                background-color: rgba(100, 200, 255, 150);
                color: #000000;
                font-weight: bold;
                border-color: #64C8FF;
            }
            QPushButton#applyBtn {
                background-color: rgba(100, 200, 255, 140);
                color: #000000;
                font-weight: bold;
                font-size: 10pt;
                border: none;
                border-radius: 5px;
            }
            QPushButton#applyBtn:hover {
                background-color: rgba(100, 200, 255, 200);
            }
            QPushButton#resetBtn {
                background-color: rgba(255, 165, 0, 120);
                color: #000000;
                font-weight: bold;
                border: none;
                border-radius: 4px;
            }
            QPushButton#resetBtn:hover {
                background-color: rgba(255, 165, 0, 180);
            }
            QPushButton#copyBtn {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
                font-weight: bold;
                border: none;
                border-radius: 4px;
            }
            QPushButton#copyBtn:hover {
                background-color: rgba(100, 200, 255, 170);
            }
            QScrollArea {
                border: none;
                background: transparent;
            }
            QScrollBar:vertical {
                background-color: rgba(20, 30, 40, 100);
                width: 10px;
                border-radius: 5px;
            }
            QScrollBar::handle:vertical {
                background-color: rgba(100, 200, 255, 100);
                border-radius: 5px;
                min-height: 30px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        # Set object names for specific button styling
        self._apply_btn.setObjectName("applyBtn")
        self._reset_btn.setObjectName("resetBtn")
        self._copy_btn.setObjectName("copyBtn")

    @staticmethod
    def _severity_badge_style(severity: str) -> str:
        """Return stylesheet for severity badge given a severity label."""
        color = SEVERITY_COLORS.get(severity, "#808080")
        return (
            f"background-color: {color}; color: #FFFFFF; font-weight: bold; "
            f"font-size: 10pt; padding: 4px 12px; border-radius: 4px;"
        )

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_version_changed(self, button: QPushButton):
        """Handle version toggle change."""
        if button == self._v31_btn:
            self._current_version = CVSSVersion.V3_1
            self._v31_panel.setVisible(True)
            self._v40_panel.setVisible(False)
            self._temporal_label.setVisible(True)
            self._env_label.setVisible(True)
        else:
            self._current_version = CVSSVersion.V4_0
            self._v31_panel.setVisible(False)
            self._v40_panel.setVisible(True)
            self._temporal_label.setVisible(False)
            self._env_label.setVisible(False)

        self._reset_metrics()

    def _on_metric_button_clicked(self, button: QPushButton):
        """Handle metric value button click."""
        metric_key = button.property("metric_key")
        metric_value = button.property("metric_value")
        version_prefix = button.property("version_prefix")

        # Only process if the button version matches the current version
        expected_prefix = "v31" if self._current_version == CVSSVersion.V3_1 else "v40"
        if version_prefix != expected_prefix:
            return

        self._metrics[metric_key] = metric_value
        self._update_score()

    def _on_apply_to_finding(self):
        """Emit the apply_to_finding signal with current score and vector."""
        score = self._get_current_base_score()
        vector = self._vector_input.text()
        if vector:
            self.apply_to_finding.emit(score, vector)

    def _copy_vector_string(self):
        """Copy the current vector string to clipboard."""
        vector = self._vector_input.text()
        if vector:
            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(vector)

    def _reset_metrics(self):
        """Reset all metric selections for the current version."""
        self._metrics.clear()

        # Uncheck all buttons for the current version
        prefix = "v31" if self._current_version == CVSSVersion.V3_1 else "v40"
        for full_key, buttons in self._metric_buttons.items():
            if full_key.startswith(prefix):
                for btn in buttons.values():
                    btn.setChecked(False)

        # Reset display
        self._score_value.setText("0.0")
        self._score_value.setStyleSheet(
            "font-size: 24pt; font-weight: bold; color: #64C8FF;"
        )
        self._severity_badge.setText("None")
        self._severity_badge.setStyleSheet(self._severity_badge_style("None"))
        self._vector_input.clear()
        self._temporal_label.setText("Temporal: —")
        self._env_label.setText("Environmental: —")
        self.score_changed.emit(0.0, "")

    # ------------------------------------------------------------------
    # Score Computation
    # ------------------------------------------------------------------

    def _update_score(self):
        """Recompute and display the score based on current metric selections."""
        if not self._has_required_base_metrics():
            # Not enough metrics selected yet - show partial state
            self._score_value.setText("—")
            self._severity_badge.setText("Incomplete")
            self._severity_badge.setStyleSheet(self._severity_badge_style("None"))
            self._vector_input.clear()
            return

        try:
            base_score, temporal_score, env_score = self._calculator.compute_score(
                self._current_version, self._metrics
            )
            vector_string = self._calculator.generate_vector_string(
                self._current_version, self._metrics
            )
            severity = self._calculator.get_severity_label(base_score)

            # Update score display
            self._score_value.setText(f"{base_score:.1f}")
            score_color = SEVERITY_COLORS.get(severity, "#64C8FF")
            self._score_value.setStyleSheet(
                f"font-size: 24pt; font-weight: bold; color: {score_color};"
            )

            # Update severity badge
            self._severity_badge.setText(severity)
            self._severity_badge.setStyleSheet(self._severity_badge_style(severity))

            # Update vector string
            self._vector_input.setText(vector_string)

            # Update temporal/environmental labels for v3.1
            if self._current_version == CVSSVersion.V3_1:
                if temporal_score != base_score:
                    self._temporal_label.setText(f"Temporal: {temporal_score:.1f}")
                else:
                    self._temporal_label.setText("Temporal: —")
                if env_score > 0.0:
                    self._env_label.setText(f"Environmental: {env_score:.1f}")
                else:
                    self._env_label.setText("Environmental: —")

            # Emit signal
            self.score_changed.emit(base_score, vector_string)

        except (ValueError, KeyError):
            # Metrics incomplete or invalid - keep partial display
            self._score_value.setText("—")
            self._severity_badge.setText("Error")
            self._severity_badge.setStyleSheet(self._severity_badge_style("None"))

    def _has_required_base_metrics(self) -> bool:
        """Check if all required base metrics are selected."""
        if self._current_version == CVSSVersion.V3_1:
            required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        else:
            required = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

        return all(m in self._metrics for m in required)

    def _get_current_base_score(self) -> float:
        """Get the current base score from the display."""
        try:
            return float(self._score_value.text())
        except (ValueError, TypeError):
            return 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_vector_string(self, vector: str):
        """Load a vector string into the calculator, setting all metrics.

        Args:
            vector: A standard CVSS vector string to parse and display.
        """
        try:
            version, metrics = self._calculator.parse_vector_string(vector)

            # Switch to correct version
            if version == CVSSVersion.V3_1:
                self._v31_btn.setChecked(True)
                self._on_version_changed(self._v31_btn)
            else:
                self._v40_btn.setChecked(True)
                self._on_version_changed(self._v40_btn)

            # Set metrics and update buttons
            self._metrics = metrics
            prefix = "v31" if version == CVSSVersion.V3_1 else "v40"

            for metric_key, value_code in metrics.items():
                full_key = f"{prefix}_{metric_key}"
                if full_key in self._metric_buttons:
                    if value_code in self._metric_buttons[full_key]:
                        self._metric_buttons[full_key][value_code].setChecked(True)

            self._update_score()

        except ValueError:
            # Invalid vector string - ignore silently
            pass

    def get_score(self) -> float:
        """Get the current computed base score.

        Returns:
            Current base score, or 0.0 if metrics are incomplete.
        """
        return self._get_current_base_score()

    def get_vector_string(self) -> str:
        """Get the current vector string.

        Returns:
            Current CVSS vector string, or empty string if incomplete.
        """
        return self._vector_input.text()

    def get_severity(self) -> str:
        """Get the current severity label.

        Returns:
            Severity label string (None, Low, Medium, High, Critical).
        """
        return self._severity_badge.text()
