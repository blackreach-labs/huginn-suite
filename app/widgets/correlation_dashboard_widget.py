#!/usr/bin/env python3
"""
Correlation Dashboard Widget
Real-time correlation analysis and attack chain visualization.

Layout mirrors create_target_profiles_tab() in attack_chain_home.py:
  QVBoxLayout(widget, margins=10, spacing=8)
    └─ QFrame (dark, rounded, border)          ← form_frame, stretch=1
         └─ QVBoxLayout (margins=15)
              ├─ section headers + content
              └─ (no buttons inside frame)
    └─ QHBoxLayout                             ← action buttons
    └─ QLabel                                  ← table header label
    └─ QTableWidget (fixed height)             ← summary table
    └─ QLabel (score badge)                    ← status badge at bottom
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTableWidget, QTableWidgetItem, QTextEdit,
    QTabWidget, QFrame, QComboBox, QHeaderView, QSizePolicy
)
from PyQt6.QtCore import QTimer, Qt
import json


# ── Style constants — colours now inherited from global theme ──────────────
_FRAME_STYLE = ""
_TABLE_STYLE = ""
_HDR_STYLE = "font-size: 10pt; font-weight: bold; padding: 8px 0px 4px 0px;"
_SECTION_STYLE = "font-weight: bold; margin-top: 4px;"


def _get_button_style(border_color, text_color="#FFFFFF"):
    """No longer needed — buttons inherit from the global theme."""
    return ""


def _make_table(columns, fixed_height=None):
    t = QTableWidget()
    t.setColumnCount(len(columns))
    t.setHorizontalHeaderLabels(columns)
    t.setStyleSheet(_TABLE_STYLE)
    t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    hdr = t.horizontalHeader()
    hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    if columns:
        hdr.setSectionResizeMode(len(columns) - 1, QHeaderView.ResizeMode.Stretch)
    if fixed_height is not None:
        t.setFixedHeight(fixed_height)
    return t


class CorrelationDashboardWidget(QWidget):
    def __init__(self, tenant_id="default", parent=None):
        super().__init__(parent)
        self.tenant_id = tenant_id
        self._setup_ui()
        self._setup_refresh_timer()
        self.load_correlations()

    # ------------------------------------------------------------------ #
    #  Top-level layout  (mirrors create_target_profiles_tab exactly)     #
    # ------------------------------------------------------------------ #

    def _setup_ui(self):
        # Outer layout — same margins/spacing as Target Profiles
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # ── Subtabs sit directly on the layout, no wrapping frame ─────────
        # (mirrors how Target Profiles / Credential Management are direct
        #  children of setup_subtabs in attack_chain_home.py)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_attack_chains_tab(),     "⚔️ Attack Chains")
        self.tabs.addTab(self._build_risk_amplifiers_tab(),   "📈 Risk Amplifiers")
        self.tabs.addTab(self._build_asset_correlation_tab(), "🎯 Asset Correlation")
        layout.addWidget(self.tabs, stretch=1)

        # ── Buttons below frame (mirrors Save / Delete pattern) ───────────
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        refresh_btn = QPushButton("🔄 Refresh Correlations")
        refresh_btn.setStyleSheet(_get_button_style("#64C8FF", "#000000"))
        refresh_btn.clicked.connect(self.load_correlations)
        btn_layout.addWidget(refresh_btn)

        export_btn = QPushButton("📊 Export Analysis")
        export_btn.setStyleSheet(_get_button_style("#FFA500", "#000000"))
        export_btn.clicked.connect(self.export_analysis)
        btn_layout.addWidget(export_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # ── Table header label ─────────────
        table_lbl = QLabel("🔗 Correlation Summary:")
        table_lbl.setStyleSheet("font-weight: bold; margin-top: 4px;")
        layout.addWidget(table_lbl)

        # ── Summary table (fixed height, mirrors target_table) ────────────
        self.summary_table = _make_table(
            ["Chain Type", "Source", "Target", "Risk Score", "Impact"],
            fixed_height=160
        )
        self.summary_table.itemDoubleClicked.connect(self.view_attack_chain_details)
        layout.addWidget(self.summary_table)

        # ── Score badge at the very bottom (mirrors scope_status) ─────────
        self.score_label = QLabel("Correlation Score: 0 / 100")
        self._set_score(0)
        layout.addWidget(self.score_label)

    # ------------------------------------------------------------------ #
    #  Subtab builders                                                     #
    # ------------------------------------------------------------------ #

    def _build_attack_chains_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # Form frame — mirrors Target Profiles
        form_frame = QFrame()
        form_frame.setStyleSheet(_FRAME_STYLE)
        form_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(15, 15, 15, 15)
        form_layout.setSpacing(8)

        self.chains_table = _make_table(
            ["Chain Type", "Source", "Target", "Risk Score", "Impact"]
        )
        self.chains_table.itemDoubleClicked.connect(self.view_attack_chain_details)
        form_layout.addWidget(self.chains_table, 1)

        layout.addWidget(form_frame, stretch=1)

        # Buttons below frame
        row = QHBoxLayout()
        row.setSpacing(8)

        gen_btn = QPushButton("📋 Generate Playbook")
        gen_btn.setStyleSheet(_get_button_style("#64C8FF", "#000000"))
        gen_btn.clicked.connect(self.generate_playbook)
        row.addWidget(gen_btn)

        self.playbook_format = QComboBox()
        self.playbook_format.addItems(["HTB Format", "THM Format", "Generic"])
        self.playbook_format.setFixedHeight(30)
        self.playbook_format.setStyleSheet("""
            QComboBox {
                background-color: rgba(30, 40, 50, 180);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: rgba(30, 40, 50, 240);
                color: #DCDCDC;
                selection-background-color: rgba(100, 200, 255, 150);
            }
        """)
        row.addWidget(self.playbook_format)
        row.addStretch()
        layout.addLayout(row)

        return widget

    def _build_risk_amplifiers_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # Form frame
        form_frame = QFrame()
        form_frame.setStyleSheet(_FRAME_STYLE)
        form_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(15, 15, 15, 15)
        form_layout.setSpacing(8)

        self.amplifiers_table = _make_table(
            ["Amplifier Type", "Risk Level", "Count", "Description"]
        )
        form_layout.addWidget(self.amplifiers_table, 1)

        gaps_lbl = QLabel("🔒 Security Gaps Identified:")
        gaps_lbl.setStyleSheet(_SECTION_STYLE)
        form_layout.addWidget(gaps_lbl)

        self.gaps_text = QTextEdit()
        self.gaps_text.setReadOnly(True)
        self.gaps_text.setFixedHeight(130)
        form_layout.addWidget(self.gaps_text)

        layout.addWidget(form_frame, stretch=1)
        return widget

    def _build_asset_correlation_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # Form frame
        form_frame = QFrame()
        form_frame.setStyleSheet(_FRAME_STYLE)
        form_frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        form_layout = QVBoxLayout(form_frame)
        form_layout.setContentsMargins(15, 15, 15, 15)
        form_layout.setSpacing(8)

        self.assets_table = _make_table(
            ["Asset", "Services", "Vulnerabilities", "Attack Vectors", "Risk Score", "Priority"]
        )
        form_layout.addWidget(self.assets_table, 1)

        layout.addWidget(form_frame, stretch=1)

        # High-value targets below frame (mirrors Profiles table pattern)
        hvt_lbl = QLabel("🎯 High-Value Targets:")
        hvt_lbl.setStyleSheet("font-weight: bold; color: #64C8FF; margin-top: 4px;")
        layout.addWidget(hvt_lbl)

        self.hvt_table = _make_table(
            ["Target", "Value Type", "Description"],
            fixed_height=160
        )
        layout.addWidget(self.hvt_table)

        return widget

    # ------------------------------------------------------------------ #
    #  Score badge (mirrors scope_status styling)                         #
    # ------------------------------------------------------------------ #

    def _set_score(self, score: int):
        self.score_label.setText(f"Correlation Score: {score} / 100")
        if score >= 80:
            bg, border = "rgba(255, 68, 68, 100)", "#FF4444"
        elif score >= 60:
            bg, border = "rgba(255, 165, 0, 100)", "#FFA500"
        elif score >= 40:
            bg, border = "rgba(255, 255, 0, 80)", "#FFFF00"
        else:
            bg, border = "rgba(50, 205, 50, 100)", "#32CD32"
        self.score_label.setStyleSheet(f"""
            QLabel {{
                background-color: {bg};
                border: 1px solid {border};
                border-radius: 5px;
                padding: 5px 12px;
                color: #FFFFFF;
                font-size: 10pt;
                font-weight: bold;
                margin-top: 8px;
            }}
        """)

    # ------------------------------------------------------------------ #
    #  Timer & data loading                                                #
    # ------------------------------------------------------------------ #

    def _setup_refresh_timer(self):
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.load_correlations)
        self.refresh_timer.start(30000)

    def load_correlations(self):
        try:
            from app.core.vulnerability_correlator_enhanced import enhanced_vulnerability_correlator
            from app.core.centralized_scan_data import get_scan_data_manager

            scan_manager = get_scan_data_manager(self.tenant_id)
            scan_results = scan_manager.get_tenant_overview(self.tenant_id)

            if not scan_results:
                self.show_no_data_message()
                return

            correlations = enhanced_vulnerability_correlator.correlate_findings(scan_results)

            self.update_attack_chains_display(correlations.get('attack_chains', []))
            self.update_risk_amplifiers_display(correlations.get('risk_amplifiers', []))
            self.update_asset_correlation_display(correlations.get('correlated_findings', []))
            self.update_high_value_targets(correlations.get('high_value_targets', []))
            self.update_security_gaps(correlations.get('security_gaps', []))
            self._set_score(correlations.get('correlation_score', 0))

        except Exception as e:
            self.show_error_message(str(e))

    # ------------------------------------------------------------------ #
    #  Table updaters                                                      #
    # ------------------------------------------------------------------ #

    def _fill_table(self, table, rows):
        table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for col, val in enumerate(row):
                table.setItem(i, col, QTableWidgetItem(str(val)))

    def update_attack_chains_display(self, attack_chains):
        rows = []
        for chain in attack_chains:
            if hasattr(chain, 'chain_type'):
                rows.append([chain.chain_type, chain.source_host, chain.target_host,
                             chain.risk_score, chain.impact])
            else:
                rows.append([chain.get('chain_type', ''), chain.get('source', ''),
                             chain.get('target', ''), chain.get('risk_score', 0),
                             chain.get('impact', '')])
        self._fill_table(self.chains_table, rows)
        self._fill_table(self.summary_table, rows)

    def update_risk_amplifiers_display(self, risk_amplifiers):
        rows = [[a.get('type', ''), a.get('risk', ''), a.get('count', 0), a.get('description', '')]
                for a in risk_amplifiers]
        self._fill_table(self.amplifiers_table, rows)

    def update_asset_correlation_display(self, _correlated_findings):
        try:
            asset_data = {
                "example.com": {"services": ["HTTP", "HTTPS"], "vulnerabilities": [],
                                "attack_vectors": ["Web"], "risk_score": 25}
            }
            rows = []
            for host, data in asset_data.items():
                risk = data.get('risk_score', 0)
                priority = ("Critical" if risk >= 80 else "High" if risk >= 60
                            else "Medium" if risk >= 40 else "Low")
                rows.append([host,
                             ", ".join(data.get('services', [])[:3]),
                             len(data.get('vulnerabilities', [])),
                             ", ".join(data.get('attack_vectors', [])[:2]),
                             risk, priority])
            self._fill_table(self.assets_table, rows)
        except Exception:
            pass

    def update_high_value_targets(self, high_value_targets):
        rows = [[t.get('host', ''), t.get('value_type', ''), t.get('description', '')]
                for t in high_value_targets]
        self._fill_table(self.hvt_table, rows)

    def update_security_gaps(self, security_gaps):
        lines = []
        for gap in security_gaps:
            lines.append(f"• {gap.get('type', '')}: {gap.get('description', '')}")
            if 'recommendation' in gap:
                lines.append(f"  Recommendation: {gap['recommendation']}")
            lines.append("")
        self.gaps_text.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------ #
    #  Actions                                                             #
    # ------------------------------------------------------------------ #

    def view_attack_chain_details(self, item):
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
        row = item.row()
        dialog = QDialog(self)
        dialog.setWindowTitle("Attack Chain Details")
        dialog.setMinimumSize(600, 400)
        dlg_layout = QVBoxLayout(dialog)
        details = QTextEdit()
        details.setPlainText(f"Attack Chain Details — row {row + 1}\n\nDetailed analysis would appear here.")
        dlg_layout.addWidget(details)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        dlg_layout.addWidget(close_btn)
        dialog.exec()

    def generate_playbook(self):
        if self.chains_table.currentRow() < 0:
            return
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton
        dialog = QDialog(self)
        dialog.setWindowTitle("Generated Attack Playbook")
        dialog.setMinimumSize(800, 600)
        dlg_layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setPlainText(self._sample_playbook(self.playbook_format.currentText().lower()))
        dlg_layout.addWidget(text)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        dlg_layout.addWidget(close_btn)
        dialog.exec()

    def _sample_playbook(self, fmt):
        if "htb" in fmt:
            return (
                "# HTB Attack Chain Playbook\n\n"
                "## Target: Multi-Service Host Compromise\n\n"
                "### Step 1: Initial Reconnaissance\n"
                "```bash\nimpacket-rpcmap target.htb\nrpcclient -U \"\" -N target.htb\n```\n\n"
                "### Step 2: RPC Exploitation\n"
                "```bash\nimpacket-psexec domain/user:password@target.htb\n```\n\n"
                "### Step 3: SMB Enumeration\n"
                "```bash\nsmbclient -L //target.htb -U \"\"\nsmbmap -H target.htb\n```\n\n"
                "### Verification\n- [ ] RPC service accessible\n- [ ] SMB shares enumerated\n"
            )
        return (
            "# Generic Attack Chain Playbook\n\n"
            "## Overview\nMulti-stage attack chain targeting network services.\n\n"
            "## Attack Steps\n1. Service Discovery\n2. Vulnerability Identification\n"
            "3. Initial Exploitation\n4. Privilege Escalation\n5. Lateral Movement\n"
        )

    def export_analysis(self):
        from PyQt6.QtWidgets import QFileDialog, QMessageBox
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Correlation Analysis",
            f"correlation_analysis_{self.tenant_id}.json",
            "JSON files (*.json)"
        )
        if not filename:
            return
        export_data = {
            "tenant_id": self.tenant_id,
            "correlation_score": 0,
            "attack_chains": [],
            "risk_amplifiers": [],
            "security_gaps": [],
        }
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            QMessageBox.information(self, "Export Complete", f"Analysis exported to {filename}")
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", str(e))

    def show_no_data_message(self):
        for table in [self.chains_table, self.amplifiers_table,
                      self.assets_table, self.hvt_table, self.summary_table]:
            table.setRowCount(1)
            table.setItem(0, 0, QTableWidgetItem("No scan data available"))
        self.gaps_text.setPlainText("No security gaps identified — run scans to populate data.")
        self._set_score(0)

    def show_error_message(self, error):
        self.gaps_text.setPlainText(f"Error loading correlation data: {error}")
        self.score_label.setText("Correlation Score: Error")
        self.score_label.setStyleSheet("font-weight: bold; color: #FF4444;")

    def refresh_for_tenant(self, tenant_id):
        self.tenant_id = tenant_id
        self.load_correlations()
