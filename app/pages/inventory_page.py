from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter, QLabel, QFrame,
    QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QMenu, QMessageBox, QGroupBox, QWidget,
    QTextEdit, QDialog
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QFont
from app.widgets.asset_graphics_widget import AssetGraphicsWidget, AssetDetailsWidget
from app.core.asset_manager import asset_manager
from app.core.logger import logger


class InventoryPage(QWidget):
    navigate_signal = pyqtSignal(str)
    status_updated  = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window   = parent
        self.current_assets = []
        self.tenant_id     = self._get_tenant()
        self.last_tenant   = self.tenant_id
        self.setObjectName("InventoryPage")
        self._setup_ui()
        self._setup_timers()
        self.load_assets()

    # ------------------------------------------------------------------ #
    #  Visibility                                                          #
    # ------------------------------------------------------------------ #

    def showEvent(self, event):
        super().showEvent(event)
        self.load_assets()

    # ------------------------------------------------------------------ #
    #  UI construction                                                     #
    # ------------------------------------------------------------------ #

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # ── Stats bar ─────────────────────────────────────────────────────
        layout.addWidget(self._build_stats_bar())

        # ── Main splitter: graphics (left) | table+details (right) ────────
        h_split = QSplitter(Qt.Orientation.Horizontal)

        # Left — network graph (fixed width, secondary surface)
        self._left_frame = self._framed()
        left_layout = QVBoxLayout(self._left_frame)
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(6)
        left_layout.addWidget(QLabel("Asset Overview", styleSheet=
            "font-size: 12pt; font-weight: bold; color: #64C8FF;"))
        self.asset_graphics = AssetGraphicsWidget()
        self.asset_graphics.asset_selected.connect(self._on_asset_selected)
        self.asset_graphics.asset_context_menu.connect(self._show_asset_context_menu)
        left_layout.addWidget(self.asset_graphics)
        h_split.addWidget(self._left_frame)

        # Right — toolbar + vertical splitter (table / details)
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(6)

        right_layout.addWidget(self._build_toolbar())

        v_split = QSplitter(Qt.Orientation.Vertical)

        # Table frame
        table_frame = self._framed()
        tf_layout = QVBoxLayout(table_frame)
        tf_layout.setContentsMargins(8, 8, 8, 8)
        self.asset_table = self._build_table()
        tf_layout.addWidget(self.asset_table)
        v_split.addWidget(table_frame)

        # Details frame (always visible, populated on selection)
        details_frame = self._framed()
        df_layout = QVBoxLayout(details_frame)
        df_layout.setContentsMargins(8, 8, 8, 8)
        self.asset_details = AssetDetailsWidget()
        # Hide the built-in back button — we no longer need show/hide toggling
        if hasattr(self.asset_details, 'back_button'):
            self.asset_details.back_button.setVisible(False)
        df_layout.addWidget(self.asset_details)
        v_split.addWidget(details_frame)

        v_split.setSizes([340, 220])
        right_layout.addWidget(v_split, 1)

        h_split.addWidget(right_container)
        h_split.setSizes([350, 750])

        layout.addWidget(h_split, 1)

    # ---- stats bar ---------------------------------------------------- #

    def _build_stats_bar(self):
        bar = QFrame()
        bar.setStyleSheet("""
            QFrame {
                background-color: rgba(20, 30, 40, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
        """)
        bar.setFixedHeight(72)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 8, 20, 8)
        layout.setSpacing(0)

        self._stat_total    = self._stat_widget("0", "Total Assets")
        self._stat_disc     = self._stat_widget("0", "Discovered")
        self._stat_ident    = self._stat_widget("0", "Identified")
        self._stat_known    = self._stat_widget("0", "Known")
        self._stat_recent   = self._stat_widget("0", "Recent Activity")

        for w in (self._stat_total, self._stat_disc,
                  self._stat_ident, self._stat_known, self._stat_recent):
            layout.addWidget(w)

        return bar

    @staticmethod
    def _stat_widget(value, label):
        w = QWidget()
        w.setStyleSheet("background: transparent; border: none;")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(1)
        v = QLabel(value)
        v.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;"
                        " background: transparent; border: none;")
        d = QLabel(label)
        d.setAlignment(Qt.AlignmentFlag.AlignCenter)
        d.setStyleSheet("font-size: 9pt; color: #87CEEB;"
                        " background: transparent; border: none;")
        lay.addWidget(v)
        lay.addWidget(d)
        w._value = v          # store ref for updates
        return w

    # ---- toolbar (filters + action buttons) --------------------------- #

    def _build_toolbar(self):
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        lbl = QLabel("Filter:")
        lbl.setStyleSheet("color: #DCDCDC; font-weight: bold;")
        layout.addWidget(lbl)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "DISCOVERED", "IDENTIFIED", "KNOWN"])
        self.status_filter.currentTextChanged.connect(self.apply_filters)
        self.status_filter.setFixedWidth(120)
        layout.addWidget(self.status_filter)

        self.os_filter = QComboBox()
        self.os_filter.addItem("All OS")
        self.os_filter.currentTextChanged.connect(self.apply_filters)
        self.os_filter.setFixedWidth(120)
        layout.addWidget(self.os_filter)

        layout.addStretch()

        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_assets)
        refresh_btn.setFixedWidth(90)
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: #000000; border: none;
                border-radius: 5px; padding: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: rgba(100, 200, 255, 200); }
        """)
        layout.addWidget(refresh_btn)

        return bar

    # ---- table -------------------------------------------------------- #

    def _build_table(self):
        table = QTableWidget()
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "IP Address", "Hostname", "OS / Type", "Status",
            "Ports", "Services", "Shares / Web", "Vulnerabilities"
        ])

        hdr = table.horizontalHeader()
        # Hostname and OS/Type stretch to fill remaining space
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        # All other columns size to their content automatically
        for col in (0, 3, 4, 5, 6, 7):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

        hdr.setMinimumSectionSize(50)

        table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 100);
                color: #DCDCDC;
                border: none;
                gridline-color: rgba(100, 200, 255, 40);
            }
            QTableWidget::item {
                padding: 6px;
                border-bottom: 1px solid rgba(100, 200, 255, 25);
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 80);
                color: #FFFFFF;
            }
        """)

        table.itemSelectionChanged.connect(self._on_table_selection)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self._show_table_context_menu)
        return table

    # ---- helpers ------------------------------------------------------ #

    @staticmethod
    def _framed():
        f = QFrame()
        f.setStyleSheet("""
            QFrame {
                background-color: rgba(0, 0, 0, 50);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
            }
        """)
        return f

    # ------------------------------------------------------------------ #
    #  Timers                                                              #
    # ------------------------------------------------------------------ #

    def _setup_timers(self):
        self._refresh_timer = QTimer()
        self._refresh_timer.timeout.connect(self.load_assets)
        self._refresh_timer.start(30000)

        self._profile_timer = QTimer()
        self._profile_timer.timeout.connect(self._check_profile_change)
        self._profile_timer.start(1000)
        self._last_known_tenant = self.tenant_id

    def _check_profile_change(self):
        current = self._get_tenant()
        if current != self._last_known_tenant:
            self._last_known_tenant = current
            self.tenant_id = current
            self.current_assets = []
            self.asset_graphics.update_assets([])
            self._populate_table([])
            self.load_assets()

    # ------------------------------------------------------------------ #
    #  Data loading                                                        #
    # ------------------------------------------------------------------ #

    def _get_tenant(self):
        try:
            if (hasattr(self.main_window, 'current_profile_name')
                    and self.main_window.current_profile_name):
                return self.main_window.current_profile_name
        except Exception:
            pass
        return 'default'

    def load_assets(self):
        try:
            old = self.tenant_id
            self.tenant_id = self._get_tenant()
            if old != self.tenant_id:
                self.current_assets = []
                self.asset_graphics.update_assets([])
                self._populate_table([])

            assets = asset_manager.get_assets(self.tenant_id)
            self.current_assets = assets
            self.asset_graphics.update_assets(assets)
            self._populate_table(assets)
            self._update_stats()
            self._update_os_filter()
            self.status_updated.emit(
                f"Loaded {len(assets)} assets for profile {self.tenant_id}")
        except Exception as e:
            self.status_updated.emit(f"Error loading assets: {e}")

    # ------------------------------------------------------------------ #
    #  Stats                                                               #
    # ------------------------------------------------------------------ #

    def _update_stats(self):
        try:
            stats = asset_manager.get_asset_statistics(self.tenant_id)
            sb = stats.get('status_breakdown', {})
            self._stat_total._value.setText(str(stats.get('total_assets', 0)))
            self._stat_disc._value.setText(str(sb.get('DISCOVERED', 0)))
            self._stat_ident._value.setText(str(sb.get('IDENTIFIED', 0)))
            self._stat_known._value.setText(str(sb.get('KNOWN', 0)))
            self._stat_recent._value.setText(str(stats.get('recent_activity', 0)))
        except Exception as e:
            self.status_updated.emit(f"Error updating statistics: {e}")

    # ------------------------------------------------------------------ #
    #  Filters                                                             #
    # ------------------------------------------------------------------ #

    def apply_filters(self):
        sf = self.status_filter.currentText()
        of = self.os_filter.currentText()
        filtered = [
            a for a in self.current_assets
            if (sf == "All" or a.get('status') == sf)
            and (of == "All OS" or a.get('os_type') == of)
        ]
        self.asset_graphics.update_assets(filtered)
        self._populate_table(filtered)
        self.status_updated.emit(
            f"Showing {len(filtered)} of {len(self.current_assets)} assets")

    def _update_os_filter(self):
        os_types = sorted({
            a.get('os_type', 'Unknown')
            for a in self.current_assets
            if a.get('os_type', 'Unknown') != 'Unknown'
        })
        sel = self.os_filter.currentText()
        self.os_filter.clear()
        self.os_filter.addItem("All OS")
        for t in os_types:
            self.os_filter.addItem(t)
        idx = self.os_filter.findText(sel)
        if idx >= 0:
            self.os_filter.setCurrentIndex(idx)

    # ------------------------------------------------------------------ #
    #  Table population                                                    #
    # ------------------------------------------------------------------ #

    def _populate_table(self, assets):
        self.asset_table.setRowCount(len(assets))
        for row, asset in enumerate(assets):
            # IP
            self._cell(self.asset_table, row, 0, asset['ip_address'])

            # Hostname
            hostname = asset.get('hostname', '')
            ip = asset['ip_address']
            display = f"{ip} ({hostname})" if hostname and hostname != ip else hostname
            self._cell(self.asset_table, row, 1, display)

            # OS / server type
            meta = asset.get('metadata', {})
            os_display = meta.get('server_type') or asset.get('os_type', 'Unknown')
            os_item = self._cell(self.asset_table, row, 2, os_display)
            if 'Domain Controller' in os_display:
                os_item.setBackground(Qt.GlobalColor.darkBlue)
                os_item.setForeground(Qt.GlobalColor.yellow)
            elif 'Windows Server' in os_display:
                os_item.setBackground(Qt.GlobalColor.blue)
                os_item.setForeground(Qt.GlobalColor.white)

            # Status
            status = asset.get('status', 'DISCOVERED')
            s_item = self._cell(self.asset_table, row, 3, status)
            if status == 'DISCOVERED':
                s_item.setBackground(Qt.GlobalColor.yellow)
                s_item.setForeground(Qt.GlobalColor.black)
            elif status == 'IDENTIFIED':
                s_item.setBackground(Qt.GlobalColor.darkYellow)
                s_item.setForeground(Qt.GlobalColor.white)
            elif status == 'KNOWN':
                s_item.setBackground(Qt.GlobalColor.green)
                s_item.setForeground(Qt.GlobalColor.white)

            # Ports / Services
            self._cell(self.asset_table, row, 4,
                       str(len(asset.get('open_ports', []))))
            self._cell(self.asset_table, row, 5,
                       str(len(asset.get('services', []))))

            # Shares / Web
            shares_web = ""
            if meta.get('shares_found'):
                shares_web = f"{meta['shares_found']} shares"
            elif meta.get('server_type') == 'web_server':
                parts = []
                if meta.get('directories_found'):
                    parts.append(f"{meta['directories_found']} dirs")
                if meta.get('files_found'):
                    parts.append(f"{meta['files_found']} files")
                shares_web = ", ".join(parts) if parts else "Web server"
            self._cell(self.asset_table, row, 6, shares_web)

            # Vulnerabilities
            vc = len(asset.get('vulnerabilities', []))
            v_item = self._cell(self.asset_table, row, 7, str(vc))
            if vc > 0:
                v_item.setBackground(Qt.GlobalColor.red)
                v_item.setForeground(Qt.GlobalColor.white)

    @staticmethod
    def _cell(table, row, col, text):
        item = QTableWidgetItem(text)
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        table.setItem(row, col, item)
        return item

    # ------------------------------------------------------------------ #
    #  Selection                                                           #
    # ------------------------------------------------------------------ #

    def _on_asset_selected(self, asset_id):
        asset = next((a for a in self.current_assets
                      if a['asset_id'] == asset_id), None)
        if asset:
            self.asset_details.update_asset(asset)
            self.status_updated.emit(f"Selected: {asset['ip_address']}")

    def _on_table_selection(self):
        row = self.asset_table.currentRow()
        if row < 0:
            return
        ip_item = self.asset_table.item(row, 0)
        if not ip_item:
            return
        asset = next((a for a in self.current_assets
                      if a['ip_address'] == ip_item.text()), None)
        if asset:
            self.asset_details.update_asset(asset)
            self.status_updated.emit(f"Selected: {asset['ip_address']}")

    # ------------------------------------------------------------------ #
    #  Context menus                                                       #
    # ------------------------------------------------------------------ #

    def _show_table_context_menu(self, position):
        item = self.asset_table.itemAt(position)
        if not item:
            return
        ip_item = self.asset_table.item(item.row(), 0)
        if not ip_item:
            return
        asset = next((a for a in self.current_assets
                      if a['ip_address'] == ip_item.text()), None)
        if asset:
            self._show_asset_context_menu(
                asset['asset_id'],
                self.asset_table.mapToGlobal(position))

    def _show_asset_context_menu(self, asset_id, position):
        asset = next((a for a in self.current_assets
                      if a['asset_id'] == asset_id), None)
        if not asset:
            return

        menu = QMenu(self)

        scan_menu = menu.addMenu("🔍 Scan")
        for label, slot in [
            ("Port Scan",        lambda: self._initiate_port_scan(asset)),
            ("Service Detection",lambda: self._initiate_service_scan(asset)),
            ("Vulnerability Scan",lambda: self._initiate_vuln_scan(asset)),
        ]:
            act = QAction(label, self)
            act.triggered.connect(slot)
            scan_menu.addAction(act)

        menu.addSeparator()

        details_act = QAction("📋 View Details", self)
        details_act.triggered.connect(lambda: self._show_details_dialog(asset))
        menu.addAction(details_act)

        menu.addSeparator()

        del_act = QAction("🗑️ Remove Asset", self)
        del_act.triggered.connect(lambda: self._remove_asset(asset))
        menu.addAction(del_act)

        menu.exec(position)

    # ------------------------------------------------------------------ #
    #  Actions                                                             #
    # ------------------------------------------------------------------ #

    def _initiate_port_scan(self, asset):
        self.status_updated.emit(f"Initiating port scan for {asset['ip_address']}")
        self.navigate_signal.emit("recon_enumeration")
        QTimer.singleShot(500, lambda: self._set_port_scan_target(asset['ip_address']))

    def _initiate_service_scan(self, asset):
        self.status_updated.emit(f"Initiating service scan for {asset['ip_address']}")
        self.navigate_signal.emit("recon_enumeration")

    def _initiate_vuln_scan(self, asset):
        self.status_updated.emit(f"Initiating vulnerability scan for {asset['ip_address']}")
        self.navigate_signal.emit("vuln_scanning")

    def _set_port_scan_target(self, ip):
        try:
            rp = getattr(self.main_window, 'recon_enumeration_page', None)
            if rp and hasattr(rp, 'port_target_input'):
                rp.port_target_input.setText(ip)
        except Exception as e:
            logger.debug(f"Could not set port scan target: {e}")

    def _remove_asset(self, asset):
        reply = QMessageBox.question(
            self, "Remove Asset",
            f"Remove {asset['ip_address']} from inventory?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                if asset_manager.remove_asset(self.tenant_id, asset['ip_address']):
                    self.load_assets()
                    self.status_updated.emit(
                        f"Asset {asset['ip_address']} removed")
                else:
                    self.status_updated.emit(
                        f"Failed to remove {asset['ip_address']}")
            except Exception as e:
                self.status_updated.emit(f"Error removing asset: {e}")

    def _show_details_dialog(self, asset):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Asset Details — {asset['ip_address']}")
        dialog.setModal(True)
        dialog.resize(700, 700)

        layout = QVBoxLayout(dialog)

        details_text = QTextEdit()
        details_text.setReadOnly(True)

        meta = asset.get('metadata', {})
        lines = [
            "Asset Information",
            f"  IP Address : {asset['ip_address']}",
            f"  Hostname   : {asset.get('hostname', 'N/A')}",
            f"  OS Type    : {asset.get('os_type', 'Unknown')}",
            f"  OS Version : {asset.get('os_version', 'N/A')}",
            f"  Status     : {asset.get('status', 'DISCOVERED')}",
            f"  Confidence : {asset.get('confidence', 0)}%",
            f"  First Seen : {asset.get('first_seen', 'N/A')}",
            f"  Last Seen  : {asset.get('last_seen', 'N/A')}",
            "",
            f"Open Ports ({len(asset.get('open_ports', []))}):",
        ]
        for p in asset.get('open_ports', []):
            lines.append(f"  {p.get('port')}/{p.get('protocol','tcp')}")

        lines += ["", f"Services ({len(asset.get('services', []))}):" ]
        for s in asset.get('services', []):
            ver = f" ({s['version']})" if s.get('version') else ""
            lines.append(f"  {s.get('port')}: {s.get('service')}{ver}")

        lines += ["", f"Vulnerabilities ({len(asset.get('vulnerabilities', []))}):" ]
        for v in asset.get('vulnerabilities', []):
            lines.append(f"  {v.get('name', v.get('id','Unknown'))} "
                         f"({v.get('severity','Unknown')})")

        if meta.get('shares_found'):
            lines += ["", f"SMB Shares ({meta['shares_found']}):" ]
            for sh in meta.get('share_list', []):
                lines.append(f"  \\\\{asset['ip_address']}\\{sh}")

        if meta.get('server_type') == 'web_server':
            lines += ["", "Web Application:"]
            if meta.get('server_header'):
                lines.append(f"  Server: {meta['server_header']}")
            if meta.get('directories_found'):
                lines.append(f"  Directories: {meta['directories_found']}")
            if meta.get('files_found'):
                lines.append(f"  Files: {meta['files_found']}")

        notes = asset.get('notes', '')
        lines += ["", "Notes:", notes if notes else "No notes."]

        details_text.setPlainText("\n".join(lines))
        layout.addWidget(details_text)

        # Notes editor
        notes_box = QGroupBox("Edit Notes")
        nb_layout = QVBoxLayout(notes_box)
        notes_edit = QTextEdit()
        notes_edit.setPlainText(notes)
        notes_edit.setMaximumHeight(100)
        nb_layout.addWidget(notes_edit)

        btn_row = QHBoxLayout()
        save_btn = QPushButton("💾 Save Notes")
        save_btn.clicked.connect(
            lambda: self._save_notes(asset, notes_edit.toPlainText(), dialog))
        btn_row.addWidget(save_btn)
        btn_row.addStretch()
        nb_layout.addLayout(btn_row)
        layout.addWidget(notes_box)

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        close_row.addWidget(close_btn)
        layout.addLayout(close_row)

        dialog.exec()

    def _save_notes(self, asset, text, dialog):
        try:
            if asset_manager.update_asset_notes(
                    self.tenant_id, asset['ip_address'], text):
                self.status_updated.emit(f"Notes saved for {asset['ip_address']}")
                self.load_assets()
                dialog.accept()
            else:
                self.status_updated.emit(
                    f"Failed to save notes for {asset['ip_address']}")
        except Exception as e:
            self.status_updated.emit(f"Error saving notes: {e}")

    def open_credentials_manager(self):
        from app.widgets.secure_credential_widget import SecureCredentialWidget
        dialog = QDialog(self)
        dialog.setWindowTitle("Credential Management")
        dialog.setModal(True)
        dialog.resize(1000, 700)
        dialog.setStyleSheet("QDialog { background-color: #1a1a1a; color: #DCDCDC; }")
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.addWidget(SecureCredentialWidget())
        self.status_updated.emit("Credentials Management opened")
        dialog.exec()

    # kept for external callers (e.g. attack_chain_home)
    def add_assets_from_profile(self, assets):
        pass
