from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QSplitter, QLabel, QFrame,
    QPushButton, QComboBox, QHeaderView, QMenu, QMessageBox,
    QGroupBox, QWidget, QTextEdit, QDialog, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QFont, QColor, QBrush
from app.widgets.asset_graphics_widget import AssetDetailsWidget
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

        # ── Toolbar (filters + refresh) ───────────────────────────────────
        layout.addWidget(self._build_toolbar())

        # ── Main splitter: tree (left) | details (right) ──────────────────
        h_split = QSplitter(Qt.Orientation.Horizontal)

        # Left — hierarchical asset tree view
        self._left_frame = self._framed()
        left_layout = QVBoxLayout(self._left_frame)
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(6)
        left_layout.addWidget(QLabel("Asset Overview", styleSheet=
            "font-size: 12pt; font-weight: bold; color: #64C8FF;"))
        self.asset_tree = self._build_asset_tree()
        left_layout.addWidget(self.asset_tree)
        h_split.addWidget(self._left_frame)

        # Right — asset details panel
        self.asset_details = AssetDetailsWidget()

        if hasattr(self.asset_details, 'back_button'):
            self.asset_details.back_button.setVisible(False)
        h_split.addWidget(self.asset_details)    

        h_split.setSizes([410, 760])

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
        bar.setFixedHeight(55)
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
        v.setStyleSheet("font-size: 13pt; font-weight: bold; color: #64C8FF;"
                        " background: transparent; border: none;")
        d = QLabel(label)
        d.setAlignment(Qt.AlignmentFlag.AlignCenter)
        d.setStyleSheet("font-size: 8pt; color: #87CEEB;"
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
        self.status_filter.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.status_filter.setMinimumContentsLength(12)
        layout.addWidget(self.status_filter)

        self.os_filter = QComboBox()
        self.os_filter.addItem("All OS")
        self.os_filter.currentTextChanged.connect(self.apply_filters)
        self.os_filter.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.os_filter.setMinimumContentsLength(16)
        layout.addWidget(self.os_filter)

        layout.addStretch()

        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_assets)
        refresh_btn.setFixedWidth(120)
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

    # ---- asset tree ----------------------------------------------------- #

    def _build_asset_tree(self):
        """Build the hierarchical tree widget for asset overview."""
        tree = QTreeWidget()
        tree.setHeaderLabels(["Name", "Details"])
        tree.setColumnCount(2)
        tree.header().setStretchLastSection(True)
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        tree.setAlternatingRowColors(False)
        tree.setAnimated(True)
        tree.setIndentation(20)
        tree.setStyleSheet("""
            QTreeWidget {
                background-color: rgba(0, 0, 0, 80);
                color: #DCDCDC;
                border: none;
                font-size: 10pt;
            }
            QTreeWidget::item {
                padding: 4px 2px;
                border-bottom: 1px solid rgba(100, 200, 255, 15);
            }
            QTreeWidget::item:selected {
                background-color: rgba(100, 200, 255, 80);
                color: #FFFFFF;
            }
            QTreeWidget::item:hover {
                background-color: rgba(100, 200, 255, 30);
            }
            QTreeWidget::branch {
                background: transparent;
            }
            QHeaderView::section {
                background-color: rgba(20, 30, 50, 200);
                color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 40);
                padding: 4px 8px;
                font-weight: bold;
            }
        """)

        tree.itemClicked.connect(self._on_tree_item_clicked)
        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree.customContextMenuRequested.connect(self._show_tree_context_menu)
        return tree

    def _populate_tree(self, assets):
        """Populate the tree with assets organized into categories."""
        self.asset_tree.clear()

        # Categorize assets
        hosts = []         # Assets with hostname and IP resolved
        ip_only = []       # Assets with IP but no meaningful hostname
        domains = []       # Assets that are domains/subdomains (FQDN, no direct IP)

        for asset in assets:
            ip = asset.get('ip_address', '')
            hostname = asset.get('hostname', '')
            fqdn = asset.get('fqdn', '')
            meta = asset.get('metadata', {})
            discovery = meta.get('discovery_method', '')

            # Determine category
            is_domain_discovery = discovery in (
                'subdomain_enumeration', 'dns_analysis', 'cert_transparency'
            )
            is_ip_like = bool(ip) and self._is_ip_address(ip)

            if is_domain_discovery and not is_ip_like:
                domains.append(asset)
            elif is_ip_like and hostname and hostname != ip:
                hosts.append(asset)
            elif is_ip_like:
                ip_only.append(asset)
            elif fqdn or hostname:
                domains.append(asset)
            else:
                ip_only.append(asset)

        # ── HOSTS category ─────────────────────────────────────────────
        if hosts:
            hosts_root = QTreeWidgetItem(self.asset_tree)
            hosts_root.setText(0, f"🖥️  HOSTS ({len(hosts)})")
            hosts_root.setFont(0, self._category_font())
            hosts_root.setForeground(0, QBrush(QColor("#64C8FF")))
            hosts_root.setExpanded(True)

            # Separate DNS-enumerated hosts (have parent_domain) from others
            dns_hosts = []
            other_hosts = []
            for asset in hosts:
                meta = asset.get('metadata', {})
                parent_domain = meta.get('parent_domain', '')
                if parent_domain and meta.get('discovery_method') == 'dns_enumeration':
                    dns_hosts.append(asset)
                else:
                    other_hosts.append(asset)

            # Group DNS hosts by parent_domain in collapsible sub-trees
            domain_groups = {}
            for asset in dns_hosts:
                parent = asset.get('metadata', {}).get('parent_domain', 'Unknown')
                domain_groups.setdefault(parent, []).append(asset)

            for parent_domain, group in sorted(domain_groups.items()):
                # Find the root domain asset to use as the parent node
                root_asset = next(
                    (a for a in domains if (a.get('fqdn', '') or a.get('hostname', '') or a.get('ip_address', '')) == parent_domain),
                    None
                )
                parent_item = QTreeWidgetItem(hosts_root)
                parent_item.setText(0, f"🌐 {parent_domain} ({len(group)})")
                parent_item.setForeground(0, QBrush(QColor("#87CEEB")))
                parent_item.setFont(0, self._category_font())
                parent_item.setExpanded(False)
                if root_asset:
                    parent_item.setData(0, Qt.ItemDataRole.UserRole, root_asset['asset_id'])

                for asset in sorted(group, key=lambda a: a.get('hostname', '')):
                    child = QTreeWidgetItem(parent_item)
                    child.setText(0, asset.get('hostname', asset['ip_address']))
                    meta = asset.get('metadata', {})
                    all_ips = meta.get('all_ips', [])
                    if all_ips:
                        child.setText(1, ", ".join(all_ips))
                    else:
                        child.setText(1, asset['ip_address'])
                    child.setData(0, Qt.ItemDataRole.UserRole, asset['asset_id'])
                    self._style_asset_item(child, asset)

            # Non-DNS hosts displayed flat as before
            for asset in sorted(other_hosts, key=lambda a: a.get('hostname', '')):
                item = QTreeWidgetItem(hosts_root)
                item.setText(0, asset.get('hostname', asset['ip_address']))
                item.setText(1, f"{asset['ip_address']} — {asset.get('status', '')}")
                item.setData(0, Qt.ItemDataRole.UserRole, asset['asset_id'])
                self._style_asset_item(item, asset)

        # ── IP ADDRESSES category ─────────────────────────────────────
        if ip_only:
            ip_root = QTreeWidgetItem(self.asset_tree)
            ip_root.setText(0, f"🌐  IP ADDRESSES ({len(ip_only)})")
            ip_root.setFont(0, self._category_font())
            ip_root.setForeground(0, QBrush(QColor("#00FF41")))
            ip_root.setExpanded(True)

            for asset in sorted(ip_only, key=lambda a: a.get('ip_address', '')):
                item = QTreeWidgetItem(ip_root)
                item.setText(0, asset['ip_address'])
                ports = asset.get('open_ports', [])
                os_type = asset.get("os_type", "")

                if os_type:
                    detail = os_type
                else:
                    detail = f"{len(ports)} ports"
                item.setText(1, detail)
                item.setData(0, Qt.ItemDataRole.UserRole, asset['asset_id'])
                self._style_asset_item(item, asset)

        # ── DOMAINS category ──────────────────────────────────────────
        # Exclude root domains that are already shown as parent nodes in HOSTS
        dns_root_domains = set()
        for asset in domains:
            meta = asset.get('metadata', {})
            if meta.get('asset_type') == 'root_domain' and meta.get('subdomains'):
                dns_root_domains.add(asset.get('asset_id'))

        filtered_domains = [a for a in domains if a.get('asset_id') not in dns_root_domains]

        if filtered_domains:
            domains_root = QTreeWidgetItem(self.asset_tree)
            domains_root.setText(0, f"🔗  DOMAINS ({len(filtered_domains)})")
            domains_root.setFont(0, self._category_font())
            domains_root.setForeground(0, QBrush(QColor("#FFD93D")))
            domains_root.setExpanded(True)

            # Group domains by parent domain
            parent_groups = {}
            for asset in filtered_domains:
                fqdn = asset.get('fqdn', '') or asset.get('hostname', '') or asset.get('ip_address', '')
                parent = self._get_parent_domain(fqdn, asset)
                parent_groups.setdefault(parent, []).append(asset)

            for parent, group in sorted(parent_groups.items()):
                if len(group) == 1 and (group[0].get('fqdn', '') or group[0].get('hostname', '')) == parent:
                    # Single domain, no nesting needed
                    asset = group[0]
                    item = QTreeWidgetItem(domains_root)
                    item.setText(0, parent)
                    item.setText(1, asset.get('status', ''))
                    item.setData(0, Qt.ItemDataRole.UserRole, asset['asset_id'])
                    self._style_asset_item(item, asset)
                else:
                    # Parent domain with children
                    parent_item = QTreeWidgetItem(domains_root)
                    parent_item.setText(0, f"{parent} ({len(group)})")
                    parent_item.setForeground(0, QBrush(QColor("#87CEEB")))
                    parent_item.setExpanded(False)

                    for asset in sorted(group, key=lambda a: a.get('fqdn', '') or a.get('hostname', '')):
                        child = QTreeWidgetItem(parent_item)
                        name = asset.get('fqdn', '') or asset.get('hostname', '') or asset.get('ip_address', '')
                        child.setText(0, name)
                        ip = asset.get('ip_address', '')
                        resolved_ip = ip if self._is_ip_address(ip) else ''
                        child.setText(1, resolved_ip or asset.get('status', ''))
                        child.setData(0, Qt.ItemDataRole.UserRole, asset['asset_id'])
                        self._style_asset_item(child, asset)

    def _style_asset_item(self, item, asset):
        """Apply color styling based on asset status."""
        status = asset.get('status', 'DISCOVERED')
        if status == 'IDENTIFIED':
            item.setForeground(0, QBrush(QColor("#00FF41")))
        elif status == 'KNOWN':
            item.setForeground(0, QBrush(QColor("#64C8FF")))
        else:
            item.setForeground(0, QBrush(QColor("#DCDCDC")))

    def _get_parent_domain(self, fqdn, asset):
        """Extract parent domain from an FQDN or asset metadata."""
        meta = asset.get('metadata', {})
        parent = meta.get('parent_domain', '')
        if parent:
            return parent
        # Derive from FQDN: take last two segments
        parts = fqdn.rsplit('.', 2)
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return fqdn

    @staticmethod
    def _is_ip_address(text):
        """Check if text looks like an IP address."""
        import re
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', text))

    @staticmethod
    def _category_font():
        f = QFont()
        f.setBold(True)
        f.setPointSize(11)
        return f

    def _on_tree_item_clicked(self, item, column):
        """Handle tree item selection — show details for leaf assets."""
        asset_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not asset_id:
            return  # Category header clicked, ignore
        asset = next((a for a in self.current_assets
                      if a['asset_id'] == asset_id), None)
        if asset:
            self.asset_details.update_asset(asset)
            self.status_updated.emit(f"Selected: {asset.get('hostname') or asset['ip_address']}")

    def _show_tree_context_menu(self, position):
        """Context menu for tree items."""
        item = self.asset_tree.itemAt(position)
        if not item:
            return
        asset_id = item.data(0, Qt.ItemDataRole.UserRole)
        if not asset_id:
            return
        self._show_asset_context_menu(
            asset_id, self.asset_tree.mapToGlobal(position))

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
            self.asset_tree.clear()
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
                self.asset_tree.clear()

            assets = asset_manager.get_assets(self.tenant_id)
            self.current_assets = assets
            self._populate_tree(assets)
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
        self._populate_tree(filtered)
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
        # Resize to fit the longest item
        max_len = max((len(t) for t in os_types), default=0)
        self.os_filter.setMinimumContentsLength(max(16, max_len))

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    #  Selection                                                           #
    # ------------------------------------------------------------------ #

    def _on_asset_selected(self, asset_id):
        asset = next((a for a in self.current_assets
                      if a['asset_id'] == asset_id), None)
        if asset:
            self.asset_details.update_asset(asset)
            self.status_updated.emit(f"Selected: {asset['ip_address']}")

    # ------------------------------------------------------------------ #
    #  Context menus                                                       #
    # ------------------------------------------------------------------ #

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
                    self.asset_details.update_asset(None)
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
