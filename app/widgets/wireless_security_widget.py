# app/widgets/wireless_security_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QComboBox, QPushButton, QTextEdit, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QTabWidget, QLineEdit, QCheckBox, QSplitter,
                            QFileDialog, QFrame, QScrollArea)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from app.core.wireless_security import wireless_security
from app.core.license_manager import license_manager

class WirelessScanWorker(QThread):
    """Worker thread for wireless scanning"""
    scan_completed = pyqtSignal(dict)
    
    def __init__(self, scan_type, **kwargs):
        super().__init__()
        self.scan_type = scan_type
        self.kwargs = kwargs
        
    def run(self):
        if self.scan_type == 'wifi_discovery':
            result = wireless_security.discover_wifi_networks()
        elif self.scan_type == 'bluetooth_discovery':
            result = wireless_security.discover_bluetooth_devices()
        elif self.scan_type == 'wpa_test':
            result = wireless_security.test_wpa_security(self.kwargs['ssid'], self.kwargs.get('wordlist'))
        elif self.scan_type == 'pmkid_attack':
            result = wireless_security.pmkid_attack(self.kwargs['ssid'], self.kwargs.get('wordlist'))
        elif self.scan_type == 'deauth_attack':
            result = wireless_security.deauth_attack(self.kwargs['ssid'], self.kwargs.get('bssid'))
        elif self.scan_type == 'evil_twin':
            result = wireless_security.evil_twin_attack(self.kwargs['ssid'], self.kwargs.get('attack_mode', 'captive_portal'))
        elif self.scan_type == 'ssid_confusion':
            result = wireless_security.ssid_confusion_attack(self.kwargs['ssid'])
        elif self.scan_type == 'wpa3_downgrade':
            result = wireless_security.wpa3_downgrade_attack(self.kwargs['ssid'])
        elif self.scan_type == 'bluetooth_attack':
            result = wireless_security.bluetooth_attack(self.kwargs['address'], self.kwargs['attack_type'])
        else:
            result = {'error': 'Unknown scan type'}

        self.scan_completed.emit(result)

class WirelessSecurityWidget(QWidget):
    """Wireless security testing widget"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker = None
        self.setup_ui()
        self.connect_signals()
        self.check_license()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Wireless Security Testing Framework")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(header)
        
        # License warning
        self.license_warning = QLabel("⚠️ Wireless Security requires Enterprise license")
        self.license_warning.setStyleSheet("color: #FF6B6B; font-weight: bold; padding: 10px;")
        layout.addWidget(self.license_warning)
        
        # Tabs for different wireless technologies
        self.wireless_tabs = QTabWidget()
        
        # WiFi Tab
        self.wifi_tab = self.create_wifi_tab()
        self.wireless_tabs.addTab(self.wifi_tab, "WiFi Security")
        
        # Bluetooth Tab
        self.bluetooth_tab = self.create_bluetooth_tab()
        self.wireless_tabs.addTab(self.bluetooth_tab, "Bluetooth Security")
        
        layout.addWidget(self.wireless_tabs)
        
        # Status
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(100)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
    def create_wifi_tab(self):
        widget = QWidget()
        outer_layout = QVBoxLayout(widget)
        outer_layout.setContentsMargins(4, 4, 4, 4)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # ── Top: Discovery ────────────────────────────────────────────────
        discovery_group = QGroupBox("WiFi Network Discovery")
        discovery_layout = QVBoxLayout(discovery_group)

        disc_btn_row = QHBoxLayout()
        self.wifi_discover_btn = QPushButton("🔍  Discover WiFi Networks")
        self.wifi_discover_btn.setStyleSheet("background-color: #64C8FF; font-weight: bold; padding: 6px 14px;")
        disc_btn_row.addWidget(self.wifi_discover_btn)
        disc_btn_row.addStretch()

        pmf_note = QLabel("PMF = Protected Management Frames (802.11w)")
        pmf_note.setStyleSheet("color: #888; font-size: 8pt;")
        disc_btn_row.addWidget(pmf_note)
        discovery_layout.addLayout(disc_btn_row)

        # Extended table: SSID | BSSID | Security | Cipher | Channel | PMF | Signal | Risk
        self.wifi_networks_table = QTableWidget()
        self.wifi_networks_table.setColumnCount(8)
        self.wifi_networks_table.setHorizontalHeaderLabels(
            ["SSID", "BSSID", "Security", "Cipher", "Channel", "PMF", "Signal", "Risk Level"]
        )
        self.wifi_networks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.wifi_networks_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.wifi_networks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.wifi_networks_table.setAlternatingRowColors(True)
        self.wifi_networks_table.setMinimumHeight(140)
        discovery_layout.addWidget(self.wifi_networks_table)

        splitter.addWidget(discovery_group)

        # ── Middle: Attack Configuration ──────────────────────────────────
        attacks_group = QGroupBox("WiFi Security Testing")
        attacks_layout = QVBoxLayout(attacks_group)

        # Target row
        target_row = QHBoxLayout()
        target_row.addWidget(QLabel("Target SSID:"))
        self.wpa_target_input = QLineEdit()
        self.wpa_target_input.setPlaceholderText("Select from table or type manually")
        target_row.addWidget(self.wpa_target_input, 2)

        target_row.addWidget(QLabel("BSSID (optional):"))
        self.bssid_input = QLineEdit()
        self.bssid_input.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.bssid_input.setMinimumWidth(200)
        target_row.addWidget(self.bssid_input, 1)
        attacks_layout.addLayout(target_row)

        # Attack type selector
        attack_type_row = QHBoxLayout()
        attack_type_row.addWidget(QLabel("Attack Type:"))
        self.wifi_attack_type = QComboBox()
        self.wifi_attack_type.addItems([
            "WPA Handshake Capture + Crack",
            "PMKID Attack (clientless)",
            "Deauthentication / DOS",
            "Evil Twin — Captive Portal",
            "Evil Twin — WPA2-Enterprise (EAP)",
            "SSID Confusion (CVE-2023-52424)",
            "WPA3 Transition Mode Downgrade",
        ])
        self.wifi_attack_type.setMinimumWidth(280)
        attack_type_row.addWidget(self.wifi_attack_type)
        attack_type_row.addStretch()
        attacks_layout.addLayout(attack_type_row)

        # Wordlist row (shown for cracking attacks)
        self.wordlist_row = QHBoxLayout()
        self.wordlist_row.addWidget(QLabel("Wordlist:"))
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("Path to wordlist (e.g. rockyou.txt) — leave blank for built-in")
        self.wordlist_row.addWidget(self.wordlist_input, 3)
        self.wordlist_browse_btn = QPushButton("Browse…")
        self.wordlist_browse_btn.setMinimumWidth(100)
        self.wordlist_row.addWidget(self.wordlist_browse_btn)
        attacks_layout.addLayout(self.wordlist_row)

        # Evil twin mode note (shown for evil twin attacks)
        self.evil_twin_note = QLabel(
            "ℹ️  Captive portal clones the SSID with a credential-harvesting login page. "
            "EAP mode uses a rogue RADIUS server to capture MSCHAP hashes (requires hostapd-mana / EAPHammer)."
        )
        self.evil_twin_note.setStyleSheet("color: #AAA; font-size: 8pt; padding: 2px 0; margin: 0;")
        self.evil_twin_note.setWordWrap(True)
        self.evil_twin_note.setMaximumHeight(36)
        self.evil_twin_note.hide()
        attacks_layout.addWidget(self.evil_twin_note)

        # Launch button
        launch_row = QHBoxLayout()
        self.wifi_attack_btn = QPushButton("▶  Launch Attack")
        self.wifi_attack_btn.setStyleSheet(
            "background-color: #FF6B6B; font-weight: bold; padding: 6px 20px;"
        )
        launch_row.addWidget(self.wifi_attack_btn)
        launch_row.addStretch()
        attacks_layout.addLayout(launch_row)

        splitter.addWidget(attacks_group)

        # ── Bottom: Detection & Mitigation reference panel ────────────────
        info_splitter = QSplitter(Qt.Orientation.Horizontal)

        detection_group = QGroupBox("Detection Indicators")
        detection_layout = QVBoxLayout(detection_group)
        self.detection_text = QTextEdit()
        self.detection_text.setReadOnly(True)
        self.detection_text.setStyleSheet("font-size: 10pt; background-color: #1a1a2e;")
        detection_layout.addWidget(self.detection_text)
        info_splitter.addWidget(detection_group)

        mitigation_group = QGroupBox("Mitigations")
        mitigation_layout = QVBoxLayout(mitigation_group)
        self.mitigation_text = QTextEdit()
        self.mitigation_text.setReadOnly(True)
        self.mitigation_text.setStyleSheet("font-size: 10pt; background-color: #1a1a2e;")
        mitigation_layout.addWidget(self.mitigation_text)
        info_splitter.addWidget(mitigation_group)

        info_splitter.setSizes([500, 500])
        info_splitter.setStretchFactor(0, 1)
        info_splitter.setStretchFactor(1, 1)

        info_container = QWidget()
        info_container.setMaximumHeight(180)
        info_container_layout = QVBoxLayout(info_container)
        info_container_layout.setContentsMargins(0, 0, 0, 0)
        info_container_layout.addWidget(info_splitter)
        splitter.addWidget(info_container)

        splitter.setSizes([200, 180, 180])
        outer_layout.addWidget(splitter)

        # Populate detection/mitigation on load
        self._update_wifi_attack_info(self.wifi_attack_type.currentText())

        return widget
        
    def create_bluetooth_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Bluetooth Discovery
        discovery_group = QGroupBox("Bluetooth Device Discovery")
        discovery_layout = QVBoxLayout(discovery_group)
        
        self.bt_discover_btn = QPushButton("Discover Bluetooth Devices")
        self.bt_discover_btn.setStyleSheet("background-color: #64C8FF; font-weight: bold;")
        discovery_layout.addWidget(self.bt_discover_btn)
        
        # Bluetooth Devices Table
        self.bt_devices_table = QTableWidget()
        self.bt_devices_table.setColumnCount(5)
        self.bt_devices_table.setHorizontalHeaderLabels(["Name", "Address", "Type", "Transport", "Security Level"])
        self.bt_devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        discovery_layout.addWidget(self.bt_devices_table)
        
        layout.addWidget(discovery_group)
        
        # Bluetooth Attacks
        attacks_group = QGroupBox("Bluetooth Security Testing")
        attacks_layout = QVBoxLayout(attacks_group)
        
        # Attack configuration
        attack_config_layout = QHBoxLayout()
        attack_config_layout.addWidget(QLabel("Target Address:"))
        self.bt_target_input = QLineEdit()
        self.bt_target_input.setPlaceholderText("Select from discovered devices")
        attack_config_layout.addWidget(self.bt_target_input)
        
        attack_config_layout.addWidget(QLabel("Attack Type:"))
        self.bt_attack_type = QComboBox()
        self.bt_attack_type.addItems(["bluejacking", "bluesnarfing", "gatt_fuzzing", "adv_tracking"])
        attack_config_layout.addWidget(self.bt_attack_type)
        attacks_layout.addLayout(attack_config_layout)
        
        self.bt_attack_btn = QPushButton("Execute Bluetooth Attack")
        self.bt_attack_btn.setStyleSheet("background-color: #FF6B6B; font-weight: bold;")
        attacks_layout.addWidget(self.bt_attack_btn)
        
        layout.addWidget(attacks_group)
        
        return widget
        
    def create_reports_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Report Generation
        report_group = QGroupBox("Wireless Security Report")
        report_layout = QVBoxLayout(report_group)
        
        self.generate_report_btn = QPushButton("Generate Wireless Security Report")
        report_layout.addWidget(self.generate_report_btn)
        
        # Report Display
        self.report_display = QTextEdit()
        self.report_display.setReadOnly(True)
        report_layout.addWidget(self.report_display)
        
        layout.addWidget(report_group)
        
        return widget
        
    def connect_signals(self):
        self.wifi_discover_btn.clicked.connect(self.discover_wifi)
        self.bt_discover_btn.clicked.connect(self.discover_bluetooth)
        self.wifi_attack_btn.clicked.connect(self.launch_wifi_attack)
        self.bt_attack_btn.clicked.connect(self.execute_bluetooth_attack)
        self.generate_report_btn.clicked.connect(self.generate_report)
        self.wordlist_browse_btn.clicked.connect(self.browse_wordlist)

        # Attack type change → update detection/mitigation panels + show/hide relevant inputs
        self.wifi_attack_type.currentTextChanged.connect(self._update_wifi_attack_info)
        self.wifi_attack_type.currentTextChanged.connect(self._toggle_wifi_attack_inputs)

        # Table selection handlers
        self.wifi_networks_table.itemSelectionChanged.connect(self.on_wifi_selection_changed)
        self.bt_devices_table.itemSelectionChanged.connect(self.on_bt_selection_changed)

        wireless_security.wireless_event.connect(self.handle_wireless_event)
        
    def check_license(self):
        if license_manager.is_feature_enabled('wireless_security'):
            self.license_warning.hide()
            self.setEnabled(True)
        else:
            self.license_warning.show()
            self.setEnabled(False)
            
    def browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.wordlist_input.setText(path)

    def _toggle_wifi_attack_inputs(self, attack_name: str):
        """Show/hide wordlist row and evil twin note based on selected attack."""
        cracking_attacks = {"WPA Handshake Capture + Crack", "PMKID Attack (clientless)"}
        evil_twin_attacks = {"Evil Twin — Captive Portal", "Evil Twin — WPA2-Enterprise (EAP)"}

        show_wordlist = attack_name in cracking_attacks
        show_et_note = attack_name in evil_twin_attacks

        # Toggle wordlist row widgets
        self.wordlist_input.setVisible(show_wordlist)
        self.wordlist_browse_btn.setVisible(show_wordlist)
        # Find the label in the row
        for i in range(self.wordlist_row.count()):
            item = self.wordlist_row.itemAt(i)
            if item and item.widget():
                item.widget().setVisible(show_wordlist)

        self.evil_twin_note.setVisible(show_et_note)

    # Detection indicators and mitigation text keyed by attack type
    _ATTACK_INFO = {
        "WPA Handshake Capture + Crack": {
            "detection": (
                "• Clients re-authenticating frequently after deauth bursts\n"
                "• Surge of EAPOL 4-way handshake frames in packet capture\n"
                "• WIDS alert: >100 deauth frames/sec from a single source\n"
                "• 802.11w-capable clients may log 'Protected frame MIC check failed'\n"
                "• Unusual offline cracking activity on captured .hccapx / .22000 files"
            ),
            "mitigation": (
                "• Enable 802.11w Protected Management Frames (PMF) — mandatory in WPA3\n"
                "• Use long, random passphrases (20+ chars) to resist offline cracking\n"
                "• Prefer WPA3-SAE: SAE handshake resists offline dictionary attacks\n"
                "• Deploy WPA2-Enterprise (802.1X) to eliminate shared PSK entirely\n"
                "• Monitor for repeated deauth events via WIDS/WIPS"
            ),
        },
        "PMKID Attack (clientless)": {
            "detection": (
                "• Unusual EAPOL/RSN IE probe requests to the AP without an associated client\n"
                "• AP logs showing roam/reassociation requests from unknown MACs\n"
                "• Offline cracking attempts against captured PMKID hashes (Hashcat mode 22000)\n"
                "• No client traffic required — harder to detect than handshake capture"
            ),
            "mitigation": (
                "• Use WPA3-SAE: PMKID attack does not apply to SAE handshakes\n"
                "• Long, random PSKs (20+ chars) make offline cracking infeasible\n"
                "• Rotate PSKs periodically and after any suspected compromise\n"
                "• Consider WPA2-Enterprise to remove PSK attack surface entirely\n"
                "• Tools: hcxdumptool v7.1.2 + Hashcat (mode 22000) are standard"
            ),
        },
        "Deauthentication / DOS": {
            "detection": (
                "• Burst of 802.11 Deauthentication or Disassociation frames (reason code 1–7)\n"
                "• Clients repeatedly dropping and reconnecting to the same AP\n"
                "• WIDS alert: deauth flood from spoofed AP/client MAC\n"
                "• 802.11w clients will reject spoofed deauth and may log the attempt\n"
                "• MDK4 / aireplay-ng traffic pattern: high-rate unicast or broadcast deauths"
            ),
            "mitigation": (
                "• Enable 802.11w (PMF) — spoofed deauth frames are cryptographically rejected\n"
                "• WPA3 mandates PMF; upgrade networks where possible\n"
                "• Deploy WIDS/WIPS to alert on deauth floods and auto-block offending MACs\n"
                "• Schedule any legitimate deauth-based tests during off-hours with narrow scope\n"
                "• Educate users: frequent disconnects may indicate an active attack"
            ),
        },
        "Evil Twin — Captive Portal": {
            "detection": (
                "• Duplicate SSID with different BSSID visible in wireless scans\n"
                "• Clients auto-connecting to a weaker-security AP with the same SSID\n"
                "• Unexpected captive portal login page on a known network\n"
                "• Rogue DHCP/DNS server responses on the wireless segment\n"
                "• WIDS alert: new AP broadcasting a known corporate SSID\n"
                "• Sudden VPN disconnection if VPN disables on 'trusted' SSIDs (SSID Confusion risk)"
            ),
            "mitigation": (
                "• Deploy WIDS to detect rogue APs broadcasting known SSIDs\n"
                "• Use OWE (Opportunistic Wireless Encryption) for open networks\n"
                "• Enforce HTTPS on all internal portals — phishing pages cannot mimic valid certs\n"
                "• Disable auto-join for SSIDs on managed devices\n"
                "• Train users: never enter credentials on unexpected captive portals\n"
                "• Tools used by attackers: Fluxion v6.28, hostapd-mana v2.6.4, WiFiPhisher"
            ),
        },
        "Evil Twin — WPA2-Enterprise (EAP)": {
            "detection": (
                "• Rogue AP with same SSID but different RADIUS certificate CN\n"
                "• Client certificate validation warnings (if properly configured)\n"
                "• MSCHAP challenge/response captured by rogue RADIUS (EAPHammer)\n"
                "• WIDS alert: new AP on known SSID with mismatched BSSID\n"
                "• Unusual EAP-PEAP/GTC downgrade attempts in 802.1X logs"
            ),
            "mitigation": (
                "• Enforce RADIUS server certificate validation on all supplicants (EAP-TLS preferred)\n"
                "• Use per-SSID certificates with distinct CNs to prevent cross-SSID confusion\n"
                "• Prefer EAP-TLS (mutual cert auth) over PEAP/MSCHAPv2\n"
                "• Deploy WIDS to catch rogue APs on enterprise SSIDs\n"
                "• Tools used by attackers: EAPHammer v1.14.1, hostapd-mana, WPA_Sycophant"
            ),
        },
        "SSID Confusion (CVE-2023-52424)": {
            "detection": (
                "• Client connected to correct SSID but unexpected BSSID (different AP)\n"
                "• Sudden VPN auto-disconnect on a 'trusted' network (VPN disables on known SSIDs)\n"
                "• Duplicate SSID entries with different security parameters in wireless scans\n"
                "• OS-level warning about duplicate network names (some platforms)\n"
                "• Network logs: new AP with same SSID/password but different MAC"
            ),
            "mitigation": (
                "• Use unique SSIDs and passwords per network segment (guest vs. corporate)\n"
                "• For Enterprise: use distinct RADIUS certificate CNs per SSID\n"
                "• Disable VPN 'trusted network' auto-disable features\n"
                "• Upcoming 802.11 amendment will include SSID in the 4-way handshake\n"
                "• Disable auto-connect to SSIDs on managed endpoints\n"
                "• CVE-2023-52424 — affects WPA2/WPA3/OWE on all major platforms"
            ),
        },
        "WPA3 Transition Mode Downgrade": {
            "detection": (
                "• Devices connecting with WPA2 on a network advertising WPA3 support\n"
                "• Repeated SAE handshake failures followed by WPA2 4-way handshake\n"
                "• WIDS alert: jamming or deauth bursts timed to SAE exchange\n"
                "• AP logs showing clients falling back from WPA3 to WPA2 unexpectedly\n"
                "• Dragonblood-style timing anomalies in SAE commit frames"
            ),
            "mitigation": (
                "• Disable WPA3/WPA2 transition mode if all devices support WPA3-only\n"
                "• Apply Dragonblood patches — ensure AP and client firmware is current\n"
                "• Use WPA3-SAE with H2E (Hash-to-Element) to resist side-channel attacks\n"
                "• Monitor for repeated SAE handshake retries in AP logs\n"
                "• Reference: Dragonblood (2019), WPA3 SAE side-channel CVEs"
            ),
        },
    }

    def _update_wifi_attack_info(self, attack_name: str):
        """Populate detection and mitigation panels for the selected attack type."""
        info = self._ATTACK_INFO.get(attack_name, {})
        self.detection_text.setPlainText(info.get("detection", "Select an attack type above."))
        self.mitigation_text.setPlainText(info.get("mitigation", "Select an attack type above."))

    def discover_wifi(self):
        if not license_manager.is_feature_enabled('wireless_security'):
            self.status_text.append("❌ Wireless Security requires Enterprise license")
            return

        self.wifi_discover_btn.setEnabled(False)
        self.status_text.append("🔍 Discovering WiFi networks...")

        self.scan_worker = WirelessScanWorker('wifi_discovery')
        self.scan_worker.scan_completed.connect(self.handle_wifi_discovery_completed)
        self.scan_worker.start()

    def launch_wifi_attack(self):
        """Dispatch the selected WiFi attack type."""
        if not license_manager.is_feature_enabled('wireless_security'):
            self.status_text.append("❌ Wireless Security requires Enterprise license")
            return

        ssid = self.wpa_target_input.text().strip()
        if not ssid:
            self.status_text.append("❌ Please enter a target SSID")
            return

        attack_name = self.wifi_attack_type.currentText()
        wordlist = self.wordlist_input.text().strip() or None
        bssid = self.bssid_input.text().strip() or None

        self.wifi_attack_btn.setEnabled(False)

        if attack_name == "WPA Handshake Capture + Crack":
            self.status_text.append(f"🔓 Starting WPA handshake capture + crack against '{ssid}'…")
            self.scan_worker = WirelessScanWorker('wpa_test', ssid=ssid, wordlist=wordlist)
            self.scan_worker.scan_completed.connect(self.handle_wpa_test_completed)

        elif attack_name == "PMKID Attack (clientless)":
            self.status_text.append(f"🔑 Starting PMKID attack against '{ssid}'…")
            self.scan_worker = WirelessScanWorker('pmkid_attack', ssid=ssid, wordlist=wordlist)
            self.scan_worker.scan_completed.connect(self.handle_pmkid_completed)

        elif attack_name == "Deauthentication / DOS":
            self.status_text.append(f"📡 Launching deauthentication attack against '{ssid}'…")
            self.scan_worker = WirelessScanWorker('deauth_attack', ssid=ssid, bssid=bssid)
            self.scan_worker.scan_completed.connect(self.handle_deauth_completed)

        elif attack_name == "Evil Twin — Captive Portal":
            self.status_text.append(f"👥 Setting up Evil Twin (captive portal) for '{ssid}'…")
            self.scan_worker = WirelessScanWorker('evil_twin', ssid=ssid, attack_mode='captive_portal')
            self.scan_worker.scan_completed.connect(self.handle_evil_twin_completed)

        elif attack_name == "Evil Twin — WPA2-Enterprise (EAP)":
            self.status_text.append(f"👥 Setting up Evil Twin (EAP/RADIUS) for '{ssid}'…")
            self.scan_worker = WirelessScanWorker('evil_twin', ssid=ssid, attack_mode='eap_relay')
            self.scan_worker.scan_completed.connect(self.handle_evil_twin_completed)

        elif attack_name == "SSID Confusion (CVE-2023-52424)":
            self.status_text.append(f"🔀 Testing SSID Confusion attack against '{ssid}'…")
            self.scan_worker = WirelessScanWorker('ssid_confusion', ssid=ssid)
            self.scan_worker.scan_completed.connect(self.handle_ssid_confusion_completed)

        elif attack_name == "WPA3 Transition Mode Downgrade":
            self.status_text.append(f"⬇️  Testing WPA3 downgrade against '{ssid}'…")
            self.scan_worker = WirelessScanWorker('wpa3_downgrade', ssid=ssid)
            self.scan_worker.scan_completed.connect(self.handle_wpa3_downgrade_completed)

        else:
            self.status_text.append(f"❌ Unknown attack type: {attack_name}")
            self.wifi_attack_btn.setEnabled(True)
            return

        self.scan_worker.start()
        
    def discover_bluetooth(self):
        if not license_manager.is_feature_enabled('wireless_security'):
            self.status_text.append("❌ Wireless Security requires Enterprise license")
            return

        self.bt_discover_btn.setEnabled(False)
        self.status_text.append("🔍 Discovering Bluetooth devices...")

        self.scan_worker = WirelessScanWorker('bluetooth_discovery')
        self.scan_worker.scan_completed.connect(self.handle_bluetooth_discovery_completed)
        self.scan_worker.start()

    def execute_bluetooth_attack(self):
        address = self.bt_target_input.text().strip()
        attack_type = self.bt_attack_type.currentText()

        if not address:
            self.status_text.append("❌ Please enter target Bluetooth address")
            return

        self.bt_attack_btn.setEnabled(False)
        self.status_text.append(f"📱 Executing {attack_type} attack against {address}...")

        self.scan_worker = WirelessScanWorker('bluetooth_attack', address=address, attack_type=attack_type)
        self.scan_worker.scan_completed.connect(self.handle_bluetooth_attack_completed)
        self.scan_worker.start()
        
    def generate_report(self):
        report = wireless_security.generate_wireless_report()

        if 'error' in report:
            self.status_text.append(f"❌ Report generation failed: {report['error']}")
            return

        wifi = report['wifi_networks']
        bt = report['bluetooth_devices']

        lines = [
            "═" * 60,
            "  WIRELESS SECURITY ASSESSMENT REPORT",
            f"  Generated: {report.get('generated_at', 'Unknown')}",
            "═" * 60,
            "",
            "WiFi NETWORKS",
            f"  Total discovered : {wifi['total_discovered']}",
            f"  Critical issues  : {wifi['critical_issues']}",
            f"  High issues      : {wifi['high_issues']}",
            f"  Medium issues    : {wifi['medium_issues']}",
            "",
            "  Security Level Breakdown:",
        ]
        for level, count in wifi['security_breakdown'].items():
            lines.append(f"    {level:<12}: {count}")

        lines += [
            "",
            "  PMF (802.11w) Status Breakdown:",
        ]
        for status, count in wifi.get('pmf_breakdown', {}).items():
            lines.append(f"    {status:<12}: {count}")

        if wifi.get('vulnerabilities'):
            lines += ["", "  Vulnerabilities Found:"]
            for v in wifi['vulnerabilities']:
                sev = v.get('severity', '')
                icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡'}.get(sev, '⚪')
                lines.append(f"    {icon} [{sev}] {v['ssid']} — {v['vulnerability']}")
                lines.append(f"       {v.get('recommendation', '')}")

        lines += [
            "",
            "BLUETOOTH DEVICES",
            f"  Total discovered  : {bt['total_discovered']}",
            f"  Vulnerable devices: {bt['vulnerable_devices']}",
            "",
            "RECOMMENDATIONS",
        ]
        for rec in report.get('recommendations', []):
            lines.append(f"  • {rec}")

        lines.append("")
        self.report_display.setPlainText("\n".join(lines))
        self.status_text.append("📊 Wireless security report generated")
        
    def handle_wifi_discovery_completed(self, result):
        self.wifi_discover_btn.setEnabled(True)

        if 'error' in result:
            self.status_text.append(f"❌ WiFi discovery failed: {result['error']}")
            return

        networks = result.get('networks', [])
        self.wifi_networks_table.setRowCount(len(networks))

        for row, network in enumerate(networks):
            self.wifi_networks_table.setItem(row, 0, QTableWidgetItem(network.get('ssid', '')))
            self.wifi_networks_table.setItem(row, 1, QTableWidgetItem(network.get('bssid', 'N/A')))
            self.wifi_networks_table.setItem(row, 2, QTableWidgetItem(network.get('authentication', '')))
            self.wifi_networks_table.setItem(row, 3, QTableWidgetItem(network.get('cipher', '')))
            self.wifi_networks_table.setItem(row, 4, QTableWidgetItem(str(network.get('channel', 'N/A'))))

            # PMF status with colour coding
            pmf = network.get('pmf', 'Unknown')
            pmf_item = QTableWidgetItem(pmf)
            if pmf in ('Required', 'Enabled'):
                pmf_item.setForeground(QColor("#00FF41"))
            elif pmf == 'Disabled':
                pmf_item.setForeground(QColor("#FF6B6B"))
            else:
                pmf_item.setForeground(QColor("#FFA500"))
            self.wifi_networks_table.setItem(row, 5, pmf_item)

            self.wifi_networks_table.setItem(row, 6, QTableWidgetItem(str(network.get('signal_strength', 'N/A'))))

            # Risk level with colour coding
            security_level = network.get('security_level', 'Unknown')
            security_item = QTableWidgetItem(security_level)
            if security_level == 'Critical':
                security_item.setForeground(QColor("#FF0000"))
            elif security_level == 'High':
                security_item.setForeground(QColor("#FF6B6B"))
            elif security_level == 'Medium':
                security_item.setForeground(QColor("#FFA500"))
            elif security_level == 'Low':
                security_item.setForeground(QColor("#00FF41"))
            self.wifi_networks_table.setItem(row, 7, security_item)

        vuln_count = len(result.get('vulnerabilities', []))
        self.status_text.append(
            f"✅ WiFi discovery completed: {len(networks)} network(s) found"
            + (f", {vuln_count} vulnerability/ies flagged" if vuln_count else "")
        )

    # ── New WiFi attack result handlers ───────────────────────────────────

    def handle_pmkid_completed(self, result):
        self.wifi_attack_btn.setEnabled(True)
        ssid = result.get('ssid', '')
        if result.get('success'):
            self.status_text.append(f"🔑 PMKID attack succeeded on '{ssid}' — PSK cracked: {result.get('cracked_password')}")
        else:
            self.status_text.append(f"🔒 PMKID attack on '{ssid}' — PSK not recovered")
        self.status_text.append(
            f"   ↳ PMKID captured: {'Yes' if result.get('pmkid_captured') else 'No'} | "
            f"Hashes tested: {result.get('passwords_tested', 0)} | "
            f"Tool: hcxdumptool + Hashcat mode 22000"
        )
        self._show_recommendations(result)

    def handle_deauth_completed(self, result):
        self.wifi_attack_btn.setEnabled(True)
        ssid = result.get('ssid', '')
        frames = result.get('frames_sent', 0)
        clients = result.get('clients_affected', 0)
        handshake = result.get('handshake_captured', False)
        self.status_text.append(
            f"📡 Deauth attack on '{ssid}': {frames} frames sent, "
            f"{clients} client(s) affected"
        )
        if handshake:
            self.status_text.append("   ↳ ✅ WPA handshake captured — ready for offline cracking")
        else:
            self.status_text.append("   ↳ No handshake captured (no active clients or PMF enabled)")
        pmf_blocked = result.get('pmf_blocked', False)
        if pmf_blocked:
            self.status_text.append("   ↳ 🔒 802.11w PMF detected — spoofed deauth frames rejected by AP/clients")
        self._show_recommendations(result)

    def handle_evil_twin_completed(self, result):
        self.wifi_attack_btn.setEnabled(True)
        mode = result.get('attack_mode', 'captive_portal')
        ssid = result.get('target_ssid', '')
        clients = result.get('clients_connected', 0)
        mode_label = "EAP relay" if mode == 'eap_relay' else "captive portal"

        if clients > 0:
            self.status_text.append(f"👥 Evil Twin ({mode_label}) on '{ssid}': {clients} client(s) connected")
            credentials = result.get('credentials_captured', [])
            hashes = result.get('mschap_hashes_captured', [])
            if credentials:
                self.status_text.append(f"   ↳ 🔑 {len(credentials)} credential set(s) captured via portal")
            if hashes:
                self.status_text.append(f"   ↳ 🔑 {len(hashes)} MSCHAPv2 hash(es) captured — crack with Hashcat mode 5500")
        else:
            self.status_text.append(f"👥 Evil Twin ({mode_label}) on '{ssid}' — no clients connected")

        tool_note = result.get('tool_note', '')
        if tool_note:
            self.status_text.append(f"   ↳ ℹ️  {tool_note}")
        self._show_recommendations(result)

    def handle_ssid_confusion_completed(self, result):
        self.wifi_attack_btn.setEnabled(True)
        ssid = result.get('ssid', '')
        vulnerable = result.get('vulnerable', False)
        self.status_text.append(
            f"🔀 SSID Confusion test on '{ssid}': "
            f"{'⚠️  VULNERABLE' if vulnerable else '🔒 Not exploitable in current config'}"
        )
        if vulnerable:
            self.status_text.append(
                "   ↳ Clients may auto-connect to rogue AP with same SSID/password\n"
                "   ↳ CVE-2023-52424 — affects WPA2/WPA3/OWE; SSID not authenticated in 4-way handshake"
            )
        conditions = result.get('conditions_checked', [])
        for cond in conditions:
            icon = "✅" if cond.get('pass') else "❌"
            self.status_text.append(f"   {icon} {cond.get('description', '')}")
        self._show_recommendations(result)

    def handle_wpa3_downgrade_completed(self, result):
        self.wifi_attack_btn.setEnabled(True)
        ssid = result.get('ssid', '')
        downgraded = result.get('downgrade_successful', False)
        transition_mode = result.get('transition_mode_detected', False)
        self.status_text.append(
            f"⬇️  WPA3 downgrade test on '{ssid}': "
            f"{'⚠️  Downgrade to WPA2 succeeded' if downgraded else '🔒 Downgrade not achieved'}"
        )
        if transition_mode:
            self.status_text.append("   ↳ WPA3/WPA2 transition mode detected — network is susceptible to downgrade")
        if downgraded:
            self.status_text.append(
                "   ↳ WPA2 4-way handshake captured after SAE disruption\n"
                "   ↳ Reference: Dragonblood (2019), WPA3-SAE side-channel CVEs"
            )
        self._show_recommendations(result)

    def _show_recommendations(self, result: dict):
        """Append recommendations from a result dict to the status log."""
        recs = result.get('recommendations', [])
        if recs:
            self.status_text.append("📋 Recommendations:")
            for rec in recs:
                self.status_text.append(f"   • {rec}")
        
    def handle_bluetooth_discovery_completed(self, result):
        self.bt_discover_btn.setEnabled(True)

        if 'error' in result:
            self.status_text.append(f"❌ Bluetooth discovery failed: {result['error']}")
            return

        devices = result.get('devices', [])
        self.bt_devices_table.setRowCount(len(devices))

        for row, device in enumerate(devices):
            self.bt_devices_table.setItem(row, 0, QTableWidgetItem(device.get('name', 'Unknown')))
            self.bt_devices_table.setItem(row, 1, QTableWidgetItem(device.get('address', '')))
            self.bt_devices_table.setItem(row, 2, QTableWidgetItem(device.get('device_type', 'Unknown')))
            self.bt_devices_table.setItem(row, 3, QTableWidgetItem(device.get('transport', '')))

            security_level = device.get('security_level', 'Unknown')
            security_item = QTableWidgetItem(security_level)

            if security_level == 'Low':
                security_item.setForeground(QColor("#FF6B6B"))
            elif security_level == 'Medium':
                security_item.setForeground(QColor("#FFA500"))
            elif security_level == 'High':
                security_item.setForeground(QColor("#00FF41"))
            # Unknown stays default

            self.bt_devices_table.setItem(row, 4, security_item)

        scan_errors = result.get('scan_errors', [])
        for err in scan_errors:
            self.status_text.append(f"⚠️ {err}")

        self.status_text.append(f"✅ Bluetooth discovery completed: {len(devices)} device(s) found")

    def handle_wpa_test_completed(self, result):
        self.wifi_attack_btn.setEnabled(True)
        ssid = result.get('ssid', '')
        if result.get('success'):
            self.status_text.append(f"🔓 WPA cracked on '{ssid}'! Password: {result.get('cracked_password')}")
        else:
            self.status_text.append(f"🔒 WPA handshake test on '{ssid}' — password not recovered")
        self.status_text.append(
            f"   ↳ Handshake captured: {'Yes' if result.get('handshake_captured') else 'No'} | "
            f"Passwords tested: {result.get('passwords_tested', 0)} | "
            f"Elapsed: {result.get('time_elapsed', 'N/A')}"
        )
        self._show_recommendations(result)


    def handle_bluetooth_attack_completed(self, result):
        self.bt_attack_btn.setEnabled(True)

        if 'error' in result and not result.get('connected'):
            self.status_text.append(f"❌ Attack error: {result['error']}")
            return

        attack_type = result.get('attack_type', 'unknown')
        target = result.get('target', '')

        if attack_type == 'bluejacking':
            if result.get('connected'):
                writable = len(result.get('writable_characteristics', []))
                attempts = result.get('write_attempts', [])
                succeeded = sum(1 for a in attempts if a.get('success'))
                self.status_text.append(
                    f"📱 Bluejacking: connected to {target} — "
                    f"{writable} writable characteristic(s), {succeeded}/{len(attempts)} write(s) succeeded"
                )
                if result.get('success'):
                    self.status_text.append("⚠️  Device accepted unsolicited write — vulnerable to bluejacking")
                else:
                    self.status_text.append("🔒 All writes rejected — device requires authentication")
            else:
                self.status_text.append(f"📱 Bluejacking: could not connect to {target}")
                if 'error' in result:
                    self.status_text.append(f"   ↳ {result['error']}")

        elif attack_type == 'bluesnarfing':
            if result.get('connected'):
                services = len(result.get('services_found', []))
                readable = result.get('readable_characteristics', [])
                protected = result.get('auth_protected_characteristics', [])
                self.status_text.append(
                    f"📱 Bluesnarfing: {services} service(s) enumerated on {target}"
                )
                if readable:
                    self.status_text.append(
                        f"⚠️  {len(readable)} characteristic(s) readable without authentication:"
                    )
                    for char in readable:
                        val = char.get('value', '')
                        display_val = (val[:60] + '…') if len(val) > 60 else val
                        self.status_text.append(f"   • {char.get('label', char.get('uuid'))}: {display_val}")
                if protected:
                    self.status_text.append(
                        f"🔒 {len(protected)} characteristic(s) auth-protected (good)"
                    )
                if not readable:
                    self.status_text.append("🔒 No characteristics readable without authentication")
            else:
                self.status_text.append(f"📱 Bluesnarfing: could not connect to {target}")
                if 'error' in result:
                    self.status_text.append(f"   ↳ {result['error']}")

        elif attack_type == 'gatt_fuzzing':
            if result.get('connected'):
                fuzzed = result.get('characteristics_fuzzed', 0)
                findings = result.get('findings', [])
                self.status_text.append(
                    f"🔬 GATT Fuzzing: {fuzzed} characteristic(s) fuzzed on {target}"
                )
                if findings:
                    self.status_text.append(f"⚠️  {len(findings)} anomalous response(s) found:")
                    for f in findings:
                        sev = f.get('severity', '')
                        icon = '🔴' if sev == 'High' else '🟡'
                        self.status_text.append(
                            f"   {icon} [{sev}] {f.get('uuid', '')} — {f.get('finding', '')}"
                        )
                else:
                    self.status_text.append("✅ No anomalous responses — device handled all payloads correctly")
            else:
                self.status_text.append(f"🔬 GATT Fuzzing: could not connect to {target}")
                if 'error' in result:
                    self.status_text.append(f"   ↳ {result['error']}")
            ref = result.get('reference', '')
            if ref:
                self.status_text.append(f"   📖 Reference: {ref}")

        elif attack_type == 'adv_tracking':
            if result.get('device_seen'):
                obs_count = len(result.get('observations', []))
                interval = result.get('adv_interval_avg_ms')
                rssi_avg = result.get('rssi_avg')
                changed = result.get('adv_data_changed', False)
                self.status_text.append(
                    f"📡 Adv Tracking: {target} observed {obs_count} time(s) "
                    f"over {result.get('observe_window_seconds', 0)}s"
                )
                if interval:
                    self.status_text.append(f"   ↳ Avg advertisement interval: {interval:.1f} ms")
                if rssi_avg is not None:
                    self.status_text.append(
                        f"   ↳ RSSI: avg {rssi_avg} dBm "
                        f"(min {result.get('rssi_min')}, max {result.get('rssi_max')})"
                    )
                self.status_text.append(
                    f"   ↳ Address type: {result.get('address_type', 'unknown')}"
                )
                if result.get('trackable'):
                    self.status_text.append(
                        "⚠️  Device is trackable — static MAC observed throughout window"
                    )
                if changed:
                    self.status_text.append(
                        f"   ↳ Advertisement data changed {len(result.get('adv_snapshots', []))} time(s)"
                    )
            elif 'error' in result:
                self.status_text.append(f"📡 Adv Tracking: {result['error']}")
            else:
                self.status_text.append(f"📡 Adv Tracking: {target} not observed in window")

        elif attack_type == 'bluebugging':
            self.status_text.append(f"📱 Bluebugging: not applicable to modern BLE devices")
            self.status_text.append(f"   ↳ {result.get('reason', '')[:120]}")
            cves = result.get('related_cves', [])
            if cves:
                self.status_text.append(f"   Related CVEs: {', '.join(c['cve'] for c in cves)}")
            self.status_text.append(f"   ℹ️  {result.get('modern_equivalent', '')}")

        # Always show recommendations
        recs = result.get('recommendations', [])
        if recs:
            self.status_text.append("📋 Recommendations:")
            for rec in recs:
                self.status_text.append(f"   • {rec}")
            
    def on_wifi_selection_changed(self):
        current_row = self.wifi_networks_table.currentRow()
        if current_row >= 0:
            ssid_item = self.wifi_networks_table.item(current_row, 0)
            bssid_item = self.wifi_networks_table.item(current_row, 1)
            if ssid_item:
                self.wpa_target_input.setText(ssid_item.text())
            if bssid_item:
                self.bssid_input.setText(bssid_item.text())
                
    def on_bt_selection_changed(self):
        current_row = self.bt_devices_table.currentRow()
        if current_row >= 0:
            address_item = self.bt_devices_table.item(current_row, 1)
            if address_item:
                self.bt_target_input.setText(address_item.text())
                
    def handle_wireless_event(self, event_type, message, data):
        self.status_text.append(f"📡 {message}")