# app/pages/cracking_page.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
                             QSplitter, QGroupBox)
from PyQt6.QtCore import pyqtSignal, Qt
from app.core.logger import logger


class CrackingPage(QWidget):
    """Cracking tools page with tabbed interface for hash cracking and SSH key parsing."""
    PAGE_TITLE = "Cracking"
    PAGE_ICON = "🔐"
    navigate_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.setObjectName("CrackingPage")

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(5, 5, 5, 5)
        self.main_layout.setSpacing(0)

        self._create_tabs()

    def _create_tabs(self):
        """Create the tabbed interface."""
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)

        ssh_tab = self._create_ssh_key_parser_tab()
        if ssh_tab:
            self.tab_widget.addTab(ssh_tab, "🔑 SSH Key Parser")

        hash_tab = self._create_hash_cracking_tab()
        self.tab_widget.addTab(hash_tab, "🔓 Hash Cracking")

        self.main_layout.addWidget(self.tab_widget)

    def _create_hash_cracking_tab(self):
        """Create the hash cracking tab — left/right split layout."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(0)

        try:
            from app.components.cracking.hash_lookup_component import HashLookupComponent
            from app.components.cracking.hash_analysis_component import HashAnalysisComponent
            from app.components.cracking.attack_configuration_component import AttackConfigurationComponent
            from app.components.cracking.live_attacks_component import LiveAttacksComponent
            from app.components.cracking.results_management_component import ResultsManagementComponent

            self.hash_lookup = HashLookupComponent()
            self.hash_analysis = HashAnalysisComponent()
            self.attack_config = AttackConfigurationComponent()
            self.live_attacks = LiveAttacksComponent()
            self.results_mgmt = ResultsManagementComponent()

            # Wire signals: when Start is clicked, build config from attack_config and run
            self.attack_config.attack_configured.connect(self.live_attacks.set_attack_config)
            self.live_attacks.start_btn.clicked.disconnect()  # disconnect default
            self.live_attacks.start_btn.clicked.connect(self._launch_attack)
            if hasattr(self.live_attacks, 'cracked_result'):
                self.live_attacks.cracked_result.connect(self._on_hash_cracked)

            # Horizontal splitter: left panel | right panel
            splitter = QSplitter(Qt.Orientation.Horizontal)

            # --- LEFT PANEL: Lookup + Analysis ---
            left_panel = QWidget()
            left_layout = QVBoxLayout(left_panel)
            left_layout.setContentsMargins(0, 0, 0, 0)
            left_layout.setSpacing(4)

            lookup_group = QGroupBox("Hash Lookup")
            lookup_gl = QVBoxLayout(lookup_group)
            lookup_gl.setContentsMargins(4, 12, 4, 4)
            lookup_gl.addWidget(self.hash_lookup)
            left_layout.addWidget(lookup_group)

            analysis_group = QGroupBox("Hash Analysis")
            analysis_gl = QVBoxLayout(analysis_group)
            analysis_gl.setContentsMargins(4, 12, 4, 4)
            analysis_gl.addWidget(self.hash_analysis)
            left_layout.addWidget(analysis_group, 1)

            splitter.addWidget(left_panel)

            # --- RIGHT PANEL: Hash Cracking (config + live output + results) ---
            right_panel = QWidget()
            right_layout = QVBoxLayout(right_panel)
            right_layout.setContentsMargins(0, 0, 0, 0)
            right_layout.setSpacing(4)

            cracking_group = QGroupBox("Hash Cracking")
            cracking_gl = QVBoxLayout(cracking_group)
            cracking_gl.setContentsMargins(4, 12, 4, 4)
            cracking_gl.setSpacing(4)
            cracking_gl.addWidget(self.attack_config)
            cracking_gl.addWidget(self.live_attacks, 1)
            right_layout.addWidget(cracking_group, 1)

            results_group = QGroupBox("Results")
            results_gl = QVBoxLayout(results_group)
            results_gl.setContentsMargins(4, 12, 4, 4)
            results_gl.addWidget(self.results_mgmt)
            right_layout.addWidget(results_group)

            splitter.addWidget(right_panel)

            # Default split: 40% left, 60% right
            splitter.setStretchFactor(0, 2)
            splitter.setStretchFactor(1, 3)

            layout.addWidget(splitter)

        except Exception as e:
            logger.error(f"Failed to create hash cracking tab: {e}")
            from PyQt6.QtWidgets import QLabel
            error_label = QLabel(f"Hash cracking components unavailable: {e}")
            error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            error_label.setStyleSheet("color: #FF6666; font-size: 12pt; padding: 50px;")
            layout.addWidget(error_label)

        return tab

    def _create_ssh_key_parser_tab(self):
        """Create the SSH key parser tab."""
        try:
            from app.components.cracking.ssh_key_parser_component import SSHKeyParserComponent
            return SSHKeyParserComponent()
        except Exception as e:
            logger.error(f"Failed to create SSH key parser tab: {e}")
            return None

    def get_page_title(self):
        return "Cracking"

    def is_page_ready(self):
        return True

    def on_page_activated(self):
        pass

    def cleanup(self):
        pass

    def _on_hash_cracked(self, result: dict):
        """Forward cracked hash to the results management component."""
        if hasattr(self, 'results_mgmt'):
            # Detect type from the hash value
            hash_val = result.get("hash", "")
            if "$sshng$" in hash_val:
                hash_type = "SSH Private Key"
            elif len(hash_val) == 32:
                hash_type = "MD5"
            elif len(hash_val) == 40:
                hash_type = "SHA1"
            elif len(hash_val) == 64:
                hash_type = "SHA256"
            else:
                hash_type = "Unknown"
            self.results_mgmt.add_result(
                hash_val,
                result.get("password", ""),
                hash_type,
            )

    def _launch_attack(self):
        """Build config from attack_config component and start the attack."""
        self.attack_config._configure_attack()  # emits attack_configured → sets config
        # Inject GPU state from live_attacks checkbox into the config
        if self.live_attacks._attack_config:
            self.live_attacks._attack_config["config"]["gpu"] = self.live_attacks.gpu_check.isChecked()
        self.live_attacks.start_attack()
