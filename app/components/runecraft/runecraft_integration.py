# app/components/runecraft/runecraft_integration.py
import time
from datetime import datetime
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QFrame
from PyQt6.QtCore import pyqtSignal, QTimer
from app.pages.exploitation.runecraft_tab import RunecraftTab
from app.core.centralized_scan_data import centralized_scan_data
from app.core.exploit_generator import exploit_generator
from app.core.shell_manager import shell_manager
from app.core.logger import logger


class RunecraftIntegrationComponent(QWidget):
    """Integration component for Runecraft with new architecture."""

    payload_generated = pyqtSignal(str, dict)
    exploit_created = pyqtSignal(str, dict)

    def __init__(self, tenant_id: str = "default", parent=None):
        super().__init__(parent)
        self.tenant_id = tenant_id
        self.setup_ui()
        self.setup_connections()

        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_payload_stats)
        self.update_timer.start(1000)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Stats row
        stats = QFrame()
        stats.setMaximumHeight(40)
        sl = QHBoxLayout(stats)
        sl.setContentsMargins(8, 4, 8, 4)
        self.payload_count_label = QLabel("Payloads: 0")
        self.sessions_count_label = QLabel("Sessions: 0")
        self.success_rate_label = QLabel("Success: 0%")
        sl.addWidget(self.payload_count_label)
        sl.addWidget(self.sessions_count_label)
        sl.addWidget(self.success_rate_label)
        sl.addStretch()
        layout.addWidget(stats)

        # Main Runecraft interface
        self.runecraft_tab = RunecraftTab()
        layout.addWidget(self.runecraft_tab, 1)

        # Controls row
        controls = QFrame()
        controls.setMaximumHeight(44)
        cl = QHBoxLayout(controls)
        cl.setContentsMargins(8, 4, 8, 4)

        deploy_btn = QPushButton("Deploy Payload")
        deploy_btn.clicked.connect(self.deploy_current_payload)
        cl.addWidget(deploy_btn)

        listener_btn = QPushButton("Create Listener")
        listener_btn.clicked.connect(self.create_payload_listener)
        cl.addWidget(listener_btn)

        export_btn = QPushButton("Export to Exploits")
        export_btn.clicked.connect(self.export_to_exploit_generator)
        cl.addWidget(export_btn)

        cl.addStretch()
        layout.addWidget(controls)

    def setup_connections(self):
        if hasattr(self.runecraft_tab, 'payload_forged'):
            self.runecraft_tab.payload_forged.connect(self.on_payload_forged)

    def on_payload_forged(self, payload_code: str, rune_data: dict):
        try:
            payload_data = {
                'payload_code': payload_code,
                'rune_data': rune_data,
                'forge_method': 'runecraft',
                'timestamp': str(datetime.now()),
            }
            centralized_scan_data.add_scan_result(
                scan_id=f"runecraft_{int(time.time())}",
                tenant_id=self.tenant_id,
                scan_type="payload_generation",
                target="runecraft_forge",
                scanner="runecraft",
                result_data=payload_data,
            )
            self.payload_generated.emit(payload_code, payload_data)
        except Exception as e:
            logger.error(f"Failed to store Runecraft payload: {e}")

    def deploy_current_payload(self):
        try:
            current_payload = self.runecraft_tab.get_current_payload()
            if not current_payload or current_payload.startswith("# No payload"):
                return
            centralized_scan_data.add_scan_result(
                scan_id=f"deploy_{int(time.time())}",
                tenant_id=self.tenant_id,
                scan_type="payload_deployment",
                target="manual_deployment",
                scanner="runecraft_integration",
                result_data={'payload_code': current_payload, 'status': 'deployed', 'timestamp': str(datetime.now())},
            )
        except Exception as e:
            logger.error(f"Failed to deploy payload: {e}")

    def create_payload_listener(self):
        try:
            listener_id = shell_manager.create_reverse_shell_listener(4444, "netcat")
            centralized_scan_data.add_scan_result(
                scan_id=f"listener_{int(time.time())}",
                tenant_id=self.tenant_id,
                scan_type="listener_creation",
                target="localhost:4444",
                scanner="runecraft_integration",
                result_data={'listener_id': listener_id, 'port': 4444, 'timestamp': str(datetime.now())},
            )
        except Exception as e:
            logger.error(f"Failed to create listener: {e}")

    def export_to_exploit_generator(self):
        try:
            current_payload = self.runecraft_tab.get_current_payload()
            if not current_payload or current_payload.startswith("# No payload"):
                return
            exploit_data = {'payload_source': 'runecraft', 'payload_code': current_payload, 'timestamp': str(datetime.now())}
            centralized_scan_data.add_scan_result(
                scan_id=f"exploit_{int(time.time())}",
                tenant_id=self.tenant_id,
                scan_type="exploit_generation",
                target="runecraft_export",
                scanner="exploit_generator",
                result_data=exploit_data,
            )
            self.exploit_created.emit(f"exploit_{int(time.time())}", exploit_data)
        except Exception as e:
            logger.error(f"Failed to export to exploit generator: {e}")

    def update_payload_stats(self):
        try:
            payload_data = centralized_scan_data.get_scan_data(tenant_id=self.tenant_id, scan_type="payload_generation", limit=100)
            active_sessions = shell_manager.get_active_sessions()
            deployment_data = centralized_scan_data.get_scan_data(tenant_id=self.tenant_id, scan_type="payload_deployment", limit=100)

            self.payload_count_label.setText(f"Payloads: {len(payload_data)}")
            self.sessions_count_label.setText(f"Sessions: {len(active_sessions)}")

            if deployment_data:
                successful = sum(1 for d in deployment_data if d.get('data', {}).get('status') == 'deployed')
                rate = (successful / len(deployment_data)) * 100
                self.success_rate_label.setText(f"Success: {rate:.0f}%")
        except Exception as e:
            logger.error(f"Failed to update payload stats: {e}")
