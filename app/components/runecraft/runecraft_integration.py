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
    """Integration component for Runecraft with new architecture"""
    
    payload_generated = pyqtSignal(str, dict)  # payload_code, metadata
    exploit_created = pyqtSignal(str, dict)    # exploit_id, exploit_data
    
    def __init__(self, tenant_id: str = "default", parent=None):
        super().__init__(parent)
        self.tenant_id = tenant_id
        self.setup_ui()
        self.setup_connections()
        
        # Real-time update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_payload_stats)
        self.update_timer.start(1000)
    
    def setup_ui(self):
        """Setup the integration UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("🔮 Runecraft - Advanced Payload Forge")
        header.setStyleSheet("""
            QLabel {
                color: #FFD700;
                font-size: 18pt;
                font-weight: bold;
                padding: 10px;
                background: rgba(0, 0, 0, 100);
                border: 2px solid #FFD700;
                border-radius: 8px;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(header)
        
        # Stats panel
        self.stats_panel = self.create_stats_panel()
        layout.addWidget(self.stats_panel)
        
        # Main Runecraft interface
        self.runecraft_tab = RunecraftTab()
        layout.addWidget(self.runecraft_tab)
        
        # Integration controls
        controls_panel = self.create_controls_panel()
        layout.addWidget(controls_panel)
    
    def create_stats_panel(self):
        """Create payload statistics panel"""
        panel = QFrame()
        panel.setMaximumHeight(80)
        layout = QHBoxLayout(panel)
        
        # Payload count
        self.payload_count_label = QLabel("Payloads Generated: 0")
        self.payload_count_label.setStyleSheet("""
            QLabel {
                color: #64C8FF;
                font-size: 12pt;
                font-weight: bold;
                padding: 5px;
            }
        """)
        layout.addWidget(self.payload_count_label)
        
        # Active sessions
        self.sessions_count_label = QLabel("Active Sessions: 0")
        self.sessions_count_label.setStyleSheet("""
            QLabel {
                color: #90EE90;
                font-size: 12pt;
                font-weight: bold;
                padding: 5px;
            }
        """)
        layout.addWidget(self.sessions_count_label)
        
        # Success rate
        self.success_rate_label = QLabel("Success Rate: 0%")
        self.success_rate_label.setStyleSheet("""
            QLabel {
                color: #FFD700;
                font-size: 12pt;
                font-weight: bold;
                padding: 5px;
            }
        """)
        layout.addWidget(self.success_rate_label)
        
        layout.addStretch()
        
        panel.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 100);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 8px;
            }
        """)
        
        return panel
    
    def create_controls_panel(self):
        """Create integration controls panel"""
        panel = QFrame()
        panel.setMaximumHeight(60)
        layout = QHBoxLayout(panel)
        
        # Deploy payload button
        deploy_btn = QPushButton("🚀 Deploy Payload")
        deploy_btn.clicked.connect(self.deploy_current_payload)
        deploy_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #4CAF50, stop:1 #2E7D32);
                color: white;
                font-size: 12pt;
                font-weight: bold;
                padding: 10px 20px;
                border: 2px solid #66BB6A;
                border-radius: 8px;
                margin: 5px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #66BB6A, stop:1 #388E3C);
            }
        """)
        layout.addWidget(deploy_btn)
        
        # Create listener button
        listener_btn = QPushButton("👂 Create Listener")
        listener_btn.clicked.connect(self.create_payload_listener)
        listener_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #FF9800, stop:1 #F57C00);
                color: white;
                font-size: 12pt;
                font-weight: bold;
                padding: 10px 20px;
                border: 2px solid #FFB74D;
                border-radius: 8px;
                margin: 5px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #FFB74D, stop:1 #FF8F00);
            }
        """)
        layout.addWidget(listener_btn)
        
        # Export to exploit generator
        export_btn = QPushButton("📤 Export to Exploits")
        export_btn.clicked.connect(self.export_to_exploit_generator)
        export_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #9C27B0, stop:1 #673AB7);
                color: white;
                font-size: 12pt;
                font-weight: bold;
                padding: 10px 20px;
                border: 2px solid #BA68C8;
                border-radius: 8px;
                margin: 5px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #AB47BC, stop:1 #7986CB);
            }
        """)
        layout.addWidget(export_btn)
        
        layout.addStretch()
        
        panel.setStyleSheet("""
            QFrame {
                background: rgba(0, 0, 0, 100);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 8px;
            }
        """)
        
        return panel
    
    def setup_connections(self):
        """Setup signal connections"""
        # Connect to Runecraft signals if available
        if hasattr(self.runecraft_tab, 'payload_forged'):
            self.runecraft_tab.payload_forged.connect(self.on_payload_forged)
    
    def on_payload_forged(self, payload_code: str, rune_data: dict):
        """Handle payload forged from Runecraft"""
        try:
            # Store payload in centralized database
            payload_data = {
                'payload_code': payload_code,
                'rune_data': rune_data,
                'forge_method': 'runecraft',
                'timestamp': str(datetime.now())
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=f"runecraft_{int(time.time())}",
                tenant_id=self.tenant_id,
                scan_type="payload_generation",
                target="runecraft_forge",
                scanner="runecraft",
                result_data=payload_data
            )
            
            self.payload_generated.emit(payload_code, payload_data)
            logger.info("Runecraft payload stored in centralized database")
            
        except Exception as e:
            logger.error(f"Failed to store Runecraft payload: {e}")
    
    def deploy_current_payload(self):
        """Deploy the current payload"""
        try:
            # Get current payload from Runecraft
            current_payload = self.runecraft_tab.get_current_payload()
            
            if not current_payload or current_payload.startswith("# No payload"):
                logger.warning("No payload available for deployment")
                return
            
            # Store deployment record
            deployment_data = {
                'payload_code': current_payload,
                'deployment_method': 'manual',
                'timestamp': str(datetime.now()),
                'status': 'deployed'
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=f"deploy_{int(time.time())}",
                tenant_id=self.tenant_id,
                scan_type="payload_deployment",
                target="manual_deployment",
                scanner="runecraft_integration",
                result_data=deployment_data
            )
            
            logger.info("Payload deployment recorded")
            
        except Exception as e:
            logger.error(f"Failed to deploy payload: {e}")
    
    def create_payload_listener(self):
        """Create listener for payload callbacks"""
        try:
            # Create reverse shell listener
            listener_id = shell_manager.create_reverse_shell_listener(4444, "netcat")
            
            # Store listener record
            listener_data = {
                'listener_id': listener_id,
                'port': 4444,
                'shell_type': 'netcat',
                'created_from': 'runecraft',
                'timestamp': str(datetime.now())
            }
            
            centralized_scan_data.add_scan_result(
                scan_id=f"listener_{int(time.time())}",
                tenant_id=self.tenant_id,
                scan_type="listener_creation",
                target="localhost:4444",
                scanner="runecraft_integration",
                result_data=listener_data
            )
            
            logger.info(f"Payload listener created: {listener_id}")
            
        except Exception as e:
            logger.error(f"Failed to create listener: {e}")
    
    def export_to_exploit_generator(self):
        """Export current payload to exploit generator"""
        try:
            current_payload = self.runecraft_tab.get_current_payload()
            
            if not current_payload or current_payload.startswith("# No payload"):
                logger.warning("No payload available for export")
                return
            
            # Create exploit record
            exploit_data = {
                'payload_source': 'runecraft',
                'payload_code': current_payload,
                'exploit_type': 'custom_payload',
                'timestamp': str(datetime.now())
            }
            
            # Store in exploit database
            centralized_scan_data.add_scan_result(
                scan_id=f"exploit_{int(time.time())}",
                tenant_id=self.tenant_id,
                scan_type="exploit_generation",
                target="runecraft_export",
                scanner="exploit_generator",
                result_data=exploit_data
            )
            
            self.exploit_created.emit(f"exploit_{int(time.time())}", exploit_data)
            logger.info("Payload exported to exploit generator")
            
        except Exception as e:
            logger.error(f"Failed to export to exploit generator: {e}")
    
    def update_payload_stats(self):
        """Update payload statistics"""
        try:
            # Get payload generation stats
            payload_data = centralized_scan_data.get_scan_data(
                tenant_id=self.tenant_id,
                scan_type="payload_generation",
                limit=100
            )
            
            # Get active sessions
            active_sessions = shell_manager.get_active_sessions()
            
            # Get deployment stats
            deployment_data = centralized_scan_data.get_scan_data(
                tenant_id=self.tenant_id,
                scan_type="payload_deployment",
                limit=100
            )
            
            # Update labels
            self.payload_count_label.setText(f"Payloads Generated: {len(payload_data)}")
            self.sessions_count_label.setText(f"Active Sessions: {len(active_sessions)}")
            
            # Calculate success rate
            if len(deployment_data) > 0:
                successful_deployments = sum(1 for d in deployment_data 
                                           if d.get('data', {}).get('status') == 'deployed')
                success_rate = (successful_deployments / len(deployment_data)) * 100
                self.success_rate_label.setText(f"Success Rate: {success_rate:.1f}%")
            
        except Exception as e:
            logger.error(f"Failed to update payload stats: {e}")