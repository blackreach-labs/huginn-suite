from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox, QSpinBox, QFrame)
from PyQt6.QtCore import pyqtSignal
from app.components.progress_component import ProgressComponent
from app.core.asset_manager import asset_manager

class NetworkSweepComponent(QWidget):
    sweep_started = pyqtSignal(str)
    sweep_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup network sweep UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Input section
        input_frame = self.create_input_section()
        layout.addWidget(input_frame)
        
        # Progress component
        self.progress_component = ProgressComponent(self)
        layout.addWidget(self.progress_component)
        
        # Output section
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Network sweep results will appear here...")
        layout.addWidget(self.output_text)

    def create_input_section(self):
        """Create input controls section"""
        frame = QFrame()
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target Network:"))
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., 192.168.1.0/24")
        target_layout.addWidget(self.target_input)
        
        layout.addLayout(target_layout)
        
        # Scan options
        options_layout = QHBoxLayout()
        
        # Scan type
        options_layout.addWidget(QLabel("Scan Type:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Ping Sweep", "TCP SYN", "UDP Scan", "ARP Scan"])
        options_layout.addWidget(self.scan_type_combo)
        
        # Threads
        options_layout.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 100)
        self.threads_spin.setValue(50)
        self.threads_spin.setFixedWidth(80)
        options_layout.addWidget(self.threads_spin)
        
        # Timeout
        options_layout.addWidget(QLabel("Timeout:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(3)
        self.timeout_spin.setSuffix("s")
        self.timeout_spin.setFixedWidth(80)
        options_layout.addWidget(self.timeout_spin)
        
        options_layout.addStretch()
        
        # Control buttons
        self.start_button = QPushButton("Start Network Sweep")
        self.start_button.clicked.connect(self.start_sweep)
        options_layout.addWidget(self.start_button)
        
        layout.addLayout(options_layout)
        
        return frame

    def start_sweep(self):
        """Start network sweep"""
        target = self.target_input.text().strip()
        if not target:
            return
        
        self.output_text.clear()
        self.progress_component.start_progress(f"Network sweep for {target}")
        self.start_button.setEnabled(False)
        
        self.sweep_started.emit(target)
        
        # Run sweep
        self.run_network_sweep(target)

    def run_network_sweep(self, target):
        """Run network sweep"""
        scan_type = self.scan_type_combo.currentText()
        threads = self.threads_spin.value()
        timeout = self.timeout_spin.value()
        
        self.append_output(f"Starting Network {scan_type} for: {target}")
        self.append_output(f"Threads: {threads}, Timeout: {timeout}s")
        self.append_output("=" * 50)
        
        # Simulate network sweep
        results = self.simulate_network_sweep(target, scan_type)
        
        self.append_output("=" * 50)
        self.append_output(f"Network sweep completed - {len(results)} hosts found")
        
        # Add discovered assets to inventory
        self.add_assets_to_inventory(results)
        
        self.progress_component.finish_progress("Sweep completed")
        self.start_button.setEnabled(True)
        
        self.sweep_completed.emit(results)

    def simulate_network_sweep(self, target, scan_type):
        """Simulate network sweep results"""
        # Parse network range
        try:
            import ipaddress
            network = ipaddress.ip_network(target, strict=False)
            
            # Simulate finding some hosts
            results = {}
            host_count = min(10, network.num_addresses)  # Limit for simulation
            
            for i, host in enumerate(network.hosts()):
                if i >= host_count:
                    break
                
                # Simulate host discovery
                if i % 3 == 0:  # Every 3rd host is "up"
                    host_ip = str(host)
                    results[host_ip] = {
                        'status': 'up',
                        'response_time': f"{(i % 5) + 1}ms",
                        'method': scan_type
                    }
                    self.append_output(f"[+] {host_ip} - Host is up ({scan_type})")
            
            return results
            
        except Exception as e:
            self.append_output(f"[ERROR] Invalid network range: {e}")
            return {}

    def add_assets_to_inventory(self, results):
        """Add discovered assets to inventory"""
        try:
            tenant_id = self.get_current_tenant()
            self.append_output(f"[DEBUG] Using tenant ID: {tenant_id}")
            added_count = 0
            
            for ip_address, data in results.items():
                if data.get('status') == 'up':
                    asset_data = {
                        'ip_address': ip_address,
                        'status': 'DISCOVERED',
                        'confidence': 50,
                        'metadata': {
                            'discovery_method': 'network_sweep',
                            'response_time': data.get('response_time'),
                            'scan_method': data.get('method')
                        }
                    }
                    
                    asset_id = asset_manager.add_or_update_asset(tenant_id, **asset_data)
                    self.append_output(f"[+] Added asset {ip_address} with ID: {asset_id}")
                    added_count += 1
            
            if added_count > 0:
                self.append_output(f"[+] Added {added_count} assets to inventory for tenant {tenant_id}")
            else:
                self.append_output(f"[!] No assets added to inventory")
            
        except Exception as e:
            self.append_output(f"[ERROR] Failed to add assets to inventory: {e}")
            import traceback
            self.append_output(f"[ERROR] Traceback: {traceback.format_exc()}")
    
    def get_current_tenant(self):
        """Get current tenant from main window"""
        try:
            # Try multiple parent levels to find main window
            widget = self
            for i in range(5):  # Check up to 5 levels up
                widget = widget.parent()
                if widget is None:
                    break
                if hasattr(widget, 'current_profile_name'):
                    profile = widget.current_profile_name or 'default'
                    print(f"Found profile at level {i}: {profile}")
                    return profile
            print("No profile found, using default")
            return 'default'
        except Exception as e:
            print(f"Error getting tenant: {e}")
            return 'default'

    def append_output(self, text):
        """Append text to output"""
        self.output_text.append(text)

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass