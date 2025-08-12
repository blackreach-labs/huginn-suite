# app/widgets/distributed_scan_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, 
                            QGroupBox, QLineEdit, QComboBox)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QColor
from app.core.distributed_scanning import distributed_scanner

class DistributedScanWidget(QWidget):
    """Widget for distributed scanning management and execution."""
    
    scan_completed = pyqtSignal(str, dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup distributed scanning widget UI."""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("Distributed Scanning")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(title)
        
        # Node discovery section
        discovery_group = QGroupBox("Node Discovery")
        discovery_layout = QHBoxLayout(discovery_group)
        
        self.discover_button = QPushButton("Discover Nodes")
        self.discover_button.clicked.connect(self.discover_nodes)
        discovery_layout.addWidget(self.discover_button)
        
        self.stop_discovery_button = QPushButton("Stop Discovery")
        self.stop_discovery_button.clicked.connect(self.stop_discovery)
        discovery_layout.addWidget(self.stop_discovery_button)
        
        discovery_layout.addStretch()
        layout.addWidget(discovery_group)
        
        # Nodes table
        nodes_label = QLabel("Available Nodes:")
        nodes_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(nodes_label)
        
        self.nodes_table = QTableWidget()
        self.nodes_table.setColumnCount(4)
        self.nodes_table.setHorizontalHeaderLabels(["Node ID", "Host", "Status", "Capabilities"])
        self.nodes_table.setMaximumHeight(150)
        layout.addWidget(self.nodes_table)
        
        # Distributed scan section
        scan_group = QGroupBox("Distributed Scan")
        scan_layout = QVBoxLayout(scan_group)
        
        # Scan controls
        controls_layout = QHBoxLayout()
        
        controls_layout.addWidget(QLabel("Scan Type:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["dns", "port", "http"])
        controls_layout.addWidget(self.scan_type_combo)
        
        self.start_scan_button = QPushButton("Start Distributed Scan")
        self.start_scan_button.clicked.connect(self.start_distributed_scan)
        controls_layout.addWidget(self.start_scan_button)
        
        controls_layout.addStretch()
        scan_layout.addLayout(controls_layout)
        
        # Targets input
        targets_layout = QHBoxLayout()
        targets_layout.addWidget(QLabel("Targets:"))
        
        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText("Enter targets separated by commas")
        targets_layout.addWidget(self.targets_input)
        
        scan_layout.addLayout(targets_layout)
        layout.addWidget(scan_group)
        
        # Results area
        results_label = QLabel("Distributed Scan Results:")
        results_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(results_label)
        
        self.results_output = QTextEdit()
        self.results_output.setMaximumHeight(200)
        self.results_output.setPlaceholderText("Distributed scan results will appear here...")
        layout.addWidget(self.results_output)
        
        layout.addStretch()
        
    def connect_signals(self):
        """Connect distributed scanning signals."""
        distributed_scanner.node_discovered.connect(self.on_node_discovered)
        distributed_scanner.scan_distributed.connect(self.on_scan_distributed)
        distributed_scanner.results_collected.connect(self.on_results_collected)
        
    def discover_nodes(self):
        """Start node discovery."""
        self.results_output.append("Starting node discovery...")
        self.nodes_table.setRowCount(0)
        
        # Start discovery
        distributed_scanner.discover_nodes()
        
        self.results_output.append("Discovery started - listening for nodes...")
        
    def stop_discovery(self):
        """Stop node discovery."""
        distributed_scanner.stop_discovery()
        self.results_output.append("Node discovery stopped")
        
    def start_distributed_scan(self):
        """Start distributed scanning."""
        targets_text = self.targets_input.text().strip()
        if not targets_text:
            # Use parent target if available
            if hasattr(self.parent(), 'target_input'):
                targets_text = self.parent().target_input.text().strip()
            
            if not targets_text:
                self.results_output.append("Please enter targets for scanning")
                return
        
        targets = [t.strip() for t in targets_text.split(',') if t.strip()]
        scan_type = self.scan_type_combo.currentText()
        
        self.results_output.append(f"Starting distributed {scan_type} scan for {len(targets)} targets...")
        
        result = distributed_scanner.distribute_scan(scan_type, targets)
        
        if 'error' in result:
            self.results_output.append(f"Error: {result['error']}")
        else:
            self.results_output.append(f"Scan distributed to {result['nodes']} nodes with {result['tasks']} tasks")
            
    def on_node_discovered(self, node_id, node_info):
        """Handle node discovery."""
        self.results_output.append(f"Discovered node: {node_id}")
        
        # Add to nodes table
        row = self.nodes_table.rowCount()
        self.nodes_table.insertRow(row)
        
        self.nodes_table.setItem(row, 0, QTableWidgetItem(node_id))
        self.nodes_table.setItem(row, 1, QTableWidgetItem(node_info['host']))
        
        status_item = QTableWidgetItem(node_info['status'].upper())
        if node_info['status'] == 'online':
            status_item.setBackground(QColor(100, 255, 100, 100))
        else:
            status_item.setBackground(QColor(255, 150, 150, 100))
        self.nodes_table.setItem(row, 2, status_item)
        
        capabilities = ', '.join(node_info.get('capabilities', []))
        self.nodes_table.setItem(row, 3, QTableWidgetItem(capabilities))
        
    def on_scan_distributed(self, scan_id, scan_info):
        """Handle scan distribution."""
        self.results_output.append(f"Scan {scan_id} distributed:")
        self.results_output.append(f"  Nodes: {scan_info['nodes']}")
        self.results_output.append(f"  Targets: {scan_info['targets']}")
        self.results_output.append(f"  Tasks: {scan_info['tasks']}")
        self.results_output.append("Waiting for results...")
        
    def on_results_collected(self, scan_id, results):
        """Handle distributed scan results."""
        self.results_output.append(f"Scan {scan_id} completed!")
        
        summary = results.get('summary', {})
        self.results_output.append(f"Results from {summary.get('total_nodes', 0)} nodes")
        self.results_output.append(f"Total results: {summary.get('total_results', 0)}")
        
        # Display results from each node
        scan_results = results.get('results', {})
        for node_id, node_results in scan_results.items():
            self.results_output.append(f"Node {node_id}:")
            self.results_output.append(f"  Targets scanned: {node_results.get('targets_scanned', 0)}")
            self.results_output.append(f"  Results: {len(node_results.get('data', []))}")
        
        self.results_output.append("---")
        self.scan_completed.emit(scan_id, results)