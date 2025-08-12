# app/core/distributed_scanning.py
import json
import socket
import threading
import time
from datetime import datetime
from PyQt6.QtCore import QObject, pyqtSignal, QThread

class DistributedNode:
    """Represents a distributed scanning node."""
    
    def __init__(self, host, port, node_id=None):
        self.host = host
        self.port = port
        self.node_id = node_id or f"{host}:{port}"
        self.status = "unknown"
        self.last_seen = None
        self.capabilities = []

class DistributedScanner(QObject):
    """Manages distributed scanning across multiple nodes."""
    
    node_discovered = pyqtSignal(str, dict)
    scan_distributed = pyqtSignal(str, dict)
    results_collected = pyqtSignal(str, dict)
    
    def __init__(self):
        super().__init__()
        self.nodes = {}
        self.active_scans = {}
        self.coordinator_port = 9999
        self.discovery_enabled = False
        
    def start_coordinator(self):
        """Start the distributed scanning coordinator."""
        try:
            self.coordinator_thread = threading.Thread(target=self._coordinator_server, daemon=True)
            self.coordinator_thread.start()
            return True
        except Exception as e:
            return False
    
    def _coordinator_server(self):
        """Run the coordinator server."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', self.coordinator_port))
            server.listen(5)
            server.settimeout(1.0)
            
            while self.discovery_enabled:
                try:
                    client, addr = server.accept()
                    threading.Thread(target=self._handle_node_connection, 
                                   args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception:
                    break
                    
        except Exception:
            pass
    
    def _handle_node_connection(self, client, addr):
        """Handle connection from a scanning node."""
        try:
            client.settimeout(10.0)
            data = client.recv(1024).decode('utf-8')
            message = json.loads(data)
            
            if message.get('type') == 'node_register':
                node_info = {
                    'host': addr[0],
                    'port': message.get('port', 9998),
                    'capabilities': message.get('capabilities', ['dns', 'port']),
                    'status': 'online',
                    'last_seen': datetime.now().isoformat()
                }
                
                node_id = f"{addr[0]}:{message.get('port', 9998)}"
                self.nodes[node_id] = DistributedNode(addr[0], message.get('port', 9998))
                self.nodes[node_id].status = 'online'
                self.nodes[node_id].capabilities = node_info['capabilities']
                self.nodes[node_id].last_seen = datetime.now()
                
                response = {'status': 'registered', 'node_id': node_id}
                client.send(json.dumps(response).encode('utf-8'))
                
                self.node_discovered.emit(node_id, node_info)
                
        except Exception:
            pass
        finally:
            client.close()
    
    def discover_nodes(self, network_range="192.168.1.0/24"):
        """Discover available scanning nodes on the network."""
        self.discovery_enabled = True
        if not hasattr(self, 'coordinator_thread') or not self.coordinator_thread.is_alive():
            self.start_coordinator()
        
        # Simple node discovery by trying common ports
        discovery_thread = threading.Thread(target=self._discover_nodes_worker, 
                                           args=(network_range,), daemon=True)
        discovery_thread.start()
        
    def _discover_nodes_worker(self, network_range):
        """Worker thread for node discovery."""
        # Simplified discovery - check localhost and common IPs
        test_hosts = ['127.0.0.1', '192.168.1.100', '192.168.1.101']
        
        for host in test_hosts:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                result = sock.connect_ex((host, 9998))
                
                if result == 0:
                    # Simulate node registration
                    node_info = {
                        'host': host,
                        'port': 9998,
                        'capabilities': ['dns', 'port', 'http'],
                        'status': 'online',
                        'last_seen': datetime.now().isoformat()
                    }
                    
                    node_id = f"{host}:9998"
                    if node_id not in self.nodes:
                        self.nodes[node_id] = DistributedNode(host, 9998)
                        self.nodes[node_id].status = 'online'
                        self.nodes[node_id].capabilities = node_info['capabilities']
                        self.nodes[node_id].last_seen = datetime.now()
                        
                        self.node_discovered.emit(node_id, node_info)
                
                sock.close()
            except Exception:
                pass
    
    def distribute_scan(self, scan_type, targets, parameters=None):
        """Distribute scan across available nodes."""
        if not self.nodes:
            return {"error": "No nodes available for distributed scanning"}
        
        # Filter nodes by capability
        capable_nodes = [node for node in self.nodes.values() 
                        if scan_type in node.capabilities and node.status == 'online']
        
        if not capable_nodes:
            return {"error": f"No nodes capable of {scan_type} scanning"}
        
        # Distribute targets across nodes
        scan_id = f"scan_{int(time.time())}"
        targets_per_node = max(1, len(targets) // len(capable_nodes))
        
        distributed_tasks = []
        for i, node in enumerate(capable_nodes):
            start_idx = i * targets_per_node
            end_idx = start_idx + targets_per_node if i < len(capable_nodes) - 1 else len(targets)
            node_targets = targets[start_idx:end_idx]
            
            if node_targets:
                task = {
                    'scan_id': scan_id,
                    'node_id': node.node_id,
                    'scan_type': scan_type,
                    'targets': node_targets,
                    'parameters': parameters or {},
                    'status': 'assigned'
                }
                distributed_tasks.append(task)
        
        self.active_scans[scan_id] = {
            'scan_type': scan_type,
            'total_targets': len(targets),
            'tasks': distributed_tasks,
            'results': {},
            'started': datetime.now().isoformat(),
            'status': 'running'
        }
        
        # Simulate task distribution and execution
        threading.Thread(target=self._simulate_distributed_execution, 
                        args=(scan_id,), daemon=True).start()
        
        self.scan_distributed.emit(scan_id, {
            'scan_id': scan_id,
            'nodes': len(capable_nodes),
            'targets': len(targets),
            'tasks': len(distributed_tasks)
        })
        
        return {"scan_id": scan_id, "nodes": len(capable_nodes), "tasks": len(distributed_tasks)}
    
    def _simulate_distributed_execution(self, scan_id):
        """Simulate distributed scan execution."""
        time.sleep(2)  # Simulate scan time
        
        scan_info = self.active_scans.get(scan_id)
        if not scan_info:
            return
        
        # Simulate results from each node
        combined_results = {}
        for task in scan_info['tasks']:
            node_results = self._simulate_node_results(task)
            combined_results[task['node_id']] = node_results
        
        scan_info['results'] = combined_results
        scan_info['status'] = 'completed'
        scan_info['completed'] = datetime.now().isoformat()
        
        self.results_collected.emit(scan_id, {
            'scan_id': scan_id,
            'status': 'completed',
            'results': combined_results,
            'summary': {
                'total_nodes': len(combined_results),
                'total_results': sum(len(r.get('data', [])) for r in combined_results.values())
            }
        })
    
    def _simulate_node_results(self, task):
        """Simulate results from a scanning node."""
        # Generate mock results based on scan type
        if task['scan_type'] == 'dns':
            return {
                'node_id': task['node_id'],
                'scan_type': 'dns',
                'targets_scanned': len(task['targets']),
                'data': [f"result_{i}.{target}" for i, target in enumerate(task['targets'][:3])]
            }
        elif task['scan_type'] == 'port':
            return {
                'node_id': task['node_id'],
                'scan_type': 'port',
                'targets_scanned': len(task['targets']),
                'data': [{'host': target, 'ports': [22, 80, 443]} for target in task['targets'][:2]]
            }
        else:
            return {
                'node_id': task['node_id'],
                'scan_type': task['scan_type'],
                'targets_scanned': len(task['targets']),
                'data': [f"scan_result_{target}" for target in task['targets'][:2]]
            }
    
    def get_scan_status(self, scan_id):
        """Get status of distributed scan."""
        return self.active_scans.get(scan_id, {"error": "Scan not found"})
    
    def get_node_status(self):
        """Get status of all nodes."""
        return {
            node_id: {
                'host': node.host,
                'port': node.port,
                'status': node.status,
                'capabilities': node.capabilities,
                'last_seen': node.last_seen.isoformat() if node.last_seen else None
            }
            for node_id, node in self.nodes.items()
        }
    
    def stop_discovery(self):
        """Stop node discovery."""
        self.discovery_enabled = False

# Global distributed scanner instance
distributed_scanner = DistributedScanner()