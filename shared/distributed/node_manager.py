import threading
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ScanNode:
    node_id: str
    host: str
    port: int
    capabilities: List[str]
    status: str = "idle"
    last_heartbeat: datetime = None
    
    def __post_init__(self):
        if self.last_heartbeat is None:
            self.last_heartbeat = datetime.now()

class NodeManager:
    """Manages distributed scan nodes"""
    
    def __init__(self):
        self.nodes: Dict[str, ScanNode] = {}
        self._lock = threading.RLock()
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
    
    def register_node(self, node: ScanNode) -> bool:
        """Register a new scan node"""
        with self._lock:
            if node.node_id in self.nodes:
                return False
            
            self.nodes[node.node_id] = node
            return True
    
    def unregister_node(self, node_id: str) -> bool:
        """Unregister a scan node"""
        with self._lock:
            if node_id in self.nodes:
                del self.nodes[node_id]
                return True
            return False
    
    def get_available_nodes(self, capability: str = None) -> List[ScanNode]:
        """Get available nodes with optional capability filter"""
        with self._lock:
            available = []
            for node in self.nodes.values():
                if node.status == "idle":
                    if capability is None or capability in node.capabilities:
                        available.append(node)
            return available
    
    def update_node_status(self, node_id: str, status: str) -> bool:
        """Update node status"""
        with self._lock:
            if node_id in self.nodes:
                self.nodes[node_id].status = status
                self.nodes[node_id].last_heartbeat = datetime.now()
                return True
            return False
    
    def start_monitoring(self):
        """Start node health monitoring"""
        with self._lock:
            if self._monitoring:
                return
            
            self._monitoring = True
            self._monitor_thread = threading.Thread(target=self._monitor_nodes, daemon=True)
            self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop node health monitoring"""
        with self._lock:
            self._monitoring = False
            if self._monitor_thread:
                self._monitor_thread.join(timeout=2.0)
    
    def _monitor_nodes(self):
        """Monitor node health and remove stale nodes"""
        while self._monitoring:
            try:
                current_time = datetime.now()
                stale_nodes = []
                
                with self._lock:
                    for node_id, node in self.nodes.items():
                        time_diff = (current_time - node.last_heartbeat).total_seconds()
                        if time_diff > 60:  # 60 second timeout
                            stale_nodes.append(node_id)
                
                for node_id in stale_nodes:
                    self.unregister_node(node_id)
                
                time.sleep(30)  # Check every 30 seconds
            except Exception:
                pass