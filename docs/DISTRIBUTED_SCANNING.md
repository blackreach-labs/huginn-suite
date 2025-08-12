# Distributed Scanning Guide

## Overview

Huggin's distributed scanning system enables scaling scan operations across multiple nodes for improved performance and parallel processing capabilities.

## Architecture

### Components
- **Coordinator**: Central node that manages task distribution and result collection
- **Scanning Nodes**: Worker nodes that execute scan tasks
- **Discovery Service**: Automatic node discovery and registration
- **Task Distributor**: Intelligent workload distribution across nodes

### Communication Protocol
- **Node Registration**: Nodes register with coordinator on startup
- **Task Assignment**: Coordinator distributes scan tasks to capable nodes
- **Result Collection**: Nodes return results to coordinator for aggregation
- **Health Monitoring**: Periodic status checks and node availability

## Implementation

### Basic Distributed Scan
```python
from app.core.distributed_scanning import distributed_scanner

# Start node discovery
distributed_scanner.discover_nodes("192.168.1.0/24")

# Distribute scan across nodes
result = distributed_scanner.distribute_scan(
    scan_type="dns",
    targets=["example1.com", "example2.com", "example3.com"],
    parameters={"record_types": ["A", "CNAME"]}
)

# Monitor scan progress
status = distributed_scanner.get_scan_status(result["scan_id"])
```

### Node Registration Format
```python
{
    "type": "node_register",
    "port": 9998,
    "capabilities": ["dns", "port", "http"],
    "max_concurrent": 10,
    "node_info": {
        "hostname": "scanner-node-01",
        "version": "1.0.0"
    }
}
```

### Task Distribution Format
```python
{
    "scan_id": "scan_1642123456",
    "node_id": "192.168.1.100:9998",
    "scan_type": "dns",
    "targets": ["example1.com", "example2.com"],
    "parameters": {
        "record_types": ["A", "CNAME"],
        "wordlist": "common.txt"
    },
    "timeout": 300
}
```

## Setting Up Distributed Scanning

### 1. Configure Coordinator
```python
# Start coordinator service
distributed_scanner.start_coordinator()

# Configure discovery settings
distributed_scanner.coordinator_port = 9999
distributed_scanner.discovery_enabled = True
```

### 2. Deploy Scanning Nodes
```python
# Example scanning node implementation
class ScanningNode:
    def __init__(self, coordinator_host, coordinator_port):
        self.coordinator_host = coordinator_host
        self.coordinator_port = coordinator_port
        self.capabilities = ["dns", "port", "http"]
    
    def register_with_coordinator(self):
        registration = {
            "type": "node_register",
            "port": 9998,
            "capabilities": self.capabilities
        }
        # Send registration to coordinator
```

### 3. Execute Distributed Scans
```python
# Discover available nodes
nodes = distributed_scanner.discover_nodes()

# Distribute large target list
targets = ["target1.com", "target2.com", "target3.com", "target4.com"]
result = distributed_scanner.distribute_scan("dns", targets)

# Collect aggregated results
final_results = distributed_scanner.get_scan_status(result["scan_id"])
```

## Node Capabilities

### Supported Scan Types
- **DNS**: Domain enumeration and DNS record queries
- **Port**: Port scanning and service detection
- **HTTP**: Web application scanning and directory enumeration

### Node Requirements
- Network connectivity to coordinator
- Required scanning tools and dependencies
- Sufficient resources for concurrent operations
- Proper firewall configuration for communication

## Load Balancing

### Distribution Strategies
- **Round Robin**: Even distribution across all nodes
- **Capability-Based**: Assignment based on node capabilities
- **Load-Aware**: Distribution considering node current load
- **Geographic**: Regional distribution for global scanning

### Target Allocation
```python
# Example target distribution
def distribute_targets(targets, nodes):
    targets_per_node = len(targets) // len(nodes)
    remainder = len(targets) % len(nodes)
    
    distributed_tasks = []
    start_idx = 0
    
    for i, node in enumerate(nodes):
        # Add extra target to first 'remainder' nodes
        node_target_count = targets_per_node + (1 if i < remainder else 0)
        end_idx = start_idx + node_target_count
        
        node_targets = targets[start_idx:end_idx]
        distributed_tasks.append({
            "node_id": node.node_id,
            "targets": node_targets
        })
        
        start_idx = end_idx
    
    return distributed_tasks
```

## Fault Tolerance

### Error Handling
- **Node Failures**: Automatic task redistribution to healthy nodes
- **Network Issues**: Retry mechanisms with exponential backoff
- **Partial Results**: Graceful handling of incomplete scan results
- **Timeout Management**: Configurable timeouts for all operations

### Recovery Mechanisms
```python
def handle_node_failure(failed_node_id, pending_tasks):
    """Redistribute tasks from failed node to healthy nodes."""
    healthy_nodes = [n for n in self.nodes.values() 
                    if n.status == 'online' and n.node_id != failed_node_id]
    
    if healthy_nodes:
        # Redistribute pending tasks
        redistributed_tasks = self.redistribute_tasks(pending_tasks, healthy_nodes)
        return redistributed_tasks
    else:
        # No healthy nodes available
        return {"error": "No healthy nodes available for task redistribution"}
```

## Performance Optimization

### Scaling Considerations
- **Node Count**: Optimal number of nodes based on target count
- **Network Bandwidth**: Consider network capacity for result transfer
- **Coordinator Resources**: Ensure coordinator can handle node management
- **Task Granularity**: Balance between overhead and parallelization

### Monitoring Metrics
- **Scan Throughput**: Targets processed per second across all nodes
- **Node Utilization**: Resource usage on individual nodes
- **Network Latency**: Communication delays between coordinator and nodes
- **Error Rates**: Failed tasks and node availability statistics

## Security Considerations

### Network Security
- **Authentication**: Secure node registration and communication
- **Encryption**: Encrypted communication channels between nodes
- **Access Control**: Restrict coordinator access to authorized nodes
- **Audit Logging**: Comprehensive logging of all distributed operations

### Best Practices
- Use VPN or secure networks for node communication
- Implement proper authentication mechanisms
- Monitor and log all distributed scanning activities
- Regularly update and patch all scanning nodes