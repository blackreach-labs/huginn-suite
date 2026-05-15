# Asset Inventory System

The Huginn Asset Inventory System provides centralized management and visualization of discovered network assets. As reconnaissance and enumeration scans are performed, the system automatically collects and correlates information about discovered targets, building a comprehensive asset database.

## 🎯 Key Features

### Visual Asset Management
- **Graphical Asset Display**: Assets are displayed as interactive graphics with different visual states
- **Status-Based Visualization**: Assets change appearance based on their discovery status
- **Real-time Updates**: Asset information updates automatically as new scan data is collected
- **Interactive Selection**: Click assets to view detailed information

### Asset States

Assets progress through different states as more information is discovered:

1. **DISCOVERED** (Gold border, pulsing animation)
   - Initial state when an asset is first detected (e.g., ping sweep)
   - Basic IP address information only
   - Confidence: 25%

2. **IDENTIFIED** (Orange border)
   - Asset has been scanned and services/ports identified
   - OS type may be inferred from open ports
   - Confidence: 50-75%

3. **KNOWN** (Green border)
   - Comprehensive information available
   - OS version confirmed through detailed scanning
   - High confidence in asset details
   - Confidence: 85-95%

### Asset Information Tracking

The system tracks comprehensive information for each asset:

- **Basic Information**: IP address, hostname, first/last seen timestamps
- **Operating System**: Type, version, confidence level
- **Network Services**: Open ports, running services, versions
- **Vulnerabilities**: Discovered security issues with severity ratings
- **Metadata**: Discovery method, scan history, additional context

### Multi-Tenant Support

- **Tenant Isolation**: Assets are isolated by tenant for enterprise deployments
- **Centralized Database**: SQLite-based storage with performance indexing
- **Data Integrity**: Automatic deduplication and conflict resolution

## 🚀 Usage

### Accessing the Inventory

1. **Via Menu**: View → Inventory (Ctrl+Shift+I)
2. **Navigation**: The inventory page provides both graphical and tabular views

### Asset Discovery Workflow

1. **Initial Discovery**: Run ping sweeps to discover live hosts
   ```
   Ping Sweep → Assets appear as "DISCOVERED" (gold, pulsing)
   ```

2. **Service Identification**: Perform port scans on discovered assets
   ```
   Port Scan → Assets upgrade to "IDENTIFIED" (orange)
   OS type inferred from port patterns
   ```

3. **Detailed Analysis**: Run service detection and OS fingerprinting
   ```
   Service Detection → Assets become "KNOWN" (green)
   Confirmed OS version and service details
   ```

4. **Security Assessment**: Perform vulnerability scans
   ```
   Vulnerability Scan → Security issues tracked per asset
   Risk assessment and remediation planning
   ```

### Filtering and Management

- **Status Filter**: View assets by discovery status (All, Discovered, Identified, Known)
- **OS Filter**: Filter by operating system type
- **Search and Sort**: Table-based searching and sorting capabilities
- **Context Actions**: Right-click assets for scan options and management

### Asset Context Menu

Right-click any asset to access:

- **🔍 Scan Options**
  - Port Scan: Discover open ports and services
  - Service Detection: Identify service versions
  - Vulnerability Scan: Check for security issues

- **📋 Information**
  - View Details: Comprehensive asset information
  - View History: Track changes over time

- **✏️ Management**
  - Update Asset: Manually edit asset information
  - Remove Asset: Delete from inventory

## 🔧 Technical Architecture

### Core Components

1. **AssetManager** (`app/core/asset_manager.py`)
   - Central asset database management
   - CRUD operations with conflict resolution
   - Statistics and reporting

2. **ScanAssetIntegrator** (`app/core/scan_asset_integration.py`)
   - Processes scan results into asset updates
   - Intelligent data merging and OS detection
   - Confidence scoring algorithms

3. **AssetGraphicsWidget** (`app/widgets/asset_graphics_widget.py`)
   - Visual asset representation
   - Interactive graphics with animations
   - Status-based styling and effects

4. **InventoryPage** (`app/pages/inventory_page.py`)
   - Main inventory interface
   - Filtering, searching, and management
   - Integration with scan systems

### Database Schema

```sql
-- Main assets table
CREATE TABLE assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT DEFAULT '',
    os_type TEXT DEFAULT 'Unknown',
    os_version TEXT DEFAULT '',
    status TEXT DEFAULT 'DISCOVERED',
    confidence INTEGER DEFAULT 0,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    open_ports TEXT DEFAULT '[]',
    services TEXT DEFAULT '[]',
    vulnerabilities TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, ip_address)
);

-- Asset change history
CREATE TABLE asset_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    change_type TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Integration Points

The inventory system automatically integrates with existing scan tools:

```python
from app.core.inventory_integration import update_inventory_from_scan

# Example: Update inventory after port scan
def on_port_scan_complete(results):
    update_inventory_from_scan('port_scan', results)
```

Supported scan types:
- `ping_sweep`: Network discovery
- `port_scan`: Port and service discovery
- `dns_enum`: DNS enumeration results
- `service_detection`: Service version detection
- `rpc_enum`: RPC enumeration
- `http_enum`: Web application enumeration
- `vulnerability_scan`: Security assessment

## 📊 Statistics and Reporting

The inventory provides real-time statistics:

- **Total Assets**: Complete asset count
- **Status Breakdown**: Assets by discovery status
- **OS Distribution**: Assets by operating system
- **Recent Activity**: Assets updated in last 24 hours

### Asset Intelligence

The system provides intelligent analysis:

- **OS Detection**: Infers OS type from port patterns and service banners
- **Service Correlation**: Links services across multiple scans
- **Vulnerability Tracking**: Maintains security issue history
- **Confidence Scoring**: Rates information reliability

## 🎨 Visual Design

### Asset Graphics

Assets are displayed as interactive cards showing:

- **Icon**: OS-specific visual indicator (🖥️ Windows, 🐧 Linux, 🌐 Router, etc.)
- **IP Address**: Primary identifier in blue
- **Hostname**: Secondary identifier if available
- **OS Type**: Operating system information
- **Status Badge**: Current discovery status with color coding
- **Service Count**: Number of discovered services
- **Vulnerability Count**: Security issues (red highlight if present)

### Status Animations

- **DISCOVERED**: Pulsing gold border animation
- **IDENTIFIED**: Solid orange border
- **KNOWN**: Solid green border
- **Hover Effects**: Scale and highlight on mouse over

### Theme Integration

The inventory follows the Huginn theme system:
- **Dark Blue Theme**: Default cybersecurity aesthetic
- **Matrix Theme**: Green-on-black terminal styling
- **Responsive Design**: Adapts to window resizing
- **Consistent Styling**: Matches application-wide design language

## 🔮 Future Enhancements

### Planned Features

1. **Asset Relationships**: Map network relationships and dependencies
2. **Timeline View**: Visualize asset discovery and changes over time
3. **Risk Scoring**: Automated risk assessment based on vulnerabilities
4. **Export Capabilities**: Generate asset reports in multiple formats
5. **Integration APIs**: REST API for external system integration
6. **Asset Grouping**: Organize assets by network segments or functions
7. **Automated Scanning**: Schedule regular asset updates
8. **Compliance Mapping**: Track assets against security frameworks

### Advanced Visualizations

- **Network Topology**: Visual network mapping
- **Risk Heat Maps**: Security risk visualization
- **Asset Timelines**: Historical change tracking
- **Dependency Graphs**: Service and system relationships

## 📝 Example Usage

```python
# Demonstrate the inventory system
from examples.inventory_demo import *

# Run the complete demo
if __name__ == "__main__":
    demo_ping_sweep()      # Discover assets
    demo_port_scan()       # Identify services
    demo_service_detection() # Confirm OS details
    demo_vulnerability_scan() # Assess security
    
    show_inventory()       # Display results
    show_statistics()      # Show analytics
```

The Asset Inventory System transforms Huginn from a collection of individual tools into a comprehensive asset management platform, providing security professionals with the situational awareness needed for effective penetration testing and security assessment.