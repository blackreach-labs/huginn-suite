# app/core/asset_manager.py
import json
import sqlite3
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict
import threading

@dataclass
class Asset:
    """Individual asset entry"""
    asset_id: str
    tenant_id: str
    ip_address: str
    hostname: str = ""
    fqdn: str = ""
    os_type: str = "Unknown"
    os_version: str = ""
    status: str = "DISCOVERED"  # DISCOVERED, IDENTIFIED, KNOWN
    confidence: int = 0  # 0-100
    first_seen: str = ""
    last_seen: str = ""
    open_ports: List[Dict] = None
    services: List[Dict] = None
    vulnerabilities: List[Dict] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.metadata is None:
            self.metadata = {}

class AssetManager:
    """Centralized asset management system"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            project_root = Path(__file__).parent.parent.parent
            resources_dir = project_root / "resources"
            resources_dir.mkdir(exist_ok=True)
            db_path = str(resources_dir / "asset_inventory.db")
        
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize asset inventory database"""
        with sqlite3.connect(self.db_path) as conn:
            # Main assets table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    hostname TEXT DEFAULT '',
                    fqdn TEXT DEFAULT '',
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
                    notes TEXT DEFAULT '',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(tenant_id, ip_address)
                )
            """)
            
            # Asset history table for tracking changes
            conn.execute("""
                CREATE TABLE IF NOT EXISTS asset_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    old_value TEXT,
                    new_value TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
                # Add fqdn column if it doesn't exist
            try:
                conn.execute("ALTER TABLE assets ADD COLUMN fqdn TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass  # Column already exists
            
            # Add notes column if it doesn't exist
            try:
                conn.execute("ALTER TABLE assets ADD COLUMN notes TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass  # Column already exists
            
            # Create indexes for performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id)",
                "CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address)",
                "CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status)",
                "CREATE INDEX IF NOT EXISTS idx_assets_os ON assets(os_type)",
                "CREATE INDEX IF NOT EXISTS idx_history_asset ON asset_history(asset_id)"
            ]
            
            for index in indexes:
                conn.execute(index)
    
    def add_or_update_asset(self, tenant_id: str, ip_address: str, **kwargs) -> str:
        """Add new asset or update existing one"""
        with self.lock:
            try:
                # Check if this is a hostname that should be resolved to an IP
                resolved_ip = self._resolve_hostname_to_ip(ip_address, tenant_id)
                if resolved_ip:
                    # Use the resolved IP as the primary identifier
                    primary_ip = resolved_ip
                    if 'hostname' not in kwargs:
                        kwargs['hostname'] = ip_address  # Store original hostname
                else:
                    primary_ip = ip_address
                
                asset_id = self._generate_asset_id(tenant_id, primary_ip)
                timestamp = datetime.now().isoformat()
                
                with sqlite3.connect(self.db_path) as conn:
                    # Check if asset exists by IP or hostname correlation
                    existing = self._find_existing_asset(conn, tenant_id, primary_ip, kwargs.get('hostname', ''))
                    
                    if existing:
                        # Update existing asset
                        self._update_existing_asset(conn, asset_id, tenant_id, primary_ip, timestamp, **kwargs)
                    else:
                        # Create new asset
                        self._create_new_asset(conn, asset_id, tenant_id, primary_ip, timestamp, **kwargs)
                
                return asset_id
            except Exception as e:
                print(f"Error adding/updating asset: {e}")
                return ""
    
    def _create_new_asset(self, conn, asset_id: str, tenant_id: str, ip_address: str, timestamp: str, **kwargs):
        """Create new asset entry"""
        hostname = kwargs.get('hostname', '')
        fqdn = kwargs.get('fqdn', '')
        os_type = kwargs.get('os_type', 'Unknown')
        os_version = kwargs.get('os_version', '')
        status = kwargs.get('status', 'DISCOVERED')
        confidence = kwargs.get('confidence', 0)
        open_ports = json.dumps(kwargs.get('open_ports', []))
        services = json.dumps(kwargs.get('services', []))
        vulnerabilities = json.dumps(kwargs.get('vulnerabilities', []))
        metadata = json.dumps(kwargs.get('metadata', {}))
        notes = kwargs.get('notes', '')
        
        conn.execute("""
            INSERT INTO assets 
            (asset_id, tenant_id, ip_address, hostname, fqdn, os_type, os_version, 
             status, confidence, first_seen, last_seen, open_ports, services, 
             vulnerabilities, metadata, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (asset_id, tenant_id, ip_address, hostname, fqdn, os_type, os_version,
              status, confidence, timestamp, timestamp, open_ports, services,
              vulnerabilities, metadata, notes))
        
        # Log creation
        self._log_asset_change(conn, asset_id, tenant_id, "CREATED", "", f"Asset created: {ip_address}")
    
    def _update_existing_asset(self, conn, asset_id: str, tenant_id: str, ip_address: str, timestamp: str, **kwargs):
        """Update existing asset with new information"""
        # Get current asset data
        cursor = conn.execute("""
            SELECT hostname, fqdn, os_type, os_version, status, confidence, open_ports, services, vulnerabilities, metadata, notes
            FROM assets WHERE tenant_id = ? AND ip_address = ?
        """, (tenant_id, ip_address))
        
        current = cursor.fetchone()
        if not current:
            return
        
        # Parse current data
        current_data = {
            'hostname': current[0],
            'fqdn': current[1],
            'os_type': current[2],
            'os_version': current[3],
            'status': current[4],
            'confidence': current[5],
            'open_ports': json.loads(current[6]),
            'services': json.loads(current[7]),
            'vulnerabilities': json.loads(current[8]),
            'metadata': json.loads(current[9]),
            'notes': current[10] if len(current) > 10 else ''
        }
        
        # Merge new data
        updated_data = self._merge_asset_data(current_data, kwargs)
        
        # Update database
        conn.execute("""
            UPDATE assets SET 
                hostname = ?, fqdn = ?, os_type = ?, os_version = ?, status = ?, confidence = ?,
                last_seen = ?, open_ports = ?, services = ?, vulnerabilities = ?, metadata = ?, notes = ?
            WHERE tenant_id = ? AND ip_address = ?
        """, (
            updated_data['hostname'], updated_data['fqdn'], updated_data['os_type'], updated_data['os_version'],
            updated_data['status'], updated_data['confidence'], timestamp,
            json.dumps(updated_data['open_ports']), json.dumps(updated_data['services']),
            json.dumps(updated_data['vulnerabilities']), json.dumps(updated_data['metadata']),
            updated_data.get('notes', ''), tenant_id, ip_address
        ))
        
        # Log significant changes
        self._log_significant_changes(conn, asset_id, tenant_id, current_data, updated_data)
    
    def _merge_asset_data(self, current: Dict, new: Dict) -> Dict:
        """Intelligently merge asset data"""
        merged = current.copy()
        
        # Update hostname - prefer non-empty values
        if new.get('hostname'):
            if not current['hostname'] or len(new['hostname']) > len(current['hostname']):
                merged['hostname'] = new['hostname']
        
        # Update fqdn - prefer non-empty values
        if new.get('fqdn'):
            if not current['fqdn'] or len(new['fqdn']) > len(current['fqdn']):
                merged['fqdn'] = new['fqdn']
        
        if new.get('os_type') and new['os_type'] != 'Unknown':
            if current['os_type'] == 'Unknown' or new.get('confidence', 0) > current['confidence']:
                merged['os_type'] = new['os_type']
        
        if new.get('os_version'):
            merged['os_version'] = new['os_version']
        
        # Update status based on information quality
        if new.get('status'):
            status_priority = {'DISCOVERED': 1, 'IDENTIFIED': 2, 'KNOWN': 3}
            current_priority = status_priority.get(current['status'], 0)
            new_priority = status_priority.get(new['status'], 0)
            if new_priority > current_priority:
                merged['status'] = new['status']
        
        # Update confidence (ensure both are integers)
        new_confidence = int(new.get('confidence', 0)) if isinstance(new.get('confidence'), (int, str)) else 0
        current_confidence = int(current['confidence']) if isinstance(current['confidence'], (int, str)) else 0
        if new_confidence > current_confidence:
            merged['confidence'] = new_confidence
        
        # Merge ports (avoid duplicates)
        if new.get('open_ports'):
            existing_ports = {p.get('port') for p in current['open_ports']}
            for port in new['open_ports']:
                if port.get('port') not in existing_ports:
                    merged['open_ports'].append(port)
        
        # Merge services (replace existing or add new)
        if new.get('services'):
            # Create a map of existing services by port:service key
            existing_service_map = {f"{s.get('port')}:{s.get('service')}": i for i, s in enumerate(current['services'])}
            
            for service in new['services']:
                service_key = f"{service.get('port')}:{service.get('service')}"
                if service_key in existing_service_map:
                    # Replace existing service with new comprehensive data
                    index = existing_service_map[service_key]
                    merged['services'][index] = service
                else:
                    # Add new service
                    merged['services'].append(service)
        
        # Merge vulnerabilities (avoid duplicates)
        if new.get('vulnerabilities'):
            existing_vulns = {v.get('id') for v in current['vulnerabilities']}
            for vuln in new['vulnerabilities']:
                if vuln.get('id') not in existing_vulns:
                    merged['vulnerabilities'].append(vuln)
        
        # Merge metadata
        if new.get('metadata'):
            merged['metadata'].update(new['metadata'])
        
        # Update notes if provided
        if 'notes' in new:
            merged['notes'] = new['notes']
        
        return merged
    
    def _log_significant_changes(self, conn, asset_id: str, tenant_id: str, old_data: Dict, new_data: Dict):
        """Log significant changes to asset"""
        changes = []
        
        # Check for OS identification
        if old_data['os_type'] == 'Unknown' and new_data['os_type'] != 'Unknown':
            changes.append(('OS_IDENTIFIED', 'Unknown', new_data['os_type']))
        
        # Check for status changes
        if old_data['status'] != new_data['status']:
            changes.append(('STATUS_CHANGE', old_data['status'], new_data['status']))
        
        # Check for new services
        old_services = {f"{s.get('port')}:{s.get('service')}" for s in old_data['services']}
        new_services = {f"{s.get('port')}:{s.get('service')}" for s in new_data['services']}
        added_services = new_services - old_services
        if added_services:
            changes.append(('SERVICES_ADDED', '', ', '.join(added_services)))
        
        # Check for new vulnerabilities
        old_vulns = {v.get('id') for v in old_data['vulnerabilities']}
        new_vulns = {v.get('id') for v in new_data['vulnerabilities']}
        added_vulns = new_vulns - old_vulns
        if added_vulns:
            changes.append(('VULNERABILITIES_ADDED', '', ', '.join(added_vulns)))
        
        # Log changes
        for change_type, old_val, new_val in changes:
            self._log_asset_change(conn, asset_id, tenant_id, change_type, old_val, new_val)
    
    def _log_asset_change(self, conn, asset_id: str, tenant_id: str, change_type: str, old_value: str, new_value: str):
        """Log asset change to history"""
        conn.execute("""
            INSERT INTO asset_history (asset_id, tenant_id, change_type, old_value, new_value)
            VALUES (?, ?, ?, ?, ?)
        """, (asset_id, tenant_id, change_type, old_value, new_value))
    
    def get_assets(self, tenant_id: str, status: str = None, os_type: str = None) -> List[Dict]:
        """Get assets for tenant with optional filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = "SELECT * FROM assets WHERE tenant_id = ?"
                params = [tenant_id]
                
                if status:
                    query += " AND status = ?"
                    params.append(status)
                
                if os_type:
                    query += " AND os_type = ?"
                    params.append(os_type)
                
                query += " ORDER BY last_seen DESC"
                
                cursor = conn.execute(query, params)
                assets = []
                
                for row in cursor.fetchall():
                    asset = dict(row)
                    # Parse JSON fields
                    asset['open_ports'] = json.loads(asset['open_ports'])
                    asset['services'] = json.loads(asset['services'])
                    asset['vulnerabilities'] = json.loads(asset['vulnerabilities'])
                    asset['metadata'] = json.loads(asset['metadata'])
                    assets.append(asset)
                
                return assets
        except Exception as e:
            print(f"Error getting assets: {e}")
            return []
    
    def get_asset_by_ip(self, tenant_id: str, ip_address: str) -> Optional[Dict]:
        """Get specific asset by IP address"""
        assets = self.get_assets(tenant_id)
        for asset in assets:
            if asset['ip_address'] == ip_address:
                return asset
        return None
    
    def get_asset_by_hostname(self, tenant_id: str, hostname: str) -> Optional[Dict]:
        """Get specific asset by hostname"""
        assets = self.get_assets(tenant_id)
        for asset in assets:
            if asset.get('hostname') == hostname:
                return asset
        return None
    
    def get_asset_by_identifier(self, tenant_id: str, identifier: str) -> Optional[Dict]:
        """Get asset by IP address or hostname"""
        # Try IP first
        asset = self.get_asset_by_ip(tenant_id, identifier)
        if asset:
            return asset
        
        # Try hostname
        return self.get_asset_by_hostname(tenant_id, identifier)
    
    def get_asset_statistics(self, tenant_id: str) -> Dict:
        """Get asset statistics for tenant"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Total assets
                cursor = conn.execute("SELECT COUNT(*) FROM assets WHERE tenant_id = ?", (tenant_id,))
                total_assets = cursor.fetchone()[0]
                
                # Assets by status
                cursor = conn.execute("""
                    SELECT status, COUNT(*) FROM assets WHERE tenant_id = ? GROUP BY status
                """, (tenant_id,))
                status_counts = dict(cursor.fetchall())
                
                # Assets by OS type
                cursor = conn.execute("""
                    SELECT os_type, COUNT(*) FROM assets WHERE tenant_id = ? GROUP BY os_type
                """, (tenant_id,))
                os_counts = dict(cursor.fetchall())
                
                # Recent activity (last 24 hours)
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM assets 
                    WHERE tenant_id = ? AND last_seen >= datetime('now', '-1 day')
                """, (tenant_id,))
                recent_activity = cursor.fetchone()[0]
                
                return {
                    'total_assets': total_assets,
                    'status_breakdown': status_counts,
                    'os_breakdown': os_counts,
                    'recent_activity': recent_activity
                }
        except Exception as e:
            print(f"Error getting asset statistics: {e}")
            return {}
    
    def update_from_scan_data(self, tenant_id: str, scan_type: str, scan_results: Dict):
        """Update assets from various scan results"""
        if scan_type == "ping_sweep":
            self._process_ping_sweep(tenant_id, scan_results)
        elif scan_type == "port_scan":
            self._process_port_scan(tenant_id, scan_results)
        elif scan_type == "os_detection":
            self._process_os_detection(tenant_id, scan_results)
        elif scan_type == "service_detection":
            self._process_service_detection(tenant_id, scan_results)
        elif scan_type == "vulnerability_scan":
            self._process_vulnerability_scan(tenant_id, scan_results)
    
    def _process_ping_sweep(self, tenant_id: str, results: Dict):
        """Process ping sweep results"""
        for ip, data in results.items():
            if data.get('status') == 'up':
                self.add_or_update_asset(
                    tenant_id=tenant_id,
                    ip_address=ip,
                    status='DISCOVERED',
                    confidence=25,
                    metadata={'discovery_method': 'ping_sweep'}
                )
    
    def _process_port_scan(self, tenant_id: str, results: Dict):
        """Process port scan results"""
        for ip, data in results.items():
            if 'open_ports' in data:
                ports = [{'port': p.get('port'), 'protocol': p.get('protocol', 'tcp')} 
                        for p in data['open_ports']]
                
                self.add_or_update_asset(
                    tenant_id=tenant_id,
                    ip_address=ip,
                    status='IDENTIFIED',
                    confidence=50,
                    open_ports=ports,
                    metadata={'discovery_method': 'port_scan'}
                )
    
    def _process_os_detection(self, tenant_id: str, results: Dict):
        """Process OS detection results"""
        for ip, data in results.items():
            if 'os_info' in data:
                os_info = data['os_info']
                confidence = 75 if os_info.get('accuracy', 0) > 80 else 60
                
                self.add_or_update_asset(
                    tenant_id=tenant_id,
                    ip_address=ip,
                    os_type=os_info.get('name', 'Unknown'),
                    os_version=os_info.get('version', ''),
                    status='IDENTIFIED',
                    confidence=confidence,
                    metadata={'os_detection': os_info}
                )
    
    def _process_service_detection(self, tenant_id: str, results: Dict):
        """Process service detection results"""
        for ip, data in results.items():
            if 'services' in data:
                services = []
                for service in data['services']:
                    services.append({
                        'port': service.get('port'),
                        'service': service.get('name'),
                        'version': service.get('version', ''),
                        'protocol': service.get('protocol', 'tcp')
                    })
                
                self.add_or_update_asset(
                    tenant_id=tenant_id,
                    ip_address=ip,
                    services=services,
                    status='IDENTIFIED',
                    confidence=70,
                    metadata={'service_detection': True}
                )
    
    def _process_vulnerability_scan(self, tenant_id: str, results: Dict):
        """Process vulnerability scan results"""
        for ip, data in results.items():
            if 'vulnerabilities' in data:
                vulns = []
                for vuln in data['vulnerabilities']:
                    vulns.append({
                        'id': vuln.get('id'),
                        'name': vuln.get('name'),
                        'severity': vuln.get('severity'),
                        'description': vuln.get('description', '')
                    })
                
                self.add_or_update_asset(
                    tenant_id=tenant_id,
                    ip_address=ip,
                    vulnerabilities=vulns,
                    status='KNOWN',
                    confidence=90,
                    metadata={'vulnerability_scan': True}
                )
    
    def remove_asset(self, tenant_id: str, ip_address: str) -> bool:
        """Remove asset from inventory"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    # Get asset_id before deletion
                    cursor = conn.execute(
                        "SELECT asset_id FROM assets WHERE tenant_id = ? AND ip_address = ?",
                        (tenant_id, ip_address)
                    )
                    result = cursor.fetchone()
                    
                    if not result:
                        return False
                    
                    asset_id = result[0]
                    
                    # Delete from assets table
                    cursor = conn.execute(
                        "DELETE FROM assets WHERE tenant_id = ? AND ip_address = ?",
                        (tenant_id, ip_address)
                    )
                    
                    if cursor.rowcount > 0:
                        # Log the removal
                        self._log_asset_change(conn, asset_id, tenant_id, "DELETED", ip_address, "Asset removed from inventory")
                        return True
                    
                return False
            except Exception as e:
                print(f"Error removing asset: {e}")
                return False
    
    def update_asset_fields(self, tenant_id: str, ip_address: str, **field_updates) -> bool:
        """Update specific fields of an asset without full merge logic"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    # Check if asset exists
                    cursor = conn.execute(
                        "SELECT asset_id FROM assets WHERE tenant_id = ? AND ip_address = ?",
                        (tenant_id, ip_address)
                    )
                    result = cursor.fetchone()
                    
                    if not result:
                        return False
                    
                    asset_id = result[0]
                    timestamp = datetime.now().isoformat()
                    
                    # Build update query dynamically
                    update_fields = []
                    update_values = []
                    
                    # Handle basic fields
                    basic_fields = ['hostname', 'fqdn', 'os_type', 'os_version', 'status', 'confidence', 'notes']
                    for field in basic_fields:
                        if field in field_updates:
                            update_fields.append(f"{field} = ?")
                            update_values.append(field_updates[field])
                    
                    # Handle JSON fields
                    json_fields = ['open_ports', 'services', 'vulnerabilities', 'metadata']
                    for field in json_fields:
                        if field in field_updates:
                            update_fields.append(f"{field} = ?")
                            update_values.append(json.dumps(field_updates[field]))
                    
                    # Always update last_seen
                    update_fields.append("last_seen = ?")
                    update_values.append(timestamp)
                    
                    if update_fields:
                        query = f"UPDATE assets SET {', '.join(update_fields)} WHERE tenant_id = ? AND ip_address = ?"
                        update_values.extend([tenant_id, ip_address])
                        
                        conn.execute(query, update_values)
                        
                        # Log the update
                        changes_summary = ', '.join([f"{k}={v}" for k, v in field_updates.items()])
                        self._log_asset_change(conn, asset_id, tenant_id, "FIELD_UPDATE", "", changes_summary)
                        
                        return True
                
                return False
            except Exception as e:
                print(f"Error updating asset fields: {e}")
                return False
    
    def get_asset_history(self, tenant_id: str, ip_address: str) -> List[Dict]:
        """Get change history for a specific asset"""
        try:
            # First get the asset_id
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT asset_id FROM assets WHERE tenant_id = ? AND ip_address = ?",
                    (tenant_id, ip_address)
                )
                result = cursor.fetchone()
                
                if not result:
                    return []
                
                asset_id = result[0]
                
                # Get history
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT * FROM asset_history 
                    WHERE asset_id = ? AND tenant_id = ? 
                    ORDER BY timestamp DESC
                """, (asset_id, tenant_id))
                
                history = []
                for row in cursor.fetchall():
                    history.append(dict(row))
                
                return history
        except Exception as e:
            print(f"Error getting asset history: {e}")
            return []
    
    def update_asset_notes(self, tenant_id: str, ip_address: str, notes: str) -> bool:
        """Update notes for a specific asset"""
        return self.update_asset_fields(tenant_id, ip_address, notes=notes)
    
    def _resolve_hostname_to_ip(self, identifier: str, tenant_id: str) -> Optional[str]:
        """Check if identifier is a hostname that resolves to an existing IP asset"""
        if self._is_valid_ip(identifier):
            return None  # Already an IP
        
        # Check if we have an existing asset with this hostname
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("""
                    SELECT ip_address FROM assets 
                    WHERE tenant_id = ? AND hostname = ? AND ip_address != hostname
                """, (tenant_id, identifier))
                result = cursor.fetchone()
                if result and self._is_valid_ip(result[0]):
                    return result[0]
        except:
            pass
        
        # Try DNS resolution as last resort
        try:
            import socket
            ip = socket.gethostbyname(identifier)
            if self._is_valid_ip(ip):
                # Check if we have an asset with this IP
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("""
                        SELECT ip_address FROM assets WHERE tenant_id = ? AND ip_address = ?
                    """, (tenant_id, ip))
                    if cursor.fetchone():
                        return ip
        except:
            pass
        
        return None
    
    def _find_existing_asset(self, conn, tenant_id: str, ip_address: str, hostname: str) -> Optional[tuple]:
        """Find existing asset by IP or hostname correlation"""
        # First check by IP
        cursor = conn.execute("""
            SELECT * FROM assets WHERE tenant_id = ? AND ip_address = ?
        """, (tenant_id, ip_address))
        existing = cursor.fetchone()
        if existing:
            return existing
        
        # If hostname provided and different from IP, check for hostname match
        if hostname and hostname != ip_address:
            cursor = conn.execute("""
                SELECT * FROM assets WHERE tenant_id = ? AND hostname = ?
            """, (tenant_id, hostname))
            existing = cursor.fetchone()
            if existing:
                # If we found an asset by hostname, update its IP if we now have a valid IP
                if self._is_valid_ip(ip_address) and existing[2] != ip_address:  # existing[2] is ip_address column
                    print(f"Updating asset hostname {hostname} with new IP {ip_address}")
                    # Generate new asset_id based on the IP
                    new_asset_id = self._generate_asset_id(tenant_id, ip_address)
                    conn.execute("""
                        UPDATE assets SET asset_id = ?, ip_address = ?, last_seen = ? WHERE tenant_id = ? AND hostname = ?
                    """, (new_asset_id, ip_address, datetime.now().isoformat(), tenant_id, hostname))
                    # Update the existing tuple with new values
                    existing = list(existing)
                    existing[1] = new_asset_id  # asset_id column
                    existing[2] = ip_address    # ip_address column
                    existing = tuple(existing)
                return existing
        
        # Special case: if ip_address is actually a hostname (not valid IP), 
        # check if there's an existing asset with that hostname
        if not self._is_valid_ip(ip_address):
            cursor = conn.execute("""
                SELECT * FROM assets WHERE tenant_id = ? AND (hostname = ? OR ip_address = ?)
            """, (tenant_id, ip_address, ip_address))
            existing = cursor.fetchone()
            if existing:
                return existing
        
        return None
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            parts = ip_str.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def get_asset_notes(self, tenant_id: str, ip_address: str) -> str:
        """Get notes for a specific asset"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT notes FROM assets WHERE tenant_id = ? AND ip_address = ?",
                    (tenant_id, ip_address)
                )
                result = cursor.fetchone()
                return result[0] if result else ""
        except Exception as e:
            print(f"Error getting asset notes: {e}")
            return ""
    
    def _generate_asset_id(self, tenant_id: str, ip_address: str) -> str:
        """Generate unique asset ID"""
        data = f"{tenant_id}:{ip_address}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

# Global instance
asset_manager = AssetManager()