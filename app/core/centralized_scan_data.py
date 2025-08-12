# app/core/centralized_scan_data.py
import json
import sqlite3
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict
import threading
from .database_pool import get_database_pool

@dataclass
class ScanResult:
    """Individual scan result entry"""
    scan_id: str
    tenant_id: str
    scan_type: str
    target: str
    scanner: str
    timestamp: str
    data: Dict[str, Any]
    dedupe_hash: str
    first_seen: str
    last_seen: str
    count: int = 1

class CentralizedScanData:
    """Centralized data collection system for all scan types with tenant isolation"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            project_root = Path(__file__).parent.parent.parent
            resources_dir = project_root / "resources"
            resources_dir.mkdir(exist_ok=True)
            db_path = str(resources_dir / "centralized_scan_data.db")
        
        self.db_path = db_path
        self.pool = get_database_pool(db_path)
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize centralized scan database"""
        with self.pool.get_connection() as conn:
            # Main scan data table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    data TEXT NOT NULL,
                    dedupe_hash TEXT NOT NULL,
                    first_seen DATETIME NOT NULL,
                    last_seen DATETIME NOT NULL,
                    count INTEGER DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(tenant_id, scan_type, dedupe_hash)
                )
            """)
            
            # Scan metadata table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    start_time DATETIME NOT NULL,
                    end_time DATETIME,
                    status TEXT DEFAULT 'running',
                    total_results INTEGER DEFAULT 0,
                    error_message TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(scan_id)
                )
            """)
            
            # Post-exploitation tables
            conn.execute("""
                CREATE TABLE IF NOT EXISTS post_exploit_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    session_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT,
                    UNIQUE(tenant_id, session_id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS post_exploit_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    output TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Create indexes for performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_scan_data_tenant ON scan_data(tenant_id)",
                "CREATE INDEX IF NOT EXISTS idx_scan_data_type ON scan_data(scan_type)",
                "CREATE INDEX IF NOT EXISTS idx_scan_data_target ON scan_data(target)",
                "CREATE INDEX IF NOT EXISTS idx_scan_data_timestamp ON scan_data(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_scan_data_dedupe ON scan_data(dedupe_hash)",
                "CREATE INDEX IF NOT EXISTS idx_scan_metadata_tenant ON scan_metadata(tenant_id)",
                "CREATE INDEX IF NOT EXISTS idx_scan_metadata_type ON scan_metadata(scan_type)",
                "CREATE INDEX IF NOT EXISTS idx_post_exploit_sessions_tenant ON post_exploit_sessions(tenant_id)",
                "CREATE INDEX IF NOT EXISTS idx_post_exploit_commands_session ON post_exploit_commands(session_id)"
            ]
            
            for index in indexes:
                conn.execute(index)
    
    def start_scan(self, scan_id: str, tenant_id: str, scan_type: str, 
                   target: str, scanner: str) -> bool:
        """Register start of a new scan"""
        try:
            return self.pool.execute_write("""
                INSERT OR REPLACE INTO scan_metadata 
                (scan_id, tenant_id, scan_type, target, scanner, start_time, status)
                VALUES (?, ?, ?, ?, ?, ?, 'running')
            """, (scan_id, tenant_id, scan_type, target, scanner, datetime.now().isoformat())) > 0
        except Exception as e:
            print(f"Error starting scan: {e}")
            return False
    
    def add_scan_result(self, scan_id: str, tenant_id: str, scan_type: str,
                       target: str, scanner: str, result_data: Dict[str, Any]) -> bool:
        """Add individual scan result with deduplication"""
        try:
            # Generate deduplication hash
            dedupe_key = self._generate_dedupe_hash(result_data)
            timestamp = datetime.now().isoformat()
            
            with self.pool.get_connection() as conn:
                # Check if this result already exists
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, count, first_seen FROM scan_data 
                    WHERE tenant_id = ? AND scan_type = ? AND dedupe_hash = ?
                """, (tenant_id, scan_type, dedupe_key))
                
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing result
                    cursor.execute("""
                        UPDATE scan_data 
                        SET last_seen = ?, count = count + 1, scan_id = ?
                        WHERE id = ?
                    """, (timestamp, scan_id, existing[0]))
                else:
                    # Insert new result
                    cursor.execute("""
                        INSERT INTO scan_data 
                        (scan_id, tenant_id, scan_type, target, scanner, timestamp, 
                         data, dedupe_hash, first_seen, last_seen, count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """, (scan_id, tenant_id, scan_type, target, scanner, timestamp,
                          json.dumps(result_data), dedupe_key, timestamp, timestamp))
                
                conn.commit()
            return True
        except Exception as e:
            print(f"Error adding scan result: {e}")
            return False
    
    def complete_scan(self, scan_id: str, total_results: int = 0, 
                     error_message: str = None) -> bool:
        """Mark scan as completed"""
        try:
            status = 'error' if error_message else 'completed'
            return self.pool.execute_write("""
                UPDATE scan_metadata 
                SET end_time = ?, status = ?, total_results = ?, error_message = ?
                WHERE scan_id = ?
            """, (datetime.now().isoformat(), status, total_results, error_message, scan_id)) > 0
        except Exception as e:
            print(f"Error completing scan: {e}")
            return False
    
    def get_scan_data(self, tenant_id: str, scan_type: str, 
                     target: str = None, limit: int = 1000) -> List[Dict]:
        """Get scan data for specific tenant and scan type"""
        try:
            query = """
                SELECT * FROM scan_data 
                WHERE tenant_id = ? AND scan_type = ?
            """
            params = [tenant_id, scan_type]
            
            if target:
                query += " AND target = ?"
                params.append(target)
            
            query += " ORDER BY last_seen DESC LIMIT ?"
            params.append(limit)
            
            rows = self.pool.execute_query(query, tuple(params))
            results = []
            
            # Column names for mapping
            columns = ['id', 'scan_id', 'tenant_id', 'scan_type', 'target', 'scanner', 
                      'timestamp', 'data', 'dedupe_hash', 'first_seen', 'last_seen', 'count', 'created_at']
            
            for row in rows:
                result = dict(zip(columns, row))
                result['data'] = json.loads(result['data'])
                results.append(result)
            
            return results
        except Exception as e:
            print(f"Error getting scan data: {e}")
            return []
    
    def get_scan_summary(self, tenant_id: str, scan_type: str) -> Dict:
        """Get summary statistics for scan type"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get basic counts
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as total_results,
                        COUNT(DISTINCT target) as unique_targets,
                        MIN(first_seen) as first_scan,
                        MAX(last_seen) as last_scan
                    FROM scan_data 
                    WHERE tenant_id = ? AND scan_type = ?
                """, (tenant_id, scan_type))
                
                basic_stats = cursor.fetchone()
                
                # Get target breakdown
                cursor = conn.execute("""
                    SELECT target, COUNT(*) as count
                    FROM scan_data 
                    WHERE tenant_id = ? AND scan_type = ?
                    GROUP BY target
                    ORDER BY count DESC
                    LIMIT 10
                """, (tenant_id, scan_type))
                
                target_breakdown = dict(cursor.fetchall())
                
                # Get recent activity (last 7 days)
                cursor = conn.execute("""
                    SELECT DATE(last_seen) as date, COUNT(*) as count
                    FROM scan_data 
                    WHERE tenant_id = ? AND scan_type = ? 
                    AND last_seen >= date('now', '-7 days')
                    GROUP BY DATE(last_seen)
                    ORDER BY date DESC
                """, (tenant_id, scan_type))
                
                recent_activity = dict(cursor.fetchall())
                
                return {
                    'total_results': basic_stats[0] if basic_stats else 0,
                    'unique_targets': basic_stats[1] if basic_stats else 0,
                    'first_scan': basic_stats[2] if basic_stats else None,
                    'last_scan': basic_stats[3] if basic_stats else None,
                    'target_breakdown': target_breakdown,
                    'recent_activity': recent_activity
                }
        except Exception as e:
            print(f"Error getting scan summary: {e}")
            return {}
    
    def get_tenant_overview(self, tenant_id: str) -> Dict:
        """Get overview of all scan types for tenant"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get scan type breakdown
                cursor = conn.execute("""
                    SELECT 
                        scan_type,
                        COUNT(*) as total_results,
                        COUNT(DISTINCT target) as unique_targets,
                        MAX(last_seen) as last_activity
                    FROM scan_data 
                    WHERE tenant_id = ?
                    GROUP BY scan_type
                    ORDER BY total_results DESC
                """, (tenant_id,))
                
                scan_types = {}
                for row in cursor.fetchall():
                    scan_types[row[0]] = {
                        'total_results': row[1],
                        'unique_targets': row[2],
                        'last_activity': row[3]
                    }
                
                # Get recent scan metadata
                cursor = conn.execute("""
                    SELECT scan_type, COUNT(*) as scan_count, 
                           AVG(total_results) as avg_results
                    FROM scan_metadata 
                    WHERE tenant_id = ? AND start_time >= date('now', '-7 days')
                    GROUP BY scan_type
                """, (tenant_id,))
                
                recent_scans = dict(cursor.fetchall())
                
                return {
                    'scan_types': scan_types,
                    'recent_scans': recent_scans,
                    'total_scan_types': len(scan_types)
                }
        except Exception as e:
            print(f"Error getting tenant overview: {e}")
            return {}
    
    def cleanup_old_data(self, tenant_id: str, days_to_keep: int = 30) -> int:
        """Clean up old scan data"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    # Delete old scan data
                    cursor = conn.execute("""
                        DELETE FROM scan_data 
                        WHERE tenant_id = ? AND last_seen < date('now', '-{} days')
                    """.format(days_to_keep), (tenant_id,))
                    
                    deleted_count = cursor.rowcount
                    
                    # Delete old scan metadata
                    conn.execute("""
                        DELETE FROM scan_metadata 
                        WHERE tenant_id = ? AND start_time < date('now', '-{} days')
                    """.format(days_to_keep), (tenant_id,))
                    
                    return deleted_count
            except Exception as e:
                print(f"Error cleaning up old data: {e}")
                return 0
    
    def _generate_dedupe_hash(self, data: Dict[str, Any]) -> str:
        """Generate deduplication hash for scan result"""
        # Create a normalized string representation for hashing
        normalized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def delete_tenant_data(self, tenant_id: str) -> int:
        """Delete all data for a tenant"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    # Delete scan data
                    cursor = conn.execute(
                        "DELETE FROM scan_data WHERE tenant_id = ?", (tenant_id,)
                    )
                    scan_data_deleted = cursor.rowcount
                    
                    # Delete scan metadata
                    cursor = conn.execute(
                        "DELETE FROM scan_metadata WHERE tenant_id = ?", (tenant_id,)
                    )
                    metadata_deleted = cursor.rowcount
                    
                    conn.commit()
                    return scan_data_deleted + metadata_deleted
            except Exception as e:
                print(f"Error deleting tenant data: {e}")
                return 0
    
    def export_tenant_data(self, tenant_id: str, format: str = 'json') -> str:
        """Export all data for a tenant"""
        try:
            data = {}
            
            # Get all scan types for tenant
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT DISTINCT scan_type FROM scan_data WHERE tenant_id = ?
                """, (tenant_id,))
                
                scan_types = [row[0] for row in cursor.fetchall()]
            
            # Get data for each scan type
            for scan_type in scan_types:
                data[scan_type] = self.get_scan_data(tenant_id, scan_type)
            
            # Add metadata
            data['_metadata'] = {
                'tenant_id': tenant_id,
                'export_time': datetime.now().isoformat(),
                'scan_types': scan_types,
                'overview': self.get_tenant_overview(tenant_id)
            }
            
            if format == 'json':
                return json.dumps(data, indent=2, default=str)
            else:
                raise ValueError(f"Unsupported format: {format}")
                
        except Exception as e:
            print(f"Error exporting tenant data: {e}")
            return ""

    def store_post_exploit_session(self, tenant_id: str, session_id: str, session_type: str, 
                                 target: str, status: str, metadata: Dict = None):
        """Store post-exploitation session data"""
        try:
            return self.pool.execute_write("""
                INSERT OR REPLACE INTO post_exploit_sessions 
                (tenant_id, session_id, session_type, target, status, metadata, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (tenant_id, session_id, session_type, target, status, 
                  json.dumps(metadata) if metadata else None)) > 0
        except Exception as e:
            print(f"Error storing post-exploit session: {e}")
            return False
    
    def store_post_exploit_command(self, tenant_id: str, session_id: str, 
                                 command: str, output: str, timestamp: str, success: bool = True):
        """Store post-exploitation command execution"""
        try:
            return self.pool.execute_write("""
                INSERT INTO post_exploit_commands 
                (tenant_id, session_id, command, output, timestamp, success)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (tenant_id, session_id, command, output, timestamp, success)) > 0
        except Exception as e:
            print(f"Error storing post-exploit command: {e}")
            return False
    
    def get_post_exploit_sessions(self, tenant_id: str) -> List[Dict]:
        """Get all post-exploitation sessions for tenant"""
        try:
            rows = self.pool.execute_query("""
                SELECT session_id, session_type, target, status, created_at, updated_at, metadata
                FROM post_exploit_sessions 
                WHERE tenant_id = ?
                ORDER BY updated_at DESC
            """, (tenant_id,))
            
            sessions = []
            for row in rows:
                session = {
                    'session_id': row[0],
                    'session_type': row[1],
                    'target': row[2],
                    'status': row[3],
                    'created_at': row[4],
                    'updated_at': row[5],
                    'metadata': json.loads(row[6]) if row[6] else {}
                }
                sessions.append(session)
            return sessions
        except Exception as e:
            print(f"Error getting post-exploit sessions: {e}")
            return []
    
    def get_post_exploit_commands(self, tenant_id: str, session_id: str) -> List[Dict]:
        """Get command history for session"""
        try:
            rows = self.pool.execute_query("""
                SELECT command, output, timestamp, success
                FROM post_exploit_commands 
                WHERE tenant_id = ? AND session_id = ?
                ORDER BY timestamp DESC
            """, (tenant_id, session_id))
            
            commands = []
            for row in rows:
                command = {
                    'command': row[0],
                    'output': row[1],
                    'timestamp': row[2],
                    'success': bool(row[3])
                }
                commands.append(command)
            return commands
        except Exception as e:
            print(f"Error getting post-exploit commands: {e}")
            return []

# Global instance
centralized_scan_data = CentralizedScanData()

def create_centralized_scan_data(db_path: str = None) -> CentralizedScanData:
    """Create centralized scan data instance"""
    return CentralizedScanData(db_path)

def get_scan_data_manager(tenant_id: str = "default") -> CentralizedScanData:
    """Get scan data manager instance"""
    return centralized_scan_data

def create_post_exploit_data_collector(tenant_id: str = "default"):
    """Create post-exploitation data collector"""
    from app.core.post_exploitation import PostExploitationFramework
    return PostExploitationFramework(tenant_id=tenant_id)