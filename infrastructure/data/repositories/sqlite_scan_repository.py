"""SQLite implementation of scan repository."""
import sqlite3
import json
import os
from typing import List, Optional
from datetime import datetime

from domain.repositories.scan_repository import ScanRepository
from domain.models.scan_result import ScanResultModel, Target, ScanStatus, Vulnerability, SeverityLevel
from shared.exceptions.scanner_exceptions import DatabaseException
import logging


class SQLiteScanRepository(ScanRepository):
    """SQLite implementation of scan repository."""
    
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self._get_default_db_path()
        self._init_database()
    
    def _get_default_db_path(self) -> str:
        """Get default database path."""
        return os.path.join(os.path.dirname(__file__), "..", "..", "..", "resources", "scan_results.db")
    
    def _init_database(self) -> None:
        """Initialize database tables."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id TEXT PRIMARY KEY,
                    target_address TEXT NOT NULL,
                    target_port INTEGER,
                    target_protocol TEXT DEFAULT 'tcp',
                    target_description TEXT,
                    scanner_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    data TEXT,
                    error_message TEXT,
                    tenant_id TEXT DEFAULT 'default',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    scan_result_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    cvss_score REAL,
                    cve_id TEXT,
                    vuln_references TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_result_id) REFERENCES scan_results (id)
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_tenant ON scan_results(tenant_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_scanner_type ON scan_results(scanner_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_result ON vulnerabilities(scan_result_id)")
    
    async def save_scan_result(self, scan_result: ScanResultModel) -> None:
        """Save a scan result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Save scan result
                conn.execute("""
                    INSERT OR REPLACE INTO scan_results 
                    (id, target_address, target_port, target_protocol, target_description,
                     scanner_type, status, started_at, completed_at, data, error_message, tenant_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_result.id,
                    scan_result.target.address,
                    scan_result.target.port,
                    scan_result.target.protocol,
                    scan_result.target.description,
                    scan_result.scanner_type,
                    scan_result.status.value,
                    scan_result.started_at.isoformat(),
                    scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                    json.dumps(scan_result.data),
                    scan_result.error_message,
                    "default"  # TODO: Add tenant support
                ))
                
                # Delete existing vulnerabilities
                conn.execute("DELETE FROM vulnerabilities WHERE scan_result_id = ?", (scan_result.id,))
                
                # Save vulnerabilities
                for vuln in scan_result.vulnerabilities:
                    conn.execute("""
                        INSERT INTO vulnerabilities 
                        (id, scan_result_id, name, description, severity, cvss_score, cve_id, vuln_references)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        vuln.id,
                        scan_result.id,
                        vuln.name,
                        vuln.description,
                        vuln.severity.value,
                        vuln.cvss_score,
                        vuln.cve_id,
                        json.dumps(vuln.references)
                    ))
                
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to save scan result: {e}")
    
    async def get_scan_result(self, scan_id: str) -> Optional[ScanResultModel]:
        """Get a scan result by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get scan result
                cursor = conn.execute("""
                    SELECT * FROM scan_results WHERE id = ?
                """, (scan_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Get vulnerabilities
                vuln_cursor = conn.execute("""
                    SELECT * FROM vulnerabilities WHERE scan_result_id = ?
                """, (scan_id,))
                
                vulnerabilities = []
                for vuln_row in vuln_cursor.fetchall():
                    vulnerabilities.append(Vulnerability(
                        id=vuln_row['id'],
                        name=vuln_row['name'],
                        description=vuln_row['description'],
                        severity=SeverityLevel(vuln_row['severity']),
                        cvss_score=vuln_row['cvss_score'],
                        cve_id=vuln_row['cve_id'],
                        references=json.loads(vuln_row['vuln_references']) if vuln_row['vuln_references'] else []
                    ))
                
                return ScanResultModel(
                    id=row['id'],
                    target=Target(
                        address=row['target_address'],
                        port=row['target_port'],
                        protocol=row['target_protocol'],
                        description=row['target_description']
                    ),
                    scanner_type=row['scanner_type'],
                    status=ScanStatus(row['status']),
                    started_at=datetime.fromisoformat(row['started_at']),
                    completed_at=datetime.fromisoformat(row['completed_at']) if row['completed_at'] else None,
                    data=json.loads(row['data']) if row['data'] else {},
                    vulnerabilities=vulnerabilities,
                    error_message=row['error_message']
                )
                
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get scan result: {e}")
    
    async def get_scan_results(self, 
                             tenant_id: Optional[str] = None,
                             scanner_type: Optional[str] = None,
                             status: Optional[ScanStatus] = None,
                             limit: int = 100) -> List[ScanResultModel]:
        """Get scan results with optional filters."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                query = "SELECT * FROM scan_results WHERE 1=1"
                params = []
                
                if tenant_id:
                    query += " AND tenant_id = ?"
                    params.append(tenant_id)
                
                if scanner_type:
                    query += " AND scanner_type = ?"
                    params.append(scanner_type)
                
                if status:
                    query += " AND status = ?"
                    params.append(status.value)
                
                query += " ORDER BY started_at DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                results = []
                
                for row in cursor.fetchall():
                    # Get vulnerabilities for this scan
                    vuln_cursor = conn.execute("""
                        SELECT * FROM vulnerabilities WHERE scan_result_id = ?
                    """, (row['id'],))
                    
                    vulnerabilities = []
                    for vuln_row in vuln_cursor.fetchall():
                        vulnerabilities.append(Vulnerability(
                            id=vuln_row['id'],
                            name=vuln_row['name'],
                            description=vuln_row['description'],
                            severity=SeverityLevel(vuln_row['severity']),
                            cvss_score=vuln_row['cvss_score'],
                            cve_id=vuln_row['cve_id'],
                            references=json.loads(vuln_row['vuln_references']) if vuln_row['vuln_references'] else []
                        ))
                    
                    results.append(ScanResultModel(
                        id=row['id'],
                        target=Target(
                            address=row['target_address'],
                            port=row['target_port'],
                            protocol=row['target_protocol'],
                            description=row['target_description']
                        ),
                        scanner_type=row['scanner_type'],
                        status=ScanStatus(row['status']),
                        started_at=datetime.fromisoformat(row['started_at']),
                        completed_at=datetime.fromisoformat(row['completed_at']) if row['completed_at'] else None,
                        data=json.loads(row['data']) if row['data'] else {},
                        vulnerabilities=vulnerabilities,
                        error_message=row['error_message']
                    ))
                
                return results
                
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get scan results: {e}")
    
    async def update_scan_status(self, scan_id: str, status: ScanStatus, 
                               completed_at: Optional[datetime] = None,
                               error_message: Optional[str] = None) -> None:
        """Update scan status."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE scan_results 
                    SET status = ?, completed_at = ?, error_message = ?
                    WHERE id = ?
                """, (
                    status.value,
                    completed_at.isoformat() if completed_at else None,
                    error_message,
                    scan_id
                ))
                
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to update scan status: {e}")
    
    async def delete_scan_result(self, scan_id: str) -> None:
        """Delete a scan result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM vulnerabilities WHERE scan_result_id = ?", (scan_id,))
                conn.execute("DELETE FROM scan_results WHERE id = ?", (scan_id,))
                
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to delete scan result: {e}")
    
    async def get_scan_statistics(self, tenant_id: Optional[str] = None) -> dict:
        """Get scan statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = "SELECT scanner_type, status, COUNT(*) as count FROM scan_results"
                params = []
                
                if tenant_id:
                    query += " WHERE tenant_id = ?"
                    params.append(tenant_id)
                
                query += " GROUP BY scanner_type, status"
                
                cursor = conn.execute(query, params)
                stats = {}
                
                for row in cursor.fetchall():
                    scanner_type = row[0]
                    status = row[1]
                    count = row[2]
                    
                    if scanner_type not in stats:
                        stats[scanner_type] = {}
                    stats[scanner_type][status] = count
                
                return stats
                
        except sqlite3.Error as e:
            raise DatabaseException(f"Failed to get scan statistics: {e}")
    
    # Legacy compatibility methods
    def save_scan(self, target: str, scan_type: str, results: dict, duration: int = 0) -> int:
        """Legacy compatibility method."""
        import uuid
        from datetime import datetime, timedelta
        
        scan_id = str(uuid.uuid4())
        scan_result = ScanResultModel(
            id=scan_id,
            target=Target(address=target, description=target),
            scanner_type=scan_type,
            status=ScanStatus.COMPLETED,
            started_at=datetime.now() - timedelta(seconds=duration),
            completed_at=datetime.now(),
            data=results,
            vulnerabilities=[]
        )
        
        import asyncio
        try:
            asyncio.run(self.save_scan_result(scan_result))
        except RuntimeError as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)
        return hash(scan_id) % (10**8)
    
    def save_export(self, session_id: str, scan_id: int, file_path: str, format: str, target: str = None) -> int:
        """Legacy compatibility method."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS exports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT, scan_id TEXT, file_path TEXT,
                        format TEXT, target TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        file_size INTEGER
                    )
                """)
                
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                cursor = conn.execute("""
                    INSERT INTO exports (session_id, scan_id, file_path, format, target, file_size)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (session_id, str(scan_id), file_path, format, target, file_size))
                return cursor.lastrowid
        except:
            return 0