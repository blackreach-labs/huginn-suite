# app/core/ssh_data_collector.py
import sqlite3
import json
import time
import hashlib
from typing import Dict, List, Optional, Any
from .centralized_scan_data import create_centralized_scan_data

class SSHDataCollector:
    """Centralized SSH scan data collector with tenant isolation"""
    
    def __init__(self, tenant_id: str = "default"):
        self.tenant_id = tenant_id
        self.db = create_centralized_scan_data()
        self.db_path = self.db.db_path
        self.current_scan_id = None
        self._init_ssh_tables()
    
    def _init_ssh_tables(self):
        """Initialize SSH-specific tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create scan_sessions table if it doesn't exist
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT UNIQUE NOT NULL,
                        tenant_id TEXT NOT NULL,
                        target_ip TEXT NOT NULL,
                        scanner_name TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        start_time REAL NOT NULL,
                        end_time REAL,
                        status TEXT DEFAULT 'running',
                        total_results INTEGER DEFAULT 0,
                        error_message TEXT
                    )
                ''')
                
                
                # SSH banners table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_banners (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        port INTEGER DEFAULT 22,
                        banner TEXT NOT NULL,
                        protocol_version TEXT,
                        software_name TEXT,
                        software_version TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH vulnerabilities table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        cve TEXT NOT NULL,
                        description TEXT,
                        severity TEXT,
                        affected_versions TEXT,
                        reference_links TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH fingerprints table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_fingerprints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        version TEXT,
                        protocol_version TEXT,
                        implementation TEXT,
                        algorithms TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH key types table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_key_types (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        key_type TEXT NOT NULL,
                        key_size INTEGER,
                        fingerprint TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH usernames table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_usernames (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        username TEXT NOT NULL,
                        enumeration_method TEXT,
                        confidence TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH authentication results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_auth_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        username TEXT NOT NULL,
                        auth_method TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        password TEXT,
                        key_path TEXT,
                        error_message TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH exploits table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_exploits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        exploit_name TEXT NOT NULL,
                        cve TEXT,
                        success BOOLEAN NOT NULL,
                        description TEXT,
                        payload TEXT,
                        result TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH system information table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_system_info (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        username TEXT,
                        os_info TEXT,
                        kernel_version TEXT,
                        architecture TEXT,
                        hostname TEXT,
                        uptime TEXT,
                        is_root BOOLEAN,
                        sudo_access TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH credentials table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_credentials (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        username TEXT NOT NULL,
                        credential_type TEXT NOT NULL,
                        hash_value TEXT,
                        hash_type TEXT,
                        source TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH lateral movement targets table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_lateral_targets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        source_ip TEXT NOT NULL,
                        target_host TEXT NOT NULL,
                        discovery_method TEXT,
                        confidence TEXT,
                        additional_info TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # SSH persistence mechanisms table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ssh_persistence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id TEXT NOT NULL,
                        scan_id TEXT,
                        target_ip TEXT NOT NULL,
                        method TEXT NOT NULL,
                        location TEXT,
                        success BOOLEAN NOT NULL,
                        description TEXT,
                        cleanup_command TEXT,
                        timestamp REAL NOT NULL,
                        data_hash TEXT UNIQUE,
                        duplicate_count INTEGER DEFAULT 1,
                        FOREIGN KEY (scan_id) REFERENCES scan_sessions (scan_id)
                    )
                ''')
                
                # Create indexes for performance
                indexes = [
                    'CREATE INDEX IF NOT EXISTS idx_ssh_banners_tenant_target ON ssh_banners (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_vulnerabilities_tenant_target ON ssh_vulnerabilities (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_fingerprints_tenant_target ON ssh_fingerprints (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_key_types_tenant_target ON ssh_key_types (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_usernames_tenant_target ON ssh_usernames (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_auth_results_tenant_target ON ssh_auth_results (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_exploits_tenant_target ON ssh_exploits (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_system_info_tenant_target ON ssh_system_info (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_credentials_tenant_target ON ssh_credentials (tenant_id, target_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_lateral_targets_tenant_source ON ssh_lateral_targets (tenant_id, source_ip)',
                    'CREATE INDEX IF NOT EXISTS idx_ssh_persistence_tenant_target ON ssh_persistence (tenant_id, target_ip)'
                ]
                
                for index_sql in indexes:
                    cursor.execute(index_sql)
                
                conn.commit()
                
        except Exception as e:
            print(f"Error initializing SSH tables: {e}")
    
    def start_ssh_scan(self, target_ip: str, scanner_name: str) -> str:
        """Start new SSH scan session"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                scan_id = f"ssh_{target_ip}_{int(time.time())}"
                
                cursor.execute('''
                    INSERT INTO scan_sessions (
                        scan_id, tenant_id, target_ip, scanner_name, 
                        scan_type, start_time, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (scan_id, self.tenant_id, target_ip, scanner_name, 
                      'ssh', time.time(), 'running'))
                
                conn.commit()
                self.current_scan_id = scan_id
                return scan_id
                
        except Exception as e:
            print(f"Error starting SSH scan: {e}")
            return f"ssh_{target_ip}_{int(time.time())}"
    
    def complete_ssh_scan(self, total_results: int, error_message: str = None):
        """Complete SSH scan session"""
        if not self.current_scan_id:
            return
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE scan_sessions 
                    SET end_time = ?, status = ?, total_results = ?, error_message = ?
                    WHERE scan_id = ?
                ''', (time.time(), 'completed' if not error_message else 'error', 
                      total_results, error_message, self.current_scan_id))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error completing SSH scan: {e}")
    
    def collect_banner(self, target_ip: str, banner_info: Dict):
        """Collect SSH banner information"""
        try:
            data_hash = hashlib.sha256(
                f"{target_ip}:{banner_info.get('banner', '')}".encode()
            ).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check for duplicate
                cursor.execute(
                    'SELECT id, duplicate_count FROM ssh_banners WHERE data_hash = ?',
                    (data_hash,)
                )
                existing = cursor.fetchone()
                
                if existing:
                    # Update duplicate count
                    cursor.execute(
                        'UPDATE ssh_banners SET duplicate_count = duplicate_count + 1 WHERE id = ?',
                        (existing[0],)
                    )
                else:
                    # Insert new record
                    cursor.execute('''
                        INSERT INTO ssh_banners (
                            tenant_id, scan_id, target_ip, port, banner,
                            protocol_version, software_name, software_version,
                            timestamp, data_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        self.tenant_id, self.current_scan_id, target_ip,
                        banner_info.get('port', 22), banner_info.get('banner', ''),
                        banner_info.get('protocol_version', ''), 
                        banner_info.get('software_name', ''),
                        banner_info.get('software_version', ''),
                        time.time(), data_hash
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH banner: {e}")
    
    def collect_vulnerabilities(self, target_ip: str, vulnerabilities: List[Dict]):
        """Collect SSH vulnerabilities"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for vuln in vulnerabilities:
                    data_hash = hashlib.sha256(
                        f"{target_ip}:{vuln.get('cve', '')}".encode()
                    ).hexdigest()
                    
                    # Check for duplicate
                    cursor.execute(
                        'SELECT id, duplicate_count FROM ssh_vulnerabilities WHERE data_hash = ?',
                        (data_hash,)
                    )
                    existing = cursor.fetchone()
                    
                    if existing:
                        cursor.execute(
                            'UPDATE ssh_vulnerabilities SET duplicate_count = duplicate_count + 1 WHERE id = ?',
                            (existing[0],)
                        )
                    else:
                        cursor.execute('''
                            INSERT INTO ssh_vulnerabilities (
                                tenant_id, scan_id, target_ip, cve, description,
                                severity, affected_versions, references, timestamp, data_hash
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            self.tenant_id, self.current_scan_id, target_ip,
                            vuln.get('cve', ''), vuln.get('description', ''),
                            vuln.get('severity', ''), 
                            json.dumps(vuln.get('affected_versions', [])),
                            json.dumps(vuln.get('references', [])),
                            time.time(), data_hash
                        ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH vulnerabilities: {e}")
    
    def collect_fingerprint(self, target_ip: str, fingerprint: Dict):
        """Collect SSH fingerprint information"""
        try:
            data_hash = hashlib.sha256(
                f"{target_ip}:{fingerprint.get('version', '')}".encode()
            ).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute(
                    'SELECT id, duplicate_count FROM ssh_fingerprints WHERE data_hash = ?',
                    (data_hash,)
                )
                existing = cursor.fetchone()
                
                if existing:
                    cursor.execute(
                        'UPDATE ssh_fingerprints SET duplicate_count = duplicate_count + 1 WHERE id = ?',
                        (existing[0],)
                    )
                else:
                    cursor.execute('''
                        INSERT INTO ssh_fingerprints (
                            tenant_id, scan_id, target_ip, version, protocol_version,
                            implementation, algorithms, timestamp, data_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        self.tenant_id, self.current_scan_id, target_ip,
                        fingerprint.get('version', ''), fingerprint.get('protocol_version', ''),
                        fingerprint.get('implementation', ''),
                        json.dumps(fingerprint.get('algorithms', {})),
                        time.time(), data_hash
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH fingerprint: {e}")
    
    def collect_key_types(self, target_ip: str, key_types: List[str]):
        """Collect SSH key types"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for key_type in key_types:
                    data_hash = hashlib.sha256(
                        f"{target_ip}:{key_type}".encode()
                    ).hexdigest()
                    
                    cursor.execute(
                        'SELECT id, duplicate_count FROM ssh_key_types WHERE data_hash = ?',
                        (data_hash,)
                    )
                    existing = cursor.fetchone()
                    
                    if existing:
                        cursor.execute(
                            'UPDATE ssh_key_types SET duplicate_count = duplicate_count + 1 WHERE id = ?',
                            (existing[0],)
                        )
                    else:
                        cursor.execute('''
                            INSERT INTO ssh_key_types (
                                tenant_id, scan_id, target_ip, key_type, timestamp, data_hash
                            ) VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            self.tenant_id, self.current_scan_id, target_ip,
                            key_type, time.time(), data_hash
                        ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH key types: {e}")
    
    def collect_usernames(self, target_ip: str, usernames: List[str]):
        """Collect enumerated usernames"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for username in usernames:
                    data_hash = hashlib.sha256(
                        f"{target_ip}:{username}".encode()
                    ).hexdigest()
                    
                    cursor.execute(
                        'SELECT id, duplicate_count FROM ssh_usernames WHERE data_hash = ?',
                        (data_hash,)
                    )
                    existing = cursor.fetchone()
                    
                    if existing:
                        cursor.execute(
                            'UPDATE ssh_usernames SET duplicate_count = duplicate_count + 1 WHERE id = ?',
                            (existing[0],)
                        )
                    else:
                        cursor.execute('''
                            INSERT INTO ssh_usernames (
                                tenant_id, scan_id, target_ip, username, 
                                enumeration_method, confidence, timestamp, data_hash
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            self.tenant_id, self.current_scan_id, target_ip,
                            username, 'timing_attack', 'medium', time.time(), data_hash
                        ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH usernames: {e}")
    
    def collect_auth_result(self, target_ip: str, auth_result: Dict):
        """Collect authentication result"""
        try:
            data_hash = hashlib.sha256(
                f"{target_ip}:{auth_result.get('username', '')}:{auth_result.get('method', '')}:{time.time()}".encode()
            ).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO ssh_auth_results (
                        tenant_id, scan_id, target_ip, username, auth_method,
                        success, password, key_path, error_message, timestamp, data_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    self.tenant_id, self.current_scan_id, target_ip,
                    auth_result.get('username', ''), auth_result.get('method', ''),
                    auth_result.get('success', False), auth_result.get('password', ''),
                    auth_result.get('key_path', ''), auth_result.get('error', ''),
                    time.time(), data_hash
                ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH auth result: {e}")
    
    def collect_exploits(self, target_ip: str, exploits: List[Dict]):
        """Collect exploit results"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for exploit in exploits:
                    data_hash = hashlib.sha256(
                        f"{target_ip}:{exploit.get('cve', '')}:{exploit.get('success', False)}".encode()
                    ).hexdigest()
                    
                    cursor.execute('''
                        INSERT INTO ssh_exploits (
                            tenant_id, scan_id, target_ip, exploit_name, cve,
                            success, description, payload, result, timestamp, data_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        self.tenant_id, self.current_scan_id, target_ip,
                        exploit.get('name', ''), exploit.get('cve', ''),
                        exploit.get('success', False), exploit.get('description', ''),
                        exploit.get('payload', ''), exploit.get('result', ''),
                        time.time(), data_hash
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH exploits: {e}")
    
    def collect_system_info(self, target_ip: str, system_info: Dict):
        """Collect system information"""
        try:
            data_hash = hashlib.sha256(
                f"{target_ip}:{system_info.get('whoami', '')}".encode()
            ).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO ssh_system_info (
                        tenant_id, scan_id, target_ip, username, os_info,
                        kernel_version, architecture, hostname, uptime,
                        is_root, sudo_access, timestamp, data_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    self.tenant_id, self.current_scan_id, target_ip,
                    system_info.get('whoami', ''), system_info.get('uname', ''),
                    system_info.get('kernel_version', ''), system_info.get('architecture', ''),
                    system_info.get('hostname', ''), system_info.get('uptime', ''),
                    system_info.get('is_root', False), system_info.get('sudo_check', ''),
                    time.time(), data_hash
                ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH system info: {e}")
    
    def collect_credentials(self, target_ip: str, credentials: List[Dict]):
        """Collect dumped credentials"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for cred in credentials:
                    data_hash = hashlib.sha256(
                        f"{target_ip}:{cred.get('username', '')}:{cred.get('hash', '')}".encode()
                    ).hexdigest()
                    
                    cursor.execute('''
                        INSERT INTO ssh_credentials (
                            tenant_id, scan_id, target_ip, username, credential_type,
                            hash_value, hash_type, source, timestamp, data_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        self.tenant_id, self.current_scan_id, target_ip,
                        cred.get('username', ''), cred.get('type', ''),
                        cred.get('hash', ''), cred.get('hash_type', ''),
                        cred.get('source', ''), time.time(), data_hash
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH credentials: {e}")
    
    def collect_ssh_agent_info(self, target_ip: str, agent_info: Dict):
        """Collect SSH agent information"""
        # This could be stored in a separate table or as part of system info
        pass
    
    def collect_lateral_targets(self, target_ip: str, targets: List[Dict]):
        """Collect lateral movement targets"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for target in targets:
                    data_hash = hashlib.sha256(
                        f"{target_ip}:{target.get('host', '')}".encode()
                    ).hexdigest()
                    
                    cursor.execute('''
                        INSERT INTO ssh_lateral_targets (
                            tenant_id, scan_id, source_ip, target_host,
                            discovery_method, confidence, additional_info, timestamp, data_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        self.tenant_id, self.current_scan_id, target_ip,
                        target.get('host', ''), target.get('source', ''),
                        'medium', json.dumps(target), time.time(), data_hash
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH lateral targets: {e}")
    
    def collect_persistence_info(self, target_ip: str, persistence: List[Dict]):
        """Collect persistence mechanism information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                for method in persistence:
                    data_hash = hashlib.sha256(
                        f"{target_ip}:{method.get('method', '')}:{method.get('location', '')}".encode()
                    ).hexdigest()
                    
                    cursor.execute('''
                        INSERT INTO ssh_persistence (
                            tenant_id, scan_id, target_ip, method, location,
                            success, description, cleanup_command, timestamp, data_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        self.tenant_id, self.current_scan_id, target_ip,
                        method.get('method', ''), method.get('location', ''),
                        method.get('success', False), method.get('description', ''),
                        method.get('cleanup', ''), time.time(), data_hash
                    ))
                
                conn.commit()
                
        except Exception as e:
            print(f"Error collecting SSH persistence info: {e}")
    
    def collect_privesc_info(self, target_ip: str, privesc_info: Dict):
        """Collect privilege escalation information"""
        # This could be stored as part of system info or in a separate table
        pass
    
    def get_ssh_data_summary(self) -> Dict:
        """Get summary of collected SSH data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                summary = {}
                
                # Count records in each table
                tables = [
                    'ssh_banners', 'ssh_vulnerabilities', 'ssh_fingerprints',
                    'ssh_key_types', 'ssh_usernames', 'ssh_auth_results',
                    'ssh_exploits', 'ssh_system_info', 'ssh_credentials',
                    'ssh_lateral_targets', 'ssh_persistence'
                ]
                
                for table in tables:
                    cursor.execute(f'SELECT COUNT(*) FROM {table} WHERE tenant_id = ?', (self.tenant_id,))
                    count = cursor.fetchone()[0]
                    summary[table] = count
                
                return summary
                
        except Exception as e:
            print(f"Error getting SSH data summary: {e}")
            return {}

def create_ssh_collector(tenant_id: str = "default") -> SSHDataCollector:
    """Factory function to create SSH data collector"""
    return SSHDataCollector(tenant_id)