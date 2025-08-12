# app/core/query_engine.py
import sqlite3
from typing import Dict, List, Optional, Tuple
from .pentest_database import pentest_db

class QueryEngine:
    """Advanced query engine for penetration testing data"""
    
    def __init__(self):
        self.db = pentest_db
    
    def find_hosts_with_service(self, service_name: str, version: str = None) -> List[Dict]:
        """Find all hosts running a specific service"""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            query = """
                SELECT t.ip, t.hostname, t.domain, s.port, s.service, s.version, s.banner
                FROM targets t
                JOIN services s ON t.id = s.target_id
                WHERE s.service LIKE ? AND s.state = 'open'
            """
            params = [f"%{service_name}%"]
            
            if version:
                query += " AND s.version LIKE ?"
                params.append(f"%{version}%")
            
            query += " ORDER BY t.ip, s.port"
            
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def find_vulnerable_services(self, severity: str = None) -> List[Dict]:
        """Find services with known vulnerabilities"""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            query = """
                SELECT DISTINCT t.ip, t.hostname, s.port, s.service, s.version,
                       COUNT(v.id) as vuln_count,
                       GROUP_CONCAT(v.name, '; ') as vulnerabilities
                FROM targets t
                JOIN services s ON t.id = s.target_id
                JOIN vulnerabilities v ON s.id = v.service_id
                WHERE 1=1
            """
            params = []
            
            if severity:
                query += " AND v.severity = ?"
                params.append(severity)
            
            query += """
                GROUP BY t.ip, s.port
                ORDER BY vuln_count DESC, t.ip, s.port
            """
            
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def find_credential_reuse(self) -> List[Dict]:
        """Find credential reuse across targets"""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            cursor = conn.execute("""
                SELECT username, password, hash_value, COUNT(*) as usage_count,
                       GROUP_CONCAT(t.ip, ', ') as targets
                FROM credentials c
                JOIN targets t ON c.target_id = t.id
                WHERE (username != '' OR password != '' OR hash_value != '')
                GROUP BY COALESCE(username, ''), COALESCE(password, ''), COALESCE(hash_value, '')
                HAVING COUNT(*) > 1
                ORDER BY usage_count DESC
            """)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def find_attack_paths(self, start_ip: str, end_ip: str = None) -> List[Dict]:
        """Find potential attack paths between hosts"""
        paths = []
        
        # Get source host details
        source = self.db.get_target_by_ip(start_ip)
        if not source:
            return paths
        
        # Find services that could be used for lateral movement
        lateral_services = ['ssh', 'rdp', 'winrm', 'smb', 'wmi']
        
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Find hosts with lateral movement services
            query = """
                SELECT t.ip, t.hostname, s.port, s.service, s.version,
                       c.username, c.password, c.hash_value
                FROM targets t
                JOIN services s ON t.id = s.target_id
                LEFT JOIN credentials c ON t.id = c.target_id
                WHERE s.service IN ({}) AND s.state = 'open'
            """.format(','.join(['?' for _ in lateral_services]))
            
            params = lateral_services
            if end_ip:
                query += " AND t.ip = ?"
                params.append(end_ip)
            
            cursor = conn.execute(query, params)
            targets = [dict(row) for row in cursor.fetchall()]
            
            # Build attack paths
            for target in targets:
                path = {
                    'source': start_ip,
                    'destination': target['ip'],
                    'service': target['service'],
                    'port': target['port'],
                    'has_credentials': bool(target['username'] or target['password']),
                    'method': self._get_attack_method(target['service'])
                }
                paths.append(path)
        
        return paths
    
    def find_high_value_targets(self) -> List[Dict]:
        """Identify high-value targets based on services and vulnerabilities"""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            cursor = conn.execute("""
                SELECT t.ip, t.hostname, t.domain,
                       COUNT(DISTINCT s.id) as service_count,
                       COUNT(DISTINCT v.id) as vuln_count,
                       COUNT(DISTINCT CASE WHEN v.severity IN ('critical', 'high') THEN v.id END) as high_vulns,
                       COUNT(DISTINCT c.id) as cred_count,
                       COUNT(DISTINCT l.id) as loot_count,
                       GROUP_CONCAT(DISTINCT s.service) as services
                FROM targets t
                LEFT JOIN services s ON t.id = s.target_id AND s.state = 'open'
                LEFT JOIN vulnerabilities v ON t.id = v.target_id
                LEFT JOIN credentials c ON t.id = c.target_id
                LEFT JOIN loot l ON t.id = l.target_id
                WHERE t.status = 'active'
                GROUP BY t.id
                HAVING service_count > 3 OR high_vulns > 0 OR cred_count > 0
                ORDER BY (high_vulns * 10 + vuln_count * 2 + service_count + cred_count) DESC
            """)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def find_weak_credentials(self) -> List[Dict]:
        """Find weak or default credentials"""
        weak_passwords = [
            'password', '123456', 'admin', 'root', 'guest', 'user',
            'default', 'blank', '', 'password123', 'admin123'
        ]
        
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            placeholders = ','.join(['?' for _ in weak_passwords])
            cursor = conn.execute(f"""
                SELECT t.ip, t.hostname, c.username, c.password, c.domain, s.service, s.port
                FROM credentials c
                JOIN targets t ON c.target_id = t.id
                LEFT JOIN services s ON c.service_id = s.id
                WHERE c.password IN ({placeholders})
                   OR (c.username = c.password AND c.username != '')
                   OR (c.username IN ('admin', 'root', 'guest') AND c.password IN ('admin', 'root', 'guest'))
                ORDER BY t.ip
            """, weak_passwords)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def find_exposed_databases(self) -> List[Dict]:
        """Find exposed database services"""
        db_ports = [1433, 3306, 5432, 1521, 27017, 6379, 11211]
        
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            placeholders = ','.join(['?' for _ in db_ports])
            cursor = conn.execute(f"""
                SELECT t.ip, t.hostname, s.port, s.service, s.version, s.banner,
                       COUNT(v.id) as vuln_count,
                       COUNT(c.id) as cred_count
                FROM targets t
                JOIN services s ON t.id = s.target_id
                LEFT JOIN vulnerabilities v ON s.id = v.service_id
                LEFT JOIN credentials c ON t.id = c.target_id
                WHERE s.port IN ({placeholders}) AND s.state = 'open'
                GROUP BY t.id, s.id
                ORDER BY vuln_count DESC, cred_count DESC, t.ip
            """, db_ports)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_network_overview(self) -> Dict:
        """Get comprehensive network overview"""
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get network segments (Class C networks)
            cursor = conn.execute("""
                SELECT 
                    SUBSTR(ip, 1, 
                        CASE 
                            WHEN INSTR(SUBSTR(ip, INSTR(ip, '.') + 1), '.') > 0 
                            THEN INSTR(ip, '.') + INSTR(SUBSTR(ip, INSTR(ip, '.') + 1), '.') 
                            ELSE LENGTH(ip) 
                        END
                    ) as network,
                    COUNT(*) as host_count
                FROM targets
                WHERE ip != '' AND status = 'active'
                GROUP BY network
                ORDER BY host_count DESC
            """)
            networks = [dict(row) for row in cursor.fetchall()]
            
            # Get service distribution
            cursor = conn.execute("""
                SELECT s.service, COUNT(*) as count
                FROM services s
                JOIN targets t ON s.target_id = t.id
                WHERE s.state = 'open' AND t.status = 'active'
                GROUP BY s.service
                ORDER BY count DESC
                LIMIT 10
            """)
            top_services = [dict(row) for row in cursor.fetchall()]
            
            # Get vulnerability summary
            cursor = conn.execute("""
                SELECT v.severity, COUNT(*) as count
                FROM vulnerabilities v
                JOIN targets t ON v.target_id = t.id
                WHERE t.status = 'active'
                GROUP BY v.severity
            """)
            vuln_summary = dict(cursor.fetchall())
            
            return {
                'networks': networks,
                'top_services': top_services,
                'vulnerability_summary': vuln_summary,
                'statistics': self.db.get_statistics()
            }
    
    def search_all(self, query: str) -> Dict:
        """Search across all data types"""
        results = {
            'targets': [],
            'services': [],
            'vulnerabilities': [],
            'credentials': [],
            'loot': []
        }
        
        with sqlite3.connect(self.db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Search targets
            cursor = conn.execute("""
                SELECT * FROM targets
                WHERE ip LIKE ? OR hostname LIKE ? OR domain LIKE ? OR notes LIKE ?
            """, [f"%{query}%"] * 4)
            results['targets'] = [dict(row) for row in cursor.fetchall()]
            
            # Search services
            cursor = conn.execute("""
                SELECT s.*, t.ip, t.hostname
                FROM services s
                JOIN targets t ON s.target_id = t.id
                WHERE s.service LIKE ? OR s.version LIKE ? OR s.banner LIKE ?
            """, [f"%{query}%"] * 3)
            results['services'] = [dict(row) for row in cursor.fetchall()]
            
            # Search vulnerabilities
            cursor = conn.execute("""
                SELECT v.*, t.ip, t.hostname
                FROM vulnerabilities v
                JOIN targets t ON v.target_id = t.id
                WHERE v.name LIKE ? OR v.cve LIKE ? OR v.description LIKE ?
            """, [f"%{query}%"] * 3)
            results['vulnerabilities'] = [dict(row) for row in cursor.fetchall()]
            
            # Search credentials
            cursor = conn.execute("""
                SELECT c.*, t.ip, t.hostname
                FROM credentials c
                JOIN targets t ON c.target_id = t.id
                WHERE c.username LIKE ? OR c.domain LIKE ?
            """, [f"%{query}%"] * 2)
            results['credentials'] = [dict(row) for row in cursor.fetchall()]
            
            # Search loot
            cursor = conn.execute("""
                SELECT l.*, t.ip, t.hostname
                FROM loot l
                JOIN targets t ON l.target_id = t.id
                WHERE l.name LIKE ? OR l.content LIKE ? OR l.notes LIKE ?
            """, [f"%{query}%"] * 3)
            results['loot'] = [dict(row) for row in cursor.fetchall()]
        
        return results
    
    def _get_attack_method(self, service: str) -> str:
        """Get attack method for service"""
        methods = {
            'ssh': 'SSH key/password authentication',
            'rdp': 'RDP credential authentication',
            'winrm': 'WinRM remote execution',
            'smb': 'SMB share access/psexec',
            'wmi': 'WMI remote execution'
        }
        return methods.get(service, f'{service} exploitation')

# Global instance
query_engine = QueryEngine()