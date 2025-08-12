# app/core/auth_database.py
import sqlite3
import json
import time
from typing import Dict, List, Optional, Any
from pathlib import Path

class AuthDatabase:
    """Database for storing authentication workflow data"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = Path(__file__).parent.parent.parent / "resources" / "auth_workflows.db"
        
        self.db_path = str(db_path)
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Auth flows table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    name TEXT,
                    start_time REAL,
                    end_time REAL,
                    duration REAL,
                    request_count INTEGER,
                    token_count INTEGER,
                    flow_data TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)
            
            # Tokens table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER,
                    name TEXT NOT NULL,
                    type TEXT,
                    value_hash TEXT,
                    length INTEGER,
                    entropy REAL,
                    source TEXT,
                    vulnerabilities TEXT,
                    analysis_data TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    FOREIGN KEY (flow_id) REFERENCES auth_flows (id)
                )
            """)
            
            # Test results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_id TEXT UNIQUE NOT NULL,
                    flow_id INTEGER,
                    test_type TEXT,
                    mutations TEXT,
                    start_time REAL,
                    end_time REAL,
                    duration REAL,
                    requests_sent INTEGER,
                    successful_requests INTEGER,
                    vulnerabilities_found INTEGER,
                    results_data TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    FOREIGN KEY (flow_id) REFERENCES auth_flows (id)
                )
            """)
            
            # Vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER,
                    test_id TEXT,
                    token_id INTEGER,
                    vuln_type TEXT NOT NULL,
                    severity TEXT,
                    description TEXT,
                    url TEXT,
                    evidence TEXT,
                    recommendation TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    FOREIGN KEY (flow_id) REFERENCES auth_flows (id),
                    FOREIGN KEY (token_id) REFERENCES tokens (id)
                )
            """)
            
            # State models table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS state_models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER UNIQUE,
                    nodes_data TEXT,
                    edges_data TEXT,
                    token_lifecycle TEXT,
                    security_issues TEXT,
                    attack_surface TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now')),
                    FOREIGN KEY (flow_id) REFERENCES auth_flows (id)
                )
            """)
            
            conn.commit()
    
    def store_flow(self, flow_data: dict) -> int:
        """Store authentication flow data"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO auth_flows 
                (session_id, name, start_time, end_time, duration, request_count, token_count, flow_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                flow_data['session_id'],
                flow_data.get('name', flow_data['session_id']),
                flow_data.get('start_time'),
                flow_data.get('end_time'),
                flow_data.get('duration'),
                len(flow_data.get('requests', [])),
                len(flow_data.get('tokens', {})),
                json.dumps(flow_data, default=str)
            ))
            
            flow_id = cursor.lastrowid
            
            # Store tokens
            for token_name, token_info in flow_data.get('tokens', {}).items():
                self._store_token(cursor, flow_id, token_name, token_info)
            
            conn.commit()
            return flow_id
    
    def _store_token(self, cursor, flow_id: int, token_name: str, token_info: dict):
        """Store token information"""
        import hashlib
        
        # Hash the token value for security
        token_value = token_info.get('value', '')
        value_hash = hashlib.sha256(token_value.encode()).hexdigest()[:32]
        
        cursor.execute("""
            INSERT INTO tokens 
            (flow_id, name, type, value_hash, length, entropy, source, analysis_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flow_id,
            token_name,
            token_info.get('type', 'unknown'),
            value_hash,
            len(token_value),
            token_info.get('entropy', 0),
            token_info.get('source', 'unknown'),
            json.dumps(token_info, default=str)
        ))
    
    def store_test_result(self, test_result: dict) -> int:
        """Store test result"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get flow_id if available
            flow_id = None
            if 'flow_session_id' in test_result:
                cursor.execute("SELECT id FROM auth_flows WHERE session_id = ?", 
                             (test_result['flow_session_id'],))
                result = cursor.fetchone()
                if result:
                    flow_id = result[0]
            
            cursor.execute("""
                INSERT INTO test_results 
                (test_id, flow_id, test_type, mutations, start_time, end_time, duration,
                 requests_sent, successful_requests, vulnerabilities_found, results_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                test_result['test_id'],
                flow_id,
                test_result.get('test_type', 'unknown'),
                json.dumps(test_result.get('mutations', [])),
                test_result.get('start_time'),
                test_result.get('end_time'),
                test_result.get('duration'),
                test_result.get('requests_sent', 0),
                test_result.get('successful_requests', 0),
                len(test_result.get('vulnerabilities', [])),
                json.dumps(test_result, default=str)
            ))
            
            test_db_id = cursor.lastrowid
            
            # Store vulnerabilities
            for vuln in test_result.get('vulnerabilities', []):
                self._store_vulnerability(cursor, flow_id, test_result['test_id'], None, vuln)
            
            conn.commit()
            return test_db_id
    
    def store_token_analysis(self, flow_session_id: str, token_name: str, analysis: dict):
        """Store token analysis results"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get flow_id and token_id
            cursor.execute("""
                SELECT af.id, t.id FROM auth_flows af
                JOIN tokens t ON af.id = t.flow_id
                WHERE af.session_id = ? AND t.name = ?
            """, (flow_session_id, token_name))
            
            result = cursor.fetchone()
            if result:
                flow_id, token_id = result
                
                # Update token with analysis
                cursor.execute("""
                    UPDATE tokens SET 
                    type = ?, entropy = ?, vulnerabilities = ?, analysis_data = ?
                    WHERE id = ?
                """, (
                    analysis.get('type', 'unknown'),
                    analysis.get('entropy', 0),
                    json.dumps(analysis.get('vulnerabilities', [])),
                    json.dumps(analysis, default=str),
                    token_id
                ))
                
                # Store vulnerabilities
                for vuln in analysis.get('vulnerabilities', []):
                    self._store_vulnerability(cursor, flow_id, None, token_id, vuln)
                
                conn.commit()
    
    def _store_vulnerability(self, cursor, flow_id: int, test_id: str, token_id: int, vuln: dict):
        """Store vulnerability information"""
        cursor.execute("""
            INSERT INTO vulnerabilities 
            (flow_id, test_id, token_id, vuln_type, severity, description, url, evidence, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flow_id,
            test_id,
            token_id,
            vuln['type'],
            vuln.get('severity', 'unknown'),
            vuln.get('description', ''),
            vuln.get('url', ''),
            json.dumps(vuln.get('evidence', {})),
            vuln.get('recommendation', '')
        ))
    
    def store_state_model(self, flow_session_id: str, model_data: dict):
        """Store state model data"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get flow_id
            cursor.execute("SELECT id FROM auth_flows WHERE session_id = ?", (flow_session_id,))
            result = cursor.fetchone()
            if result:
                flow_id = result[0]
                
                cursor.execute("""
                    INSERT OR REPLACE INTO state_models 
                    (flow_id, nodes_data, edges_data, token_lifecycle, security_issues, attack_surface)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    flow_id,
                    json.dumps(model_data.get('nodes', {}), default=str),
                    json.dumps(model_data.get('edges', []), default=str),
                    json.dumps(model_data.get('token_lifecycle', {}), default=str),
                    json.dumps(model_data.get('security_issues', []), default=str),
                    json.dumps(model_data.get('attack_surface', {}), default=str)
                ))
                
                conn.commit()
    
    def get_flows(self, limit: int = 100, offset: int = 0) -> List[dict]:
        """Get stored flows"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT session_id, name, start_time, end_time, duration, 
                       request_count, token_count, created_at
                FROM auth_flows 
                ORDER BY created_at DESC 
                LIMIT ? OFFSET ?
            """, (limit, offset))
            
            flows = []
            for row in cursor.fetchall():
                flows.append({
                    'session_id': row[0],
                    'name': row[1],
                    'start_time': row[2],
                    'end_time': row[3],
                    'duration': row[4],
                    'request_count': row[5],
                    'token_count': row[6],
                    'created_at': row[7]
                })
            
            return flows
    
    def get_flow_data(self, session_id: str) -> Optional[dict]:
        """Get full flow data"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT flow_data FROM auth_flows WHERE session_id = ?", (session_id,))
            result = cursor.fetchone()
            
            if result:
                return json.loads(result[0])
            return None
    
    def get_vulnerabilities(self, flow_session_id: str = None, severity: str = None) -> List[dict]:
        """Get vulnerabilities"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT v.vuln_type, v.severity, v.description, v.url, 
                       v.evidence, v.recommendation, v.created_at,
                       af.session_id, v.test_id
                FROM vulnerabilities v
                JOIN auth_flows af ON v.flow_id = af.id
            """
            params = []
            
            conditions = []
            if flow_session_id:
                conditions.append("af.session_id = ?")
                params.append(flow_session_id)
            
            if severity:
                conditions.append("v.severity = ?")
                params.append(severity)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY v.created_at DESC"
            
            cursor.execute(query, params)
            
            vulnerabilities = []
            for row in cursor.fetchall():
                vulnerabilities.append({
                    'type': row[0],
                    'severity': row[1],
                    'description': row[2],
                    'url': row[3],
                    'evidence': json.loads(row[4]) if row[4] else {},
                    'recommendation': row[5],
                    'created_at': row[6],
                    'flow_session_id': row[7],
                    'test_id': row[8]
                })
            
            return vulnerabilities
    
    def get_statistics(self) -> dict:
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Flow statistics
            cursor.execute("SELECT COUNT(*) FROM auth_flows")
            stats['total_flows'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM tokens")
            stats['total_tokens'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM test_results")
            stats['total_tests'] = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            stats['total_vulnerabilities'] = cursor.fetchone()[0]
            
            # Vulnerability breakdown by severity
            cursor.execute("""
                SELECT severity, COUNT(*) 
                FROM vulnerabilities 
                GROUP BY severity
            """)
            stats['vulnerabilities_by_severity'] = dict(cursor.fetchall())
            
            # Token type breakdown
            cursor.execute("""
                SELECT type, COUNT(*) 
                FROM tokens 
                GROUP BY type
            """)
            stats['tokens_by_type'] = dict(cursor.fetchall())
            
            # Recent activity
            cursor.execute("""
                SELECT COUNT(*) 
                FROM auth_flows 
                WHERE created_at > ?
            """, (time.time() - 86400,))  # Last 24 hours
            stats['flows_last_24h'] = cursor.fetchone()[0]
            
            return stats
    
    def cleanup_old_data(self, days_old: int = 30):
        """Clean up old data"""
        cutoff_time = time.time() - (days_old * 86400)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Delete old flows and related data (cascading)
            cursor.execute("DELETE FROM auth_flows WHERE created_at < ?", (cutoff_time,))
            
            conn.commit()
            
            return cursor.rowcount
    
    def export_data(self, filepath: str, session_ids: List[str] = None):
        """Export data to JSON file"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            export_data = {
                'export_timestamp': time.time(),
                'flows': [],
                'vulnerabilities': [],
                'statistics': self.get_statistics()
            }
            
            # Export flows
            if session_ids:
                placeholders = ','.join('?' * len(session_ids))
                cursor.execute(f"""
                    SELECT session_id, flow_data 
                    FROM auth_flows 
                    WHERE session_id IN ({placeholders})
                """, session_ids)
            else:
                cursor.execute("SELECT session_id, flow_data FROM auth_flows")
            
            for row in cursor.fetchall():
                export_data['flows'].append({
                    'session_id': row[0],
                    'data': json.loads(row[1])
                })
            
            # Export vulnerabilities
            export_data['vulnerabilities'] = self.get_vulnerabilities()
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
    
    def close(self):
        """Close database connection"""
        # SQLite connections are closed automatically with context managers
        pass