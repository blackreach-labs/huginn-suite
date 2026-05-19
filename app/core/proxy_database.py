# app/core/proxy_database.py
import sqlite3
import json
import time
from typing import Dict, List, Optional
from pathlib import Path
import os

class ProxyDatabase:
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default to resources folder
            project_root = Path(__file__).parent.parent.parent
            resources_dir = project_root / "resources"
            resources_dir.mkdir(exist_ok=True)
            self.db_path = str(resources_dir / "proxy.db")
        else:
            self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the proxy database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER,
                    response_time REAL,
                    request_size INTEGER,
                    response_size INTEGER,
                    request_headers TEXT,
                    response_headers TEXT,
                    request_body TEXT,
                    response_body TEXT,
                    content_type TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create index for faster queries
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON requests(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON requests(url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_method ON requests(method)")
    
    def store_request(self, request_data: Dict) -> int:
        """Store a request/response pair in the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO requests (
                    timestamp, method, url, host, path, status_code, response_time,
                    request_size, response_size, request_headers, response_headers,
                    request_body, response_body, content_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_data.get('timestamp', time.time()),
                request_data.get('method', ''),
                request_data.get('url', ''),
                request_data.get('host', ''),
                request_data.get('path', ''),
                request_data.get('status_code'),
                request_data.get('response_time', 0),
                request_data.get('request_size', 0),
                request_data.get('response_size', 0),
                json.dumps(request_data.get('request_headers', {})),
                json.dumps(request_data.get('response_headers', {})),
                request_data.get('request_body', ''),
                request_data.get('response_body', ''),
                request_data.get('content_type', '')
            ))
            return cursor.lastrowid
    
    def get_requests(self, limit: int = 1000, offset: int = 0) -> List[Dict]:
        """Get requests from database for history display"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT id, timestamp, method, url, status_code, response_time, 
                       request_size, response_size, content_type,
                       datetime(timestamp, 'unixepoch', 'localtime') as formatted_time
                FROM requests 
                ORDER BY timestamp ASC 
                LIMIT ? OFFSET ?
            """, (limit, offset))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_request_details(self, request_id: int) -> Optional[Dict]:
        """Get full request details by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM requests WHERE id = ?
            """, (request_id,))
            
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # Parse JSON fields
                data['request_headers'] = json.loads(data['request_headers'] or '{}')
                data['response_headers'] = json.loads(data['response_headers'] or '{}')
                return data
            return None
    
    def clear_history(self):
        """Clear all stored requests"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM requests")
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total_requests,
                    COUNT(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 END) as success_count,
                    COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count,
                    AVG(response_time) as avg_response_time
                FROM requests
            """)
            
            row = cursor.fetchone()
            return {
                'total_requests': row[0] or 0,
                'success_count': row[1] or 0,
                'error_count': row[2] or 0,
                'avg_response_time': round(row[3] or 0, 2)
            }