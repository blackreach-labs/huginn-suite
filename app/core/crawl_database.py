import sqlite3
import os
from datetime import datetime
from urllib.parse import urlparse

class CrawlDatabase:
    def __init__(self, db_path=None):
        if db_path is None:
            # Default to resources/crawl.db
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            db_path = os.path.join(project_root, "resources", "crawl.db")
        
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the crawl database with required tables"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create crawl_results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crawl_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    url TEXT NOT NULL,
                    path TEXT,
                    status_code INTEGER,
                    content_type TEXT,
                    content_length INTEGER,
                    response_time REAL,
                    parent_url TEXT,
                    depth INTEGER,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain, url)
                )
            ''')
            
            # Create index for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON crawl_results(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_path ON crawl_results(path)')
            
            conn.commit()
    
    def save_crawl_result(self, domain, url, path=None, status_code=None, 
                         content_type=None, content_length=None, response_time=None,
                         parent_url=None, depth=0):
        """Save a crawl result to the database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO crawl_results 
                (domain, url, path, status_code, content_type, content_length, 
                 response_time, parent_url, depth)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (domain, url, path, status_code, content_type, content_length,
                  response_time, parent_url, depth))
            
            conn.commit()
    
    def get_crawl_results(self, domain=None, limit=None):
        """Get crawl results from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if domain:
                query = 'SELECT * FROM crawl_results WHERE domain = ? ORDER BY discovered_at DESC'
                params = (domain,)
            else:
                query = 'SELECT * FROM crawl_results ORDER BY discovered_at DESC'
                params = ()
            
            if limit:
                query += f' LIMIT {limit}'
            
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def get_stats(self, domain=None):
        """Get crawl statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if domain:
                cursor.execute('SELECT COUNT(*) FROM crawl_results WHERE domain = ?', (domain,))
                total = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM crawl_results WHERE domain = ? AND status_code = 200', (domain,))
                accessible = cursor.fetchone()[0]
            else:
                cursor.execute('SELECT COUNT(*) FROM crawl_results')
                total = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM crawl_results WHERE status_code = 200')
                accessible = cursor.fetchone()[0]
            
            return {'total': total, 'accessible': accessible}

# Global instance
crawl_db = CrawlDatabase()