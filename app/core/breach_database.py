# app/core/breach_database.py
import os
import json
import sqlite3
from typing import List, Dict, Optional

class BreachDatabase:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'resources', 'breach_data.db')
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize breach database with sample data"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS breaches (
                    id INTEGER PRIMARY KEY,
                    email TEXT,
                    domain TEXT,
                    breach_name TEXT,
                    breach_date TEXT,
                    password_hash TEXT,
                    password_plain TEXT,
                    source TEXT
                )
            ''')
            
            # Add sample breach data if empty
            cursor = conn.execute('SELECT COUNT(*) FROM breaches')
            if cursor.fetchone()[0] == 0:
                sample_data = [
                    ('user@example.com', 'example.com', 'ExampleBreach2020', '2020-03-15', 'md5:5d41402abc4b2a76b9719d911017c592', 'hello', 'local_db'),
                    ('admin@test.org', 'test.org', 'TestLeak2019', '2019-08-22', 'sha1:aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d', 'hello', 'local_db'),
                    ('john.doe@company.com', 'company.com', 'CompanyHack2021', '2021-12-01', 'md5:098f6bcd4621d373cade4e832627b4f6', 'test', 'local_db'),
                ]
                conn.executemany('INSERT INTO breaches (email, domain, breach_name, breach_date, password_hash, password_plain, source) VALUES (?, ?, ?, ?, ?, ?, ?)', sample_data)
    
    def search_email(self, email: str) -> List[Dict]:
        """Search for email in breach database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT breach_name, breach_date, password_hash, password_plain, source
                FROM breaches WHERE email = ? COLLATE NOCASE
            ''', (email,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'breach_name': row[0],
                    'breach_date': row[1],
                    'password_hash': row[2],
                    'password_plain': row[3],
                    'source': row[4]
                })
            return results
    
    def search_domain(self, domain: str) -> List[Dict]:
        """Search for domain in breach database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT email, breach_name, breach_date, password_hash, password_plain, source
                FROM breaches WHERE domain = ? COLLATE NOCASE
            ''', (domain,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'email': row[0],
                    'breach_name': row[1],
                    'breach_date': row[2],
                    'password_hash': row[3],
                    'password_plain': row[4],
                    'source': row[5]
                })
            return results

# Global instance
breach_db = BreachDatabase()