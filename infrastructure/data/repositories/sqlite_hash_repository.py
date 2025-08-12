"""SQLite hash repository implementation"""

import sqlite3
from typing import Optional, List, Tuple
from domain.repositories.hash_repository import HashRepository
from infrastructure.data.database.hash_db_initializer import init_hash_db

class SQLiteHashRepository(HashRepository):
    def __init__(self, db_path: str):
        self.db_path = db_path
        init_hash_db(db_path)
    
    def lookup(self, hash_value: str) -> Optional[str]:
        """Lookup plaintext for hash value"""
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute("SELECT plaintext FROM hashes WHERE hash=?", (hash_value,))
            row = cur.fetchone()
            return row[0] if row else None
    
    def bulk_insert(self, records: List[Tuple[str, str, str]]) -> int:
        """Bulk insert hash records in chunks, returns number of actually inserted records"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN TRANSACTION")
            cursor = conn.executemany("INSERT OR IGNORE INTO hashes VALUES (?, ?, ?)", records)
            conn.commit()
            return cursor.rowcount
    
    def get_stats(self) -> dict:
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            sources = conn.execute("SELECT source, COUNT(*) FROM hashes GROUP BY source").fetchall()
            return {"total": total, "sources": dict(sources)}