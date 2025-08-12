"""Hash database initialization"""

import sqlite3
import os

def init_hash_db(db_path: str):
    """Initialize hash lookup database with optimized settings"""
    db_dir = os.path.dirname(db_path)
    if db_dir:  # Only create directory if path has a directory component
        os.makedirs(db_dir, exist_ok=True)
    
    with sqlite3.connect(db_path) as conn:
        # Performance optimizations
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA cache_size=10000")
        
        # Create table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hashes (
                hash TEXT PRIMARY KEY,
                plaintext TEXT NOT NULL,
                source TEXT NOT NULL
            )
        """)
        
        # Create index on source for filtering
        conn.execute("CREATE INDEX IF NOT EXISTS idx_source ON hashes(source)")
        
        conn.commit()