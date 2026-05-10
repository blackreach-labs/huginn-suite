# app/core/database_pool.py
import sqlite3
import threading
import time
from queue import Queue, Empty
from contextlib import contextmanager
from typing import Optional
from app.core.logger import logger

class DatabaseConnectionPool:
    """Thread-safe SQLite connection pool for improved performance"""
    
    def __init__(self, database_path: str, pool_size: int = 10, timeout: int = 30):
        self.database_path = database_path
        self.pool_size = pool_size
        self.timeout = timeout
        self.pool = Queue(maxsize=pool_size)
        self.lock = threading.Lock()
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize the connection pool"""
        for _ in range(self.pool_size):
            conn = sqlite3.connect(
                self.database_path,
                check_same_thread=False,
                timeout=self.timeout
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=MEMORY")
            self.pool.put(conn)
    
    @contextmanager
    def get_connection(self):
        """Get a connection from the pool"""
        conn = None
        try:
            conn = self.pool.get(timeout=5)
            yield conn
        except Empty:
            # Create temporary connection if pool is exhausted
            conn = sqlite3.connect(
                self.database_path,
                check_same_thread=False,
                timeout=self.timeout
            )
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
        finally:
            if conn:
                try:
                    self.pool.put_nowait(conn)
                except Exception:
                    # Pool is full, close the connection
                    conn.close()
    
    def execute_query(self, query: str, params: tuple = ()):
        """Execute a query and return results"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def execute_write(self, query: str, params: tuple = ()):
        """Execute a write query"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount
    
    def execute_many(self, query: str, params_list: list):
        """Execute multiple queries in a batch"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(query, params_list)
            conn.commit()
            return cursor.rowcount
    
    def close_all(self):
        """Close all connections in the pool"""
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
            except Empty:
                break

# Global connection pool instance
_connection_pools = {}
_pool_lock = threading.Lock()

def get_database_pool(database_path: str) -> DatabaseConnectionPool:
    """Get or create a database connection pool"""
    with _pool_lock:
        if database_path not in _connection_pools:
            _connection_pools[database_path] = DatabaseConnectionPool(database_path)
        return _connection_pools[database_path]