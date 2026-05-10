"""Database utility functions for common operations"""
import re
import sqlite3
import os
import shutil
from typing import List, Tuple, Dict, Any
from pathlib import Path


def _quote_identifier(name: str) -> str:
    """Return a safely bracket-quoted SQLite identifier.

    SQLite bracket-quoting (``[name]``) neutralises all special characters
    including semicolons, quotes, and whitespace.  We additionally reject
    names that contain a closing bracket (``]``) because that is the only
    character that cannot be escaped inside bracket-quoted identifiers.

    Raises ``ValueError`` for invalid identifiers so callers can surface a
    clear error rather than silently executing a malformed query.
    """
    if not name or not isinstance(name, str):
        raise ValueError(f"Invalid identifier: {name!r}")
    # Reject names containing ] — cannot be safely bracket-quoted
    if ']' in name:
        raise ValueError(
            f"Identifier contains illegal character ']': {name!r}"
        )
    # Reject obviously dangerous patterns (semicolons, null bytes)
    if any(c in name for c in (';', '\x00')):
        raise ValueError(
            f"Identifier contains illegal character: {name!r}"
        )
    return f"[{name}]"

class DatabaseUtils:
    """Utility class for common database operations"""
    
    @staticmethod
    def get_database_info(db_path: str) -> Dict[str, Any]:
        """Get comprehensive database information"""
        if not os.path.exists(db_path):
            return {"error": "Database file not found"}
        
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                # Basic file info
                file_size = os.path.getsize(db_path)
                
                # Get tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                # Get table info
                table_info = {}
                total_rows = 0
                
                for table in tables:
                    try:
                        quoted = _quote_identifier(table)
                        # Use string concatenation (not f-string) to make it
                        # clear that only the pre-validated quoted identifier
                        # is interpolated — no user input reaches the SQL.
                        cursor.execute("SELECT COUNT(*) FROM " + quoted)
                        row_count = cursor.fetchone()[0]
                        total_rows += row_count
                        
                        cursor.execute("PRAGMA table_info(" + quoted + ")")
                        columns = cursor.fetchall()
                        
                        table_info[table] = {
                            "rows": row_count,
                            "columns": len(columns),
                            "column_details": columns
                        }
                    except Exception as e:
                        table_info[table] = {"error": str(e)}
                
                # Database settings
                cursor.execute("PRAGMA database_list")
                db_list = cursor.fetchall()
                
                cursor.execute("PRAGMA journal_mode")
                journal_mode = cursor.fetchone()[0]
                
                cursor.execute("PRAGMA synchronous")
                synchronous = cursor.fetchone()[0]
                
                return {
                    "file_size": file_size,
                    "file_size_formatted": DatabaseUtils.format_file_size(file_size),
                    "tables": tables,
                    "table_count": len(tables),
                    "total_rows": total_rows,
                    "table_info": table_info,
                    "journal_mode": journal_mode,
                    "synchronous": synchronous,
                    "database_list": db_list
                }
                
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    @staticmethod
    def vacuum_database(db_path: str) -> Tuple[bool, str]:
        """Vacuum (compact) database"""
        try:
            original_size = os.path.getsize(db_path)
            
            with sqlite3.connect(db_path) as conn:
                conn.execute("VACUUM")
                conn.commit()
            
            new_size = os.path.getsize(db_path)
            saved_bytes = original_size - new_size
            
            return True, f"Database compacted successfully. Saved {DatabaseUtils.format_file_size(saved_bytes)}"
        except Exception as e:
            return False, f"Failed to compact database: {str(e)}"
    
    @staticmethod
    def analyze_database(db_path: str) -> Tuple[bool, str]:
        """Analyze database and update statistics"""
        try:
            with sqlite3.connect(db_path) as conn:
                conn.execute("ANALYZE")
                conn.commit()
            
            return True, "Database analysis completed successfully"
        except Exception as e:
            return False, f"Failed to analyze database: {str(e)}"
    
    @staticmethod
    def backup_database(db_path: str, backup_path: str) -> Tuple[bool, str]:
        """Create database backup"""
        try:
            shutil.copy2(db_path, backup_path)
            return True, f"Database backed up to {backup_path}"
        except Exception as e:
            return False, f"Failed to backup database: {str(e)}"
    
    @staticmethod
    def integrity_check(db_path: str) -> Tuple[bool, str, List[str]]:
        """Check database integrity"""
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check")
                results = cursor.fetchall()
                
                if len(results) == 1 and results[0][0] == "ok":
                    return True, "Database integrity check passed", []
                else:
                    issues = [row[0] for row in results]
                    return False, "Database integrity issues found", issues
                    
        except Exception as e:
            return False, f"Failed to check integrity: {str(e)}", []
    
    @staticmethod
    def get_schema_sql(db_path: str) -> Dict[str, str]:
        """Get CREATE SQL for all database objects"""
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name")
                results = cursor.fetchall()
                
                return {name: sql for name, sql in results}
                
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def execute_safe_query(db_path: str, query: str, params: tuple = ()) -> Tuple[bool, List[Tuple], List[str], str]:
        """Execute query safely with results.

        Args:
            db_path: Path to the SQLite database file.
            query:   SQL query string.  Identifiers must already be quoted by
                     the caller using ``_quote_identifier()``.  Values must be
                     passed via ``params`` — never interpolated into the string.
            params:  Bound parameters for the query (default: empty tuple).
        """
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                
                if query.strip().upper().startswith(('SELECT', 'PRAGMA')):
                    results = cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description] if cursor.description else []
                    return True, results, columns, f"{len(results)} rows returned"
                else:
                    conn.commit()
                    return True, [], [], f"Query executed successfully. {cursor.rowcount} rows affected"
                    
        except Exception as e:
            return False, [], [], str(e)
    
    @staticmethod
    def get_table_sample(db_path: str, table_name: str, limit: int = 100) -> Tuple[bool, List[Tuple], List[str], str]:
        """Get sample data from table"""
        try:
            quoted = _quote_identifier(table_name)
        except ValueError as e:
            return False, [], [], str(e)
        # limit is always an int from our own code — cast defensively
        safe_limit = max(1, min(int(limit), 10_000))
        query = f"SELECT * FROM {quoted} LIMIT {safe_limit}"
        return DatabaseUtils.execute_safe_query(db_path, query)
    
    @staticmethod
    def cleanup_old_data(db_path: str, table_name: str, date_column: str, days_old: int) -> Tuple[bool, str]:
        """Clean up old data from table"""
        try:
            quoted_table = _quote_identifier(table_name)
            quoted_col = _quote_identifier(date_column)
        except ValueError as e:
            return False, str(e)
        try:
            safe_days = max(0, int(days_old))
            query = (
                f"DELETE FROM {quoted_table} "
                f"WHERE {quoted_col} < date('now', ?)"
            )
            success, _, _, message = DatabaseUtils.execute_safe_query(
                db_path, query, params=(f"-{safe_days} days",)
            )
            return success, message
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def export_table_csv(db_path: str, table_name: str, output_path: str) -> Tuple[bool, str]:
        """Export table to CSV"""
        try:
            import csv
            quoted = _quote_identifier(table_name)
            
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM " + quoted)
                
                with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # Write headers
                    if cursor.description:
                        headers = [desc[0] for desc in cursor.description]
                        writer.writerow(headers)
                    
                    # Write data
                    rows_written = 0
                    for row in cursor:
                        writer.writerow(row)
                        rows_written += 1
                    
                    return True, f"Exported {rows_written} rows to {output_path}"
                    
        except Exception as e:
            return False, f"Failed to export table: {str(e)}"