"""Remote database connection manager for various database types"""
import sqlite3
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class DatabaseConnection:
    """Database connection configuration"""
    name: str
    db_type: str
    host: str
    port: int
    database: str
    username: str
    password: str
    ssl_enabled: bool = False
    connection_string: str = ""

class DatabaseConnector(ABC):
    """Abstract base class for database connectors"""
    
    @abstractmethod
    def connect(self, config: DatabaseConnection) -> Any:
        """Establish database connection"""
        pass
    
    @abstractmethod
    def execute_query(self, connection: Any, query: str) -> Tuple[bool, List[Tuple], List[str], str]:
        """Execute query and return results"""
        pass
    
    @abstractmethod
    def get_tables(self, connection: Any) -> List[str]:
        """Get list of tables"""
        pass
    
    @abstractmethod
    def get_schema(self, connection: Any, table_name: str) -> List[Dict]:
        """Get table schema"""
        pass
    
    @abstractmethod
    def close(self, connection: Any):
        """Close connection"""
        pass

class MySQLConnector(DatabaseConnector):
    """MySQL database connector"""
    
    def connect(self, config: DatabaseConnection) -> Any:
        try:
            import mysql.connector
            return mysql.connector.connect(
                host=config.host,
                port=config.port,
                database=config.database,
                user=config.username,
                password=config.password,
                ssl_disabled=not config.ssl_enabled
            )
        except ImportError:
            raise Exception("mysql-connector-python not installed. Install with: pip install mysql-connector-python")
    
    def execute_query(self, connection: Any, query: str) -> Tuple[bool, List[Tuple], List[str], str]:
        try:
            cursor = connection.cursor()
            cursor.execute(query)
            
            if query.strip().upper().startswith(('SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN')):
                results = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                return True, results, columns, f"{len(results)} rows returned"
            else:
                connection.commit()
                return True, [], [], f"Query executed successfully. {cursor.rowcount} rows affected"
        except Exception as e:
            return False, [], [], str(e)
    
    def get_tables(self, connection: Any) -> List[str]:
        success, results, _, _ = self.execute_query(connection, "SHOW TABLES")
        return [row[0] for row in results] if success else []
    
    def get_schema(self, connection: Any, table_name: str) -> List[Dict]:
        success, results, columns, _ = self.execute_query(connection, f"DESCRIBE {table_name}")
        if success:
            return [dict(zip(columns, row)) for row in results]
        return []
    
    def close(self, connection: Any):
        if connection:
            connection.close()

class PostgreSQLConnector(DatabaseConnector):
    """PostgreSQL database connector"""
    
    def connect(self, config: DatabaseConnection) -> Any:
        try:
            import psycopg2
            return psycopg2.connect(
                host=config.host,
                port=config.port,
                database=config.database,
                user=config.username,
                password=config.password,
                sslmode='require' if config.ssl_enabled else 'disable'
            )
        except ImportError:
            raise Exception("psycopg2 not installed. Install with: pip install psycopg2-binary")
    
    def execute_query(self, connection: Any, query: str) -> Tuple[bool, List[Tuple], List[str], str]:
        try:
            cursor = connection.cursor()
            cursor.execute(query)
            
            if query.strip().upper().startswith(('SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN')):
                results = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                return True, results, columns, f"{len(results)} rows returned"
            else:
                connection.commit()
                return True, [], [], f"Query executed successfully. {cursor.rowcount} rows affected"
        except Exception as e:
            return False, [], [], str(e)
    
    def get_tables(self, connection: Any) -> List[str]:
        success, results, _, _ = self.execute_query(connection, 
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        return [row[0] for row in results] if success else []
    
    def get_schema(self, connection: Any, table_name: str) -> List[Dict]:
        success, results, columns, _ = self.execute_query(connection, f"""
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns 
            WHERE table_name = '{table_name}'
        """)
        if success:
            return [dict(zip(columns, row)) for row in results]
        return []
    
    def close(self, connection: Any):
        if connection:
            connection.close()

class MSSQLConnector(DatabaseConnector):
    """Microsoft SQL Server connector using custom TDS client"""
    
    def connect(self, config: DatabaseConnection) -> Any:
        from app.core.mssql_client import MSSQLClient, MSSQLConnection, MSSQLCredential
        from app.core.credential_manager import get_mssql_credentials_for_auth_type
        
        # Get credentials from credential manager
        credentials = get_mssql_credentials_for_auth_type('SQL Server Auth')
        if not credentials:
            credentials = get_mssql_credentials_for_auth_type('Windows Auth')
        
        if not credentials:
            # Fallback to config credentials
            credential = MSSQLCredential(
                username=config.username,
                password=config.password,
                auth_type="SQL Server Auth"
            )
        else:
            # Use first available credential
            cred = credentials[0]
            credential = MSSQLCredential(
                username=cred.username,
                password=cred.password,
                domain=cred.domain,
                auth_type=cred.credential_type
            )
        
        mssql_conn = MSSQLConnection(
            host=config.host,
            port=config.port,
            database=config.database,
            credential=credential,
            use_tls=config.ssl_enabled
        )
        
        client = MSSQLClient(mssql_conn)
        success, message = client.connect()
        
        if not success:
            raise Exception(f"MSSQL connection failed: {message}")
        
        return client
    
    def execute_query(self, connection: Any, query: str) -> Tuple[bool, List[Tuple], List[str], str]:
        return connection.execute_query(query)
    
    def get_tables(self, connection: Any) -> List[str]:
        return connection.get_tables()
    
    def get_schema(self, connection: Any, table_name: str) -> List[Dict]:
        return connection.get_schema(table_name)
    
    def close(self, connection: Any):
        if connection:
            connection.close()

class OracleConnector(DatabaseConnector):
    """Oracle database connector"""
    
    def connect(self, config: DatabaseConnection) -> Any:
        try:
            import oracledb
            # Use explicit host/port/service_name params — compatible with
            # oracledb thin mode (no Oracle Client libraries required).
            return oracledb.connect(
                user=config.username,
                password=config.password,
                host=config.host,
                port=config.port,
                service_name=config.database
            )
        except ImportError:
            raise Exception("oracledb not installed. Install with: pip install oracledb")
    
    def execute_query(self, connection: Any, query: str) -> Tuple[bool, List[Tuple], List[str], str]:
        try:
            cursor = connection.cursor()
            cursor.execute(query)
            
            if query.strip().upper().startswith(('SELECT', 'SHOW', 'DESCRIBE', 'EXPLAIN')):
                results = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                return True, results, columns, f"{len(results)} rows returned"
            else:
                connection.commit()
                return True, [], [], f"Query executed successfully. {cursor.rowcount} rows affected"
        except Exception as e:
            return False, [], [], str(e)
    
    def get_tables(self, connection: Any) -> List[str]:
        success, results, _, _ = self.execute_query(connection, 
            "SELECT table_name FROM user_tables")
        return [row[0] for row in results] if success else []
    
    def get_schema(self, connection: Any, table_name: str) -> List[Dict]:
        success, results, columns, _ = self.execute_query(connection, f"""
            SELECT column_name, data_type, nullable, data_default
            FROM user_tab_columns 
            WHERE table_name = '{table_name.upper()}'
        """)
        if success:
            return [dict(zip(columns, row)) for row in results]
        return []
    
    def close(self, connection: Any):
        if connection:
            connection.close()

class RemoteDatabaseManager:
    """Manager for remote database connections"""
    
    def __init__(self):
        self.connectors = {
            'mysql': MySQLConnector(),
            'postgresql': PostgreSQLConnector(),
            'mssql': MSSQLConnector(),
            'oracle': OracleConnector()
        }
        self.active_connections = {}
    
    def get_supported_types(self) -> List[str]:
        """Get list of supported database types"""
        return list(self.connectors.keys())
    
    def test_connection(self, config: DatabaseConnection) -> Tuple[bool, str]:
        """Test database connection"""
        try:
            connector = self.connectors.get(config.db_type.lower())
            if not connector:
                return False, f"Unsupported database type: {config.db_type}"
            
            connection = connector.connect(config)
            connector.close(connection)
            return True, "Connection successful"
        except Exception as e:
            return False, str(e)
    
    def connect(self, config: DatabaseConnection) -> Tuple[bool, str]:
        """Establish connection to remote database"""
        try:
            connector = self.connectors.get(config.db_type.lower())
            if not connector:
                return False, f"Unsupported database type: {config.db_type}"
            
            connection = connector.connect(config)
            self.active_connections[config.name] = {
                'connection': connection,
                'connector': connector,
                'config': config
            }
            return True, f"Connected to {config.name}"
        except Exception as e:
            return False, str(e)
    
    def execute_query(self, connection_name: str, query: str) -> Tuple[bool, List[Tuple], List[str], str]:
        """Execute query on remote database"""
        if connection_name not in self.active_connections:
            return False, [], [], "Connection not found"
        
        conn_info = self.active_connections[connection_name]
        return conn_info['connector'].execute_query(conn_info['connection'], query)
    
    def get_tables(self, connection_name: str) -> List[str]:
        """Get tables from remote database"""
        if connection_name not in self.active_connections:
            return []
        
        conn_info = self.active_connections[connection_name]
        return conn_info['connector'].get_tables(conn_info['connection'])
    
    def get_schema(self, connection_name: str, table_name: str) -> List[Dict]:
        """Get table schema from remote database"""
        if connection_name not in self.active_connections:
            return []
        
        conn_info = self.active_connections[connection_name]
        return conn_info['connector'].get_schema(conn_info['connection'], table_name)
    
    def disconnect(self, connection_name: str) -> bool:
        """Disconnect from remote database"""
        if connection_name in self.active_connections:
            conn_info = self.active_connections[connection_name]
            conn_info['connector'].close(conn_info['connection'])
            del self.active_connections[connection_name]
            return True
        return False
    
    def get_active_connections(self) -> List[str]:
        """Get list of active connection names"""
        return list(self.active_connections.keys())
    
    def disconnect_all(self):
        """Disconnect all active connections"""
        for conn_name in list(self.active_connections.keys()):
            self.disconnect(conn_name)

# Global instance
remote_db_manager = RemoteDatabaseManager()