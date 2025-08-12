# test_mssql_client.py
"""Test script for the custom MSSQL client"""

from app.core.mssql_client import MSSQLClient, MSSQLConnection, MSSQLCredential

def test_mssql_connection():
    """Test MSSQL connection"""
    
    # Example connection (replace with actual values)
    credential = MSSQLCredential(
        username="sa",
        password="YourPassword123!",
        auth_type="SQL Server Auth"
    )
    
    connection = MSSQLConnection(
        host="localhost",
        port=1433,
        database="master",
        credential=credential,
        use_tls=False  # Set to True for production
    )
    
    client = MSSQLClient(connection)
    
    print("Testing MSSQL connection...")
    success, message = client.connect()
    
    if success:
        print(f"✅ Connection successful: {message}")
        
        # Test basic query
        print("\nTesting basic query...")
        success, results, columns, msg = client.execute_query("SELECT @@VERSION")
        
        if success:
            print(f"✅ Query successful: {msg}")
            print(f"Columns: {columns}")
            print(f"Results: {results}")
        else:
            print(f"❌ Query failed: {msg}")
        
        # Test table listing
        print("\nTesting table listing...")
        tables = client.get_tables()
        print(f"Tables found: {len(tables)}")
        for table in tables[:5]:  # Show first 5
            print(f"  - {table}")
        
        client.close()
        print("\n✅ Connection closed")
        
    else:
        print(f"❌ Connection failed: {message}")

if __name__ == "__main__":
    test_mssql_connection()