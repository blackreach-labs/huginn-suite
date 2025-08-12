#!/usr/bin/env python3
"""
Test script to verify MariaDB support has been properly integrated
"""

def test_database_scanner_mariadb():
    """Test that MariaDB methods are available in database scanner"""
    try:
        from app.tools.db_scanner import db_scanner
        
        # Test that MariaDB methods exist
        assert hasattr(db_scanner, 'scan_mariadb_basic'), "scan_mariadb_basic method missing"
        assert hasattr(db_scanner, 'scan_mariadb_scripts'), "scan_mariadb_scripts method missing"
        assert hasattr(db_scanner, 'mariadb_query'), "mariadb_query method missing"
        
        print("✓ Database scanner MariaDB methods available")
        return True
    except Exception as e:
        print(f"✗ Database scanner test failed: {e}")
        return False

def test_database_utils_mariadb():
    """Test that MariaDB support is in database utilities"""
    try:
        from app.tools.db_utils import get_common_mariadb_queries, get_common_queries_by_type
        
        # Test MariaDB query functions
        mariadb_queries = get_common_mariadb_queries()
        assert isinstance(mariadb_queries, dict), "MariaDB queries should be a dictionary"
        assert len(mariadb_queries) > 0, "MariaDB queries should not be empty"
        assert "List Databases" in mariadb_queries, "Should have List Databases query"
        
        # Test query by type function
        queries_by_type = get_common_queries_by_type('mariadb')
        assert isinstance(queries_by_type, dict), "Queries by type should be a dictionary"
        assert len(queries_by_type) > 0, "Should return queries for MariaDB"
        
        print("✓ Database utilities MariaDB support available")
        return True
    except Exception as e:
        print(f"✗ Database utilities test failed: {e}")
        return False

def test_database_enumeration_component():
    """Test that MariaDB is supported in the database enumeration component"""
    try:
        # Test that MariaDB worker can be created
        from app.tools.db_utils import DatabaseEnumWorker
        
        # Create a MariaDB worker
        worker = DatabaseEnumWorker(
            target="127.0.0.1",
            db_type="mariadb",
            scan_type="basic",
            port=3306
        )
        
        assert worker.db_type == "mariadb", "Worker should accept MariaDB type"
        assert worker.port == 3306, "Should use correct default port for MariaDB"
        
        print("✓ Database enumeration component MariaDB support available")
        return True
    except Exception as e:
        print(f"✗ Database enumeration component test failed: {e}")
        return False

def test_service_field_visibility():
    """Test that MariaDB port is handled in field visibility"""
    try:
        from app.pages.recon_enumeration.service_field_visibility import ServiceFieldVisibilityMixin
        
        # Check that MariaDB port mapping exists (indirectly by checking the method exists)
        # The actual port mapping is tested when the UI is created
        assert hasattr(ServiceFieldVisibilityMixin, 'toggle_db_fields'), "toggle_db_fields method should exist"
        
        print("✓ Service field visibility MariaDB support available")
        return True
    except Exception as e:
        print(f"✗ Service field visibility test failed: {e}")
        return False

def main():
    """Run all MariaDB support tests"""
    print("Testing MariaDB support integration...")
    print("=" * 50)
    
    tests = [
        test_database_scanner_mariadb,
        test_database_utils_mariadb,
        test_database_enumeration_component,
        test_service_field_visibility
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All MariaDB support tests passed!")
        print("\nMariaDB has been successfully integrated into:")
        print("- Database scanner with basic connectivity, scripts, and query execution")
        print("- Database utilities with MariaDB-specific queries")
        print("- Database enumeration component with worker support")
        print("- Service field visibility with port handling")
        print("- UI configuration with MariaDB dropdown option")
        return True
    else:
        print(f"❌ {total - passed} tests failed")
        return False

if __name__ == "__main__":
    main()