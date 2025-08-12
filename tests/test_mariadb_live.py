#!/usr/bin/env python3
"""
Live test script to verify MariaDB support against 192.168.1.111
"""

def test_mariadb_basic_scan():
    """Test basic MariaDB connectivity"""
    try:
        from app.tools.db_scanner import db_scanner
        
        print("Testing MariaDB basic connectivity...")
        result = db_scanner.scan_mariadb_basic("192.168.1.111", 3306)
        
        print(f"Target: {result['target']}")
        print(f"Port: {result['port']}")
        print(f"Service: {result['service']}")
        print(f"Accessible: {result['accessible']}")
        
        if result.get('version'):
            print(f"Version: {result['version']}")
        
        if result.get('error'):
            print(f"Error: {result['error']}")
        
        return result['accessible']
        
    except Exception as e:
        print(f"✗ MariaDB basic scan failed: {e}")
        return False

def test_mariadb_info():
    """Test MariaDB info gathering"""
    try:
        from app.tools.db_scanner import db_scanner
        
        print("Testing MariaDB info gathering with credentials...")
        result = db_scanner.scan_mariadb_info("192.168.1.111", 3306, "admin", "password")
        
        print(f"Target: {result['target']}")
        print(f"Port: {result['port']}")
        print(f"Info items: {len(result.get('info', {}))}")
        
        if result.get('info'):
            for info_name, info_value in result['info'].items():
                print(f"  - {info_name}: {info_value}")
        
        if result.get('error'):
            print(f"Error: {result['error']}")
        
        return len(result.get('info', {})) > 0
        
    except Exception as e:
        print(f"✗ MariaDB info test failed: {e}")
        return False

def test_mariadb_query():
    """Test MariaDB custom query execution"""
    try:
        from app.tools.db_scanner import db_scanner
        
        print("Testing MariaDB custom query...")
        
        # Test basic version query
        result = db_scanner.mariadb_query("192.168.1.111", 3306, "admin", "password", "SELECT VERSION()")
        
        print(f"Query: SELECT VERSION()")
        print(f"Target: {result['target']}")
        print(f"Port: {result['port']}")
        
        if result.get('result'):
            print(f"Query result: {result['result']}")
        
        if result.get('error'):
            print(f"Error: {result['error']}")
        
        return result.get('result') is not None
        
    except Exception as e:
        print(f"✗ MariaDB query test failed: {e}")
        return False

def test_mariadb_worker():
    """Test MariaDB database worker"""
    try:
        from app.tools.db_utils import DatabaseEnumWorker
        import time
        
        print("Testing MariaDB database worker...")
        
        # Create output callback to capture results
        output_lines = []
        def output_callback(text):
            output_lines.append(text)
            print(f"Worker output: {text.strip()}")
        
        results = {}
        def results_callback(result):
            results.update(result)
            print(f"Worker results: {result}")
        
        # Create MariaDB worker
        worker = DatabaseEnumWorker(
            target="192.168.1.111",
            db_type="mariadb",
            scan_type="basic",
            port=3306,
            username="admin",
            password="password",
            output_callback=output_callback,
            results_callback=results_callback
        )
        
        print(f"Worker created - DB Type: {worker.db_type}, Port: {worker.port}")
        
        # Run worker
        worker.run()
        
        # Wait a moment for completion
        time.sleep(2)
        
        print(f"Output lines captured: {len(output_lines)}")
        print(f"Results captured: {bool(results)}")
        
        return len(output_lines) > 0 or bool(results)
        
    except Exception as e:
        print(f"✗ MariaDB worker test failed: {e}")
        return False

def test_mariadb_queries():
    """Test MariaDB-specific queries"""
    try:
        from app.tools.db_utils import get_common_mariadb_queries, get_common_queries_by_type
        
        print("Testing MariaDB query collections...")
        
        # Test MariaDB-specific queries
        mariadb_queries = get_common_mariadb_queries()
        print(f"MariaDB queries available: {len(mariadb_queries)}")
        
        for query_name, query_sql in mariadb_queries.items():
            print(f"  - {query_name}: {query_sql}")
        
        # Test query by type function
        queries_by_type = get_common_queries_by_type('mariadb')
        print(f"Queries by type (MariaDB): {len(queries_by_type)}")
        
        return len(mariadb_queries) > 0 and len(queries_by_type) > 0
        
    except Exception as e:
        print(f"✗ MariaDB queries test failed: {e}")
        return False

def main():
    """Run all MariaDB live tests against 192.168.1.111"""
    print("Testing MariaDB support against 192.168.1.111 (admin/password)")
    print("=" * 60)
    
    tests = [
        ("MariaDB Basic Scan", test_mariadb_basic_scan),
        ("MariaDB Info", test_mariadb_info),
        ("MariaDB Query", test_mariadb_query),
        ("MariaDB Worker", test_mariadb_worker),
        ("MariaDB Queries", test_mariadb_queries)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n[*] Running {test_name}...")
        print("-" * 40)
        
        try:
            if test_func():
                print(f"[PASS] {test_name} PASSED")
                passed += 1
            else:
                print(f"[FAIL] {test_name} FAILED")
        except Exception as e:
            print(f"[FAIL] {test_name} FAILED with exception: {e}")
        
        print()
    
    print("=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("[SUCCESS] All MariaDB live tests passed!")
        print("\nMariaDB support is working correctly with:")
        print("- Basic connectivity testing")
        print("- Nmap script execution")
        print("- Custom query execution")
        print("- Database worker integration")
        print("- MariaDB-specific query collections")
    elif passed > 0:
        print(f"[WARNING] Partial success: {passed}/{total} tests passed")
        print("Some MariaDB functionality is working, but there may be issues with:")
        failed_tests = [name for name, _ in tests[passed:]]
        for failed_test in failed_tests:
            print(f"  - {failed_test}")
    else:
        print("[ERROR] All MariaDB tests failed")
        print("There may be connectivity issues or missing dependencies")
    
    return passed == total

if __name__ == "__main__":
    main()