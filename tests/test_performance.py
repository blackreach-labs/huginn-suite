#!/usr/bin/env python3
"""
Test performance improvements with database connection pooling
"""

import sys
import os
import time
import threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_connection_pool():
    """Test database connection pool performance"""
    print("Testing Database Connection Pool Performance...")
    
    try:
        from app.core.database_pool import get_database_pool
        
        # Create test database
        test_db = "test_performance.db"
        if os.path.exists(test_db):
            os.remove(test_db)
        
        pool = get_database_pool(test_db)
        
        # Initialize test table
        pool.execute_write("CREATE TABLE test (id INTEGER PRIMARY KEY, data TEXT)")
        print("[OK] Connection pool created and initialized")
        
        # Test concurrent operations
        def worker(worker_id, operations):
            for i in range(operations):
                pool.execute_write("INSERT INTO test (data) VALUES (?)", (f"worker_{worker_id}_op_{i}",))
        
        # Performance test with multiple threads
        start_time = time.time()
        threads = []
        
        for i in range(5):  # 5 threads
            thread = threading.Thread(target=worker, args=(i, 20))  # 20 operations each
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        
        # Verify results
        results = pool.execute_query("SELECT COUNT(*) FROM test")
        total_records = results[0][0] if results else 0
        
        print(f"[OK] Inserted {total_records} records in {end_time - start_time:.2f} seconds")
        print(f"[OK] Performance: {total_records / (end_time - start_time):.1f} operations/second")
        
        # Cleanup
        pool.close_all()
        os.remove(test_db)
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Connection pool test failed: {e}")
        return False

def test_centralized_data_performance():
    """Test centralized data system performance"""
    print("\nTesting Centralized Data Performance...")
    
    try:
        from app.core.centralized_scan_data import create_centralized_scan_data
        
        # Create test instance
        test_db = "test_centralized.db"
        if os.path.exists(test_db):
            os.remove(test_db)
        
        data_system = create_centralized_scan_data(test_db)
        print("[OK] Centralized data system created")
        
        # Performance test
        start_time = time.time()
        
        # Start multiple scans
        scan_ids = []
        for i in range(10):
            scan_id = f"test_scan_{i}"
            data_system.start_scan(scan_id, "test_tenant", "test_scan", f"target_{i}", "test_scanner")
            scan_ids.append(scan_id)
        
        # Add results to each scan
        for scan_id in scan_ids:
            for j in range(20):  # 20 results per scan
                data_system.add_scan_result(
                    scan_id, "test_tenant", "test_scan", f"target_{scan_id[-1]}", 
                    "test_scanner", {"result": f"data_{j}", "value": j}
                )
        
        # Complete scans
        for scan_id in scan_ids:
            data_system.complete_scan(scan_id, 20)
        
        end_time = time.time()
        
        # Verify results
        scan_data = data_system.get_scan_data("test_tenant", "test_scan")
        summary = data_system.get_scan_summary("test_tenant", "test_scan")
        
        print(f"[OK] Processed {len(scan_ids)} scans with {len(scan_data)} results in {end_time - start_time:.2f} seconds")
        print(f"[OK] Summary: {summary.get('total_results', 0)} total results, {summary.get('unique_targets', 0)} targets")
        
        # Cleanup
        os.remove(test_db)
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Centralized data test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run performance tests"""
    print("Starting Performance Tests\n")
    
    tests = [
        ("Database Connection Pool", test_connection_pool),
        ("Centralized Data System", test_centralized_data_performance)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"[PASS] {test_name}: PASSED\n")
            else:
                print(f"[FAIL] {test_name}: FAILED\n")
        except Exception as e:
            print(f"[ERROR] {test_name}: ERROR - {e}\n")
    
    print(f"Performance Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All performance optimizations are working correctly!")
        return True
    else:
        print("Some performance tests failed.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)