# run_tests.py
import unittest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_tests():
    """Run all unit and integration tests"""
    loader = unittest.TestLoader()
    
    # Load unit tests
    unit_suite = loader.discover('tests', pattern='test_*.py')
    
    # Load integration tests
    integration_suite = loader.discover('tests/integration', pattern='test_*.py')
    
    # Combine test suites
    combined_suite = unittest.TestSuite([unit_suite, integration_suite])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(combined_suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)