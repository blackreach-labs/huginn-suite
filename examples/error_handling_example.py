# examples/error_handling_example.py
"""
Example usage of centralized error handling

This example demonstrates how to use the error handling system.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.error_handler import setup_global_error_handling
from app.core.error_context import handle_errors

def example_with_context_manager():
    """Example using the error context manager"""
    
    # This will catch and handle the error gracefully
    with handle_errors("File Operation"):
        # This will raise an exception
        with open("nonexistent_file.txt", "r") as f:
            content = f.read()

def example_unhandled_exception():
    """Example that will be caught by global handler"""
    # This will be caught by the global exception handler
    raise ValueError("This is an unhandled exception for testing")

def main():
    """Run error handling examples"""
    # Setup global error handling
    setup_global_error_handling()
    
    print("Testing context manager error handling...")
    try:
        example_with_context_manager()
    except Exception:
        print("Context manager handled the error")
    
    print("\nTesting global error handler...")
    # This will trigger the global handler
    example_unhandled_exception()

if __name__ == "__main__":
    main()