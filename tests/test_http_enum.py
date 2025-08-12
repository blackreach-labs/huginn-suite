#!/usr/bin/env python3
"""
Quick test for HTTP enumeration functionality
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.tools.http_scanner import HTTPEnumWorker
from PyQt6.QtCore import QCoreApplication

def test_http_enum():
    app = QCoreApplication(sys.argv)
    
    def on_output(text):
        print(f"OUTPUT: {text}")
    
    def on_results(results):
        print(f"RESULTS: {results}")
    
    def on_finished():
        print("FINISHED")
        app.quit()
    
    worker = HTTPEnumWorker(
        target="http://httpbin.org",
        scan_type="Basic Fingerprint"
    )
    
    worker.signals.output.connect(on_output)
    worker.signals.results.connect(on_results)
    worker.signals.finished.connect(on_finished)
    
    print("Starting HTTP enumeration test...")
    worker.run()
    
    return app.exec()

if __name__ == "__main__":
    test_http_enum()