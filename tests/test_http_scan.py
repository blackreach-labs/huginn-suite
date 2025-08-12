#!/usr/bin/env python3
# Test HTTP scan functionality

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.tools.http_scanner import HTTPEnumWorker
from PyQt6.QtCore import QCoreApplication

def test_http_scan():
    app = QCoreApplication([])
    
    # Create HTTP worker
    worker = HTTPEnumWorker(
        target="http://httpbin.org",
        scan_type="Fingerprinting"
    )
    
    # Connect signals to print output
    worker.signals.output.connect(lambda msg: print(f"OUTPUT: {msg}"))
    worker.signals.status.connect(lambda msg: print(f"STATUS: {msg}"))
    worker.signals.finished.connect(lambda: print("FINISHED"))
    worker.signals.results.connect(lambda results: print(f"RESULTS: {len(results)} items"))
    
    print("Starting HTTP scan test...")
    worker.run()
    print("HTTP scan test completed")

if __name__ == "__main__":
    test_http_scan()