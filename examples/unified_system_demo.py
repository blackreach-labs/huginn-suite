# examples/unified_system_demo.py
"""
Demonstration of the unified HTTP request handling system.
This shows how all components work together seamlessly.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer
from app.core.unified_request_handler import UnifiedRequestHandler
from app.core.http_client import HttpRequest

def demo_unified_system():
    """Demonstrate the unified system capabilities"""
    
    # Create the unified handler
    handler = UnifiedRequestHandler()
    
    # Connect to signals to see what happens
    handler.request_sent.connect(lambda req, resp: print(f"✓ Request sent: {req.method} {req.url} -> {resp.status_code}"))
    handler.finding_detected.connect(lambda finding: print(f"🔍 Security finding: {finding['type']} - {finding['title']}"))
    handler.history_updated.connect(lambda history: print(f"📝 History updated: {len(history)} entries"))
    
    # 1. Repeater functionality - Send a single request
    print("\\n=== REPEATER DEMO ===")
    request = HttpRequest(
        method="GET",
        url="https://httpbin.org/get",
        headers={"User-Agent": "Huggin-Demo/1.0"}
    )
    
    response = handler.send_request(request)
    if response:
        print(f"Response: {response.status_code} ({response.elapsed_time:.3f}s)")
    
    # 2. Intruder functionality - Send multiple requests
    print("\\n=== INTRUDER DEMO ===")
    responses = handler.send_multiple(request, 3)
    print(f"Sent {len(responses)} requests")
    
    # 3. Scanner functionality - Test for vulnerabilities
    print("\\n=== SCANNER DEMO ===")
    test_request = HttpRequest(
        method="GET",
        url="https://httpbin.org/get",
        params={"test": "value"}
    )
    
    # This would normally find vulnerabilities in a real target
    handler.scan_request(test_request)
    
    # 4. History functionality
    print("\\n=== HISTORY DEMO ===")
    history = handler.get_history()
    print(f"History contains {len(history)} entries:")
    for i, entry in enumerate(history[-3:]):  # Show last 3
        print(f"  {i+1}. {entry['method']} {entry['url']} -> {entry['status_code']}")
    
    # 5. Findings
    print("\\n=== FINDINGS DEMO ===")
    findings = handler.get_findings()
    print(f"Total findings: {len(findings)}")
    for finding in findings[:3]:  # Show first 3
        print(f"  - {finding['type']}: {finding['title']}")
    
    print("\\n=== DEMO COMPLETE ===")
    print("The unified system successfully:")
    print("✓ Sent HTTP requests using Python requests (not subprocess)")
    print("✓ Maintained request/response history")
    print("✓ Performed passive security scanning")
    print("✓ Provided a single interface for all HTTP operations")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Run demo after a short delay to let Qt initialize
    QTimer.singleShot(100, demo_unified_system)
    QTimer.singleShot(5000, app.quit)  # Exit after 5 seconds
    
    sys.exit(app.exec())