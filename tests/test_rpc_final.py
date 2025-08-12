#!/usr/bin/env python3
"""Test the complete RPC scanner functionality"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.tools.rpc_scanner import RPCWorker
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QObject, pyqtSignal

class TestSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)
    table_data = pyqtSignal(dict)
    graph_data = pyqtSignal(dict)
    progress_start = pyqtSignal(int, str)
    progress_update = pyqtSignal(int, int, str)
    
    def __init__(self):
        super().__init__()
        self.output.connect(self.handle_output)
        self.finished.connect(self.handle_finished)
        self.results.connect(self.handle_results)
        self.progress_start.connect(self.handle_progress_start)
        self.progress_update.connect(self.handle_progress_update)
        
    def handle_output(self, text):
        # Clean HTML formatting
        clean_text = text.replace('<p style="color: #87CEEB;">', '[INFO] ')
        clean_text = clean_text.replace('<p style="color: #00FF41;">', '[SUCCESS] ')
        clean_text = clean_text.replace('<p style="color: #FFD700;">', '[WORKING] ')
        clean_text = clean_text.replace('<p style="color: #FF6B6B;">', '[ERROR] ')
        clean_text = clean_text.replace('<p style="color: #FFAA00;">', '[WARNING] ')
        clean_text = clean_text.replace('<p style="color: #FF6B6B;">', '[VULN] ')
        clean_text = clean_text.replace('<p style="color: #FF0000;">', '[CRITICAL] ')
        clean_text = clean_text.replace('<p style="color: #FFA500;">', '[HIGH] ')
        clean_text = clean_text.replace('<p>', '')
        clean_text = clean_text.replace('</p><br>', '')
        clean_text = clean_text.replace('</p>', '')
        print(clean_text)
    
    def handle_finished(self):
        print("\n[COMPLETE] RPC scan finished")
    
    def handle_results(self, data):
        print(f"\n[RESULTS] Found {len(data.get('rpc_endpoints', []))} RPC endpoints")
        for endpoint in data.get('rpc_endpoints', []):
            print(f"  - {endpoint.get('service', 'Unknown')}: {endpoint.get('uuid', 'N/A')}")
        
        # Show vulnerability results
        vulnerabilities = data.get('rpc_vulnerabilities', [])
        security_issues = data.get('rpc_security_issues', [])
        risk_score = data.get('rpc_risk_score', 0)
        
        if vulnerabilities:
            print(f"\n[VULNERABILITIES] {len(vulnerabilities)} found:")
            for vuln in vulnerabilities:
                name = vuln.get('name', 'Unknown')
                severity = vuln.get('severity', 'Unknown')
                cve = vuln.get('cve', '')
                print(f"  - [{severity}] {name} {cve}")
        
        if security_issues:
            print(f"\n[SECURITY ISSUES] {len(security_issues)} found:")
            for issue in security_issues:
                name = issue.get('name', 'Unknown')
                severity = issue.get('severity', 'Unknown')
                print(f"  - [{severity}] {name}")
        
        if risk_score > 0:
            print(f"\n[RISK SCORE] {risk_score}/100")
        
        # Show enhanced service info
        service_info = data.get('service_info', {})
        if service_info:
            print(f"\n[SERVICES] {len(service_info)} RPC services analyzed")
    
    def handle_progress_start(self, total, desc):
        print(f"[PROGRESS] Starting: {desc} ({total} steps)")
    
    def handle_progress_update(self, current, value, desc):
        print(f"[PROGRESS] Step {current}: {desc}")

def main():
    app = QApplication([])
    
    print("Testing RPC Scanner with Vulnerability Assessment")
    print("=" * 50)
    
    # Test complete assessment
    worker = RPCWorker('192.168.1.106', 'Complete Assessment', 'Anonymous')
    worker.signals = TestSignals()
    
    print("Running RPC vulnerability scan...")
    worker.run()

if __name__ == "__main__":
    main()