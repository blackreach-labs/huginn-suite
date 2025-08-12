# app/tools/smb_utils.py
from PyQt6.QtCore import QThreadPool
from .smb_scanner import SMBEnumWorker

def run_smb_enumeration(target, username="", password="", scan_type="basic", output_callback=None, status_callback=None, finished_callback=None, results_callback=None):
    """Run SMB enumeration on target"""
    worker = SMBEnumWorker(target, username, password, scan_type)
    
    # Connect signals
    if output_callback:
        worker.signals.output.connect(output_callback)
    if status_callback:
        worker.signals.status.connect(status_callback)
    if finished_callback:
        worker.signals.finished.connect(finished_callback)
    if results_callback:
        worker.signals.results_ready.connect(results_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker