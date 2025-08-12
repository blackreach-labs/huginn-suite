# app/tools/snmp_utils.py
from PyQt6.QtCore import QThreadPool
from .snmp_scanner import SNMPEnumWorker

def run_snmp_enumeration(target, communities=None, scan_type="basic", version="2c", output_callback=None, status_callback=None, finished_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None):
    """Run SNMP enumeration on target"""
    worker = SNMPEnumWorker(target, communities, scan_type, version)
    
    # Connect signals
    if output_callback:
        worker.signals.output.connect(output_callback)
    if status_callback:
        worker.signals.status.connect(status_callback)
    if finished_callback:
        worker.signals.finished.connect(finished_callback)
    if results_callback:
        worker.signals.results_ready.connect(results_callback)
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker

def get_default_communities():
    """Get default SNMP community strings"""
    return [
        "public", "private", "community", "manager", "admin", "administrator",
        "root", "guest", "read", "write", "test", "cisco", "default", "snmp"
    ]