# app/tools/rpc_utils.py
from PyQt6.QtCore import QThreadPool
from .rpc_scanner import RPCEnumWorker

def run_rpc_enumeration(target, username="", password="", ntlm_hash="", output_callback=None, status_callback=None, finished_callback=None, results_callback=None):
    """Run RPC enumeration on target"""
    worker = RPCEnumWorker(target, username, password, ntlm_hash)
    
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