# app/tools/smtp_utils.py
from PyQt6.QtCore import QThreadPool
from .smtp_scanner import SMTPEnumWorker

def run_smtp_enumeration(target, port=25, wordlist_path=None, domain="", helo_name="test.local", output_callback=None, status_callback=None, finished_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None):
    """Run SMTP enumeration on target"""
    worker = SMTPEnumWorker(target, port, wordlist_path, domain, helo_name)
    
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