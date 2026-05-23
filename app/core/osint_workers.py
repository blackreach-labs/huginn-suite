"""
Background worker threads for OSINT reconnaissance tools.
"""

from PyQt6.QtCore import QThread, pyqtSignal


class OSINTWorker(QThread):
    """Generic OSINT worker that runs a function in a background thread."""
    output_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal()

    def __init__(self, func, domain, **kwargs):
        super().__init__()
        self.func = func
        self.domain = domain
        self.kwargs = kwargs

    def run(self):
        try:
            def progress_cb(msg):
                self.output_signal.emit(msg)

            result = self.func(self.domain, progress_callback=progress_cb, **self.kwargs)
            self.result_signal.emit(result)
        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
            self.result_signal.emit({"error": str(e)})
        finally:
            self.finished_signal.emit()
