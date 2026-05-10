# app/core/base_worker.py
import subprocess
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from app.core.logger import logger
from app.core.html_utils import h

class WorkerSignals(QObject):
    """Standard signals for all workers"""
    output = pyqtSignal(str)
    error = pyqtSignal(str)
    finished = pyqtSignal()
    progress = pyqtSignal(int)

class BaseWorker(QRunnable):
    """Base worker class for consistent threading"""
    
    def __init__(self):
        super().__init__()
        self.signals = WorkerSignals()
        self.is_running = True
    
    def stop(self):
        """Stop the worker"""
        self.is_running = False
    
    def run_command(self, cmd, cwd=None):
        """Run subprocess command safely"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                cwd=cwd,
                timeout=300  # 5 minute timeout
            )
            
            if result.stdout:
                self.signals.output.emit(f"<pre style='color: #DCDCDC;'>{h(result.stdout)}</pre>")
            
            if result.stderr:
                self.signals.error.emit(f"<p style='color: #FF4500;'>{h(result.stderr)}</p>")
                
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            self.signals.error.emit("<p style='color: #FF4500;'>[ERROR] Command timed out</p>")
            return False
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            return False

class CommandWorker(BaseWorker):
    """Worker for running shell commands"""
    
    def __init__(self, cmd, description, cwd=None):
        super().__init__()
        self.cmd = cmd
        self.description = description
        self.cwd = cwd
    
    def run(self):
        """Execute the command"""
        try:
            self.signals.output.emit(f"<p style='color: #64C8FF;'>[*] {h(self.description)}</p><br>")
            self.run_command(self.cmd, self.cwd)
        except Exception as e:
            logger.error(f"Worker error: {str(e)}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
        finally:
            self.signals.finished.emit()