from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QProgressBar, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal
from ..core.update_manager import update_manager

class UpdateWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(bool)
    
    def __init__(self, manifest):
        super().__init__()
        self.manifest = manifest
        
    def run(self):
        self.progress.emit("Downloading update...")
        success = update_manager.install_update(self.manifest)
        self.finished.emit(success)

class UpdateDialog(QDialog):
    def __init__(self, manifest, parent=None):
        super().__init__(parent)
        self.manifest = manifest
        self.setWindowTitle("Update Available")
        self.setFixedSize(400, 300)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Update info
        info_text = f"Version {self.manifest['version']} is available.\n"
        info_text += f"Current version: {update_manager.updater.current_version}"
        
        info_label = QLabel(info_text)
        layout.addWidget(info_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Status text
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(100)
        self.status_text.setVisible(False)
        layout.addWidget(self.status_text)
        
        # Buttons
        self.install_btn = QPushButton("Install Update")
        self.install_btn.clicked.connect(self.install_update)
        layout.addWidget(self.install_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        layout.addWidget(cancel_btn)
        
        self.setLayout(layout)
        
    def install_update(self):
        self.install_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.status_text.setVisible(True)
        
        self.worker = UpdateWorker(self.manifest)
        self.worker.progress.connect(self.update_status)
        self.worker.finished.connect(self.update_finished)
        self.worker.start()
        
    def update_status(self, message):
        self.status_text.append(message)
        
    def update_finished(self, success):
        self.progress_bar.setVisible(False)
        if success:
            self.status_text.append("Update completed! Application will restart.")
            self.accept()
        else:
            self.status_text.append("Update failed!")
            self.install_btn.setEnabled(True)