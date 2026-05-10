# app/core/error_handler.py
import sys
import traceback
import logging
from pathlib import Path
from PyQt6.QtWidgets import QMessageBox, QApplication
from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from app.core.logger import logger


class GlobalErrorHandler(QObject):
    """Centralized error handling for the application."""

    error_occurred = pyqtSignal(str, str)  # error_type, error_message

    def __init__(self, log_file="error.log"):
        super().__init__()
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(exist_ok=True)
        self._setup_file_logging()
        self.error_count = 0
        self.max_errors_per_session = 50

    def _setup_file_logging(self):
        """Add a dedicated file handler for unhandled exceptions."""
        handler = logging.FileHandler(self.log_file, encoding="utf-8")
        handler.setLevel(logging.ERROR)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        # Attach to the root logger so it catches everything
        logging.getLogger().addHandler(handler)

    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """sys.excepthook — called for every unhandled exception."""
        # Let KeyboardInterrupt propagate normally
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return

        self.error_count += 1
        if self.error_count > self.max_errors_per_session:
            return  # Suppress dialog storm

        # Log the full traceback
        error_msg = "".join(
            traceback.format_exception(exc_type, exc_value, exc_traceback)
        )
        logger.error(f"Unhandled exception:\n{error_msg}")

        # Emit signal for any connected listeners
        self.error_occurred.emit(exc_type.__name__, str(exc_value))

        # Show the dialog deferred via QTimer so we are outside the
        # exception-handling call stack when exec() runs.  Calling
        # QMessageBox.exec() directly inside sys.excepthook causes a Qt
        # re-entrancy crash (SystemError: returned a result with an
        # exception set).
        msg = str(exc_value)
        log_path = str(self.log_file)
        QTimer.singleShot(
            0,
            lambda: self._show_error_dialog(msg, error_msg, log_path),
        )

    def _show_error_dialog(self, short_msg: str, detail: str, log_path: str):
        """Show a user-friendly error dialog (must be called from the Qt event loop)."""
        app = QApplication.instance()
        if not app:
            return
        try:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Icon.Critical)
            msg_box.setWindowTitle("Unexpected Error")
            msg_box.setText("An unexpected error has occurred.")
            msg_box.setInformativeText(
                f"Error details have been logged to:\n{log_path}"
            )
            msg_box.setDetailedText(detail)
            msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
            msg_box.exec()
        except Exception as e:
            # Last-resort: if the dialog itself fails, just log it
            logger.error(f"Failed to show error dialog: {e}")

    # Keep the old name as an alias for any external callers
    def show_error_dialog(self, error_message: str):
        self._show_error_dialog(error_message, error_message, str(self.log_file))


# Global instance
error_handler = GlobalErrorHandler()


def setup_global_error_handling():
    """Install the global exception hook."""
    sys.excepthook = error_handler.handle_exception
