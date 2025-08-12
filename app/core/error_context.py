# app/core/error_context.py
import logging
from contextlib import contextmanager
from PyQt6.QtWidgets import QMessageBox, QApplication

@contextmanager
def handle_errors(operation_name="Operation", show_dialog=True):
    """Context manager for handling errors in specific operations"""
    try:
        yield
    except Exception as e:
        # Log the error
        logging.error(f"Error in {operation_name}: {str(e)}", exc_info=True)
        
        # Show dialog if requested
        if show_dialog:
            app = QApplication.instance()
            if app:
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Icon.Warning)
                msg_box.setWindowTitle(f"{operation_name} Error")
                msg_box.setText(f"An error occurred during {operation_name.lower()}.")
                msg_box.setInformativeText(str(e))
                msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
                msg_box.exec()
        
        # Re-raise for caller to handle if needed
        raise