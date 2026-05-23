# app/pages/script_editor_page.py
"""Script Editor page for writing and saving scripts/wordlists."""
import os
from PyQt6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QLineEdit, QPushButton, QFileDialog, QMessageBox,
    QPlainTextEdit, QFrame, QSizePolicy, QWidget,
    QGridLayout, QSpacerItem
)
from PyQt6.QtGui import QFont, QKeySequence, QShortcut, QTextCursor
from PyQt6.QtCore import Qt, QTimer

from app.pages.components.base_page import BasePage
from app.core.logger import logger


class ScriptEditorPage(BasePage):
    """A text editor page for writing/pasting scripts and wordlists,
    with the ability to save them into the resources subfolders."""

    # Save target definitions: display name -> relative folder path
    SAVE_TARGETS = {
        "Exploits": os.path.join("scripts", "exploits"),
        "Scripts (Windows)": os.path.join("scripts", "windows"),
        "Scripts (Linux)": os.path.join("scripts", "linux"),
        "Wordlists": os.path.join("resources", "wordlists"),
    }

    def __init__(self, parent=None):
        self._current_file_path = None  # Track the file currently open for overwrite
        super().__init__(parent)

    def setup_ui(self):
        """Build the Script Editor UI."""
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(15, 15, 15, 15)
        self.main_layout.setSpacing(0)

        self._create_header_panel()
        self._create_toolbar_panel()
        self._create_editor_panel()
        self._create_save_panel()
        self._create_status_strip()
        self.setup_shortcuts()
        self.apply_theme()

        # Update stats on text change
        self.editor.textChanged.connect(self._update_stats)
        self.editor.cursorPositionChanged.connect(self._update_cursor_info)

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _create_header_panel(self):
        """Create a visually rich header panel."""
        header_frame = QFrame()
        header_frame.setObjectName("headerFrame")
        header_frame.setFixedHeight(60)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(16, 8, 16, 8)

        # Icon + Title
        icon_label = QLabel("📝")
        icon_label.setStyleSheet("font-size: 24pt; border: none; background: transparent;")
        header_layout.addWidget(icon_label)

        title_label = QLabel("Script Editor")
        title_label.setObjectName("pageTitle")
        title_label.setStyleSheet(
            "font-size: 18pt; font-weight: bold; color: #64C8FF; "
            "border: none; background: transparent;"
        )
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Subtitle / hint
        hint_label = QLabel("Write, paste, and save scripts or wordlists")
        hint_label.setStyleSheet(
            "font-size: 10pt; color: rgba(200, 200, 200, 150); "
            "border: none; background: transparent;"
        )
        header_layout.addWidget(hint_label)

        self.main_layout.addWidget(header_frame)

    def _create_toolbar_panel(self):
        """Create a toolbar panel with action buttons."""
        toolbar_frame = QFrame()
        toolbar_frame.setObjectName("toolbarFrame")
        toolbar_frame.setFixedHeight(50)
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(12, 6, 12, 6)
        toolbar_layout.setSpacing(8)

        self.btn_new = QPushButton("  New")
        self.btn_new.setObjectName("toolbarBtn")
        self.btn_new.setToolTip("Clear the editor (Ctrl+N)")
        self.btn_new.clicked.connect(self._on_new)

        self.btn_open = QPushButton("  Open")
        self.btn_open.setObjectName("toolbarBtn")
        self.btn_open.setToolTip("Open a file (Ctrl+O)")
        self.btn_open.clicked.connect(self._on_open)

        self.btn_save_quick = QPushButton("  Save")
        self.btn_save_quick.setObjectName("toolbarBtnAccent")
        self.btn_save_quick.setToolTip("Overwrite the currently open file (Ctrl+S)")
        self.btn_save_quick.clicked.connect(self._on_save_overwrite)

        toolbar_layout.addWidget(self.btn_new)
        toolbar_layout.addWidget(self.btn_open)
        toolbar_layout.addWidget(self.btn_save_quick)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setStyleSheet("color: rgba(100, 200, 255, 60);")
        sep.setFixedWidth(2)
        toolbar_layout.addWidget(sep)

        # Word wrap toggle
        self.btn_wrap = QPushButton("Wrap: On")
        self.btn_wrap.setObjectName("toolbarBtn")
        self.btn_wrap.setCheckable(True)
        self.btn_wrap.setChecked(True)
        self.btn_wrap.clicked.connect(self._toggle_word_wrap)
        toolbar_layout.addWidget(self.btn_wrap)

        toolbar_layout.addStretch()

        self.main_layout.addWidget(toolbar_frame)

    def _create_editor_panel(self):
        """Create the main editor area with a surrounding frame."""
        editor_frame = QFrame()
        editor_frame.setObjectName("editorFrame")
        editor_layout = QVBoxLayout(editor_frame)
        editor_layout.setContentsMargins(2, 2, 2, 2)
        editor_layout.setSpacing(0)

        self.editor = QPlainTextEdit()
        self.editor.setObjectName("codeEditor")
        self.editor.setPlaceholderText(
            "Write or paste your script / wordlist content here...\n\n"
            "  Shortcuts:\n"
            "    Ctrl+S  —  Save\n"
            "    Ctrl+N  —  New\n"
            "    Ctrl+O  —  Open file"
        )
        self.editor.setFont(QFont("Consolas", 11))
        self.editor.setTabStopDistance(32.0)
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.editor.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )

        editor_layout.addWidget(self.editor)
        self.main_layout.addWidget(editor_frame, 1)  # stretch factor 1

    def _create_save_panel(self):
        """Create the save panel with target selector, filename, and save button."""
        save_frame = QFrame()
        save_frame.setObjectName("saveFrame")
        save_frame.setFixedHeight(56)
        save_layout = QHBoxLayout(save_frame)
        save_layout.setContentsMargins(12, 8, 12, 8)
        save_layout.setSpacing(12)

        # Save target combo
        lbl_target = QLabel("Save to:")
        lbl_target.setObjectName("saveLabel")
        self.combo_target = QComboBox()
        self.combo_target.setObjectName("saveCombo")
        self.combo_target.addItems(self.SAVE_TARGETS.keys())
        self.combo_target.setMinimumWidth(170)

        # Filename input
        lbl_filename = QLabel("Filename:")
        lbl_filename.setObjectName("saveLabel")
        self.txt_filename = QLineEdit()
        self.txt_filename.setObjectName("filenameInput")
        self.txt_filename.setPlaceholderText("e.g. my_script.py")
        self.txt_filename.setMinimumWidth(220)

        # Save button (prominent)
        self.btn_save = QPushButton("  Save File")
        self.btn_save.setObjectName("saveBtn")
        self.btn_save.setToolTip("Save the editor content to the selected folder")
        self.btn_save.clicked.connect(self._on_save)

        save_layout.addWidget(lbl_target)
        save_layout.addWidget(self.combo_target)
        save_layout.addSpacing(8)
        save_layout.addWidget(lbl_filename)
        save_layout.addWidget(self.txt_filename)
        save_layout.addStretch()
        save_layout.addWidget(self.btn_save)

        self.main_layout.addWidget(save_frame)

    def _create_status_strip(self):
        """Create a bottom status strip showing line/col and character count."""
        status_frame = QFrame()
        status_frame.setObjectName("statusStrip")
        status_frame.setFixedHeight(26)
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(12, 2, 12, 2)
        status_layout.setSpacing(20)

        self.lbl_cursor = QLabel("Ln 1, Col 1")
        self.lbl_cursor.setObjectName("statusLabel")

        self.lbl_chars = QLabel("0 characters")
        self.lbl_chars.setObjectName("statusLabel")

        self.lbl_lines = QLabel("0 lines")
        self.lbl_lines.setObjectName("statusLabel")

        status_layout.addWidget(self.lbl_cursor)
        status_layout.addWidget(self.lbl_chars)
        status_layout.addWidget(self.lbl_lines)
        status_layout.addStretch()

        self.main_layout.addWidget(status_frame)

    # ------------------------------------------------------------------
    # Shortcuts
    # ------------------------------------------------------------------

    def setup_shortcuts(self):
        """Register keyboard shortcuts."""
        save_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        save_shortcut.activated.connect(self._on_save_overwrite)

        new_shortcut = QShortcut(QKeySequence("Ctrl+N"), self)
        new_shortcut.activated.connect(self._on_new)

        open_shortcut = QShortcut(QKeySequence("Ctrl+O"), self)
        open_shortcut.activated.connect(self._on_open)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _on_new(self):
        """Clear the editor for a fresh file."""
        if self.editor.toPlainText().strip():
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "The editor has content. Discard and start fresh?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        self.editor.clear()
        self.txt_filename.clear()
        self._current_file_path = None
        self.status_updated.emit("New file started")

    def _on_open(self):
        """Open a file from disk into the editor."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    self.editor.setPlainText(f.read())
                self.txt_filename.setText(os.path.basename(file_path))
                self._current_file_path = file_path
                self.status_updated.emit(f"Opened: {file_path}")
            except Exception as e:
                logger.error(f"Failed to open file: {e}")
                QMessageBox.critical(self, "Error", f"Could not open file:\n{e}")

    def _on_save_overwrite(self):
        """Save (overwrite) the currently open file in place."""
        content = self.editor.toPlainText()
        if not content.strip():
            QMessageBox.warning(self, "Empty Content", "There is nothing to save.")
            return

        if not self._current_file_path:
            # No file open yet — fall through to Save File behavior
            self._on_save()
            return

        try:
            with open(self._current_file_path, "w", encoding="utf-8") as f:
                f.write(content)
            self.status_updated.emit(f"Saved: {self._current_file_path}")
            logger.info(f"Script Editor overwrote file: {self._current_file_path}")
        except Exception as e:
            logger.error(f"Failed to save file: {e}")
            QMessageBox.critical(self, "Save Error", f"Could not save file:\n{e}")

    def _on_save(self):
        """Save editor content to the selected target folder as a new file."""
        content = self.editor.toPlainText()
        if not content.strip():
            QMessageBox.warning(self, "Empty Content", "There is nothing to save.")
            return

        filename = self.txt_filename.text().strip()
        if not filename:
            QMessageBox.warning(
                self, "No Filename", "Please enter a filename before saving."
            )
            self.txt_filename.setFocus()
            return

        # Resolve the target directory
        target_key = self.combo_target.currentText()
        relative_dir = self.SAVE_TARGETS[target_key]
        project_root = self._get_project_root()
        target_dir = os.path.join(project_root, relative_dir)

        # Ensure the directory exists
        os.makedirs(target_dir, exist_ok=True)

        dest_path = os.path.join(target_dir, filename)

        # Warn if file already exists
        if os.path.exists(dest_path):
            reply = QMessageBox.question(
                self,
                "Overwrite?",
                f"'{filename}' already exists in {target_key}.\nOverwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        try:
            with open(dest_path, "w", encoding="utf-8") as f:
                f.write(content)
            self._current_file_path = dest_path
            self.status_updated.emit(f"Saved: {dest_path}")
            QMessageBox.information(
                self, "Saved", f"File saved successfully to:\n{dest_path}"
            )
            logger.info(f"Script Editor saved file: {dest_path}")
        except Exception as e:
            logger.error(f"Failed to save file: {e}")
            QMessageBox.critical(self, "Save Error", f"Could not save file:\n{e}")

    def _toggle_word_wrap(self):
        """Toggle word wrap in the editor."""
        if self.btn_wrap.isChecked():
            self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
            self.btn_wrap.setText("Wrap: On")
        else:
            self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            self.btn_wrap.setText("Wrap: Off")

    def _update_stats(self):
        """Update character and line count in the status strip."""
        text = self.editor.toPlainText()
        char_count = len(text)
        line_count = text.count("\n") + 1 if text else 0
        self.lbl_chars.setText(f"{char_count:,} characters")
        self.lbl_lines.setText(f"{line_count:,} lines")

    def _update_cursor_info(self):
        """Update cursor position in the status strip."""
        cursor = self.editor.textCursor()
        line = cursor.blockNumber() + 1
        col = cursor.columnNumber() + 1
        self.lbl_cursor.setText(f"Ln {line}, Col {col}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_project_root(self) -> str:
        """Resolve the project root directory."""
        if self.main_window and hasattr(self.main_window, "project_root"):
            return self.main_window.project_root
        # Fallback: walk up from this file
        return os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..")
        )

    def get_page_title(self):
        return "Script Editor"

    def get_page_icon(self):
        return None

    # ------------------------------------------------------------------
    # Theming
    # ------------------------------------------------------------------

    def apply_theme(self):
        """Apply a polished dark theme with visual depth."""
        self.setStyleSheet("""
            /* ── Header Panel ─────────────────────────────────────── */
            QFrame#headerFrame {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(20, 35, 55, 220),
                    stop:1 rgba(10, 20, 35, 220)
                );
                border: 1px solid rgba(100, 200, 255, 60);
                border-radius: 8px;
                margin-bottom: 4px;
            }

            /* ── Toolbar Panel ────────────────────────────────────── */
            QFrame#toolbarFrame {
                background-color: rgba(18, 25, 38, 180);
                border: 1px solid rgba(100, 200, 255, 40);
                border-radius: 6px;
                margin: 4px 0;
            }

            QPushButton#toolbarBtn {
                background-color: rgba(35, 50, 65, 180);
                border: 1px solid rgba(100, 200, 255, 80);
                border-radius: 6px;
                color: #DCDCDC;
                font-weight: bold;
                font-size: 10pt;
                padding: 6px 14px;
            }
            QPushButton#toolbarBtn:hover {
                background-color: rgba(50, 75, 100, 220);
                border: 1px solid #64C8FF;
                color: #FFFFFF;
            }
            QPushButton#toolbarBtn:pressed {
                background-color: rgba(70, 110, 150, 220);
            }
            QPushButton#toolbarBtn:checked {
                background-color: rgba(40, 80, 120, 200);
                border: 1px solid #64C8FF;
                color: #64C8FF;
            }

            QPushButton#toolbarBtnAccent {
                background: qlineargradient(
                    x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(30, 100, 160, 200),
                    stop:1 rgba(20, 70, 120, 200)
                );
                border: 1px solid rgba(100, 200, 255, 150);
                border-radius: 6px;
                color: #FFFFFF;
                font-weight: bold;
                font-size: 10pt;
                padding: 6px 14px;
            }
            QPushButton#toolbarBtnAccent:hover {
                background: qlineargradient(
                    x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(50, 130, 200, 230),
                    stop:1 rgba(30, 90, 150, 230)
                );
                border: 1px solid #64C8FF;
            }
            QPushButton#toolbarBtnAccent:pressed {
                background-color: rgba(80, 160, 220, 240);
            }

            /* ── Editor Panel ─────────────────────────────────────── */
            QFrame#editorFrame {
                background-color: rgba(10, 14, 22, 240);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 8px;
                margin: 4px 0;
            }

            QPlainTextEdit#codeEditor {
                background-color: rgba(8, 12, 20, 250);
                border: none;
                border-radius: 6px;
                color: #E8E8E8;
                font-family: Consolas, 'Courier New', monospace;
                font-size: 11pt;
                padding: 12px;
                selection-background-color: rgba(100, 200, 255, 80);
                selection-color: #FFFFFF;
            }

            /* ── Save Panel ───────────────────────────────────────── */
            QFrame#saveFrame {
                background-color: rgba(18, 25, 38, 200);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 8px;
                margin: 4px 0;
            }

            QLabel#saveLabel {
                color: rgba(200, 220, 240, 200);
                font-weight: bold;
                font-size: 10pt;
                border: none;
                background: transparent;
            }

            QComboBox#saveCombo {
                background-color: rgba(25, 35, 50, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px 10px;
                font-size: 10pt;
                min-width: 160px;
            }
            QComboBox#saveCombo:hover {
                border: 1px solid #64C8FF;
            }
            QComboBox#saveCombo::drop-down {
                border: none;
                width: 24px;
            }
            QComboBox#saveCombo QAbstractItemView {
                background-color: rgba(25, 35, 50, 245);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                selection-background-color: rgba(100, 200, 255, 120);
                padding: 4px;
            }

            QLineEdit#filenameInput {
                background-color: rgba(25, 35, 50, 200);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                padding: 5px 10px;
                font-size: 10pt;
            }
            QLineEdit#filenameInput:focus {
                border: 1px solid #64C8FF;
                background-color: rgba(30, 45, 60, 220);
            }

            QPushButton#saveBtn {
                background: qlineargradient(
                    x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(20, 160, 100, 200),
                    stop:1 rgba(15, 120, 75, 200)
                );
                border: 1px solid rgba(80, 220, 150, 150);
                border-radius: 6px;
                color: #FFFFFF;
                font-weight: bold;
                font-size: 10pt;
                padding: 8px 20px;
            }
            QPushButton#saveBtn:hover {
                background: qlineargradient(
                    x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(30, 190, 120, 230),
                    stop:1 rgba(20, 150, 90, 230)
                );
                border: 1px solid rgba(100, 240, 170, 200);
            }
            QPushButton#saveBtn:pressed {
                background-color: rgba(50, 200, 140, 240);
            }

            /* ── Status Strip ─────────────────────────────────────── */
            QFrame#statusStrip {
                background-color: rgba(12, 18, 28, 200);
                border: 1px solid rgba(100, 200, 255, 30);
                border-radius: 4px;
                margin-top: 2px;
            }

            QLabel#statusLabel {
                color: rgba(150, 180, 210, 180);
                font-size: 9pt;
                border: none;
                background: transparent;
            }
        """)
