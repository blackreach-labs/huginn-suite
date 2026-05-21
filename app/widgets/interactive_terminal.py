"""
Interactive Terminal Widget using Windows ConPTY via pywinpty + pyte VT100 emulator.

Provides a fully interactive terminal (PowerShell by default) embedded
in a PyQt6 widget. Uses pyte to properly interpret VT100 escape sequences
for cursor movement, line editing, colors, and screen management.
"""

import threading
import pyte
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QPlainTextEdit, QApplication,
                             QTabWidget, QPushButton, QHBoxLayout)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QKeyEvent


class TerminalDisplay(QPlainTextEdit):
    """Custom text widget that captures all keyboard input for the PTY."""

    key_pressed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(False)
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(QFont("Consolas", 11))
        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: #0C0C0C;
                color: #CCCCCC;
                border: none;
                selection-background-color: #264F78;
            }
        """)
        self.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse |
            Qt.TextInteractionFlag.TextSelectableByKeyboard
        )

    def keyPressEvent(self, event: QKeyEvent):
        """Intercept all key presses and send to PTY."""
        # Allow Ctrl+C for copy when text is selected
        if (event.key() == Qt.Key.Key_C and
                event.modifiers() == Qt.KeyboardModifier.ControlModifier and
                self.textCursor().hasSelection()):
            super().keyPressEvent(event)
            return

        data = self._key_to_str(event)
        if data:
            self.key_pressed.emit(data)

    def _key_to_str(self, event: QKeyEvent) -> str:
        """Convert a Qt key event to a string to send to the PTY."""
        key = event.key()
        modifiers = event.modifiers()
        text = event.text()
        ctrl = bool(modifiers & Qt.KeyboardModifier.ControlModifier)

        # Ctrl combinations
        if ctrl and key == Qt.Key.Key_C:
            return '\x03'
        if ctrl and key == Qt.Key.Key_D:
            return '\x04'
        if ctrl and key == Qt.Key.Key_Z:
            return '\x1a'
        if ctrl and key == Qt.Key.Key_L:
            return '\x0c'
        if ctrl and key == Qt.Key.Key_A:
            return '\x01'
        if ctrl and key == Qt.Key.Key_E:
            return '\x05'
        if ctrl and key == Qt.Key.Key_U:
            return '\x15'
        if ctrl and key == Qt.Key.Key_K:
            return '\x0b'
        if ctrl and key == Qt.Key.Key_W:
            return '\x17'

        # Special keys
        key_map = {
            Qt.Key.Key_Return: '\r',
            Qt.Key.Key_Enter: '\r',
            Qt.Key.Key_Backspace: '\x7f',
            Qt.Key.Key_Tab: '\t',
            Qt.Key.Key_Escape: '\x1b',
            Qt.Key.Key_Up: '\x1b[A',
            Qt.Key.Key_Down: '\x1b[B',
            Qt.Key.Key_Right: '\x1b[C',
            Qt.Key.Key_Left: '\x1b[D',
            Qt.Key.Key_Home: '\x1b[H',
            Qt.Key.Key_End: '\x1b[F',
            Qt.Key.Key_Delete: '\x1b[3~',
            Qt.Key.Key_Insert: '\x1b[2~',
            Qt.Key.Key_PageUp: '\x1b[5~',
            Qt.Key.Key_PageDown: '\x1b[6~',
            Qt.Key.Key_F1: '\x1bOP',
            Qt.Key.Key_F2: '\x1bOQ',
            Qt.Key.Key_F3: '\x1bOR',
            Qt.Key.Key_F4: '\x1bOS',
            Qt.Key.Key_F5: '\x1b[15~',
            Qt.Key.Key_F6: '\x1b[17~',
            Qt.Key.Key_F7: '\x1b[18~',
            Qt.Key.Key_F8: '\x1b[19~',
            Qt.Key.Key_F9: '\x1b[20~',
            Qt.Key.Key_F10: '\x1b[21~',
            Qt.Key.Key_F11: '\x1b[23~',
            Qt.Key.Key_F12: '\x1b[24~',
        }
        if key in key_map:
            return key_map[key]

        # Ctrl+letter -> control character
        if ctrl and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            return chr(key - Qt.Key.Key_A + 1)

        # Regular text
        if text:
            return text

        return ''

    def contextMenuEvent(self, event):
        """Custom context menu with Copy/Paste."""
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        copy_action = menu.addAction("Copy")
        paste_action = menu.addAction("Paste")
        menu.addSeparator()
        clear_action = menu.addAction("Clear Scrollback")

        action = menu.exec(event.globalPos())
        if action == copy_action:
            self.copy()
        elif action == paste_action:
            clipboard = QApplication.clipboard()
            text = clipboard.text()
            if text:
                self.key_pressed.emit(text)
        elif action == clear_action:
            self.key_pressed.emit('\x0c')  # Ctrl+L


class InteractiveTerminalWidget(QWidget):
    """Fully interactive terminal widget using Windows ConPTY + pyte.

    Spawns a real shell process with a pseudo-terminal. Uses pyte as a
    VT100 terminal emulator to properly handle all escape sequences,
    cursor movement, and screen updates.
    """

    output_ready = pyqtSignal(str)

    def __init__(self, shell: str = None, cols: int = 120, rows: int = 30, parent=None):
        super().__init__(parent)
        self._pty = None
        self._reader_thread = None
        self._running = False
        self._shell = shell or self._detect_shell()
        self._cols = cols
        self._rows = rows

        # pyte virtual terminal screen with scrollback history
        self._screen = pyte.HistoryScreen(cols, rows, history=10000)
        self._screen.set_mode(pyte.modes.LNM)
        self._stream = pyte.Stream(self._screen)

        self._setup_ui()
        self._start_pty()

        # Connect output signal to UI update (thread-safe)
        self.output_ready.connect(self._on_output)

        # Periodic screen refresh
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_display)
        self._refresh_timer.start(33)  # ~30 FPS

        self._screen_dirty = False

    def _detect_shell(self) -> str:
        """Detect the best available shell (full path)."""
        import shutil
        pwsh = shutil.which('pwsh')
        if pwsh:
            return pwsh
        ps = shutil.which('powershell')
        if ps:
            return ps
        return shutil.which('cmd') or 'cmd.exe'

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._display = TerminalDisplay()
        self._display.key_pressed.connect(self._send_input)
        layout.addWidget(self._display)

    def _start_pty(self):
        """Start the PTY process."""
        try:
            import winpty

            self._pty = winpty.PTY(self._cols, self._rows)
            self._pty.spawn(self._shell)
            self._running = True

            # Start reader thread
            self._reader_thread = threading.Thread(
                target=self._read_loop, daemon=True
            )
            self._reader_thread.start()

            # Resize check timer
            self._resize_timer = QTimer(self)
            self._resize_timer.timeout.connect(self._check_resize)
            self._resize_timer.start(1000)

        except Exception as e:
            self._display.setPlainText(
                f"Failed to start interactive terminal: {e}\n"
                f"Shell: {self._shell}\n"
            )

    def _read_loop(self):
        """Background thread: read PTY output and emit signal."""
        import time
        while self._running:
            try:
                data = self._pty.read(8192, blocking=False)
                if data:
                    self.output_ready.emit(data)
                else:
                    time.sleep(0.01)

                if not self._pty.isalive():
                    self.output_ready.emit("\r\n[Process exited]\r\n")
                    self._running = False
                    break
            except Exception:
                time.sleep(0.03)

    def _on_output(self, text: str):
        """Feed PTY output into the pyte terminal emulator."""
        self._stream.feed(text)
        self._screen_dirty = True

    def _refresh_display(self):
        """Refresh the QPlainTextEdit from the pyte screen buffer."""
        if not self._screen_dirty:
            return
        self._screen_dirty = False

        # Build scrollback history lines
        history_lines = []
        if hasattr(self._screen, 'history') and self._screen.history.top:
            for hist_line in self._screen.history.top:
                chars = []
                for col in range(self._screen.columns):
                    char = hist_line.get(col)
                    chars.append(char.data if char and char.data else ' ')
                history_lines.append(''.join(chars).rstrip())

        # Build visible screen lines
        visible_lines = []
        last_non_empty = -1
        for row in range(self._screen.lines):
            line_chars = []
            for col in range(self._screen.columns):
                char = self._screen.buffer[row][col]
                line_chars.append(char.data if char.data else ' ')
            line = ''.join(line_chars).rstrip()
            visible_lines.append(line)
            if line:
                last_non_empty = row

        # Combine history + visible screen
        display_lines = history_lines + visible_lines[:last_non_empty + 1]
        new_text = '\n'.join(display_lines)

        # Only update if content changed
        current_text = self._display.toPlainText()
        if new_text != current_text:
            # Preserve scroll position if user scrolled up
            scrollbar = self._display.verticalScrollBar()
            was_at_bottom = (scrollbar.value() >= scrollbar.maximum() - 5)

            self._display.setPlainText(new_text)

            if was_at_bottom:
                # Move cursor to end and scroll to bottom
                cursor = self._display.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.End)
                self._display.setTextCursor(cursor)
                self._display.ensureCursorVisible()

    def _send_input(self, data: str):
        """Send keyboard input to the PTY."""
        if self._pty and self._running:
            try:
                self._pty.write(data)
            except Exception:
                pass

    def _check_resize(self):
        """Check if widget was resized and update PTY dimensions."""
        if not self._pty or not self._running:
            return

        font_metrics = self._display.fontMetrics()
        char_width = max(font_metrics.averageCharWidth(), 1)
        char_height = max(font_metrics.height(), 1)
        viewport = self._display.viewport()
        cols = max(40, viewport.width() // char_width)
        rows = max(10, viewport.height() // char_height)

        if cols != self._cols or rows != self._rows:
            try:
                self._pty.set_size(cols, rows)
                self._screen.resize(rows, cols)
                self._cols = cols
                self._rows = rows
                self._screen_dirty = True
            except Exception:
                pass

    def restart_shell(self, shell: str = None):
        """Restart the terminal with a new shell."""
        self.stop()
        self._display.clear()
        self._screen.reset()
        self._shell = shell or self._shell
        self._start_pty()

    def stop(self):
        """Stop the PTY process."""
        self._running = False
        if self._pty:
            try:
                self._pty.write('exit\r\n')
            except Exception:
                pass
            self._pty = None

    def closeEvent(self, event):
        """Clean up on widget close."""
        self.stop()
        super().closeEvent(event)


class MultiTerminalWidget(QWidget):
    """Tabbed container that allows launching multiple interactive terminals.
    
    Provides a tab bar with a "+" button to spawn new terminal instances,
    and closable tabs to terminate individual sessions.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._terminal_count = 0
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Tab widget for multiple terminals
        self._tabs = QTabWidget()
        self._tabs.setTabsClosable(True)
        self._tabs.tabCloseRequested.connect(self._close_tab)

        # "+" button in the tab bar corner to add new terminals
        new_tab_btn = QPushButton("+")
        new_tab_btn.setFixedSize(28, 28)
        new_tab_btn.setToolTip("Open new terminal")
        new_tab_btn.setStyleSheet("""
            QPushButton {
                background: rgba(100, 200, 255, 150);
                color: #000;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: rgba(120, 220, 255, 200);
            }
        """)
        new_tab_btn.clicked.connect(self.add_terminal)
        self._tabs.setCornerWidget(new_tab_btn, Qt.Corner.TopRightCorner)

        layout.addWidget(self._tabs)

        # Start with one terminal
        self.add_terminal()

    def add_terminal(self):
        """Spawn a new interactive terminal tab."""
        self._terminal_count += 1
        terminal = InteractiveTerminalWidget()
        index = self._tabs.addTab(terminal, f"Terminal {self._terminal_count}")
        self._tabs.setCurrentIndex(index)
        terminal._display.setFocus()

    def _close_tab(self, index: int):
        """Close a terminal tab and stop its PTY process."""
        widget = self._tabs.widget(index)
        if widget:
            widget.stop()
        self._tabs.removeTab(index)

        # If all tabs closed, open a fresh one
        if self._tabs.count() == 0:
            self.add_terminal()

    def stop_all(self):
        """Stop all terminal processes."""
        for i in range(self._tabs.count()):
            widget = self._tabs.widget(i)
            if widget:
                widget.stop()

    def closeEvent(self, event):
        """Clean up all terminals on widget close."""
        self.stop_all()
        super().closeEvent(event)
