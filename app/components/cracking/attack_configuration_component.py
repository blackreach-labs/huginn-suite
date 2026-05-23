# app/components/cracking/attack_configuration_component.py
"""Attack configuration component — builds crack engine parameters."""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QLineEdit, QPushButton, QComboBox, QSpinBox,
                            QCheckBox, QFileDialog)
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QFont


class AttackConfigurationComponent(QWidget):
    """Configures attack parameters and emits the config for execution."""
    attack_configured = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.setup_ui()
        # Trigger initial mode state
        self._on_mode_changed(self.mode_combo.currentText())

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)

        # Row 1: Hash type + Attack mode
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Type:"))
        self.hash_type_combo = QComboBox()
        self._populate_hash_types()
        row1.addWidget(self.hash_type_combo, 1)
        row1.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Dictionary", "Brute Force", "Hybrid", "Rule-based"])
        self.mode_combo.currentTextChanged.connect(self._on_mode_changed)
        row1.addWidget(self.mode_combo, 1)
        layout.addLayout(row1)

        # Row 2: Hash value / file
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Hash:"))
        self.hash_file_input = QLineEdit()
        self.hash_file_input.setPlaceholderText("Paste hash or path to hash file...")
        row2.addWidget(self.hash_file_input)
        self.browse_hash_btn = QPushButton("...")
        self.browse_hash_btn.setFixedWidth(30)
        self.browse_hash_btn.clicked.connect(self._browse_hash_file)
        row2.addWidget(self.browse_hash_btn)
        layout.addLayout(row2)

        # Row 3: Wordlist (Dictionary / Hybrid / Rule-based modes)
        self.wordlist_row = QWidget()
        row3 = QHBoxLayout(self.wordlist_row)
        row3.setContentsMargins(0, 0, 0, 0)
        wordlist_label = QLabel("Wordlist:")
        wordlist_label.setFixedWidth(110)
        row3.addWidget(wordlist_label)
        self.wordlist_combo = QComboBox()
        self.wordlist_combo.setEditable(True)
        self.wordlist_combo.setPlaceholderText("Select or type path...")
        self._populate_wordlists()
        row3.addWidget(self.wordlist_combo)
        self.browse_wordlist_btn = QPushButton("...")
        self.browse_wordlist_btn.setFixedWidth(30)
        self.browse_wordlist_btn.clicked.connect(self._browse_wordlist)
        row3.addWidget(self.browse_wordlist_btn)
        layout.addWidget(self.wordlist_row)

        # Row 3b: Mask (Hybrid mode only)
        self.mask_row = QWidget()
        row3b = QHBoxLayout(self.mask_row)
        row3b.setContentsMargins(0, 0, 0, 0)
        row3b.addWidget(QLabel("Mask:"))
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("?a?a?a?a (charsets: ?l ?u ?d ?s ?a)")
        row3b.addWidget(self.mask_input)
        layout.addWidget(self.mask_row)

        # Row 3c: Brute-force charset options
        self.brute_row = QWidget()
        row3c = QHBoxLayout(self.brute_row)
        row3c.setContentsMargins(0, 0, 0, 0)
        row3c.setSpacing(2)
        charset_label = QLabel("Charset:")
        charset_label.setFixedWidth(120)
        row3c.addWidget(charset_label)
        self.charset_lower = QCheckBox("a-z")
        self.charset_lower.setChecked(True)
        row3c.addWidget(self.charset_lower)
        self.charset_upper = QCheckBox("A-Z")
        self.charset_upper.setChecked(True)
        row3c.addWidget(self.charset_upper)
        self.charset_digits = QCheckBox("0-9")
        self.charset_digits.setChecked(True)
        row3c.addWidget(self.charset_digits)
        self.charset_special = QCheckBox("#!^% ")
        row3c.addWidget(self.charset_special)
        maxlen_label = QLabel("Max Chars:")
        maxlen_label.setFixedWidth(140)
        row3c.addWidget(maxlen_label)
        self.max_len_spin = QSpinBox()
        self.max_len_spin.setRange(1, 16)
        self.max_len_spin.setValue(6)
        self.max_len_spin.setFixedWidth(70)
        row3c.addWidget(self.max_len_spin)
        row3c.addStretch()
        layout.addWidget(self.brute_row)

        # Row 4: Rules (Rule-based mode only)
        self.rules_row = QWidget()
        row4 = QHBoxLayout(self.rules_row)
        row4.setContentsMargins(0, 0, 0, 0)
        rules_label = QLabel("Rules:")
        rules_label.setFixedWidth(90)
        row4.addWidget(rules_label)
        self.rules_combo = QComboBox()
        self.rules_combo.addItem("(none)")
        self._populate_rules()
        row4.addWidget(self.rules_combo)
        layout.addWidget(self.rules_row)

        # GPU checkbox stored for use by live attacks start button
        self.gpu_check = QCheckBox("GPU")
        self.gpu_check.setToolTip("Use GPU acceleration (requires compatible hardware)")
        # GPU is placed next to Start button in live_attacks via cracking_page wiring

    def _populate_hash_types(self):
        """Populate hash type dropdown with common types."""
        from app.core.hashcat_engine import HASH_TYPES
        for name, code in sorted(HASH_TYPES.items(), key=lambda x: x[1]):
            self.hash_type_combo.addItem(f"{name} ({code})", code)

    def _populate_rules(self):
        """Populate rules dropdown from available rule files."""
        try:
            from app.core.hashcat_engine import get_available_rules
            for rule in get_available_rules():
                self.rules_combo.addItem(rule, rule)
        except Exception:
            pass

    def _on_mode_changed(self, mode: str):
        """Show/hide fields based on attack mode."""
        is_dict = mode == "Dictionary"
        is_brute = mode == "Brute Force"
        is_hybrid = mode == "Hybrid"
        is_rules = mode == "Rule-based"

        # Wordlist row: visible for Dictionary, Hybrid, Rule-based
        self.wordlist_row.setVisible(not is_brute)

        # Mask row: visible only for Hybrid
        self.mask_row.setVisible(is_hybrid)

        # Brute force row: visible only for Brute Force
        self.brute_row.setVisible(is_brute)

        # Rules row: visible only for Rule-based
        self.rules_row.setVisible(is_rules)

    def _browse_hash_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Hash File", "", "All Files (*)")
        if path:
            self.hash_file_input.setText(path)

    def _browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.wordlist_combo.setCurrentText(path)

    def _populate_wordlists(self):
        """Populate wordlist dropdown from resources/wordlists/hashcrack/."""
        from pathlib import Path
        wordlist_dir = Path(__file__).resolve().parent.parent.parent.parent / "resources" / "wordlists" / "hashcrack"
        if wordlist_dir.exists():
            for f in sorted(wordlist_dir.glob("*")):
                if f.is_file() and f.suffix in (".txt", ".lst", ".dict", ""):
                    self.wordlist_combo.addItem(f.name, str(f))

    def _get_wordlist_path(self) -> str:
        """Get the wordlist path from the combo box (selected item or typed text)."""
        # If user selected a dropdown item, use its full path data
        data = self.wordlist_combo.currentData()
        if data:
            return data
        # Otherwise use whatever text is in the editable field
        return self.wordlist_combo.currentText().strip()

    def _get_brute_charset(self) -> str:
        """Build charset string from brute-force checkboxes."""
        charset = ""
        if self.charset_lower.isChecked():
            charset += "abcdefghijklmnopqrstuvwxyz"
        if self.charset_upper.isChecked():
            charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if self.charset_digits.isChecked():
            charset += "0123456789"
        if self.charset_special.isChecked():
            charset += "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
        return charset or "abcdefghijklmnopqrstuvwxyz0123456789"

    def _configure_attack(self):
        """Build the attack config and emit it."""
        from app.core.hashcat_engine import get_hashcat_dir

        mode_text = self.mode_combo.currentText()

        rules_file = ""
        if mode_text == "Rule-based" and self.rules_combo.currentIndex() > 0:
            rules_file = self.rules_combo.currentData()

        config = {
            "tool": "Built-in Engine",
            "mode": mode_text,
            "config": {
                "hash_value": self.hash_file_input.text().strip(),
                "hash_file": self.hash_file_input.text().strip(),
                "hash_type": self.hash_type_combo.currentData() or 0,
                "wordlist": self._get_wordlist_path() if not mode_text == "Brute Force" else "",
                "mask": self.mask_input.text().strip() if mode_text == "Hybrid" else "",
                "rules": rules_file,
                "gpu": self.gpu_check.isChecked() if hasattr(self, 'gpu_check') else False,
                "charset": self._get_brute_charset() if mode_text == "Brute Force" else "",
                "max_length": self.max_len_spin.value() if mode_text == "Brute Force" else 8,
                "min_length": 1,
            },
        }

        # If hash_file is a file path, read the first hash from it
        from pathlib import Path
        hash_input = config["config"]["hash_value"]
        if hash_input and Path(hash_input).is_file():
            try:
                with open(hash_input, "r", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline().strip()
                    if first_line:
                        config["config"]["hash_value"] = first_line
            except Exception:
                pass

        # Emit config for the live attacks component
        self.attack_configured.emit(config)
