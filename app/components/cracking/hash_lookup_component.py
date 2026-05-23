"""Hash lookup UI component — local database + online API lookups."""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLineEdit,
                            QComboBox, QPushButton, QTextEdit, QLabel, QProgressBar)
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont

from shared.configuration.hash_config import SOURCES, API_PROVIDERS


class HashLookupWorker(QThread):
    """Worker thread for hash lookups (local + online)."""
    result_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, hash_value, source, service):
        super().__init__()
        self.hash_value = hash_value
        self.source = source
        self.service = service

    def run(self):
        try:
            source_data = self.source

            # Check if this is an online source and validate API keys
            if source_data.startswith("Online:"):
                provider = source_data.split(":", 1)[1].strip()
                api_issue = self._check_api_config(provider)
                if api_issue:
                    self.result_signal.emit(api_issue)
                    return

            # Perform the lookup
            result = self.service.lookup_single_hash(self.hash_value, source_data)

            hash_type = self._detect_type(self.hash_value)
            output = f"Hash:   {self.hash_value}\n"
            output += f"Type:   {hash_type}\n"
            output += f"Source: {source_data}\n\n"

            if result:
                plaintext = result.plaintext
                if plaintext and plaintext.startswith("API_ERROR:"):
                    output += f"⚠ {plaintext.replace('API_ERROR: ', '')}\n\n"
                    output += self._get_api_help(source_data)
                elif plaintext == "<REDACTED>":
                    output += "Status: FOUND in breach database ✓\n\n"
                    output += "The hash was confirmed in breach data, but the plaintext\n"
                    output += "could not be resolved by free reverse-lookup services.\n\n"
                    output += "To get the plaintext, try:\n"
                    output += "  • Online: HashesAPI (requires free API key from hashes.com)\n"
                    output += "  • Use the Attack Configuration panel with a wordlist"
                else:
                    output += f"Plaintext: {plaintext}\n"
                    output += "Status: CRACKED ✓"
            else:
                output += "Status: NOT FOUND ✗\n\n"
                output += "Try:\n"
                output += "  • A different online source\n"
                output += "  • The Attack Configuration panel for dictionary/brute-force cracking"

            self.result_signal.emit(output)

        except Exception as e:
            self.result_signal.emit(f"[ERROR] Lookup failed: {str(e)}")
        finally:
            self.finished_signal.emit()

    def _check_api_config(self, provider: str) -> str:
        """Check if API keys are configured for the provider. Returns error message or empty string."""
        from shared.configuration.global_settings import global_settings

        if provider == "HIBP":
            return ""  # HIBP doesn't need an API key for password range queries

        if provider == "HashesAPI":
            key = global_settings.get("api_keys.hashes_com") or API_PROVIDERS.get("HashesAPI", {}).get("params", {}).get("key", "")
            if not key or key == "your_api_key_here":
                return (
                    "⚠ API Key Required: HashesAPI (hashes.com)\n\n"
                    "To use this service:\n"
                    "  1. Register at https://hashes.com\n"
                    "  2. Get your API key from your account settings\n"
                    "  3. Go to Tools → Global Settings → API Keys\n"
                    "  4. Set 'hashes_com' to your API key\n\n"
                    "Alternatively, try 'Online: HIBP' which works without an API key."
                )
            return ""

        if provider == "MD5Decrypt":
            key = global_settings.get("api_keys.md5decrypt_key") or API_PROVIDERS.get("MD5Decrypt", {}).get("params", {}).get("code", "")
            email = global_settings.get("api_keys.md5decrypt_email") or API_PROVIDERS.get("MD5Decrypt", {}).get("params", {}).get("email", "")
            if not key or key == "your_api_key_here" or not email or email == "your_email@example.com":
                return (
                    "⚠ API Key Required: MD5Decrypt\n\n"
                    "To use this service:\n"
                    "  1. Register at https://md5decrypt.net\n"
                    "  2. Get your API key and registered email\n"
                    "  3. Go to Tools → Global Settings → API Keys\n"
                    "  4. Set 'md5decrypt_key' and 'md5decrypt_email'\n\n"
                    "Alternatively, try 'Online: HIBP' which works without an API key."
                )
            return ""

        return ""

    def _detect_type(self, hash_value: str) -> str:
        """Detect hash type from value."""
        h = hash_value.strip()
        if h.startswith("$sshng$"):
            return "SSH Private Key"
        if h.startswith("$2"):
            return "bcrypt"
        length = len(h)
        types = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}
        return types.get(length, f"Unknown ({length} chars)")

    def _get_api_help(self, source_data: str) -> str:
        """Get help text for API configuration."""
        return "\nCheck Tools → Global Settings → API Keys for configuration."


class HashUpdateWorker(QThread):
    """Worker thread for hash database updates."""
    progress = pyqtSignal(str)
    finished = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, service, source_name):
        super().__init__()
        self.service = service
        self.source_name = source_name

    def run(self):
        try:
            self.progress.emit(f"Updating {self.source_name}...")
            from infrastructure.data.repositories.sqlite_hash_repository import SQLiteHashRepository
            from infrastructure.external.hash_source_updater import HashSourceUpdater
            from shared.configuration.hash_config import DB_PATH

            repo = SQLiteHashRepository(DB_PATH)
            updater = HashSourceUpdater(repo, progress_callback=self.progress.emit)
            count = updater.update_source(self.source_name)
            self.finished.emit(count)
        except Exception as e:
            self.error.emit(str(e))


class HashLookupComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_service()
        self.init_ui()

    def init_service(self):
        """Initialize hash lookup service."""
        from shared.configuration.hash_config import DB_PATH
        from infrastructure.data.repositories.sqlite_hash_repository import SQLiteHashRepository
        from infrastructure.external.hash_source_updater import HashSourceUpdater
        from domain.services.hash_lookup_manager import HashLookupManager
        from application.services.hash_lookup_service import HashLookupService

        repo = SQLiteHashRepository(DB_PATH)
        updater = HashSourceUpdater(repo)
        manager = HashLookupManager(repo)
        self.service = HashLookupService(manager, updater)

    def init_ui(self):
        """Initialize user interface."""
        layout = QVBoxLayout()

        # Hash input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Hash:"))
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter hash (MD5, SHA1, SHA256, NTLM, $sshng$...)")
        self.hash_input.returnPressed.connect(self.lookup_hash)
        input_layout.addWidget(self.hash_input)
        layout.addLayout(input_layout)

        # Source selection
        source_layout = QHBoxLayout()
        source_layout.addWidget(QLabel("Source:"))
        self.source_combo = QComboBox()
        self.populate_sources()
        source_layout.addWidget(self.source_combo)
        layout.addLayout(source_layout)

        # Buttons
        button_layout = QHBoxLayout()
        self.lookup_btn = QPushButton("🔍 Lookup Hash")
        self.lookup_btn.clicked.connect(self.lookup_hash)
        button_layout.addWidget(self.lookup_btn)

        self.update_btn = QPushButton("📥 Update Database")
        self.update_btn.clicked.connect(self.update_database)
        self.update_btn.setToolTip("Download and install hash databases from external sources")
        button_layout.addWidget(self.update_btn)

        self.stats_btn = QPushButton("📊 Stats")
        self.stats_btn.clicked.connect(self.show_stats)
        button_layout.addWidget(self.stats_btn)
        layout.addLayout(button_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Results
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setMaximumHeight(180)
        self.results_text.setFont(QFont("Neuropol X", 9))
        layout.addWidget(self.results_text)

        self.setLayout(layout)

    def populate_sources(self):
        """Populate source dropdown with local and online options."""
        self.source_combo.clear()

        # Online sources first (most useful for quick lookups)
        self.source_combo.addItem("Online: HIBP (no key needed)", "Online: HIBP")
        self.source_combo.addItem("Online: HashesAPI (hashes.com)", "Online: HashesAPI")
        self.source_combo.addItem("Online: MD5Decrypt", "Online: MD5Decrypt")

        # Local sources
        try:
            stats = self.service.get_database_stats()
            for source_name, count in stats.get('sources', {}).items():
                if count > 0:
                    self.source_combo.addItem(f"Local: {source_name} ({count:,})", f"Local: {source_name}")
        except Exception:
            pass

    def lookup_hash(self):
        """Perform hash lookup using selected source."""
        hash_value = self.hash_input.text().strip()
        if not hash_value:
            self.results_text.setPlainText("Please enter a hash value.")
            return

        source_data = self.source_combo.currentData()
        if not source_data:
            self.results_text.setPlainText("Please select a lookup source.")
            return

        # Handle structured hashes — these can't be looked up online
        if hash_value.startswith("$") and not hash_value.startswith("$0"):
            # Check if it's a type that could potentially be in online DBs
            if hash_value.startswith("$sshng$") or hash_value.startswith("$krb5"):
                self._show_structured_hash_info(hash_value)
                return

        # Validate raw hex hashes
        if not hash_value.startswith("$"):
            clean = hash_value.strip()
            if not all(c in "0123456789abcdefABCDEF" for c in clean):
                self.results_text.setPlainText(
                    f"Invalid hash format.\n\n"
                    f"Expected: hex string (MD5, SHA1, SHA256, SHA512, NTLM)\n"
                    f"Got: {hash_value[:50]}..."
                )
                return

        # Run lookup in background thread
        self.lookup_btn.setEnabled(False)
        self.results_text.setPlainText(f"Looking up hash using {source_data}...")

        self.worker = HashLookupWorker(hash_value, source_data, self.service)
        self.worker.result_signal.connect(self._on_lookup_result)
        self.worker.finished_signal.connect(self._on_lookup_finished)
        self.worker.start()

    def _on_lookup_result(self, text: str):
        self.results_text.setPlainText(text)

    def _on_lookup_finished(self):
        self.lookup_btn.setEnabled(True)
        if self.worker:
            self.worker.quit()
            self.worker.wait(2000)
            self.worker = None

    def _show_structured_hash_info(self, hash_value: str):
        """Show info for structured hashes that can't be rainbow-tabled."""
        hash_type = self._identify_structured_hash(hash_value)
        output = f"Hash: {hash_value[:80]}{'...' if len(hash_value) > 80 else ''}\n"
        output += f"Type: {hash_type}\n\n"
        output += "⚠ Structured hashes cannot be looked up in rainbow tables or online databases.\n\n"
        output += "To crack this hash:\n"
        output += "  1. Paste it into the 'Hash' field in Hash Cracking\n"
        output += "  2. Select a wordlist (e.g. rockyou.txt)\n"
        output += "  3. Click '▶ Start Attack'\n"
        if "$sshng$" in hash_value:
            output += "\nNote: SSH key cracking is slow due to bcrypt KDF.\n"
            output += "Use a targeted wordlist for best results."
        self.results_text.setPlainText(output)

    def _identify_structured_hash(self, hash_value):
        """Identify a structured hash format by prefix."""
        prefixes = {
            "$sshng$": "SSH Private Key",
            "$2b$": "bcrypt",
            "$2a$": "bcrypt",
            "$2y$": "bcrypt",
            "$6$": "SHA-512 Crypt",
            "$5$": "SHA-256 Crypt",
            "$1$": "MD5 Crypt",
            "$krb5tgs$": "Kerberos TGS-REP",
            "$krb5asrep$": "Kerberos AS-REP",
            "$NETNTLMv2$": "NetNTLMv2",
            "$office$": "MS Office",
            "$keepass$": "KeePass",
        }
        for prefix, name in prefixes.items():
            if hash_value.startswith(prefix):
                return name
        return "Structured hash (unknown type)"

    def update_database(self):
        """Update hash database from a source."""
        from PyQt6.QtWidgets import QInputDialog

        sources = list(SOURCES.keys())
        source_name, ok = QInputDialog.getItem(
            self, "Update Database", "Select source to update:", sources, 0, False
        )
        if not ok:
            return

        self.update_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        self._update_worker = HashUpdateWorker(self.service, source_name)
        self._update_worker.progress.connect(self._update_progress)
        self._update_worker.finished.connect(self._update_finished)
        self._update_worker.error.connect(self._update_error)
        self._update_worker.start()

    def _update_progress(self, message):
        self.results_text.append(message)
        scrollbar = self.results_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _update_finished(self, count):
        self.progress_bar.setVisible(False)
        self.update_btn.setEnabled(True)
        self.results_text.append(f"\n✓ Database updated! Added {count:,} records.")
        self.populate_sources()

    def _update_error(self, error):
        self.progress_bar.setVisible(False)
        self.update_btn.setEnabled(True)
        self.results_text.append(f"\n✗ Update failed: {error}")

    def show_stats(self):
        """Show database statistics."""
        try:
            stats = self.service.get_database_stats()
            output = "Database Statistics\n"
            output += "─" * 30 + "\n"
            output += f"Total hashes: {stats.get('total', 0):,}\n\n"
            output += "By source:\n"
            for source, count in stats.get('sources', {}).items():
                output += f"  {source}: {count:,}\n"

            output += "\nOnline APIs:\n"
            output += "  HIBP: ✓ (no key needed, SHA1 only)\n"

            from shared.configuration.global_settings import global_settings
            hashes_key = global_settings.get("api_keys.hashes_com") or API_PROVIDERS.get("HashesAPI", {}).get("params", {}).get("key", "")
            if hashes_key and hashes_key != "your_api_key_here":
                output += "  HashesAPI: ✓ (key configured)\n"
            else:
                output += "  HashesAPI: ✗ (key needed — Tools → Global Settings)\n"

            md5_key = global_settings.get("api_keys.md5decrypt_key") or ""
            if md5_key and md5_key != "your_api_key_here":
                output += "  MD5Decrypt: ✓ (key configured)\n"
            else:
                output += "  MD5Decrypt: ✗ (key needed — Tools → Global Settings)\n"

            self.results_text.setPlainText(output)
        except Exception as e:
            self.results_text.setPlainText(f"Error loading stats: {e}")
