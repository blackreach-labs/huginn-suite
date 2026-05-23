# app/components/cracking/live_attacks_component.py
"""Live attack execution component — runs the built-in crack engine."""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                            QPushButton, QTextEdit, QProgressBar, QCheckBox)
from PyQt6.QtCore import pyqtSignal, QThread
from PyQt6.QtGui import QFont


class CrackWorker(QThread):
    """Worker thread that runs the crack engine."""
    output_signal = pyqtSignal(str)
    cracked_signal = pyqtSignal(dict)
    stats_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal(int)  # 0=success, 1=exhausted, -1=error

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self._stop = False

    def run(self):
        try:
            from app.core.crack_engine import (
                crack, CrackJob, AttackMode, HashType,
                identify_hash_type, load_rules, get_hash_function,
            )
            from app.core.hashcat_engine import get_hashcat_dir

            cfg = self.config.get("config", {})
            hash_value = cfg.get("hash_value", "").strip()
            mode_text = self.config.get("mode", "Dictionary")

            if not hash_value:
                self.output_signal.emit("[ERROR] No hash value provided.")
                self.finished_signal.emit(-1)
                return

            # Detect hash type
            hash_type = identify_hash_type(hash_value)
            self.output_signal.emit(f"[INFO] Hash type detected: {hash_type.value}")

            # Map attack mode
            mode_map = {
                "Dictionary": AttackMode.DICTIONARY,
                "Brute Force": AttackMode.BRUTE_FORCE,
                "Hybrid": AttackMode.BRUTE_FORCE,
                "Rule-based": AttackMode.RULE_BASED,
            }
            attack_mode = mode_map.get(mode_text, AttackMode.DICTIONARY)

            # Load rules if needed
            rules = []
            if attack_mode == AttackMode.RULE_BASED and cfg.get("rules"):
                rules_path = str(get_hashcat_dir() / "rules" / cfg["rules"])
                rules = load_rules(rules_path)
                self.output_signal.emit(f"[INFO] Loaded {len(rules)} rules from {cfg['rules']}")

            # Build the job
            charset = cfg.get("charset", "") or "abcdefghijklmnopqrstuvwxyz0123456789"
            use_gpu = cfg.get("gpu", False)
            job = CrackJob(
                hash_value=hash_value,
                hash_type=hash_type,
                attack_mode=attack_mode,
                wordlist_path=cfg.get("wordlist", ""),
                mask=cfg.get("mask", ""),
                rules=rules,
                charset=charset,
                max_length=cfg.get("max_length", 8),
                min_length=cfg.get("min_length", 1),
                use_gpu=use_gpu,
            )

            if use_gpu:
                try:
                    from app.core.gpu_crack_engine import is_gpu_available, get_available_gpus
                    if is_gpu_available():
                        gpus = get_available_gpus()
                        self.output_signal.emit(f"[GPU] Enabled — {gpus[0].name}")
                    else:
                        self.output_signal.emit("[GPU] No compatible GPU found, falling back to CPU")
                except Exception:
                    self.output_signal.emit("[GPU] pyopencl not available, falling back to CPU")

            # Validate inputs
            if attack_mode == AttackMode.DICTIONARY and not job.wordlist_path:
                self.output_signal.emit("[ERROR] No wordlist specified for dictionary attack.")
                self.finished_signal.emit(-1)
                return

            if attack_mode == AttackMode.BRUTE_FORCE and not job.mask:
                self.output_signal.emit(f"[INFO] Brute force: charset={len(charset)} chars, length={job.min_length}-{job.max_length}")

            # Calculate total keyspace for progress tracking
            total_candidates = 0
            if attack_mode == AttackMode.BRUTE_FORCE and not job.mask:
                cs_len = len(charset)
                for l in range(job.min_length, job.max_length + 1):
                    total_candidates += cs_len ** l
                self.output_signal.emit(f"[INFO] Keyspace: {total_candidates:,} candidates")
            elif attack_mode == AttackMode.DICTIONARY and job.wordlist_path:
                try:
                    import os
                    # Fast line count
                    with open(job.wordlist_path, "rb") as f:
                        total_candidates = sum(1 for _ in f)
                    self.output_signal.emit(f"[INFO] Wordlist: {total_candidates:,} words")
                except Exception:
                    total_candidates = 0
            elif attack_mode == AttackMode.RULE_BASED and job.wordlist_path and rules:
                try:
                    with open(job.wordlist_path, "rb") as f:
                        wl_count = sum(1 for _ in f)
                    total_candidates = wl_count * len(rules)
                    self.output_signal.emit(f"[INFO] Keyspace: {wl_count:,} words × {len(rules)} rules = {total_candidates:,}")
                except Exception:
                    total_candidates = 0

            self.output_signal.emit(f"[START] {mode_text} attack on {hash_type.value} hash")
            self.output_signal.emit(f"[INFO] Target: {hash_value[:60]}{'...' if len(hash_value) > 60 else ''}")
            if job.wordlist_path:
                self.output_signal.emit(f"[INFO] Wordlist: {job.wordlist_path}")
            if job.mask:
                self.output_signal.emit(f"[INFO] Mask: {job.mask}")
            self.output_signal.emit("")

            # Run the crack
            def progress_cb(attempts, speed, candidate):
                pct = int((attempts / total_candidates) * 100) if total_candidates > 0 else 0
                pct = min(pct, 99)  # Don't show 100% until actually done
                self.progress_signal.emit(pct)
                self.stats_signal.emit({
                    "status": f"Running ({pct}%)",
                    "speed": f"{speed:,.0f} H/s",
                    "recovered": "0/1",
                    "attempts": attempts,
                })
                self.output_signal.emit(
                    f"[{pct}%] {attempts:,} attempts | {speed:,.0f} H/s | trying: {candidate[:30]}"
                )

            def stop_check():
                return self._stop

            result = crack(job, progress_callback=progress_cb, stop_check=stop_check)

            # Report result
            if result.cracked:
                self.output_signal.emit("")
                self.output_signal.emit(f"[CRACKED] {result.password}")
                self.output_signal.emit(f"[STATS] {result.attempts:,} attempts in {result.elapsed:.2f}s ({result.speed:,.0f} H/s)")
                self.cracked_signal.emit({
                    "hash": hash_value[:32] + "..." if len(hash_value) > 32 else hash_value,
                    "password": result.password,
                })
                self.stats_signal.emit({
                    "status": "Cracked",
                    "speed": f"{result.speed:,.0f} H/s",
                    "recovered": "1/1",
                    "attempts": result.attempts,
                })
                self.progress_signal.emit(100)
                self.finished_signal.emit(0)
            else:
                self.output_signal.emit("")
                self.output_signal.emit(f"[EXHAUSTED] No match found after {result.attempts:,} attempts")
                self.output_signal.emit(f"[STATS] {result.elapsed:.2f}s ({result.speed:,.0f} H/s)")
                self.stats_signal.emit({
                    "status": "Exhausted",
                    "speed": f"{result.speed:,.0f} H/s",
                    "recovered": "0/1",
                    "attempts": result.attempts,
                })
                self.progress_signal.emit(100)
                self.finished_signal.emit(1)

        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
            self.finished_signal.emit(-1)

    def stop(self):
        self._stop = True


class LiveAttacksComponent(QWidget):
    """Live attack execution panel — runs the built-in cracking engine."""
    cracked_result = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.worker = None
        self._attack_config = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)

        # Attack controls
        controls_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        self.stop_btn = QPushButton("■ Stop")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        self.gpu_check = QCheckBox("GPU")
        self.gpu_check.setToolTip("Use GPU acceleration (requires compatible hardware)")
        controls_layout.addWidget(self.gpu_check)
        controls_layout.addWidget(self.start_btn)
        controls_layout.addWidget(self.stop_btn)
        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Statistics row
        stats_layout = QHBoxLayout()
        stats_layout.addWidget(QLabel("Status:"))
        self.status_label = QLabel("Idle")
        self.status_label.setStyleSheet("font-weight: bold;")
        stats_layout.addWidget(self.status_label)
        stats_layout.addWidget(QLabel("Speed:"))
        self.speed_label = QLabel("—")
        stats_layout.addWidget(self.speed_label)
        stats_layout.addWidget(QLabel("Recovered:"))
        self.recovered_label = QLabel("—")
        stats_layout.addWidget(self.recovered_label)
        stats_layout.addStretch()
        layout.addLayout(stats_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        layout.addWidget(self.progress_bar)

        # Live output
        self.live_output = QTextEdit()
        self.live_output.setReadOnly(True)
        self.live_output.setFont(QFont("Neuropol X", 9))
        self.live_output.setPlaceholderText("Attack output will appear here...")
        layout.addWidget(self.live_output)

    def set_attack_config(self, config: dict):
        """Set the attack configuration (called by AttackConfigurationComponent)."""
        self._attack_config = config

    def start_attack(self):
        """Start the cracking attack."""
        if not self._attack_config:
            self.live_output.append("[!] No attack configured. Use Attack Configuration first.")
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.live_output.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting...")

        self.worker = CrackWorker(self._attack_config)
        self.worker.output_signal.connect(self.live_output.append)
        self.worker.cracked_signal.connect(self._on_cracked)
        self.worker.stats_signal.connect(self._update_stats)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def stop_attack(self):
        """Stop the running attack."""
        if self.worker:
            self.worker.stop()
        self.status_label.setText("Stopping...")

    def _on_cracked(self, result: dict):
        self.cracked_result.emit(result)

    def _update_stats(self, stats: dict):
        self.status_label.setText(stats.get("status", ""))
        self.speed_label.setText(stats.get("speed", "—"))
        self.recovered_label.setText(stats.get("recovered", "—"))

    def _on_finished(self, exit_code: int):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if exit_code == 0:
            self.status_label.setText("Cracked ✓")
        elif exit_code == 1:
            self.status_label.setText("Exhausted")
        else:
            self.status_label.setText("Error")

        if self.worker:
            self.worker.quit()
            self.worker.wait(3000)
            self.worker = None
