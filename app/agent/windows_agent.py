#!/usr/bin/env python3
"""
Windows Agent - Native service component
Handles privileged operations with HMAC attestation and audit logging.

Attestation model
-----------------
Privileged operations (modify_firewall, modify_defender) require a signed
attestation token produced by the orchestrator.  The token is an HMAC-SHA256
MAC over a canonical message:

    "<operation>:<nonce>:<expiry_unix_timestamp>"

using a shared secret read from the ``HUGINN_AGENT_SECRET`` environment
variable (or a key file — see ``_load_agent_secret``).

The orchestrator creates a token with :func:`create_attestation_token` and
passes it to the agent.  The agent verifies it with :meth:`verify_attestation`.
Tokens are single-use: once accepted they are marked ``used=TRUE`` in the
audit database and rejected on any subsequent call.

Key properties
~~~~~~~~~~~~~~
- Secret never appears in source code.
- Each token carries a nonce (random 32-byte hex) — replay is impossible even
  if the same operation is requested twice within the validity window.
- Tokens expire after ``ATTESTATION_VALIDITY_SECONDS`` (default 300 s).
- Constant-time comparison prevents timing side-channels.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attestation constants
# ---------------------------------------------------------------------------

# How long (seconds) an attestation token remains valid after creation.
ATTESTATION_VALIDITY_SECONDS = 300  # 5 minutes

# Environment variable that holds the shared HMAC secret.
_SECRET_ENV_VAR = "HUGINN_AGENT_SECRET"

# Fallback key-file path (owner-read-only, 0o600).
_SECRET_KEY_FILE = Path(os.environ.get("HUGINN_AGENT_KEY_FILE",
                                        str(Path.home() / ".huginn" / "agent.key")))


# ---------------------------------------------------------------------------
# Secret management
# ---------------------------------------------------------------------------

def _load_agent_secret() -> bytes:
    """Load the HMAC secret for attestation.

    Priority:
    1. ``HUGINN_AGENT_SECRET`` environment variable (hex-encoded).
    2. Key file at ``HUGINN_AGENT_KEY_FILE`` (default ``~/.huginn/agent.key``).
    3. Generate a new random secret, persist it to the key file, and warn.

    The secret must be at least 32 bytes (256 bits).  Shorter values are
    rejected to prevent weak-key attacks.
    """
    # 1. Environment variable
    env_secret = os.environ.get(_SECRET_ENV_VAR, "")
    if env_secret:
        try:
            raw = bytes.fromhex(env_secret)
            if len(raw) < 32:
                raise ValueError("Secret too short (< 32 bytes)")
            return raw
        except (ValueError, TypeError) as e:
            logger.error(
                f"Invalid {_SECRET_ENV_VAR}: {e}. "
                "Falling back to key file."
            )

    # 2. Key file
    if _SECRET_KEY_FILE.exists():
        try:
            raw = bytes.fromhex(_SECRET_KEY_FILE.read_text().strip())
            if len(raw) < 32:
                raise ValueError("Key file secret too short (< 32 bytes)")
            return raw
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid key file {_SECRET_KEY_FILE}: {e}. Regenerating.")

    # 3. Generate and persist
    logger.warning(
        f"No agent secret found in {_SECRET_ENV_VAR} or {_SECRET_KEY_FILE}. "
        "Generating a new random secret.  Set HUGINN_AGENT_SECRET or "
        f"protect {_SECRET_KEY_FILE} (chmod 600)."
    )
    raw = secrets.token_bytes(32)
    try:
        _SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SECRET_KEY_FILE.write_text(raw.hex())
        os.chmod(_SECRET_KEY_FILE, 0o600)
    except OSError as e:
        logger.error(f"Could not persist agent secret: {e}")
    return raw


def _canonical_message(operation: str, nonce: str, expiry: int) -> bytes:
    """Build the canonical HMAC message for an attestation token."""
    return f"{operation}:{nonce}:{expiry}".encode("utf-8")


def create_attestation_token(operation: str,
                              secret: Optional[bytes] = None,
                              validity_seconds: int = ATTESTATION_VALIDITY_SECONDS
                              ) -> Dict[str, str]:
    """Create a signed attestation token for a privileged operation.

    This is called by the **orchestrator** (not the agent itself).

    Returns a dict with keys:
        ``operation``, ``nonce``, ``expiry``, ``mac``

    Pass the entire dict (JSON-serialised) as the ``attestation_data``
    argument to :meth:`WindowsAgent.verify_attestation`.

    Example::

        token = create_attestation_token("modify_firewall")
        agent.modify_firewall(rule_name, action, json.dumps(token))
    """
    if secret is None:
        secret = _load_agent_secret()
    nonce = secrets.token_hex(32)
    expiry = int(time.time()) + validity_seconds
    msg = _canonical_message(operation, nonce, expiry)
    mac = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return {
        "operation": operation,
        "nonce": nonce,
        "expiry": str(expiry),
        "mac": mac,
    }


# ---------------------------------------------------------------------------
# Main agent class
# ---------------------------------------------------------------------------

class WindowsAgent:
    """Windows agent that executes privileged operations with attestation."""

    def __init__(self, config_path: str = "agent_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self.audit_db = "agent_audit.db"
        self._init_audit_db()
        self._secret = _load_agent_secret()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _load_config(self) -> Dict[str, Any]:
        """Load agent configuration."""
        default_config = {
            "allowed_operations": [
                "collect_eventlogs",
                "collect_processes",
                "collect_screenshots",
                "collect_network_info",
            ],
            "restricted_operations": [
                "modify_firewall",
                "modify_defender",
                "collect_pcap",
            ],
            "audit_retention_days": 90,
            "max_evidence_size_mb": 100,
        }
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    config = json.load(f)
                default_config.update(config)
            except Exception as e:
                logger.error(f"Failed to load config {self.config_path}: {e}")
        return default_config

    # ------------------------------------------------------------------
    # Audit database
    # ------------------------------------------------------------------

    def _init_audit_db(self):
        """Initialise the audit database."""
        try:
            conn = sqlite3.connect(self.audit_db)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    log_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    user_context TEXT NOT NULL,
                    attestation_nonce TEXT,
                    success BOOLEAN NOT NULL,
                    details TEXT NOT NULL,
                    evidence_path TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attestations (
                    attestation_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    nonce TEXT NOT NULL UNIQUE,
                    valid_until TEXT NOT NULL,
                    used BOOLEAN DEFAULT FALSE
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to initialise audit DB: {e}")

    # ------------------------------------------------------------------
    # Attestation
    # ------------------------------------------------------------------

    def verify_attestation(self, operation: str, attestation_data: str) -> bool:
        """Verify a signed attestation token for a privileged operation.

        ``attestation_data`` must be a JSON string produced by
        :func:`create_attestation_token`.

        Verification steps
        ~~~~~~~~~~~~~~~~~~
        1. Parse the JSON token.
        2. Check the ``operation`` field matches the requested operation.
        3. Check the token has not expired.
        4. Recompute the HMAC and compare in constant time.
        5. Check the nonce has not been used before (replay protection).
        6. Mark the nonce as used in the audit database.

        Returns ``True`` only if all checks pass.
        """
        try:
            token = json.loads(attestation_data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Attestation parse error for {operation}: {e}")
            self._audit_log(operation, "SYSTEM", None, False,
                            "Attestation parse error")
            return False

        token_op = token.get("operation", "")
        nonce = token.get("nonce", "")
        expiry_str = token.get("expiry", "0")
        provided_mac = token.get("mac", "")

        # 1. Operation must match
        if token_op != operation:
            logger.warning(
                f"Attestation operation mismatch: expected {operation!r}, "
                f"got {token_op!r}"
            )
            self._audit_log(operation, "SYSTEM", nonce, False,
                            "Attestation operation mismatch")
            return False

        # 2. Expiry check
        try:
            expiry = int(expiry_str)
        except (ValueError, TypeError):
            self._audit_log(operation, "SYSTEM", nonce, False,
                            "Attestation expiry invalid")
            return False

        if time.time() > expiry:
            logger.warning(f"Attestation expired for {operation}")
            self._audit_log(operation, "SYSTEM", nonce, False,
                            "Attestation expired")
            return False

        # 3. HMAC verification (constant-time)
        msg = _canonical_message(operation, nonce, expiry)
        expected_mac = hmac.new(self._secret, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_mac, provided_mac):
            logger.warning(f"Attestation MAC invalid for {operation}")
            self._audit_log(operation, "SYSTEM", nonce, False,
                            "Attestation MAC invalid")
            return False

        # 4. Replay protection — nonce must not have been used before
        try:
            conn = sqlite3.connect(self.audit_db)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT used FROM attestations WHERE nonce = ?", (nonce,)
            )
            row = cursor.fetchone()
            if row is not None:
                conn.close()
                logger.warning(
                    f"Attestation nonce replay attempt for {operation}"
                )
                self._audit_log(operation, "SYSTEM", nonce, False,
                                "Attestation nonce already used (replay)")
                return False

            # 5. Record the nonce as used
            cursor.execute(
                """
                INSERT INTO attestations
                    (attestation_id, timestamp, operation, nonce, valid_until, used)
                VALUES (?, ?, ?, ?, ?, TRUE)
                """,
                (
                    str(uuid.uuid4()),
                    datetime.now().isoformat(),
                    operation,
                    nonce,
                    datetime.fromtimestamp(expiry).isoformat(),
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Attestation DB error for {operation}: {e}")
            self._audit_log(operation, "SYSTEM", nonce, False,
                            f"Attestation DB error: {e}")
            return False

        logger.info(f"Attestation verified for {operation} (nonce={nonce[:8]}…)")
        return True

    # ------------------------------------------------------------------
    # Allowed operations (no attestation required)
    # ------------------------------------------------------------------

    def collect_eventlogs(self, log_names: List[str], hours_back: int = 24) -> str:
        """Collect Windows Event Logs."""
        operation = "collect_eventlogs"
        if operation not in self.config["allowed_operations"]:
            self._audit_log(operation, "SYSTEM", None, False, "Operation not allowed")
            return ""

        try:
            events = []
            for log_name in log_names:
                # Validate log_name — only allow alphanumeric, spaces, hyphens,
                # forward slashes (e.g. "Microsoft-Windows-Security-Auditing").
                if not all(c.isalnum() or c in (' ', '-', '/', '_') for c in log_name):
                    logger.warning(f"Skipping invalid log name: {log_name!r}")
                    continue
                try:
                    # Pass log name and hours_back as separate PS arguments to
                    # avoid injection via a crafted log_name string.
                    ps_command = (
                        f'Get-WinEvent -LogName $env:LOG_NAME -MaxEvents 1000 | '
                        f'Where-Object {{$_.TimeCreated -gt (Get-Date).AddHours(-{int(hours_back)})}} | '
                        f'Select-Object TimeCreated, Id, LevelDisplayName, Message | '
                        f'ConvertTo-Json'
                    )
                    result = subprocess.run(
                        ["powershell", "-Command", ps_command],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        env={**os.environ, "LOG_NAME": log_name},
                    )
                    if result.returncode == 0 and result.stdout:
                        log_events = json.loads(result.stdout)
                        if isinstance(log_events, list):
                            events.extend(log_events)
                        else:
                            events.append(log_events)
                except Exception as e:
                    self._audit_log(operation, "SYSTEM", None, False,
                                    f"Error collecting {log_name}: {e}")

            output_file = f"eventlogs_{int(time.time())}.json"
            evidence_path = Path("evidence") / output_file
            evidence_path.parent.mkdir(exist_ok=True)
            with open(evidence_path, "w") as f:
                json.dump(events, f, indent=2, default=str)

            self._audit_log(operation, "SYSTEM", None, True,
                            f"Collected {len(events)} events", str(evidence_path))
            return str(evidence_path)

        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False,
                            f"Collection failed: {e}")
            return ""

    def collect_processes(self) -> str:
        """Collect running processes."""
        operation = "collect_processes"
        if operation not in self.config["allowed_operations"]:
            self._audit_log(operation, "SYSTEM", None, False, "Operation not allowed")
            return ""
        try:
            ps_command = (
                "Get-Process | "
                "Select-Object Name, Id, CPU, WorkingSet, Path, Company | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                output_file = f"processes_{int(time.time())}.json"
                evidence_path = Path("evidence") / output_file
                evidence_path.parent.mkdir(exist_ok=True)
                with open(evidence_path, "w") as f:
                    f.write(result.stdout)
                self._audit_log(operation, "SYSTEM", None, True,
                                "Process list collected", str(evidence_path))
                return str(evidence_path)
        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False,
                            f"Collection failed: {e}")
        return ""

    def collect_screenshots(self, count: int = 1) -> List[str]:
        """Collect desktop screenshots."""
        operation = "collect_screenshots"
        if operation not in self.config["allowed_operations"]:
            self._audit_log(operation, "SYSTEM", None, False, "Operation not allowed")
            return []
        screenshots = []
        try:
            import PIL.ImageGrab as ImageGrab
            for i in range(max(1, int(count))):
                screenshot = ImageGrab.grab()
                filename = f"screenshot_{int(time.time())}_{i}.png"
                evidence_path = Path("evidence") / filename
                evidence_path.parent.mkdir(exist_ok=True)
                screenshot.save(evidence_path)
                screenshots.append(str(evidence_path))
                if count > 1:
                    time.sleep(2)
            self._audit_log(operation, "SYSTEM", None, True,
                            f"Collected {len(screenshots)} screenshots")
        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False,
                            f"Screenshot failed: {e}")
        return screenshots

    # ------------------------------------------------------------------
    # Restricted operations (attestation required)
    # ------------------------------------------------------------------

    def modify_firewall(self, rule_name: str, action: str,
                        attestation: str) -> bool:
        """Modify Windows Firewall rules (requires valid attestation token).

        ``rule_name`` is passed to PowerShell via an environment variable to
        prevent PS injection.  ``action`` is validated against an allowlist.
        """
        operation = "modify_firewall"
        if not self.verify_attestation(operation, attestation):
            return False

        # Validate action against allowlist
        if action not in ("add", "remove"):
            self._audit_log(operation, "SYSTEM", None, False,
                            f"Invalid action: {action!r}")
            return False

        try:
            if action == "add":
                ps_command = (
                    'New-NetFirewallRule -DisplayName $env:RULE_NAME '
                    '-Direction Inbound -Action Allow -Protocol TCP -LocalPort 4444'
                )
            else:  # remove
                ps_command = 'Remove-NetFirewallRule -DisplayName $env:RULE_NAME'

            # Pass rule_name via environment variable — never interpolated
            # into the PS command string, preventing PS injection.
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, "RULE_NAME": rule_name},
            )
            success = result.returncode == 0
            details = f"Firewall rule {action}: {rule_name}"
            if not success:
                details += f" — Error: {result.stderr.strip()}"
            self._audit_log(operation, "SYSTEM", None, success, details)
            return success

        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False,
                            f"Firewall modification failed: {e}")
            return False

    def modify_defender(self, exclusion_path: str, action: str,
                        attestation: str) -> bool:
        """Modify Windows Defender exclusions (requires valid attestation token).

        ``exclusion_path`` is passed via an environment variable to prevent
        PS injection.  ``action`` is validated against an allowlist.
        """
        operation = "modify_defender"
        if not self.verify_attestation(operation, attestation):
            return False

        if action not in ("add", "remove"):
            self._audit_log(operation, "SYSTEM", None, False,
                            f"Invalid action: {action!r}")
            return False

        try:
            if action == "add":
                ps_command = 'Add-MpPreference -ExclusionPath $env:EXCL_PATH'
            else:  # remove
                ps_command = 'Remove-MpPreference -ExclusionPath $env:EXCL_PATH'

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, "EXCL_PATH": exclusion_path},
            )
            success = result.returncode == 0
            details = f"Defender exclusion {action}: {exclusion_path}"
            if not success:
                details += f" — Error: {result.stderr.strip()}"
            self._audit_log(operation, "SYSTEM", None, success, details)
            return success

        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False,
                            f"Defender modification failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Self-clean
    # ------------------------------------------------------------------

    def self_clean(self):
        """Revert all successful system modifications recorded in the audit log."""
        operation = "self_clean"
        try:
            conn = sqlite3.connect(self.audit_db)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT operation, details FROM audit_logs
                WHERE success = 1
                  AND operation IN ('modify_firewall', 'modify_defender')
                ORDER BY timestamp DESC
                """
            )
            modifications = cursor.fetchall()
            conn.close()

            reverted = 0
            for op, details in modifications:
                try:
                    # Parse the structured details string safely.
                    # Format: "Firewall rule add: <name>" or
                    #         "Defender exclusion add: <path>"
                    # We only revert "add" operations.
                    if ": " not in details:
                        continue
                    action_part, value = details.split(": ", 1)
                    # Strip any trailing error annotation
                    value = value.split(" — Error:")[0].strip()

                    if op == "modify_firewall" and "add" in action_part:
                        result = subprocess.run(
                            ["powershell", "-Command",
                             "Remove-NetFirewallRule -DisplayName $env:RULE_NAME"],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            env={**os.environ, "RULE_NAME": value},
                        )
                        if result.returncode == 0:
                            reverted += 1
                        else:
                            logger.warning(
                                f"Failed to revert firewall rule {value!r}: "
                                f"{result.stderr.strip()}"
                            )

                    elif op == "modify_defender" and "add" in action_part:
                        result = subprocess.run(
                            ["powershell", "-Command",
                             "Remove-MpPreference -ExclusionPath $env:EXCL_PATH"],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            env={**os.environ, "EXCL_PATH": value},
                        )
                        if result.returncode == 0:
                            reverted += 1
                        else:
                            logger.warning(
                                f"Failed to revert Defender exclusion {value!r}: "
                                f"{result.stderr.strip()}"
                            )

                except Exception as e:
                    logger.error(f"Failed to revert '{details}': {e}")

            self._audit_log(operation, "SYSTEM", None, True,
                            f"Reverted {reverted} modifications")

        except Exception as e:
            self._audit_log(operation, "SYSTEM", None, False,
                            f"Self-clean failed: {e}")

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _audit_log(self, operation: str, user_context: str,
                   attestation_nonce: Optional[str],
                   success: bool, details: str,
                   evidence_path: Optional[str] = None):
        """Append an entry to the audit log."""
        try:
            conn = sqlite3.connect(self.audit_db)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_logs
                    (log_id, timestamp, operation, user_context,
                     attestation_nonce, success, details, evidence_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    datetime.now().isoformat(),
                    operation,
                    user_context,
                    attestation_nonce,
                    success,
                    details,
                    evidence_path,
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            # Audit failures must not silently swallow the original error.
            logger.error(f"Audit log write failed: {e}")

    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Return the most recent audit log entries."""
        try:
            conn = sqlite3.connect(self.audit_db)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
                (max(1, int(limit)),),
            )
            logs = []
            for row in cursor.fetchall():
                logs.append({
                    "log_id": row[0],
                    "timestamp": row[1],
                    "operation": row[2],
                    "user_context": row[3],
                    "attestation_nonce": row[4],
                    "success": bool(row[5]),
                    "details": row[6],
                    "evidence_path": row[7],
                })
            conn.close()
            return logs
        except Exception as e:
            logger.error(f"Failed to read audit logs: {e}")
            return []


# ---------------------------------------------------------------------------
# Windows Service wrapper
# ---------------------------------------------------------------------------

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager

    class HuginnAgentService(win32serviceutil.ServiceFramework):
        """Windows Service wrapper for Huginn Agent."""

        _svc_name_ = "HuginnAgent"
        _svc_display_name_ = "Huginn Security Agent"
        _svc_description_ = "Huginn Security Assessment Agent Service"

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.agent = WindowsAgent()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.agent.self_clean()
            win32event.SetEvent(self.hWaitStop)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            while True:
                rc = win32event.WaitForSingleObject(self.hWaitStop, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                # Periodic tasks would be dispatched here via RPC/REST.

except ImportError:
    # pywin32 not available (e.g. running on Linux for testing).
    HuginnAgentService = None  # type: ignore


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) == 1:
        # Standalone mode — basic smoke test
        agent = WindowsAgent()

        logger.info("Collecting event logs...")
        logs_path = agent.collect_eventlogs(["System", "Application"])
        logger.info(f"Event logs saved to: {logs_path}")

        logger.info("Collecting processes...")
        proc_path = agent.collect_processes()
        logger.info(f"Process list saved to: {proc_path}")

    elif HuginnAgentService is not None:
        win32serviceutil.HandleCommandLine(HuginnAgentService)
    else:
        logger.error("pywin32 not available — cannot run as Windows service.")
        sys.exit(1)
