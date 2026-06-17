# app/core/credential_manager.py
"""
Credential manager for scan-time credentials (usernames, passwords, hashes,
Kerberos tickets, etc. discovered or used during an engagement).

Storage
-------
Credentials are persisted per-engagement inside the engagement directory:
``resources/engagements/<engagement_id>/credentials.enc``

Files are Fernet-encrypted using the same key as SecureCredentialManager —
**no plaintext passwords are ever written to disk**.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.fernet import InvalidToken

from app.core.logger import logger


@dataclass
class Credential:
    """Represents a credential entry"""
    username: str
    password: str
    domain: str = ""
    service: str = ""
    notes: str = ""
    source: str = "manual"   # manual | enumeration | exploitation
    credential_type: str = "Username/Password"
    # Username/Password | NTLM Hash | Kerberos Ticket | SQL Server Auth | Windows Auth | API Key

    def to_dict(self) -> Dict:
        return {
            'username': self.username,
            'password': self.password,
            'domain': self.domain,
            'service': self.service,
            'notes': self.notes,
            'source': self.source,
            'credential_type': self.credential_type,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Credential':
        return cls(
            username=data.get('username', ''),
            password=data.get('password', ''),
            domain=data.get('domain', ''),
            service=data.get('service', ''),
            notes=data.get('notes', ''),
            source=data.get('source', 'manual'),
            credential_type=data.get('credential_type', 'Username/Password'),
        )

    def display_text(self) -> str:
        """Human-readable credential label (no password exposed)."""
        parts = []
        if self.credential_type == "Username/Password":
            parts.append(
                f"{self.domain}\\{self.username}" if self.domain else self.username
            )
        elif self.credential_type == "NTLM Hash":
            parts.append(f"{self.username} (NTLM)")
        elif self.credential_type == "Kerberos Ticket":
            parts.append(f"Ticket: {self.password}")
        elif self.credential_type == "SQL Server Auth":
            parts.append(f"{self.username} (SQL Auth)")
        elif self.credential_type == "Windows Auth":
            parts.append(
                f"{self.domain}\\{self.username} (Windows)"
                if self.domain
                else f"{self.username} (Windows)"
            )
        elif self.credential_type == "API Key":
            parts.append(f"{self.username} (API Key)")
        if self.service:
            parts.append(f"({self.service})")
        if self.notes:
            parts.append(f"- {self.notes}")
        return " ".join(parts)


class CredentialManager:
    """Manages credentials discovered during testing.

    All persistence goes through :class:`~app.core.secure_credential_manager.SecureCredentialManager`
    so that credentials are Fernet-encrypted at rest.  The in-memory
    ``Credential`` objects are plain dataclasses for ease of use within the
    application; they are only serialised (and encrypted) when saved.
    """

    def __init__(self):
        self.credentials: List[Credential] = []
        self.profile_credentials: Dict[str, List[Credential]] = {}
        self.current_profile: Optional[str] = None
        self._explicit_profile: Optional[str] = None   # set when user picks a named profile

        # Don't auto-load any profile at startup. Credentials are loaded
        # when the user explicitly selects a profile in the UI (which calls
        # set_profile). This prevents stale data from appearing before a
        # profile is selected.

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_credential(
        self,
        username: str,
        password: str,
        domain: str = "",
        service: str = "",
        notes: str = "",
        source: str = "manual",
        credential_type: str = "Username/Password",
    ) -> Credential:
        """Add a new credential and auto-save."""
        cred = Credential(username, password, domain, service, notes, source,
                          credential_type)
        self.credentials.append(cred)
        if self.current_profile:
            self._save_profile_credentials()
        return cred

    def remove_credential(self, index: int) -> bool:
        """Remove credential by index and auto-save."""
        if 0 <= index < len(self.credentials):
            del self.credentials[index]
            if self.current_profile:
                self._save_profile_credentials()
            return True
        return False

    def get_credentials(self, service: str = None) -> List[Credential]:
        """Return credentials, optionally filtered by service."""
        if service:
            return [c for c in self.credentials
                    if c.service.lower() == service.lower()]
        return self.credentials.copy()

    def get_credentials_by_auth_type(self, auth_type: str) -> List[Credential]:
        """Return credentials filtered by authentication type."""
        mapping = {
            'Credentials':      'Username/Password',
            'Pass-the-Hash':    'NTLM Hash',
            'Kerberos Ticket':  'Kerberos Ticket',
            'Kerberos Password':'Username/Password',
            'SQL Server Auth':  'SQL Server Auth',
            'Windows Auth':     'Windows Auth',
            'API Key':          'API Key',
        }
        target_type = mapping.get(auth_type)
        if target_type is None:
            return []
        return [c for c in self.credentials
                if getattr(c, 'credential_type', 'Username/Password') == target_type]

    def clear_credentials(self):
        """Clear all in-memory credentials (does not delete persisted file)."""
        self.credentials.clear()

    def to_dict(self) -> Dict:
        """Serialise credentials to a plain dictionary."""
        return {'credentials': [c.to_dict() for c in self.credentials]}

    def from_dict(self, data: Dict):
        """Deserialise credentials from a plain dictionary."""
        self.credentials.clear()
        for cred_data in data.get('credentials', []):
            self.credentials.append(Credential.from_dict(cred_data))

    def set_profile(self, engagement_id: str):
        """Switch to a different engagement — load only, never saves.

        Saving happens exclusively via add_credential(), remove_credential(),
        and save_to_profile_json(). Engagement switching must never overwrite
        the target engagement's file with stale in-memory data.
        """
        self.current_profile = engagement_id
        self._explicit_profile = engagement_id
        self._persist_explicit_profile(engagement_id)
        self.credentials.clear()
        self._load_profile_credentials()

    def _persist_explicit_profile(self, engagement_id: str):
        """Write the active engagement ID to disk so it survives restarts."""
        try:
            import os as _os
            path = _os.path.join(
                _os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))),
                "resources", "config", "last_engagement.json"
            )
            _os.makedirs(_os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                import json as _json
                _json.dump({"engagement_id": engagement_id}, f)
        except Exception as exc:
            logger.debug(f"Could not persist active engagement: {exc}")

    @staticmethod
    def _load_explicit_profile() -> Optional[str]:
        """Return the last active engagement ID, or None."""
        try:
            import os as _os, json as _json
            # Try new format first
            path = _os.path.join(
                _os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))),
                "resources", "config", "last_engagement.json"
            )
            if _os.path.exists(path):
                data = _json.load(open(path))
                return data.get("engagement_id") or data.get("explicit_profile")
            # Fallback to legacy format
            legacy_path = _os.path.join(
                _os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))),
                "resources", "config", "last_profile.json"
            )
            if _os.path.exists(legacy_path):
                return _json.load(open(legacy_path)).get("explicit_profile")
        except Exception:
            pass
        return None

    def get_profile_credentials(self, profile_name: str) -> List[Credential]:
        return self.profile_credentials.get(profile_name, [])

    def clear_profile_credentials(self, profile_name: str):
        if profile_name in self.profile_credentials:
            del self.profile_credentials[profile_name]
        if self.current_profile == profile_name:
            self.credentials.clear()

    def get_credential_summary(self) -> str:
        if not self.credentials:
            return "No credentials stored"
        by_source: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for cred in self.credentials:
            by_source[cred.source] = by_source.get(cred.source, 0) + 1
            ct = getattr(cred, 'credential_type', 'Username/Password')
            by_type[ct] = by_type.get(ct, 0) + 1
        parts = [f"{v} {k}" for k, v in by_source.items()]
        type_parts = [
            f"{v} {k.replace('Username/Password','User/Pass').replace('SQL Server Auth','SQL').replace('Windows Auth','Win')}"
            for k, v in by_type.items()
        ]
        return (
            f"Total: {len(self.credentials)} ({', '.join(parts)}) "
            f"| Types: {', '.join(type_parts)}"
        )

    def get_current_profile(self) -> str:
        return self.current_profile or "default"

    def save_to_profile_json(self):
        """Public alias — saves credentials for the current profile."""
        self._save_profile_credentials()

    # ------------------------------------------------------------------
    # MSSQL helpers
    # ------------------------------------------------------------------

    def get_mssql_credentials(self) -> List[Credential]:
        return [c for c in self.credentials
                if c.credential_type in ('SQL Server Auth', 'Windows Auth')]

    def add_sql_server_credential(self, username: str, password: str,
                                   notes: str = "") -> Credential:
        return self.add_credential(username, password, "", "MSSQL", notes,
                                   "manual", "SQL Server Auth")

    def add_windows_auth_credential(self, username: str, password: str,
                                     domain: str, notes: str = "") -> Credential:
        return self.add_credential(username, password, domain, "MSSQL", notes,
                                   "manual", "Windows Auth")

    # ------------------------------------------------------------------
    # Internal persistence (encrypted)
    # ------------------------------------------------------------------

    def _get_enc_file_path(self) -> Path:
        """Return the path to the encrypted credential file for the current engagement.

        Credentials are stored inside the engagement directory:
        resources/engagements/<engagement_id>/credentials.enc
        """
        engagement_id = self.current_profile or "default"
        project_root = Path(__file__).parent.parent.parent
        eng_dir = project_root / "resources" / "engagements" / engagement_id
        eng_dir.mkdir(parents=True, exist_ok=True)
        return eng_dir / "credentials.enc"

    def _get_fernet(self):
        """Return the Fernet cipher from SecureCredentialManager."""
        # Import lazily to avoid circular imports at module load time.
        from app.core.secure_credential_manager import secure_credential_manager
        return secure_credential_manager

    def _save_profile_credentials(self):
        """Encrypt and persist credentials for the current profile.

        Uses ``_resolve_current_profile()`` so the save always targets the
        active session's file, even if the singleton was created before the
        session was established.
        """
        profile = self._resolve_current_profile()
        if not profile:
            return
        # Keep current_profile in sync so subsequent reads use the same file.
        self.current_profile = profile
        try:
            scm = self._get_fernet()
            json_bytes = json.dumps(self.to_dict()).encode('utf-8')
            encrypted = scm.encrypt_data(json_bytes)
            enc_path = self._get_enc_file_path()
            enc_path.write_bytes(encrypted)
            logger.debug(
                f"Credentials saved (encrypted) for profile '{profile}'"
            )
        except Exception as e:
            logger.error(
                f"Error saving credentials for profile '{profile}': {e}",
                exc_info=True,
            )

    def _load_profile_credentials(self):
        """Load and decrypt credentials for the current engagement."""
        if not self.current_profile:
            return

        enc_path = self._get_enc_file_path()

        if not enc_path.exists():
            return

        try:
            scm = self._get_fernet()
            encrypted = enc_path.read_bytes()
            decrypted = scm.decrypt_data(encrypted)
            data = json.loads(decrypted.decode('utf-8'))
            self.from_dict(data)
            logger.debug(
                f"Credentials loaded for engagement '{self.current_profile}'"
            )
        except InvalidToken:
            logger.error(
                f"Failed to decrypt credentials for engagement "
                f"'{self.current_profile}' — wrong key or corrupted file."
            )
        except Exception as e:
            logger.error(
                f"Error loading credentials for profile "
                f"'{self.current_profile}': {e}",
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Profile auto-detection
    # ------------------------------------------------------------------

    def _resolve_current_profile(self) -> str:
        """Return the engagement ID that should be active right now.

        Priority:
        1. Explicit engagement ID set by the user via set_profile() from the UI
           — this always wins.
        2. Active session ID from the session manager (for session-scoped saves).
        3. self.current_profile as set at init time.
        4. "default" fallback.
        """
        if self._explicit_profile:
            return self._explicit_profile

        try:
            import sys
            if 'app.core.session_manager' in sys.modules:
                session_module = sys.modules['app.core.session_manager']
                if hasattr(session_module, 'session_manager'):
                    current_session = (
                        session_module.session_manager.get_current_session()
                    )
                    if current_session:
                        return current_session['id']
        except Exception:
            pass
        return self.current_profile or "default"

    def _auto_set_profile(self):
        """Automatically set profile from session manager if available."""
        try:
            import sys
            if 'app.core.session_manager' in sys.modules:
                session_module = sys.modules['app.core.session_manager']
                if hasattr(session_module, 'session_manager'):
                    current_session = (
                        session_module.session_manager.get_current_session()
                    )
                    if current_session:
                        self.current_profile = current_session['id']
                        return
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        self.current_profile = "default"


# ---------------------------------------------------------------------------
# Module-level singletons and helpers
# ---------------------------------------------------------------------------

# Global credential manager instance
credential_manager = CredentialManager()


def get_mssql_credentials_for_auth_type(auth_type: str) -> List[Credential]:
    """Get MSSQL credentials filtered by authentication type."""
    return credential_manager.get_credentials_by_auth_type(auth_type)


def sync_credential_profile_with_session():
    """Sync credential manager profile with current session."""
    try:
        from app.core.session_manager import session_manager as _sm
        current_session = _sm.get_current_session()
        if current_session:
            credential_manager.set_profile(current_session['id'])
        else:
            credential_manager.set_profile("default")
    except Exception as e:
        logger.error(f"Error syncing credential profile: {e}", exc_info=True)


def get_mssql_auth_options() -> List[str]:
    """Get available MSSQL authentication options."""
    return ['SQL Server Auth', 'Windows Auth']
