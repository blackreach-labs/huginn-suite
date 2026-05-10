# resources/rpc/secure_credential_manager.py
# Re-export the canonical singleton from app/core to prevent duplicate instances.
# Previously this file contained a full copy of the class, creating a second
# independent SecureCredentialManager instance with its own separate key and
# credential store — credentials saved via one instance were invisible to the other.
from app.core.secure_credential_manager import (
    SecureCredential,
    SecureMemory,
    SecretsManagerIntegration,
    SecureCredentialManager,
    secure_credential_manager,
)

__all__ = [
    "SecureCredential",
    "SecureMemory",
    "SecretsManagerIntegration",
    "SecureCredentialManager",
    "secure_credential_manager",
]
