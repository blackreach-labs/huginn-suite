# resources/rpc/dns_settings.py
# Re-export the canonical singleton from app/core to prevent duplicate instances.
# Previously this file contained a full copy of the class, creating a second
# independent DNSSettingsManager instance that did not share state with the
# one used by the rest of the application.
from app.core.dns_settings import DNSSettingsManager, dns_settings

__all__ = ["DNSSettingsManager", "dns_settings"]
