"""Hash lookup application service"""

from typing import Optional
from domain.services.hash_lookup_manager import HashLookupManager
from domain.models.hash_record import HashRecord
from infrastructure.external.hash_source_updater import HashSourceUpdater
from shared.events.hash_events import (
    HashLookupStartedEvent, HashLookupCompletedEvent,
    HashUpdateStartedEvent, HashUpdateCompletedEvent
)

class HashLookupService:
    def __init__(self, manager: HashLookupManager, updater: HashSourceUpdater):
        self.manager = manager
        self.updater = updater
    
    def lookup_single_hash(self, hash_value: str, source_name: str = "Local") -> Optional[HashRecord]:
        """Lookup single hash value using specified source"""
        # Emit start event
        # event_bus.emit(HashLookupStartedEvent(hash_value, source_name))
        
        result = self.manager.lookup_hash(hash_value, source_name)
        
        # Emit completion event
        # event_bus.emit(HashLookupCompletedEvent(hash_value, result))
        
        return result
    
    def update_source(self, source_name: str) -> int:
        """Update hash database from source"""
        # Emit start event
        # event_bus.emit(HashUpdateStartedEvent(source_name))
        
        count = self.updater.update_source(source_name)
        
        # Emit completion event
        # event_bus.emit(HashUpdateCompletedEvent(source_name, count))
        
        return count
    
    def get_database_stats(self) -> dict:
        """Get database statistics"""
        return self.manager.repository.get_stats()
    
    def get_hash_info(self, hash_value: str) -> dict:
        """Get hash information"""
        return {
            "hash": hash_value,
            "type": self.manager.get_hash_type(hash_value),
            "valid": self.manager._validate_hash(hash_value)
        }
    
    def get_available_sources(self) -> list:
        """Get list of available lookup sources"""
        sources = []
        
        # Add local sources
        stats = self.get_database_stats()
        for source_name, count in stats['sources'].items():
            if count > 0:
                sources.append(f"Local: {source_name}")
        
        # Add online sources
        from shared.configuration.hash_config import API_PROVIDERS
        for provider in API_PROVIDERS.keys():
            sources.append(f"Online: {provider}")
        
        return sources