"""Hash repository interface"""

from abc import ABC, abstractmethod
from typing import Optional, List, Tuple

class HashRepository(ABC):
    @abstractmethod
    def lookup(self, hash_value: str) -> Optional[str]:
        """Lookup plaintext for hash"""
        pass
    
    @abstractmethod
    def bulk_insert(self, records: List[Tuple[str, str, str]]) -> None:
        """Bulk insert hash records"""
        pass
    
    @abstractmethod
    def get_stats(self) -> dict:
        """Get database statistics"""
        pass