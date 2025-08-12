"""Hash lookup events"""

from dataclasses import dataclass
from typing import Optional
from domain.models.hash_record import HashRecord

@dataclass
class HashLookupStartedEvent:
    hash_value: str
    source_name: str

@dataclass
class HashLookupCompletedEvent:
    hash_value: str
    result: Optional[HashRecord]

@dataclass
class HashUpdateStartedEvent:
    source_name: str

@dataclass
class HashUpdateCompletedEvent:
    source_name: str
    records_added: int