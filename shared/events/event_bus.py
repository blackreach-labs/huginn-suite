"""Event bus system for decoupled communication."""
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Callable, Any


@dataclass
class ScanStartedEvent:
    """Event emitted when a scan starts."""
    type: str = "scan_started"
    scan_id: str = ""
    target: str = ""
    scanner_type: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScanCompletedEvent:
    """Event emitted when a scan completes successfully."""
    type: str = "scan_completed"
    scan_id: str = ""
    results: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScanErrorEvent:
    """Event emitted when a scan encounters an error."""
    type: str = "scan_error"
    scan_id: str = ""
    error: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ScanProgressEvent:
    """Event emitted for scan progress updates."""
    type: str = "scan_progress"
    scan_id: str = ""
    current: int = 0
    total: int = 0
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


class EventBus:
    """Central event bus for application-wide communication."""
    
    def __init__(self):
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)
    
    def subscribe(self, event_type: str, handler: Callable):
        """Subscribe to an event type."""
        self.subscribers[event_type].append(handler)
    
    def unsubscribe(self, event_type: str, handler: Callable):
        """Unsubscribe from an event type."""
        if handler in self.subscribers[event_type]:
            self.subscribers[event_type].remove(handler)
    
    def publish(self, event):
        """Publish an event to all subscribers."""
        event_type = getattr(event, 'type', type(event).__name__)
        
        for handler in self.subscribers[event_type]:
            try:
                handler(event)
            except Exception as e:
                print(f"Error in event handler for {event_type}: {e}")
    
    def clear_subscribers(self, event_type: str = None):
        """Clear subscribers for a specific event type or all."""
        if event_type:
            self.subscribers[event_type].clear()
        else:
            self.subscribers.clear()


# Global event bus instance
_event_bus = None

def get_event_bus() -> EventBus:
    """Get global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus