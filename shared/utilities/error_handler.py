import logging
import traceback
from typing import Optional, Callable, Any
from functools import wraps
from ..events.event_bus import EventBus
from ..events.plugin_events import PluginErrorEvent

class ErrorHandler:
    """Advanced error handling with logging and event publishing"""
    
    def __init__(self, logger: Optional[logging.Logger] = None, event_bus: Optional[EventBus] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.event_bus = event_bus
    
    def handle_error(self, error: Exception, context: str = "", publish_event: bool = True) -> None:
        """Handle error with logging and optional event publishing"""
        error_msg = f"{context}: {str(error)}" if context else str(error)
        stack_trace = traceback.format_exc()
        
        self.logger.error(error_msg)
        self.logger.debug(stack_trace)
        
        if publish_event and self.event_bus:
            self.event_bus.publish(PluginErrorEvent(
                plugin_name=context,
                error_message=error_msg,
                stack_trace=stack_trace
            ))
    
    def with_error_handling(self, context: str = "", reraise: bool = False):
        """Decorator for automatic error handling"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    self.handle_error(e, context or func.__name__)
                    if reraise:
                        raise
                    return None
            return wrapper
        return decorator

# Global error handler instance
error_handler = ErrorHandler()