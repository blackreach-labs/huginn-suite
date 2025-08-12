from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

@dataclass
class PluginLoadedEvent:
    type: str = "plugin_loaded"
    plugin_name: str = ""
    file_path: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class PluginExecutedEvent:
    type: str = "plugin_executed"
    plugin_name: str = ""
    success: bool = True
    result: Any = None
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class PluginErrorEvent:
    type: str = "plugin_error"
    plugin_name: str = ""
    error_message: str = ""
    stack_trace: str = ""
    timestamp: datetime = field(default_factory=datetime.now)