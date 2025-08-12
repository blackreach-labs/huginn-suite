import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

class ScanState(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class SessionState:
    """Session state for scan management"""
    scan_id: str
    target: str
    profile: str
    state: ScanState = ScanState.IDLE
    start_time: float = field(default_factory=time.time)
    current_phase: str = ""
    phase_progress: int = 0
    total_phases: int = 23
    vulnerabilities_found: int = 0
    requests_made: int = 0
    errors: list = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class StateManager:
    """Manages scan session state and CSRF tokens"""
    
    def __init__(self):
        self.sessions: Dict[str, SessionState] = {}
        self.csrf_tokens: Dict[str, str] = {}
        self.form_states: Dict[str, Dict] = {}
    
    def create_session(self, scan_id: str, target: str, profile: str) -> SessionState:
        """Create new scan session"""
        session = SessionState(scan_id=scan_id, target=target, profile=profile)
        self.sessions[scan_id] = session
        return session
    
    def get_session(self, scan_id: str) -> Optional[SessionState]:
        """Get session by ID"""
        return self.sessions.get(scan_id)
    
    def update_session(self, scan_id: str, **updates):
        """Update session state"""
        if scan_id in self.sessions:
            for key, value in updates.items():
                if hasattr(self.sessions[scan_id], key):
                    setattr(self.sessions[scan_id], key, value)
    
    def set_csrf_token(self, form_action: str, token: str):
        """Store CSRF token for form"""
        self.csrf_tokens[form_action] = token
    
    def get_csrf_token(self, form_action: str) -> Optional[str]:
        """Get CSRF token for form"""
        return self.csrf_tokens.get(form_action)
    
    def store_form_state(self, form_id: str, state: Dict):
        """Store form state for multi-step testing"""
        self.form_states[form_id] = state
    
    def get_form_state(self, form_id: str) -> Dict:
        """Get stored form state"""
        return self.form_states.get(form_id, {})
    
    def cleanup_session(self, scan_id: str):
        """Clean up session data"""
        self.sessions.pop(scan_id, None)
        # Clean related CSRF tokens and form states
        keys_to_remove = [k for k in self.csrf_tokens.keys() if scan_id in k]
        for key in keys_to_remove:
            self.csrf_tokens.pop(key, None)