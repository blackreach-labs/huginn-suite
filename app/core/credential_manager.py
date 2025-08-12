# app/core/credential_manager.py
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path
import json

@dataclass
class Credential:
    """Represents a credential entry"""
    username: str
    password: str
    domain: str = ""
    service: str = ""
    notes: str = ""
    source: str = "manual"  # manual, enumeration, exploitation
    credential_type: str = "Username/Password"  # Username/Password, NTLM Hash, Kerberos Ticket, SQL Server Auth, Windows Auth
    
    def to_dict(self) -> Dict:
        return {
            'username': self.username,
            'password': self.password,
            'domain': self.domain,
            'service': self.service,
            'notes': self.notes,
            'source': self.source,
            'credential_type': self.credential_type
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
            credential_type=data.get('credential_type', 'Username/Password')
        )
    
    def display_text(self) -> str:
        """Get display text for credential"""
        parts = []
        
        if self.credential_type == "Username/Password":
            if self.domain:
                parts.append(f"{self.domain}\\{self.username}")
            else:
                parts.append(self.username)
        elif self.credential_type == "NTLM Hash":
            parts.append(f"{self.username} (NTLM)")
        elif self.credential_type == "Kerberos Ticket":
            parts.append(f"Ticket: {self.password}")
        elif self.credential_type == "SQL Server Auth":
            parts.append(f"{self.username} (SQL Auth)")
        elif self.credential_type == "Windows Auth":
            if self.domain:
                parts.append(f"{self.domain}\\{self.username} (Windows)")
            else:
                parts.append(f"{self.username} (Windows)")
        
        if self.service:
            parts.append(f"({self.service})")
        
        if self.notes:
            parts.append(f"- {self.notes}")
        
        return " ".join(parts)

class CredentialManager:
    """Manages credentials discovered during testing"""
    
    def __init__(self):
        self.credentials: List[Credential] = []
        self.profile_credentials: Dict[str, List[Credential]] = {}  # Profile-specific credentials
        self.current_profile: Optional[str] = None
        self._auto_set_profile()
        self._load_profile_credentials()
    
    def add_credential(self, username: str, password: str, domain: str = "", 
                     service: str = "", notes: str = "", source: str = "manual",
                     credential_type: str = "Username/Password") -> Credential:
        """Add a new credential"""
        cred = Credential(username, password, domain, service, notes, source, credential_type)
        self.credentials.append(cred)
        
        # Auto-save for current profile/tenant
        if self.current_profile:
            self._save_profile_credentials()
        
        return cred
    
    def remove_credential(self, index: int) -> bool:
        """Remove credential by index"""
        if 0 <= index < len(self.credentials):
            del self.credentials[index]
            
            # Auto-save for current profile/tenant
            if self.current_profile:
                self._save_profile_credentials()
            
            return True
        return False
    
    def get_credentials(self, service: str = None) -> List[Credential]:
        """Get credentials, optionally filtered by service"""
        if service:
            return [c for c in self.credentials if c.service.lower() == service.lower()]
        return self.credentials.copy()
    
    def get_credentials_by_auth_type(self, auth_type: str) -> List[Credential]:
        """Get credentials filtered by authentication type"""
        filtered_credentials = []
        
        for cred in self.credentials:
            cred_type = getattr(cred, 'credential_type', 'Username/Password')
            
            if auth_type == 'Credentials' and cred_type == 'Username/Password':
                filtered_credentials.append(cred)
            elif auth_type == 'Pass-the-Hash' and cred_type == 'NTLM Hash':
                filtered_credentials.append(cred)
            elif auth_type == 'Kerberos Ticket' and cred_type == 'Kerberos Ticket':
                filtered_credentials.append(cred)
            elif auth_type == 'Kerberos Password' and cred_type == 'Username/Password':
                filtered_credentials.append(cred)
            elif auth_type == 'SQL Server Auth' and cred_type == 'SQL Server Auth':
                filtered_credentials.append(cred)
            elif auth_type == 'Windows Auth' and cred_type == 'Windows Auth':
                filtered_credentials.append(cred)
        
        return filtered_credentials
    
    def clear_credentials(self):
        """Clear all credentials"""
        self.credentials.clear()
    
    def to_dict(self) -> Dict:
        """Export credentials to dictionary"""
        return {
            'credentials': [cred.to_dict() for cred in self.credentials]
        }
    
    def from_dict(self, data: Dict):
        """Import credentials from dictionary"""
        self.credentials.clear()
        for cred_data in data.get('credentials', []):
            self.credentials.append(Credential.from_dict(cred_data))
    
    def set_profile(self, profile_name: str):
        """Set current profile and load its credentials"""
        # Save current credentials to current profile
        if self.current_profile:
            self._save_profile_credentials()
        
        # Load credentials for new profile
        self.current_profile = profile_name
        self.credentials.clear()  # Clear current credentials
        self._load_profile_credentials()
    
    def get_profile_credentials(self, profile_name: str) -> List[Credential]:
        """Get credentials for specific profile"""
        return self.profile_credentials.get(profile_name, [])
    
    def clear_profile_credentials(self, profile_name: str):
        """Clear credentials for specific profile"""
        if profile_name in self.profile_credentials:
            del self.profile_credentials[profile_name]
        if self.current_profile == profile_name:
            self.credentials.clear()
    
    def get_credential_summary(self) -> str:
        """Get summary of credentials"""
        if not self.credentials:
            return "No credentials stored"
        
        by_source = {}
        by_type = {}
        for cred in self.credentials:
            source = cred.source
            if source not in by_source:
                by_source[source] = 0
            by_source[source] += 1
            
            cred_type = getattr(cred, 'credential_type', 'Username/Password')
            if cred_type not in by_type:
                by_type[cred_type] = 0
            by_type[cred_type] += 1
        
        parts = []
        for source, count in by_source.items():
            parts.append(f"{count} {source}")
        
        type_parts = []
        for cred_type, count in by_type.items():
            short_type = cred_type.replace("Username/Password", "User/Pass").replace("SQL Server Auth", "SQL").replace("Windows Auth", "Win")
            type_parts.append(f"{count} {short_type}")
        
        return f"Total: {len(self.credentials)} ({', '.join(parts)}) | Types: {', '.join(type_parts)}"
    
    def _get_credentials_file_path(self) -> str:
        """Get credentials file path for current profile"""
        project_root = Path(__file__).parent.parent.parent
        profiles_dir = project_root / "profiles"
        profiles_dir.mkdir(exist_ok=True)
        
        profile_name = self.current_profile or "default"
        return str(profiles_dir / f"{profile_name}_credentials.json")
    
    def _save_profile_credentials(self):
        """Save credentials for current profile"""
        if not self.current_profile:
            return
        
        try:
            # Save to separate credentials file
            credentials_file = self._get_credentials_file_path()
            data = self.to_dict()
            
            with open(credentials_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Also save to main profile JSON file if it exists
            self._save_to_main_profile_json()
            
        except Exception as e:
            print(f"Error saving profile credentials: {e}")
    
    def _save_to_main_profile_json(self):
        """Save credentials to main profile JSON file"""
        if not self.current_profile or self.current_profile == "default":
            return
        
        try:
            project_root = Path(__file__).parent.parent.parent
            profiles_dir = project_root / "profiles"
            profile_file = profiles_dir / f"{self.current_profile}.json"
            
            # Load existing profile or create new one
            profile_data = {}
            if profile_file.exists():
                try:
                    with open(profile_file, 'r') as f:
                        profile_data = json.load(f)
                except Exception:
                    pass
            
            # Update credentials section
            profile_data['credentials'] = self.to_dict()
            
            # Save back to file
            profiles_dir.mkdir(exist_ok=True)
            with open(profile_file, 'w') as f:
                json.dump(profile_data, f, indent=2)
                
        except Exception as e:
            print(f"Error saving to main profile JSON: {e}")
    
    def _load_profile_credentials(self):
        """Load credentials for current profile"""
        if not self.current_profile:
            return
        
        try:
            credentials_file = self._get_credentials_file_path()
            if Path(credentials_file).exists():
                with open(credentials_file, 'r') as f:
                    data = json.load(f)
                self.from_dict(data)
        except Exception as e:
            print(f"Error loading profile credentials: {e}")
    
    def _auto_set_profile(self):
        """Automatically set profile from session manager"""
        try:
            import sys
            if 'app.core.session_manager' in sys.modules:
                session_module = sys.modules['app.core.session_manager']
                if hasattr(session_module, 'session_manager'):
                    current_session = session_module.session_manager.get_current_session()
                    if current_session:
                        self.current_profile = current_session['id']
                        return
        except Exception:
            pass
        self.current_profile = "default"
    
    def get_current_profile(self) -> str:
        """Get current profile name"""
        return self.current_profile or "default"
    
    def save_to_profile_json(self):
        """Public method to save credentials to profile JSON"""
        self._save_to_main_profile_json()
    
    def get_mssql_credentials(self) -> List[Credential]:
        """Get credentials suitable for MSSQL connections"""
        return [c for c in self.credentials if c.credential_type in ['SQL Server Auth', 'Windows Auth']]
    
    def add_sql_server_credential(self, username: str, password: str, notes: str = "") -> Credential:
        """Add SQL Server authentication credential"""
        return self.add_credential(username, password, "", "MSSQL", notes, "manual", "SQL Server Auth")
    
    def add_windows_auth_credential(self, username: str, password: str, domain: str, notes: str = "") -> Credential:
        """Add Windows authentication credential"""
        return self.add_credential(username, password, domain, "MSSQL", notes, "manual", "Windows Auth")

# Global credential manager instance
credential_manager = CredentialManager()

# MSSQL-specific credential helpers
def get_mssql_credentials_for_auth_type(auth_type: str) -> List[Credential]:
    """Get MSSQL credentials filtered by authentication type"""
    return credential_manager.get_credentials_by_auth_type(auth_type)

def sync_credential_profile_with_session():
    """Sync credential manager profile with current session"""
    try:
        from .session_manager import session_manager
        current_session = session_manager.get_current_session()
        if current_session:
            credential_manager.set_profile(current_session['id'])
        else:
            credential_manager.set_profile("default")
    except Exception as e:
        print(f"Error syncing credential profile: {e}")

def get_mssql_auth_options() -> List[str]:
    """Get available MSSQL authentication options"""
    return ['SQL Server Auth', 'Windows Auth']