# app/core/session_manager.py
import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional
import asyncio
from infrastructure.data.repositories.sqlite_scan_repository import SQLiteScanRepository
from domain.models.scan_result import ScanResultModel, Target, ScanStatus
from app.core.logger import logger

class SessionManager:
    """Manage scanning sessions and project organization"""
    
    def __init__(self):
        self.current_session = None
        self.sessions_file = os.path.join("resources", "config", "sessions.json")
        self.sessions = self.load_sessions()
        self.scan_repository = SQLiteScanRepository()
        self._init_session_tables()
        self.auto_start_session()
    
    def _init_session_tables(self):
        """Initialize session-related database tables."""
        import sqlite3
        try:
            with sqlite3.connect(self.scan_repository.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS session_scans (
                        session_id TEXT,
                        scan_result_id TEXT,
                        added_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (session_id, scan_result_id)
                    )
                """)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def create_session(self, name: str, description: str = "", targets: List[str] = None) -> Dict:
        """Create a new scanning session"""
        
        session = {
            'id': self._generate_session_id(),
            'name': name,
            'description': description,
            'created_date': datetime.now().isoformat(),
            'targets': targets or [],
            'scan_ids': [],
            'status': 'active',
            'tags': [],
            'notes': ""
        }
        
        self.sessions[session['id']] = session
        self.save_sessions()
        
        return session
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def get_all_sessions(self) -> List[Dict]:
        """Get all sessions"""
        return list(self.sessions.values())
    
    def update_session(self, session_id: str, updates: Dict) -> bool:
        """Update session information"""
        
        if session_id in self.sessions:
            self.sessions[session_id].update(updates)
            self.sessions[session_id]['modified_date'] = datetime.now().isoformat()
            self.save_sessions()
            return True
        
        return False
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        
        if session_id in self.sessions:
            del self.sessions[session_id]
            self.save_sessions()
            return True
        
        return False
    
    def add_scan_to_session(self, session_id: str, scan_result_id: str) -> bool:
        """Add scan to session using new repository."""
        import sqlite3
        try:
            with sqlite3.connect(self.scan_repository.db_path) as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO session_scans (session_id, scan_result_id)
                    VALUES (?, ?)
                """, (session_id, scan_result_id))
            return True
        except Exception:
            return False
    
    def remove_scan_from_session(self, session_id: str, scan_id: int) -> bool:
        """Remove scan from session"""
        
        if session_id in self.sessions:
            if scan_id in self.sessions[session_id]['scan_ids']:
                self.sessions[session_id]['scan_ids'].remove(scan_id)
                self.save_sessions()
            return True
        
        return False
    
    def get_session_scans(self, session_id: str) -> List[ScanResultModel]:
        """Get all scans for a session using new repository."""
        import sqlite3
        try:
            with sqlite3.connect(self.scan_repository.db_path) as conn:
                cursor = conn.execute("""
                    SELECT scan_result_id FROM session_scans WHERE session_id = ?
                """, (session_id,))
                
                scans = []
                for row in cursor.fetchall():
                    scan_result = asyncio.run(self.scan_repository.get_scan_result(row[0]))
                    if scan_result:
                        scans.append(scan_result)
                return scans
        except Exception:
            return []
    
    def set_current_session(self, session_id: str) -> bool:
        """Set current active session"""
        
        if session_id in self.sessions:
            self.current_session = session_id
            
            # Sync credential manager profile (avoid circular import)
            self._sync_credential_profile(session_id)
            
            return True
        
        return False
    
    def get_current_session(self) -> Optional[Dict]:
        """Get current active session"""
        
        if self.current_session:
            return self.get_session(self.current_session)
        
        return None
    
    def get_session_statistics(self, session_id: str) -> Dict:
        """Get statistics for a session using new repository."""
        scans = self.get_session_scans(session_id)
        exports = self.get_session_exports(session_id)
        
        stats = {
            'total_scans': len(scans),
            'total_exports': len(exports),
            'targets_scanned': len(set(scan.target.address for scan in scans)),
            'scan_types': {},
            'export_types': {},
            'date_range': {'start': None, 'end': None}
        }
        
        for scan in scans:
            # Count scan types
            if scan.scanner_type not in stats['scan_types']:
                stats['scan_types'][scan.scanner_type] = 0
            stats['scan_types'][scan.scanner_type] += 1
            
            # Track date range
            scan_date = scan.started_at.isoformat()
            if not stats['date_range']['start'] or scan_date < stats['date_range']['start']:
                stats['date_range']['start'] = scan_date
            if not stats['date_range']['end'] or scan_date > stats['date_range']['end']:
                stats['date_range']['end'] = scan_date
        
        # Count export types
        for export in exports:
            export_type = export.get('format', 'unknown')
            if export_type not in stats['export_types']:
                stats['export_types'][export_type] = 0
            stats['export_types'][export_type] += 1
        
        return stats
    
    def export_session(self, session_id: str, export_path: str) -> bool:
        """Export session data to file"""
        
        session = self.get_session(session_id)
        if not session:
            return False
        
        scans = self.get_session_scans(session_id)
        
        export_data = {
            'session': session,
            'scans': scans,
            'statistics': self.get_session_statistics(session_id),
            'exported_date': datetime.now().isoformat()
        }
        
        try:
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            return True
        except Exception:
            return False
    
    def import_session(self, import_path: str) -> Optional[str]:
        """Import session from file"""
        
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            session_data = import_data.get('session', {})
            scans_data = import_data.get('scans', [])
            
            # Create new session
            new_session = self.create_session(
                name=f"Imported: {session_data.get('name', 'Unknown')}",
                description=session_data.get('description', ''),
                targets=session_data.get('targets', [])
            )
            
            # Import scans using new repository
            for scan_data in scans_data:
                # Create proper scan result model
                scan_result = ScanResultModel(
                    id=str(uuid.uuid4()),
                    target=Target(address=scan_data['target'], description=scan_data['target']),
                    scanner_type=scan_data['scan_type'],
                    status=ScanStatus.COMPLETED,
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                    data=scan_data.get('results', {}),
                    vulnerabilities=[]
                )
                
                # Save using async repository method
                try:
                    asyncio.run(self.scan_repository.save_scan_result(scan_result))
                    self.add_scan_to_session(new_session['id'], scan_result.id)
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            
            return new_session['id']
        
        except Exception:
            return None
    
    def save_sessions(self):
        """Save sessions to file"""
        
        try:
            with open(self.sessions_file, 'w') as f:
                json.dump(self.sessions, f, indent=2, default=str)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def load_sessions(self) -> Dict:
        """Load sessions from file"""
        
        try:
            if os.path.exists(self.sessions_file):
                with open(self.sessions_file, 'r') as f:
                    return json.load(f)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return {}
    
    def auto_start_session(self):
        """Automatically start a new session on application launch"""
        session_name = f"Session {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        session = self.create_session(
            name=session_name,
            description="Auto-generated session",
            targets=[]
        )
        self.set_current_session(session['id'])
        return session
    
    def add_export_to_session(self, session_id: str, export_info: Dict) -> bool:
        """Add export information to session"""
        if session_id in self.sessions:
            if 'exports' not in self.sessions[session_id]:
                self.sessions[session_id]['exports'] = []
            
            export_info['timestamp'] = datetime.now().isoformat()
            self.sessions[session_id]['exports'].append(export_info)
            self.save_sessions()
            return True
        return False
    
    def get_session_exports(self, session_id: str) -> List[Dict]:
        """Get all exports for a session"""
        session = self.get_session(session_id)
        if session:
            return session.get('exports', [])
        return []
    
    def get_current_session_exports(self) -> List[Dict]:
        """Get exports for current session"""
        if self.current_session:
            return self.get_session_exports(self.current_session)
        return []
    
    def save_current_session(self, save_path: str = None) -> bool:
        """Save current session with all data"""
        if not self.current_session:
            return False
        
        if not save_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            save_path = f"session_backup_{timestamp}.json"
        
        return self.export_session(self.current_session, save_path)
    
    def restore_session(self, session_path: str) -> Optional[str]:
        """Restore session from backup file"""
        return self.import_session(session_path)
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return str(uuid.uuid4())[:8]
    
    def _sync_credential_profile(self, session_id: str):
        """Sync credential manager profile with session"""
        try:
            # Use globals() to access the credential manager after it's fully loaded
            import sys
            if 'app.core.credential_manager' in sys.modules:
                credential_module = sys.modules['app.core.credential_manager']
                if hasattr(credential_module, 'credential_manager'):
                    credential_module.credential_manager.set_profile(session_id)
        except Exception as _exc:
            pass  # Silently ignore sync errors
            logger.debug("Suppressed exception", exc_info=True)

# Global instance
session_manager = SessionManager()