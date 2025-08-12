# app/core/credential_migration.py
import os
import json
from typing import Dict, List, Tuple
from pathlib import Path
from .credential_manager import credential_manager
from .secure_credential_manager import secure_credential_manager

class CredentialMigration:
    """Handles migration from old credential manager to secure credential manager"""
    
    def __init__(self):
        self.migration_log = []
    
    def check_migration_needed(self) -> bool:
        """Check if migration is needed"""
        # Check if old credentials exist
        old_creds = credential_manager.get_credentials()
        return len(old_creds) > 0
    
    def migrate_credentials(self) -> Tuple[bool, List[str]]:
        """Migrate credentials from old system to secure system"""
        self.migration_log.clear()
        success_count = 0
        error_count = 0
        
        try:
            # Get all credentials from old system
            old_credentials = credential_manager.get_credentials()
            
            if not old_credentials:
                self.migration_log.append("No credentials found in old system")
                return True, self.migration_log
            
            self.migration_log.append(f"Found {len(old_credentials)} credentials to migrate")
            
            for credential in old_credentials:
                try:
                    # Determine service name from credential data
                    service_name = self._determine_service_name(credential)
                    
                    # Migrate to secure credential manager
                    success = secure_credential_manager.store_credential(
                        service=service_name,
                        username=credential.username,
                        password=credential.password,
                        domain=credential.domain,
                        notes=credential.notes,
                        source=f"migrated_from_{credential.source}"
                    )
                    
                    if success:
                        success_count += 1
                        self.migration_log.append(f"✓ Migrated credential for {service_name}")
                    else:
                        error_count += 1
                        self.migration_log.append(f"✗ Failed to migrate credential for {service_name}")
                        
                except Exception as e:
                    error_count += 1
                    self.migration_log.append(f"✗ Error migrating credential: {str(e)}")
            
            # Summary
            self.migration_log.append(f"\nMigration Summary:")
            self.migration_log.append(f"  Successfully migrated: {success_count}")
            self.migration_log.append(f"  Failed to migrate: {error_count}")
            
            if error_count == 0:
                self.migration_log.append("\n✓ All credentials migrated successfully!")
                return True, self.migration_log
            else:
                self.migration_log.append(f"\n⚠ Migration completed with {error_count} errors")
                return False, self.migration_log
                
        except Exception as e:
            self.migration_log.append(f"Migration failed: {str(e)}")
            return False, self.migration_log
    
    def _determine_service_name(self, credential) -> str:
        """Determine service name from credential data"""
        # Try to extract service name from various fields
        if credential.service:
            return credential.service.lower().replace(' ', '-')
        
        # Check notes for service indicators
        notes_lower = credential.notes.lower()
        service_indicators = {
            'shodan': ['shodan'],
            'virustotal': ['virustotal', 'virus total', 'vt'],
            'aws': ['aws', 'amazon'],
            'azure': ['azure', 'microsoft'],
            'database': ['database', 'db', 'mysql', 'postgres', 'mssql'],
            'web': ['web', 'http', 'website'],
            'ssh': ['ssh', 'server'],
            'ftp': ['ftp'],
            'smtp': ['smtp', 'email', 'mail']
        }
        
        for service, indicators in service_indicators.items():
            if any(indicator in notes_lower for indicator in indicators):
                return service
        
        # Check username for service indicators
        username_lower = credential.username.lower()
        for service, indicators in service_indicators.items():
            if any(indicator in username_lower for indicator in indicators):
                return service
        
        # Default to generic service name
        if credential.domain:
            return f"{credential.domain.lower()}-service"
        else:
            return f"service-{credential.username.lower()}"
    
    def backup_old_credentials(self, backup_path: str = None) -> bool:
        """Create backup of old credentials before migration"""
        try:
            if not backup_path:
                backup_dir = Path.home() / ".huggin" / "backups"
                backup_dir.mkdir(parents=True, exist_ok=True)
                backup_path = backup_dir / f"credentials_backup_{int(time.time())}.json"
            
            # Export old credentials
            old_data = credential_manager.to_dict()
            
            with open(backup_path, 'w') as f:
                json.dump(old_data, f, indent=2, default=str)
            
            self.migration_log.append(f"✓ Backup created at: {backup_path}")
            return True
            
        except Exception as e:
            self.migration_log.append(f"✗ Failed to create backup: {str(e)}")
            return False
    
    def cleanup_old_credentials(self) -> bool:
        """Clean up old credential storage after successful migration"""
        try:
            credential_manager.clear_credentials()
            self.migration_log.append("✓ Old credentials cleared")
            return True
        except Exception as e:
            self.migration_log.append(f"✗ Failed to clear old credentials: {str(e)}")
            return False
    
    def validate_migration(self) -> Tuple[bool, List[str]]:
        """Validate that migration was successful"""
        validation_log = []
        
        try:
            # Get services from secure manager
            secure_services = secure_credential_manager.list_services()
            old_credentials = credential_manager.get_credentials()
            
            validation_log.append(f"Secure manager has {len(secure_services)} services")
            validation_log.append(f"Old manager has {len(old_credentials)} credentials")
            
            # Check if all old credentials have been migrated
            missing_services = []
            for old_cred in old_credentials:
                service_name = self._determine_service_name(old_cred)
                if service_name not in secure_services:
                    missing_services.append(service_name)
            
            if missing_services:
                validation_log.append(f"✗ Missing services: {', '.join(missing_services)}")
                return False, validation_log
            else:
                validation_log.append("✓ All credentials successfully migrated")
                return True, validation_log
                
        except Exception as e:
            validation_log.append(f"Validation failed: {str(e)}")
            return False, validation_log
    
    def get_migration_summary(self) -> Dict:
        """Get summary of migration status"""
        old_count = len(credential_manager.get_credentials())
        secure_count = len(secure_credential_manager.list_services())
        
        return {
            "migration_needed": old_count > 0,
            "old_credentials": old_count,
            "secure_credentials": secure_count,
            "migration_log": self.migration_log
        }

# Global migration instance
credential_migration = CredentialMigration()