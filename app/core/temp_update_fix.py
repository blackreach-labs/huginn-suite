"""
Temporary fix for update system - bypasses S3 authentication issues
"""

import json
from .auto_updater import SecureUpdater

class TempSecureUpdater(SecureUpdater):
    """Temporary updater that handles S3 auth issues gracefully"""
    
    def check_for_updates(self):
        """Check for updates with better error handling"""
        try:
            return super().check_for_updates()
        except Exception as e:
            error_msg = str(e)
            
            if "authorization mechanism" in error_msg.lower() or "signature version 4" in error_msg.lower():
                # S3 authentication issue
                raise Exception(
                    "S3 Authentication Required: The update files need to be made publicly accessible. "
                    "Please go to your S3 bucket and make the manifest/manifest.json, public.key, and "
                    "release files publicly readable, or configure AWS credentials."
                )
            elif "400" in error_msg or "bad request" in error_msg.lower():
                raise Exception(
                    "S3 Access Error: The S3 bucket requires proper authentication. "
                    "Please make the update files public or configure AWS credentials."
                )
            else:
                # Re-raise original exception
                raise e

# Replace the original updater in update_manager
def patch_update_manager():
    """Patch the update manager to use the temporary fix"""
    from . import update_manager
    update_manager.update_manager.updater = TempSecureUpdater()