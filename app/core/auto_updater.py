import os
import json
import hashlib
import zipfile
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen, urlretrieve
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import base64
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

class SecureUpdater:
    def __init__(self):
        self.base_url = "https://d1uxlqm5uueawt.cloudfront.net"
        self.current_version = "1.3.1"  # Current app version
        self.app_root = Path(__file__).parent.parent.parent
        
    def check_for_updates(self):
        """Check if updates are available"""
        try:
            manifest_url = f"{self.base_url}/manifest/manifest.json"
            print(f"Checking for updates at: {manifest_url}")
            
            with urlopen(manifest_url) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status}: {response.reason}")
                manifest_data = response.read()
            
            print(f"Downloaded manifest: {len(manifest_data)} bytes")
            manifest = json.loads(manifest_data.decode())
            print(f"Parsed manifest: {manifest}")
            
            # Verify manifest signature
            if not self._verify_manifest(manifest_data, manifest.get('signature')):
                raise Exception("Manifest signature verification failed")
            
            print(f"Current version: {self.current_version}, Available: {manifest['version']}")
            
            # Compare versions
            if manifest['version'] != self.current_version:
                return manifest
            return None
            
        except Exception as e:
            print(f"Update check failed: {e}")
            import traceback
            traceback.print_exc()
            raise e
    

    def _verify_manifest(self, manifest_data, signature):
        """Verify manifest signature using embedded public key"""
        try:
            public_key_url = f"{self.base_url}/public.key"
            with urlopen(public_key_url) as response:
                public_key_data = response.read()
            
            public_key = serialization.load_pem_public_key(public_key_data)
            
            # Remove signature from manifest for verification
            manifest_dict = json.loads(manifest_data.decode())
            manifest_dict.pop('signature', None)
            clean_manifest = json.dumps(manifest_dict, sort_keys=True).encode()
            
            # Verify signature
            signature_bytes = base64.b64decode(signature)
            public_key.verify(
                signature_bytes,
                clean_manifest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
            
        except (InvalidSignature, Exception):
            return False
    
    def download_and_install(self, manifest):
        """Download and install update"""
        try:
            # Download update file
            update_url = f"{self.base_url}/releases/{manifest['filename']}"
            temp_file = self.app_root / "temp_update.zip"
            
            print(f"Downloading update {manifest['version']}...")
            urlretrieve(update_url, temp_file)
            
            # Verify SHA256 hash
            if not self._verify_hash(temp_file, manifest['sha256']):
                raise Exception("Update file hash verification failed")
            
            # Backup current installation
            backup_dir = self.app_root / "backup"
            if backup_dir.exists():
                shutil.rmtree(backup_dir)
            shutil.copytree(self.app_root / "app", backup_dir)
            
            # Extract update
            print("Installing update...")
            with zipfile.ZipFile(temp_file, 'r') as zip_ref:
                zip_ref.extractall(self.app_root)
            
            # Cleanup
            temp_file.unlink()
            
            print(f"Update to version {manifest['version']} completed!")
            return True
            
        except Exception as e:
            print(f"Update installation failed: {e}")
            return False
    
    def _verify_hash(self, file_path, expected_hash):
        """Verify file SHA256 hash"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest() == expected_hash
    
    def restart_application(self):
        """Restart the application"""
        try:
            python = sys.executable
            subprocess.Popen([python] + sys.argv)
            sys.exit(0)
        except Exception as e:
            print(f"Failed to restart application: {e}")

def main():
    updater = SecureUpdater()
    
    print("Checking for updates...")
    manifest = updater.check_for_updates()
    
    if manifest:
        print(f"Update available: {manifest['version']}")
        if input("Install update? (y/n): ").lower() == 'y':
            if updater.download_and_install(manifest):
                updater.restart_application()
    else:
        print("No updates available")

if __name__ == "__main__":
    main()