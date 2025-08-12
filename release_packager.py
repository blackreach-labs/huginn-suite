import os
import json
import hashlib
import zipfile
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class ReleasePackager:
    def __init__(self, version, private_key_path="private.key"):
        self.version = version
        self.private_key_path = private_key_path
        self.app_root = Path(__file__).parent
        
    def create_release(self):
        """Create a complete release package"""
        print(f"Creating release {self.version}...")
        
        # Create zip file
        zip_filename = f"huggin_{self.version}.zip"
        zip_path = self.app_root / zip_filename
        
        self._create_zip(zip_path)
        
        # Calculate SHA256
        sha256_hash = self._calculate_hash(zip_path)
        
        # Create and sign manifest
        manifest = self._create_manifest(zip_filename, sha256_hash)
        
        print(f"Release {self.version} created successfully!")
        print(f"Files: {zip_filename}, manifest.json")
        print(f"SHA256: {sha256_hash}")
        
        return zip_filename, manifest
    
    def _create_zip(self, zip_path):
        """Create zip file of the application"""
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            app_dir = self.app_root / "app"
            for file_path in app_dir.rglob("*"):
                if file_path.is_file() and not file_path.name.endswith('.pyc'):
                    arcname = file_path.relative_to(self.app_root)
                    zipf.write(file_path, arcname)
    
    def _calculate_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _create_manifest(self, filename, sha256_hash):
        """Create and sign manifest"""
        manifest = {
            "version": self.version,
            "filename": filename,
            "sha256": sha256_hash,
            "release_date": "2024-01-15T10:00:00Z"
        }
        
        # Sign manifest
        signature = self._sign_manifest(manifest)
        manifest["signature"] = signature
        
        # Save manifest
        with open("manifest.json", "w") as f:
            json.dump(manifest, f, indent=2)
        
        return manifest
    
    def _sign_manifest(self, manifest):
        """Sign manifest with private key"""
        # Load private key
        with open(self.private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        
        # Create signature
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
        signature = private_key.sign(
            manifest_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode()
    
    def generate_keys(self):
        """Generate RSA key pair for signing"""
        print("Generating RSA key pair...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Save private key
        with open("private.key", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        public_key = private_key.public_key()
        with open("public.key", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        print("Keys generated: private.key, public.key")

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python release_packager.py <version> [--generate-keys]")
        sys.exit(1)
    
    if "--generate-keys" in sys.argv:
        packager = ReleasePackager("1.0.0")
        packager.generate_keys()
        return
    
    version = sys.argv[1]
    packager = ReleasePackager(version)
    
    # Check if keys exist
    if not Path("private.key").exists():
        print("Private key not found. Run with --generate-keys first.")
        sys.exit(1)
    
    packager.create_release()
    
    print("\nNext steps:")
    print("1. Upload files to S3:")
    print(f"   aws s3 cp huggin_{version}.zip s3://arn:aws:s3:ap-southeast-2:917026075470:accesspoint/huggin-secure-updater/releases/")
    print("   aws s3 cp manifest.json s3://arn:aws:s3:ap-southeast-2:917026075470:accesspoint/huggin-secure-updater/manifest/")
    print("   aws s3 cp public.key s3://arn:aws:s3:ap-southeast-2:917026075470:accesspoint/huggin-secure-updater/")

if __name__ == "__main__":
    main()