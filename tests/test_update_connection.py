#!/usr/bin/env python3
"""Test script to debug update connection issues"""

import json
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

def test_s3_connection():
    base_url = "https://huginn-secure-update-fkhespeu5aa4yuc3pmfqwuabd7334aps2b-s3alias.s3-accesspoint.ap-southeast-2.amazonaws.com"
    
    # Test manifest URL
    manifest_url = f"{base_url}/manifest/manifest.json"
    print(f"Testing manifest URL: {manifest_url}")
    
    try:
        with urlopen(manifest_url) as response:
            print(f"Response status: {response.status}")
            print(f"Response headers: {dict(response.headers)}")
            
            manifest_data = response.read()
            print(f"Downloaded {len(manifest_data)} bytes")
            
            manifest = json.loads(manifest_data.decode())
            print(f"Manifest content: {json.dumps(manifest, indent=2)}")
            
            # Check required fields
            required_fields = ['version', 'sha256', 'filename', 'signature']
            missing_fields = [field for field in required_fields if field not in manifest]
            
            if missing_fields:
                print(f"WARNING: Missing required fields: {missing_fields}")
            else:
                print("✓ All required fields present")
                
    except HTTPError as e:
        print(f"HTTP Error {e.code}: {e.reason}")
        print(f"Response body: {e.read().decode()}")
    except URLError as e:
        print(f"URL Error: {e.reason}")
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        print(f"Raw data: {manifest_data}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()

    # Test public key URL
    print("\n" + "="*50)
    public_key_url = f"{base_url}/public.key"
    print(f"Testing public key URL: {public_key_url}")
    
    try:
        with urlopen(public_key_url) as response:
            print(f"Response status: {response.status}")
            key_data = response.read()
            print(f"Downloaded {len(key_data)} bytes")
            print(f"Key starts with: {key_data[:50]}...")
            
    except Exception as e:
        print(f"Public key test failed: {e}")

if __name__ == "__main__":
    test_s3_connection()