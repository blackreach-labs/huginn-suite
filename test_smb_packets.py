#!/usr/bin/env python3
"""
Minimal test to verify SMB packets are being sent
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.tools.smb_raw_proto import SMBRawClient

def test_smb_packets(target):
    """Test that SMB packets are actually sent to target"""
    print(f"🔍 Testing SMB packet transmission to {target}")
    print("=" * 50)
    
    client = SMBRawClient(target, 445, timeout=5.0)
    
    try:
        print(f"[1] Connecting to {target}:445...")
        client.connect()
        print(f"✅ TCP connection established")
        
        print(f"[2] Attempting SMB 3.1.1 negotiate...")
        result = client._negotiate_smb311_with_contexts()
        print(f"✅ SMB 3.1.1 negotiate result: {result}")
        
        print(f"[3] Attempting SMB 3.0.2 negotiate...")
        client.close()
        client.connect()
        result = client._negotiate_smb302_simple()
        print(f"✅ SMB 3.0.2 negotiate result: {result}")
        
        print(f"[4] Attempting SMB 2.1 negotiate...")
        client.close()
        client.connect()
        result = client._negotiate_smb21_basic()
        print(f"✅ SMB 2.1 negotiate result: {result}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        print(f"Debug: {traceback.format_exc()}")
    finally:
        client.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test_smb_packets.py <target_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    test_smb_packets(target)