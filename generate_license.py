#!/usr/bin/env python3
"""
Huggin License Generator
Generate professional and enterprise licenses for customers
"""

import json
import base64
import hashlib
from datetime import datetime, timedelta

def generate_license(user_id: str, license_type: str, duration_days: int = 365, features: list = None):
    """Generate a license key for Huggin"""
    
    # Default features based on license type
    if features is None:
        if license_type == "Professional":
            features = [
                'stealth_mode',
                'proxychains', 
                'web_scanner',
                'hacking_mode'
            ]
        elif license_type == "Enterprise":
            features = [
                'stealth_mode',
                'proxychains',
                'web_scanner', 
                'hacking_mode',
                'exploit_database',
                'post_exploitation',
                'ad_enumeration',
                'enhanced_reporting',
                'wireless_security',
                'api_integrations'
            ]
        else:  # Trial
            features = ['stealth_mode', 'proxychains', 'web_scanner']
    
    # Calculate expiry date
    expiry_date = datetime.now() + timedelta(days=duration_days)
    
    # Create license data
    license_data = {
        'user_id': user_id,
        'license_type': license_type,
        'expiry_date': expiry_date.isoformat(),
        'features': features,
        'issued_date': datetime.now().isoformat(),
        'duration_days': duration_days
    }
    
    # Generate signature
    signature_string = json.dumps(license_data, sort_keys=True)
    secret_key = "huggin_license_secret_2024"
    signature = hashlib.sha256((signature_string + secret_key).encode()).hexdigest()
    license_data['signature'] = signature
    
    # Encode license
    license_key = base64.b64encode(json.dumps(license_data).encode()).decode()
    
    return license_key, license_data

def validate_license_key(license_key: str):
    """Validate and decode a license key"""
    try:
        # Decode license key
        decoded = base64.b64decode(license_key.encode()).decode()
        license_data = json.loads(decoded)
        
        # Verify signature
        signature_data = {k: v for k, v in license_data.items() if k != 'signature'}
        signature_string = json.dumps(signature_data, sort_keys=True)
        secret_key = "huggin_license_secret_2024"
        expected_signature = hashlib.sha256((signature_string + secret_key).encode()).hexdigest()
        
        if license_data.get('signature') != expected_signature:
            return False, "Invalid signature"
        
        # Check expiry
        expiry_date = datetime.fromisoformat(license_data['expiry_date'])
        if datetime.now() > expiry_date:
            return False, "License expired"
        
        return True, license_data
        
    except Exception as e:
        return False, f"Invalid license: {str(e)}"

def main():
    """Interactive license generator"""
    print("🔑 Huggin License Generator")
    print("=" * 40)
    
    while True:
        print("\nOptions:")
        print("1. Generate Professional License")
        print("2. Generate Enterprise License") 
        print("3. Generate Trial License")
        print("4. Validate License Key")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == "1":
            user_id = input("Enter User ID/Email: ").strip()
            days = int(input("Enter duration in days (default 365): ") or "365")
            
            license_key, license_data = generate_license(user_id, "Professional", days)
            
            print(f"\n✅ Professional License Generated:")
            print(f"User: {user_id}")
            print(f"Type: Professional")
            print(f"Duration: {days} days")
            print(f"Expires: {license_data['expiry_date'][:10]}")
            print(f"Features: {len(license_data['features'])}")
            print(f"\n🔑 License Key:")
            print(license_key)
            
        elif choice == "2":
            user_id = input("Enter User ID/Email: ").strip()
            days = int(input("Enter duration in days (default 365): ") or "365")
            
            license_key, license_data = generate_license(user_id, "Enterprise", days)
            
            print(f"\n✅ Enterprise License Generated:")
            print(f"User: {user_id}")
            print(f"Type: Enterprise")
            print(f"Duration: {days} days")
            print(f"Expires: {license_data['expiry_date'][:10]}")
            print(f"Features: {len(license_data['features'])}")
            print(f"\n🔑 License Key:")
            print(license_key)
            
        elif choice == "3":
            user_id = input("Enter User ID/Email: ").strip()
            days = int(input("Enter trial duration in days (default 30): ") or "30")
            
            license_key, license_data = generate_license(user_id, "Trial", days)
            
            print(f"\n✅ Trial License Generated:")
            print(f"User: {user_id}")
            print(f"Type: Trial")
            print(f"Duration: {days} days")
            print(f"Expires: {license_data['expiry_date'][:10]}")
            print(f"Features: {len(license_data['features'])}")
            print(f"\n🔑 License Key:")
            print(license_key)
            
        elif choice == "4":
            license_key = input("Enter license key to validate: ").strip()
            
            valid, result = validate_license_key(license_key)
            
            if valid:
                print(f"\n✅ License Valid:")
                print(f"User: {result['user_id']}")
                print(f"Type: {result['license_type']}")
                print(f"Expires: {result['expiry_date'][:10]}")
                print(f"Features: {', '.join(result['features'])}")
                
                # Calculate days remaining
                expiry = datetime.fromisoformat(result['expiry_date'])
                days_remaining = (expiry - datetime.now()).days
                print(f"Days Remaining: {days_remaining}")
            else:
                print(f"\n❌ License Invalid: {result}")
                
        elif choice == "5":
            print("\nGoodbye! 👋")
            break
        else:
            print("\n❌ Invalid option. Please select 1-5.")

if __name__ == "__main__":
    main()