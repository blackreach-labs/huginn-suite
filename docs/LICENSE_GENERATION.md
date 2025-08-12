# 🔑 Huggin License Generation Guide

## Quick Start

Run the license generator:
```bash
python generate_license.py
```

## License Types

### 1. Trial License (30 days)
**Features**: Stealth Mode, ProxyChains, Web Scanner
```bash
# Example Trial License
User: trial@example.com
Duration: 30 days
Features: 3 (stealth_mode, proxychains, web_scanner)
```

### 2. Professional License ($99/month)
**Features**: Stealth Mode, ProxyChains, Web Scanner, Basic Hacking Mode
```bash
# Example Professional License  
User: pro@company.com
Duration: 365 days
Features: 4 (stealth_mode, proxychains, web_scanner, hacking_mode)
```

### 3. Enterprise License ($299/month)
**Features**: All features including AD Enumeration, Enhanced Reporting, Wireless Security
```bash
# Example Enterprise License
User: enterprise@company.com  
Duration: 365 days
Features: 10 (all professional features + enterprise modules)
```

## Usage Examples

### Generate Professional License
```bash
python generate_license.py
# Select option 1
# Enter: user@company.com
# Enter: 365 (days)
```

### Generate Enterprise License
```bash
python generate_license.py
# Select option 2  
# Enter: admin@enterprise.com
# Enter: 365 (days)
```

### Validate License
```bash
python generate_license.py
# Select option 4
# Paste license key to validate
```

## License Key Format

License keys are base64-encoded JSON with signature:
```json
{
  "user_id": "user@example.com",
  "license_type": "Professional", 
  "expiry_date": "2025-07-10T12:00:00",
  "features": ["stealth_mode", "proxychains", "web_scanner", "hacking_mode"],
  "issued_date": "2024-07-10T12:00:00",
  "duration_days": 365,
  "signature": "sha256_hash_signature"
}
```

## Security Features

- **Digital Signature**: SHA256 HMAC with secret key
- **Expiry Validation**: Automatic expiration checking
- **Feature Control**: Granular feature enablement
- **Tamper Protection**: Invalid signatures rejected

## Customer Delivery

1. **Generate License**: Use appropriate tier for customer
2. **Send License Key**: Provide base64 license string
3. **Installation**: Customer enters key in License Manager
4. **Activation**: Features unlock automatically

## Bulk License Generation

For multiple customers, modify the script or use programmatically:

```python
from generate_license import generate_license

# Generate multiple licenses
customers = [
    ("customer1@company.com", "Professional", 365),
    ("customer2@enterprise.com", "Enterprise", 365)
]

for user_id, license_type, days in customers:
    license_key, license_data = generate_license(user_id, license_type, days)
    print(f"{user_id}: {license_key}")
```

## License Management

- **Renewal**: Generate new license with extended expiry
- **Upgrade**: Generate new license with additional features  
- **Revocation**: Not implemented (licenses expire naturally)
- **Transfer**: Generate new license for different user

## Revenue Tracking

Track license generation for revenue management:
- Professional: $99/month per license
- Enterprise: $299/month per license  
- Trial: Free (conversion tracking)

**The license system provides secure, flexible licensing for Huggin's professional features with automated validation and feature control.**