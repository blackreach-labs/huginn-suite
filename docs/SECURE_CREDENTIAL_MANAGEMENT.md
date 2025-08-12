# Secure Credential and API Key Management System

## Overview

The Huggin framework now includes a comprehensive secure credential and API key management system that provides centralized, encrypted storage with enterprise secrets management integration. This system replaces manual credential input across all tools and ensures consistent security practices.

## Key Features

### 🔐 Centralized Security
- **Mandatory Usage**: All tools must use the secure credential manager
- **No Manual Input**: UI components pull credentials from secure storage
- **Unified Interface**: Single point of credential management

### 🏢 Enterprise Integration
- **HashiCorp Vault**: Full integration with Vault for enterprise environments
- **AWS Secrets Manager**: Native support for AWS-based credential storage
- **Azure Key Vault**: Integration with Microsoft Azure Key Vault
- **Priority System**: Environment variables > Secrets manager > Local storage

### 🛡️ Advanced Security
- **Fernet Encryption**: Military-grade encryption for local storage
- **In-Memory Protection**: Secure memory handling with automatic cleanup
- **Access Logging**: Complete audit trail of credential access
- **Permission Controls**: Restrictive file permissions (600 on Unix, hidden on Windows)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│  API Integration │ AWS Pentest │ Auth Crawler │ Other Tools │
├─────────────────────────────────────────────────────────────┤
│              Secure Credential Manager                     │
├─────────────────────────────────────────────────────────────┤
│ Priority 1: Environment Variables                          │
│ Priority 2: Enterprise Secrets Manager                    │
│ Priority 3: Local Encrypted Storage                       │
├─────────────────────────────────────────────────────────────┤
│   Vault API   │  AWS Secrets  │  Azure KV   │  Local File  │
└─────────────────────────────────────────────────────────────┘
```

## Installation & Setup

### 1. Install Dependencies

```bash
# Core dependencies
pip install cryptography

# Enterprise integrations (optional)
pip install hvac boto3 azure-keyvault-secrets azure-identity
```

### 2. Environment Variables

Set up environment variables for automatic credential detection:

```bash
# API Keys
export SHODAN_API_KEY="your_shodan_key_here"
export VIRUSTOTAL_API_KEY="your_virustotal_key_here"

# AWS Credentials
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."  # Optional

# Database Credentials
export MYSQL_USERNAME="root"
export MYSQL_PASSWORD="password"
export MSSQL_USERNAME="sa"
export MSSQL_PASSWORD="password"

# Web Authentication
export WEB_LOGIN_USERNAME="admin"
export WEB_LOGIN_PASSWORD="password"

# Master Password (optional)
export HUGGIN_MASTER_PASSWORD="your_secure_master_password"
```

### 3. Enterprise Secrets Manager Setup

#### HashiCorp Vault
```bash
# Set Vault environment
export VAULT_ADDR="https://vault.company.com:8200"
export VAULT_TOKEN="hvs.XXXXXXXXXXXXXXXX"

# Store secrets in Vault
vault kv put huggin/shodan api_key="your_key"
vault kv put huggin/aws username="AKIA..." password="secret_key" token="session_token"
```

#### AWS Secrets Manager
```bash
# Create secrets in AWS
aws secretsmanager create-secret \
  --name "huggin/shodan" \
  --secret-string '{"api_key":"your_key"}'

aws secretsmanager create-secret \
  --name "huggin/aws-prod" \
  --secret-string '{"username":"AKIA...","password":"secret_key"}'
```

#### Azure Key Vault
```bash
# Create secrets in Azure Key Vault
az keyvault secret set \
  --vault-name "company-keyvault" \
  --name "huggin-shodan" \
  --value '{"api_key":"your_key"}'
```

## Usage Guide

### 1. UI Configuration

Access the secure credential management through the main interface:

1. Navigate to **Settings** → **Credential Management**
2. Use the **Credentials** tab to add/edit credentials
3. Configure enterprise integration in the **Enterprise** tab
4. Monitor security status in the **Security** tab

### 2. Adding Credentials

```python
from app.core.secure_credential_manager import secure_credential_manager

# Store API key
secure_credential_manager.store_credential(
    service="shodan",
    api_key="your_api_key_here",
    notes="Shodan API for host enumeration"
)

# Store AWS credentials
secure_credential_manager.store_credential(
    service="aws-prod",
    username="AKIA...",  # Access Key ID
    password="...",      # Secret Access Key
    token="...",         # Session Token (optional)
    notes="Production AWS environment"
)

# Store database credentials
secure_credential_manager.store_credential(
    service="mysql-prod",
    username="dbuser",
    password="secure_password",
    domain="prod.company.com",
    notes="Production MySQL database"
)
```

### 3. Tool Integration

All tools automatically use the secure credential manager:

```python
# API Integration - automatically uses stored credentials
from app.core.api_integration import api_integration

# No need to provide API key - retrieved from secure storage
result = api_integration.query_shodan("192.168.1.1")

# AWS Pentest - uses stored AWS credentials
from app.core.aws_pentest_engine import AWSPentestWorker

worker = AWSPentestWorker(
    scan_type="iam_enum",
    service_name="aws-prod"  # References stored credential
)
```

### 4. Secure Memory Usage

For sensitive operations requiring in-memory protection:

```python
# Get secure memory reference
ref_id = secure_credential_manager.get_secure_memory_ref("aws-prod", "password")

# Use the reference
secret_value = secure_credential_manager.read_secure_memory(ref_id)

# Clear when done
secure_credential_manager.clear_secure_memory(ref_id=ref_id)
```

## Migration from Old System

### Automatic Migration

The system includes automatic migration from the old credential manager:

```python
from app.core.credential_migration import credential_migration

# Check if migration is needed
if credential_migration.check_migration_needed():
    # Create backup
    credential_migration.backup_old_credentials()
    
    # Perform migration
    success, log = credential_migration.migrate_credentials()
    
    if success:
        # Clean up old system
        credential_migration.cleanup_old_credentials()
```

### Manual Migration Steps

1. **Backup Existing Credentials**
   ```bash
   # Export current credentials
   python -c "from app.core.credential_manager import credential_manager; print(credential_manager.to_dict())"
   ```

2. **Configure New System**
   - Set environment variables for critical credentials
   - Configure enterprise secrets manager if available
   - Add credentials through the UI

3. **Validate Migration**
   - Test all integrated tools
   - Verify credential access in security tab
   - Check audit logs

## Security Best Practices

### 1. Credential Hierarchy

Follow the security hierarchy for credential storage:

1. **Environment Variables** (Development/Testing)
   - Easy to set and change
   - No persistent storage
   - Good for CI/CD pipelines

2. **Enterprise Secrets Manager** (Production)
   - Centralized management
   - Access controls and auditing
   - Automatic rotation support

3. **Local Encrypted Storage** (Fallback)
   - Encrypted with Fernet
   - Restrictive file permissions
   - Suitable for personal use

### 2. Access Controls

```python
# Configure access controls
secure_credential_manager.configure_secrets_manager(
    provider="vault",
    vault_url="https://vault.company.com:8200",
    vault_token="hvs.XXXXXXXXXXXXXXXX"
)

# Test credential validity
result = secure_credential_manager.test_credential("aws-prod")
if result["success"]:
    print("Credential is valid")
else:
    print(f"Credential test failed: {result['error']}")
```

### 3. Monitoring and Auditing

```python
# Get security summary
summary = secure_credential_manager.get_security_summary()
print(f"Total credentials: {summary['total_credentials']}")
print(f"Encryption enabled: {summary['encryption_enabled']}")
print(f"Secrets manager configured: {summary['secrets_manager_configured']}")

# Monitor credential access
def on_credential_accessed(service, username):
    print(f"Credential accessed: {service} ({username})")

secure_credential_manager.credential_accessed.connect(on_credential_accessed)
```

## Tool Integration Examples

### 1. API Integration Tools

```python
# Shodan integration
from app.core.api_integration import api_integration

# Automatically uses stored Shodan API key
result = api_integration.query_shodan("8.8.8.8")

# VirusTotal integration
result = api_integration.query_virustotal("malicious-domain.com")
```

### 2. AWS Penetration Testing

```python
# AWS pentest with stored credentials
from app.core.aws_pentest_engine import AWSPentestWorker

worker = AWSPentestWorker(
    scan_type="full_pentest",
    service_name="aws-prod",  # Uses stored AWS credentials
    target_regions=["us-east-1", "us-west-2"]
)
worker.start()
```

### 3. Authenticated Web Crawling

```python
# Web crawler with stored credentials
from app.core.authenticated_crawler import AuthenticatedCrawler

crawler = AuthenticatedCrawler()

# Automatically tries stored web credentials
success = crawler.authenticate(
    target_url="https://app.company.com/login",
    auth_method="auto"  # Uses stored credentials
)
```

### 4. Database Enumeration

```python
# Database tools automatically use stored credentials
from app.tools.db_enum import DatabaseEnumerator

enumerator = DatabaseEnumerator()

# Uses stored MySQL credentials
results = enumerator.enumerate_mysql("192.168.1.100")
```

## Enterprise Deployment

### 1. HashiCorp Vault Integration

```yaml
# vault-policy.hcl
path "huggin/*" {
  capabilities = ["read", "list"]
}

path "huggin/aws/*" {
  capabilities = ["read"]
}
```

```bash
# Deploy policy
vault policy write huggin-policy vault-policy.hcl

# Create token
vault token create -policy=huggin-policy -ttl=24h
```

### 2. AWS Secrets Manager Integration

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:ListSecrets"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:huggin/*"
    }
  ]
}
```

### 3. Azure Key Vault Integration

```bash
# Grant access to Key Vault
az keyvault set-policy \
  --name "company-keyvault" \
  --object-id "user-object-id" \
  --secret-permissions get list
```

## Troubleshooting

### Common Issues

1. **Credential Not Found**
   ```
   Error: Credential not found for service 'shodan'
   
   Solution:
   - Check environment variables: SHODAN_API_KEY
   - Verify credential is stored in secure manager
   - Test secrets manager connection
   ```

2. **Encryption Key Error**
   ```
   Error: Failed to decrypt credentials
   
   Solution:
   - Check HUGGIN_MASTER_PASSWORD environment variable
   - Verify file permissions on credential files
   - Re-initialize credential manager if needed
   ```

3. **Secrets Manager Connection Failed**
   ```
   Error: Failed to connect to HashiCorp Vault
   
   Solution:
   - Verify VAULT_ADDR and VAULT_TOKEN
   - Check network connectivity
   - Validate Vault policies
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Test credential retrieval
credential = secure_credential_manager.get_credential("shodan")
if not credential:
    print("Credential not found - check debug logs")
```

### Health Check

```python
# Perform comprehensive health check
def health_check():
    summary = secure_credential_manager.get_security_summary()
    
    print("=== Credential Manager Health Check ===")
    print(f"Encryption: {'✓' if summary['encryption_enabled'] else '✗'}")
    print(f"Secrets Manager: {'✓' if summary['secrets_manager_configured'] else '✗'}")
    print(f"Total Credentials: {summary['total_credentials']}")
    print(f"Environment Credentials: {summary['environment_credentials']}")
    
    # Test each service
    for service in secure_credential_manager.list_services():
        result = secure_credential_manager.test_credential(service)
        status = "✓" if result["success"] else "✗"
        print(f"{service}: {status}")

health_check()
```

## API Reference

### SecureCredentialManager

#### Methods

- `store_credential(service, username, password, api_key, token, domain, notes, source)`
- `get_credential(service, use_env, use_secrets_manager)`
- `remove_credential(service)`
- `list_services()`
- `test_credential(service)`
- `configure_secrets_manager(provider, **kwargs)`
- `get_secure_memory_ref(service, field)`
- `clear_secure_memory(service, ref_id)`

#### Signals

- `credential_stored(service)` - Emitted when credential is stored
- `credential_accessed(service, username)` - Emitted when credential is accessed
- `security_event(event_type, message)` - Emitted for security events

### Environment Variable Patterns

```
SERVICE_USERNAME or SERVICE_USER
SERVICE_PASSWORD or SERVICE_PASS
SERVICE_API_KEY or SERVICE_KEY
SERVICE_TOKEN
```

Examples:
- `SHODAN_API_KEY`
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
- `MYSQL_USERNAME` / `MYSQL_PASSWORD`
- `VIRUSTOTAL_API_KEY`

## Conclusion

The secure credential management system provides enterprise-grade security while maintaining ease of use. By centralizing credential storage and mandating its use across all tools, Huggin ensures consistent security practices and reduces the risk of credential exposure.

Key benefits:
- ✅ Centralized credential management
- ✅ Enterprise secrets manager integration
- ✅ Encrypted local storage with secure memory handling
- ✅ Automatic migration from old system
- ✅ Comprehensive audit logging
- ✅ Tool integration enforcement
- ✅ Environment variable prioritization

This system is particularly critical for AWS penetration testing where credential compromise could lead to full cloud environment takeover.