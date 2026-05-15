# Azure Tenant Enumeration Toolkit

A comprehensive, modern Azure enumeration toolkit built using official Azure SDKs for Python. This toolkit provides authenticated enumeration of Azure tenants with compliance-focused design and professional-grade capabilities.

## 🚀 Features

### Core Modules

- **🔐 Authentication Layer** (`auth.py`) - Multi-method Azure authentication
- **👥 Azure AD Reconnaissance** (`ad_recon.py`) - Directory enumeration via Microsoft Graph
- **🏗️ ARM Resource Enumeration** (`arm_recon.py`) - Resource Manager API integration
- **💾 Storage Enumeration** (`storage_enum.py`) - Blob storage analysis
- **🌐 DNS Reconnaissance** (`dns_recon.py`) - Passive domain discovery
- **🎯 Main Orchestrator** (`main.py`) - Unified command-line interface

### Authentication Methods

- **Default Credential** - Managed identity, Azure CLI, environment variables
- **Interactive Browser** - OAuth2 device code flow
- **Client Secret** - Service principal authentication

### Enumeration Capabilities

#### DNS Enumeration (Passive)
- Azure domain discovery (*.azurewebsites.net, *.blob.core.windows.net, etc.)
- Tenant validation via OpenID configuration
- Service type identification
- Federation information gathering

#### Azure AD Enumeration
- User and group enumeration
- Service principal discovery
- Directory role analysis
- Application registration listing
- Privileged role identification

#### ARM Resource Enumeration
- Subscription listing
- Resource group enumeration
- Storage account discovery
- Key Vault identification
- Resource permission analysis

#### Storage Enumeration
- Container and blob listing
- Public access detection
- Sensitive file identification
- Security configuration analysis

## 📦 Installation

### Dependencies

```bash
pip install -r requirements.txt
```

### Required Packages

```
azure-identity>=1.12.0
azure-mgmt-resource>=22.0.0
azure-mgmt-storage>=21.0.0
azure-mgmt-keyvault>=10.2.0
azure-storage-blob>=12.14.0
msal>=1.20.0
requests>=2.28.0
dnspython>=2.3.0
tabulate>=0.9.0
```

## 🔧 Usage

### Command Line Interface

```bash
# DNS enumeration (passive, no authentication required)
python -m app.core.azure_toolkit.main --domain company.com --module dns

# Azure AD enumeration with default credentials
python -m app.core.azure_toolkit.main --module ad

# ARM resource enumeration with interactive authentication
python -m app.core.azure_toolkit.main --module arm --auth-method interactive

# Storage enumeration for specific subscription
python -m app.core.azure_toolkit.main --module storage --subscription-id <sub-id>

# Comprehensive scan with client secret authentication
python -m app.core.azure_toolkit.main --module all --domain company.com \
  --subscription-id <sub-id> --auth-method client-secret \
  --tenant-id <tenant-id> --client-id <client-id> --client-secret <secret>
```

### Python API Usage

```python
from app.core.azure_toolkit import AzureToolkit

# Initialize toolkit
toolkit = AzureToolkit()

# DNS enumeration (passive)
dns_results = toolkit.run_dns_enumeration('company.com')

# Authenticated enumeration
from azure.identity import DefaultAzureCredential
credential = DefaultAzureCredential()

ad_results = toolkit.run_ad_enumeration(credential)
arm_results = toolkit.run_arm_enumeration(credential)
storage_results = toolkit.run_storage_enumeration('subscription-id', credential)

# Comprehensive scan
comprehensive_results = toolkit.run_comprehensive_scan(
    domain='company.com',
    subscription_id='subscription-id',
    credential=credential
)
```

### GUI Integration

The toolkit integrates with the Huginn framework through:

- **AzureToolkitWidget** - Modern Qt-based interface
- **Enhanced AzurePentestEngine** - Legacy compatibility layer
- **Unified reporting** - JSON, table, and summary formats

## 📊 Output Formats

### JSON Format
```json
{
  "scan_type": "comprehensive",
  "timestamp": "2024-01-15T10:30:00",
  "dns_enumeration": {
    "summary": {
      "has_azure_tenant": true,
      "discovered_services": 5,
      "high_value_targets": [...]
    }
  },
  "summary": {
    "total_findings": 15,
    "high_risk_findings": [...],
    "recommendations": [...]
  }
}
```

### Table Format
```
SCAN SUMMARY
============
Modules Executed    | DNS Enumeration, Azure AD Enumeration
Total Findings      | 15
High Risk          | 3
Medium Risk        | 7
Low Risk           | 5
```

### Executive Summary
```
AZURE ENUMERATION EXECUTIVE SUMMARY
===================================
Scan Date: 2024-01-15T10:30:00
Modules: DNS Enumeration, Azure AD Enumeration

HIGH RISK FINDINGS:
  • Found 2 privileged roles with members
  • Public blob containers discovered: 3

RECOMMENDATIONS:
  • Review privileged role assignments
  • Secure public storage containers
```

## 🔒 Security Considerations

### Authentication Security
- Credential caching with expiry validation
- Support for least-privilege service principals
- Secure token handling and storage

### Enumeration Ethics
- Read-only operations only
- Respects Azure API rate limits
- Designed for authorized testing only
- Comprehensive audit logging

### Data Protection
- No credential storage in results
- Sensitive data truncation
- Configurable output sanitization

## 🏗️ Architecture

### Module Structure
```
azure_toolkit/
├── __init__.py          # Package initialization
├── auth.py              # Authentication layer
├── ad_recon.py          # Azure AD enumeration
├── arm_recon.py         # ARM resource enumeration
├── storage_enum.py      # Storage enumeration
├── dns_recon.py         # DNS reconnaissance
├── main.py              # CLI orchestrator
├── requirements.txt     # Dependencies
└── README.md           # Documentation
```

### Integration Points
- **Huginn Framework** - Native Qt widget integration
- **Legacy Engine** - Backward compatibility layer
- **External Tools** - JSON/API output for automation
- **CI/CD Pipelines** - Command-line automation support

## 🧪 Testing

### Unit Tests
```bash
pytest app/core/azure_toolkit/tests/
```

### Integration Tests
```bash
# Requires valid Azure credentials
pytest app/core/azure_toolkit/tests/integration/
```

### Mock Testing
```bash
# Uses mocked Azure SDK responses
pytest app/core/azure_toolkit/tests/unit/
```

## 📈 Performance

### Optimization Features
- Connection pooling for API requests
- Intelligent result caching
- Concurrent enumeration where possible
- Rate limiting compliance

### Scalability
- Supports multiple subscription enumeration
- Batch processing for large tenants
- Memory-efficient result streaming
- Configurable timeout handling

## 🔄 Migration from Legacy

### Compatibility Layer
The new toolkit maintains compatibility with existing Huginn Azure features:

```python
# Legacy usage still works
from app.core.azure_pentest_engine import azure_engine
results = azure_engine.run_comprehensive_scan('company.com')

# Enhanced results now include toolkit data
toolkit_results = results['toolkit_scan']
legacy_results = results['legacy_scan']
```

### Migration Benefits
- **Official SDK compliance** - No more custom HTTP implementations
- **Better error handling** - Proper exception management
- **Enhanced authentication** - Multiple auth methods
- **Improved reporting** - Structured output formats
- **Professional grade** - Enterprise-ready architecture

## 📝 License

This toolkit is part of the Huginn security framework and follows the same licensing terms.

## 🤝 Contributing

1. Follow Azure SDK best practices
2. Maintain backward compatibility
3. Add comprehensive tests
4. Update documentation
5. Respect rate limits and API guidelines

## 📞 Support

For issues and feature requests, please use the main Huginn framework issue tracker.

---

**⚠️ Important**: This toolkit is designed for authorized security testing only. Ensure you have proper permissions before enumerating any Azure tenant or resources.