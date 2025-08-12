# Azure Tenant Enumeration Toolkit (Python)

## Project Overview

This toolkit is designed for security professionals to perform authenticated enumeration of Azure tenants. It leverages the official Azure SDKs for Python, ensuring compliance with licensing requirements.

## Project Structure

```css
azure_enum_tool/
├── src/
│   ├── auth.py
│   ├── ad_recon.py
│   ├── arm_recon.py
│   ├── storage_enum.py
│   ├── dns_recon.py
│   └── main.py
├── tests/
│   ├── test_auth.py
│   ├── test_ad_recon.py
│   └── ...
├── requirements.txt
├── pyproject.toml
├── README.md
└── LICENSE
```

## Module Descriptions

### auth.py – Authentication Layer

- Purpose: Handles authentication to Azure using various methods.
- Dependencies: azure-identity
- Functions:
    get_token(scopes: List[str]): Acquires an access token for the specified scopes.

### ad_recon.py – Azure AD Enumeration

- Purpose: Enumerates Azure Active Directory entities.
- Dependencies: msal, requests
- Functions:
    list_users(token: str): Lists users in the tenant.
    list_groups(token: str): Lists groups in the tenant.
    list_service_principals(token: str): Lists service principals.
    list_roles_and_assignments(token: str): Lists directory roles and assignments.

### arm_recon.py – Azure Resource Manager Enumeration

- Purpose: Enumerates Azure resources.
- Dependencies: azure-mgmt-resource, azure-mgmt-storage, azure-mgmt-keyvault
- Functions:
    list_subscriptions(): Lists subscriptions.
    list_resource_groups(subscription_id: str): Lists resource groups in a subscription.
    list_resources(subscription_id: str): Lists resources in a subscription.
    list_storage_accounts(subscription_id: str): Lists storage accounts.

### storage_enum.py – Storage Account Enumeration

- Purpose: Enumerates Azure storage accounts and containers.
- Dependencies: azure-storage-blob
- Functions:
    enumerate_storage_accounts(): Enumerates storage accounts.
    list_containers_and_blobs(storage_account: str, credentials: str): Lists containers and blobs in a storage account.

### dns_recon.py – DNS Enumeration

- Purpose: Performs passive DNS enumeration to discover Azure-related domains.
- Dependencies: dnspython
- Functions:
    enumerate_domains(domain: str): Enumerates related domains.

### main.py – Orchestration

- Purpose: Coordinates the execution of various enumeration modules based on user input.
- Dependencies: argparse, json, tabulate
- Functions:
    main(): Main function to parse arguments and execute corresponding modules.

### Requirements

- Python Version: 3.8 or higher
- Dependencies:
    azure-identity
    msal
    requests
    azure-mgmt-resource
    azure-mgmt-storage
    azure-mgmt-keyvault
    azure-storage-blob
    dnspython
    argparse
    json
    tabulate

### Testing

- Framework: pytest
- Mocking: Use unittest.mock or pytest-mock to mock Azure SDK calls.
- Test Coverage: Aim for 80% or higher test coverage.

### Documentation

- README.md: Provide detailed documentation on installation, usage, and examples.
- Inline Comments: Ensure code is well-commented for clarity.
