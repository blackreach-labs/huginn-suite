# API Integration Guide

## Overview

Huggin's API integration system enables connectivity with external services for enhanced intelligence gathering and data enrichment.

## Supported APIs

### Shodan
- **Purpose**: Internet-connected device discovery
- **Authentication**: API key required
- **Data**: Open ports, services, geolocation, organization info

### VirusTotal
- **Purpose**: Domain and file reputation analysis
- **Authentication**: API key required
- **Data**: Malware detection, reputation scores, analysis results

### URLVoid
- **Purpose**: Domain reputation checking
- **Authentication**: Free tier available
- **Data**: Reputation status, blacklist checks

### Custom APIs
- **Purpose**: Generic HTTP API integration
- **Authentication**: Configurable headers
- **Data**: Flexible JSON response handling

## Implementation

### Basic API Query
```python
from app.core.api_integration import api_integration

# Query with API key
result = api_integration.query_shodan("8.8.8.8", "your_api_key")

# Handle response
if 'error' not in result:
    print(f"Found {len(result['ports'])} open ports")
else:
    print(f"Error: {result['error']}")
```

### Custom API Integration
```python
# Custom API request
result = api_integration.custom_api_request(
    url="https://api.example.com/lookup",
    method="POST",
    headers={"Authorization": "Bearer token"},
    data={"target": "example.com"}
)
```

### Response Format
All API integrations return standardized response format:
```python
{
    "source": "API_NAME",
    "target": "queried_target",
    "data": {...},  # API-specific data
    "success": True,  # Optional success indicator
    "error": "Error message"  # If error occurred
}
```

## Adding New APIs

### 1. Extend APIIntegration Class
```python
def query_new_service(self, target, api_key=None):
    """Query new API service."""
    try:
        url = f"https://api.newservice.com/lookup/{target}"
        headers = {"X-API-Key": api_key} if api_key else {}
        response = self.session.get(url, headers=headers, timeout=self.timeout)
        
        if response.status_code == 200:
            data = response.json()
            result = {
                "source": "NewService",
                "target": target,
                "data": data,
                "success": True
            }
            self.api_response.emit("newservice", result)
            return result
        else:
            return {"error": f"API error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
```

### 2. Update UI Widget
Add new service to combo box in `api_integration_widget.py`:
```python
self.service_combo.addItems(["Shodan", "VirusTotal", "URLVoid", "NewService", "Custom API"])
```

### 3. Handle Service Selection
Add case in `execute_api_query` method:
```python
elif service == "NewService":
    result = api_integration.query_new_service(target, api_key)
```

## Best Practices

### Error Handling
- Always handle network timeouts
- Provide meaningful error messages
- Gracefully handle API rate limits

### Security
- Never log API keys
- Use secure storage for credentials
- Validate API responses

### Performance
- Implement request timeouts
- Use session pooling for multiple requests
- Cache responses when appropriate

### Rate Limiting
- Respect API rate limits
- Implement backoff strategies
- Monitor API usage quotas