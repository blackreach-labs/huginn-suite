# Threat Intelligence Guide

## Overview

Huginn's threat intelligence system provides IOC (Indicator of Compromise) checking against multiple threat feeds to identify malicious IPs and domains.

## Supported Threat Feeds

### Abuse.ch Feodo Tracker
- **Purpose**: Malware C&C server tracking
- **Data Type**: IP addresses
- **Update Frequency**: Real-time
- **Coverage**: Banking trojans, botnets, malware infrastructure

### Malware Domains
- **Purpose**: Malware hosting domain identification
- **Data Type**: Domain names
- **Update Frequency**: Daily
- **Coverage**: Known malware distribution sites

### Phishing Army
- **Purpose**: Phishing domain detection
- **Data Type**: Domain names
- **Update Frequency**: Real-time
- **Coverage**: Active phishing campaigns

## Implementation

### Basic IOC Check
```python
from app.core.threat_intelligence import threat_intelligence

# Check IP reputation
result = threat_intelligence.check_ip_reputation("192.168.1.1")

# Check domain reputation
result = threat_intelligence.check_domain_reputation("suspicious.com")

# Automatic detection (IP or domain)
result = threat_intelligence.get_ioc_summary("target")
```

### Response Format
```python
{
    "ip": "192.168.1.1",  # or "domain": "example.com"
    "threats": [
        {
            "source": "Abuse.ch Feodo Tracker",
            "type": "malware",
            "description": "Malware C&C server: Emotet",
            "severity": "high",
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-15T12:00:00Z"
        }
    ],
    "feeds_checked": ["abuse_ch", "malware_domains"],
    "timestamp": "2024-01-15T12:30:00Z"
}
```

## Adding New Threat Feeds

### 1. Add Feed Configuration
```python
self.feeds = {
    "existing_feed": "https://example.com/feed.json",
    "new_feed": "https://newfeed.com/indicators.txt"
}
```

### 2. Implement Feed Parser
```python
def check_new_feed(self, target):
    """Check target against new threat feed."""
    try:
        response = self.session.get(self.feeds["new_feed"], timeout=self.timeout)
        if response.status_code == 200:
            # Parse feed data
            indicators = self.parse_new_feed(response.text)
            
            if target in indicators:
                return {
                    "source": "New Threat Feed",
                    "type": "malware",
                    "description": "Detected in new feed",
                    "severity": "medium"
                }
    except Exception:
        pass
    return None
```

### 3. Integrate into Check Methods
```python
def check_ip_reputation(self, ip_address):
    # Existing checks...
    
    # Add new feed check
    new_threat = self.check_new_feed(ip_address)
    if new_threat:
        results["threats"].append(new_threat)
        results["feeds_checked"].append("new_feed")
```

## Feed Management

### Feed Status Monitoring
```python
# Check all feed availability
status = threat_intelligence.get_feed_status()

# Example response
{
    "abuse_ch": {
        "status": "online",
        "last_checked": "2024-01-15T12:30:00Z"
    },
    "malware_domains": {
        "status": "offline",
        "last_checked": "2024-01-15T12:30:00Z"
    }
}
```

### Error Handling
- Network timeouts handled gracefully
- Feed unavailability doesn't block other checks
- Partial results returned when some feeds fail
- Status monitoring for feed health

## Best Practices

### Performance
- Use appropriate timeouts for feed requests
- Implement caching for frequently checked IOCs
- Handle large feed files efficiently
- Monitor feed response times

### Accuracy
- Validate feed data formats
- Handle false positives appropriately
- Provide context for threat classifications
- Include confidence scores when available

### Security
- Verify feed source authenticity
- Use secure connections (HTTPS) when possible
- Sanitize feed data before processing
- Log security-relevant events

### Maintenance
- Monitor feed availability and quality
- Update feed URLs when they change
- Remove deprecated or inactive feeds
- Document feed characteristics and limitations