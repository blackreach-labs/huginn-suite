# Machine Learning Pattern Detection Guide

## Overview

Huginn's ML pattern detection system provides automated analysis of scan results to identify patterns, anomalies, and generate actionable insights.

## Supported Analysis Types

### DNS Enumeration Analysis
- **Subdomain Patterns**: Common naming conventions and prefixes
- **Wildcard Detection**: Potential wildcard DNS responses
- **Response Patterns**: Unusual response distributions

### Port Scan Analysis
- **Service Patterns**: Common service combinations (web, remote access)
- **Port Clustering**: Related service groupings
- **Anomaly Detection**: Excessive open ports, unusual combinations

### HTTP Enumeration Analysis
- **Response Code Patterns**: WAF detection, uniform responses
- **Content Patterns**: Similar response sizes or content
- **Security Indicators**: Protection mechanisms and filtering

## Implementation

### Basic Pattern Analysis
```python
from app.core.ml_pattern_detection import ml_pattern_detection

# Analyze scan results
analysis = ml_pattern_detection.analyze_scan_results(results, "dns_enum")

# Extract patterns and anomalies
patterns = analysis["patterns"]
anomalies = analysis["anomalies"]
insights = analysis["insights"]
```

### Analysis Result Format
```python
{
    "scan_type": "dns_enum",
    "timestamp": "2024-01-15T12:30:00Z",
    "patterns": [
        {
            "type": "subdomain_naming",
            "pattern": "Common prefixes: www, mail, ftp",
            "confidence": 0.8
        }
    ],
    "anomalies": [
        {
            "type": "potential_wildcard",
            "description": "High number of duplicate responses detected",
            "severity": "medium"
        }
    ],
    "insights": [
        "Found 15 unique subdomains",
        "Detected common naming pattern"
    ]
}
```

### Anomaly Detection
```python
# Compare with historical data
anomalies = ml_pattern_detection.detect_scan_anomalies(
    current_results, 
    historical_results
)

# Generate insights
insights = ml_pattern_detection.generate_insights(analysis_results)
```

## Adding New Pattern Detection

### 1. Implement Analysis Method
```python
def _analyze_new_scan_type(self, results):
    """Analyze new scan type for patterns."""
    patterns = []
    anomalies = []
    insights = []
    
    # Pattern detection logic
    if self._detect_specific_pattern(results):
        patterns.append({
            "type": "new_pattern",
            "pattern": "Description of detected pattern",
            "confidence": 0.7
        })
    
    # Anomaly detection logic
    if self._detect_anomaly(results):
        anomalies.append({
            "type": "new_anomaly",
            "description": "Description of anomaly",
            "severity": "medium"
        })
    
    insights.append("Analysis completed")
    return {"patterns": patterns, "anomalies": anomalies, "insights": insights}
```

### 2. Integrate into Main Analysis
```python
def analyze_scan_results(self, results, scan_type):
    # Existing analysis types...
    
    elif scan_type == "new_scan_type":
        analysis.update(self._analyze_new_scan_type(results))
```

### 3. Update UI Integration
Add new scan type handling in the widget and enumeration page.

## Pattern Types

### Confidence Levels
- **High (>80%)**: Strong statistical evidence
- **Medium (60-80%)**: Moderate confidence
- **Low (<60%)**: Weak indicators

### Severity Classifications
- **High**: Critical security implications
- **Medium**: Notable deviations requiring attention
- **Low**: Minor anomalies for awareness

## Best Practices

### Algorithm Development
- Use statistical methods for pattern detection
- Implement confidence scoring based on evidence strength
- Consider false positive rates in threshold setting
- Validate patterns against known good/bad examples

### Performance Optimization
- Limit analysis to significant result sets
- Use efficient algorithms for large datasets
- Cache common pattern calculations
- Implement timeout handling for complex analysis

### Accuracy Improvement
- Collect feedback on pattern accuracy
- Adjust thresholds based on user validation
- Implement learning from historical data
- Provide context for pattern interpretations

### Integration Guidelines
- Trigger automatic analysis for significant results
- Provide manual analysis options
- Display results with appropriate confidence indicators
- Generate actionable insights and recommendations