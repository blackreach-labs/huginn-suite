# Huginn Scanner API Reference

## Core Classes

### HuginnVulnScanner

Main scanner class that orchestrates the vulnerability assessment process.

```python
class HuginnVulnScanner:
    def __init__(self, target_url: str, profile: str = 'normal', config_path: str = None)
```

**Parameters:**
- `target_url`: Target URL to scan
- `profile`: Scan profile ('light', 'normal', 'aggressive', 'insane')
- `config_path`: Optional path to custom configuration file

**Methods:**

#### `async scan() -> Dict`
Executes the complete vulnerability scan.

**Returns:** Dictionary containing scan results with keys:
- `target`: Target URL
- `scan_time`: Timestamp of scan execution
- `vulnerabilities`: List of discovered vulnerabilities
- `tech_stack`: Detected technologies
- `ai_insights`: AI-generated insights
- `vulnerability_correlations`: Attack chain analysis
- `owasp_report`: OWASP Top 10 compliance
- `pci_dss_report`: PCI DSS compliance
- `security_gate`: Pass/fail status

#### `export_results(format: str) -> str`
Exports scan results in specified format.

**Parameters:**
- `format`: Export format ('json', 'html', 'executive', 'owasp', 'pci')

**Returns:** Formatted report string

#### `generate_cicd_config(pipeline_type: str) -> str`
Generates CI/CD pipeline configuration.

**Parameters:**
- `pipeline_type`: Pipeline type ('jenkins', 'github')

**Returns:** Pipeline configuration string

### ConfigManager

Manages scanner configuration and profiles.

```python
class ConfigManager:
    def __init__(self, config_path: str = None)
    
    def get_profile(self, profile_name: str) -> Dict
    def set_auth(self, method: str, **kwargs)
    def get_headers(self) -> Dict
    def update_profile(self, profile_name: str, updates: Dict)
```

### StateManager

Handles session state and CSRF tokens.

```python
class StateManager:
    def __init__(self, session: aiohttp.ClientSession)
    
    async def get_csrf_token(self, url: str, form_selector: str = 'form') -> Optional[str]
    async def login(self, login_url: str, username: str, password: str) -> bool
```

### PayloadManager

Context-aware payload generation system.

```python
class PayloadManager:
    def __init__(self, tech_stack: List[str] = None, limit: int = 3)
    
    def get_xss_payloads(self, context: str = 'generic') -> List[str]
    def get_sqli_payloads(self) -> List[str]
```

## AI & ML Components

### NeuralVulnerabilityEngine

Neural network-based vulnerability detection.

```python
class NeuralVulnerabilityEngine:
    def __init__(self)
    
    def train_on_vulnerability(self, vulnerability_data: Dict, is_vulnerable: bool)
    def predict_vulnerability(self, test_data: Dict) -> Tuple[float, str]
    def generate_targeted_payloads(self, target_profile: Dict) -> List[str]
```

### QuantumFuzzer

Quantum-inspired fuzzing engine.

```python
class QuantumFuzzer:
    def __init__(self)
    
    def create_payload_superposition(self, base_payloads: List[str]) -> List[Dict]
    def collapse_superposition(self, quantum_payload: Dict, context: Dict) -> str
    def create_entangled_payloads(self, payload_pairs: List[Tuple[str, str]]) -> Dict
    def quantum_tunneling_bypass(self, blocked_payloads: List[str]) -> List[str]
```

### AutonomousSecurityAgent

AI agent for autonomous penetration testing.

```python
class AutonomousSecurityAgent:
    def __init__(self, session: aiohttp.ClientSession)
    
    async def execute_autonomous_mission(self, target: str, objectives: List[str]) -> Dict
```

## Advanced Detection Modules

### SSTIDetector

Server-Side Template Injection detection.

```python
class SSTIDetector:
    def __init__(self, session: aiohttp.ClientSession)
    
    async def test_ssti(self, url: str, param: str) -> Optional[Dict]
```

### DeserializationDetector

Insecure deserialization detection.

```python
class DeserializationDetector:
    def __init__(self, session: aiohttp.ClientSession)
    
    async def check_cookies(self, cookies: Dict[str, str]) -> List[Dict]
```

### BusinessLogicTester

Business logic vulnerability testing.

```python
class BusinessLogicTester:
    def __init__(self, session: aiohttp.ClientSession)
    
    async def test_idor(self, url: str) -> List[Dict]
    async def test_mass_assignment(self, form_url: str, form_data: Dict) -> Optional[Dict]
```

### APISecurityTester

API security testing module.

```python
class APISecurityTester:
    def __init__(self, session: aiohttp.ClientSession)
    
    async def test_api_security(self, target: str) -> List[Dict]
    async def _test_graphql_security(self, target: str) -> List[Dict]
    async def _test_jwt_security(self, target: str) -> List[Dict]
```

## Enterprise Components

### MultiTargetOrchestrator

Multi-target campaign management.

```python
class MultiTargetOrchestrator:
    def __init__(self, max_concurrent_targets: int = 3)
    
    def add_scan_campaign(self, campaign_name: str, targets: List[str], profile: str = 'normal')
    async def execute_campaign(self, campaign_name: str) -> Dict
    def generate_campaign_summary(self, campaign_name: str) -> Dict
```

### ComplianceReporter

Compliance reporting engine.

```python
class ComplianceReporter:
    def __init__(self)
    
    def generate_owasp_report(self, scan_results: Dict) -> Dict
    def generate_pci_dss_report(self, scan_results: Dict) -> Dict
    def generate_executive_summary(self, scan_results: Dict) -> str
```

### CICDIntegration

CI/CD pipeline integration.

```python
class CICDIntegration:
    def __init__(self)
    
    def generate_jenkins_pipeline(self, target_url: str, profile: str = 'normal') -> str
    def generate_github_action(self, target_url: str, profile: str = 'normal') -> str
    def evaluate_security_gate(self, scan_results: Dict) -> Dict
```

## Utility Components

### EvidenceCollector

Evidence collection for vulnerability findings.

```python
class EvidenceCollector:
    def __init__(self)
    
    def capture_evidence(self, vuln_id: str, request_data: Dict, response_data: Dict)
    def get_evidence(self, vuln_id: str) -> Optional[Dict]
    def generate_evidence_html(self, vuln_id: str) -> str
```

### WebhookNotifier

Real-time webhook notifications.

```python
class WebhookNotifier:
    def __init__(self, webhook_url: str = None)
    
    async def notify_vulnerability(self, vulnerability: Dict, target: str)
    def set_webhook_url(self, url: str)
```

### OSINTCollector

OSINT and reconnaissance module.

```python
class OSINTCollector:
    def __init__(self, session: aiohttp.ClientSession)
    
    async def collect_intelligence(self, target: str) -> Dict
    async def _enumerate_subdomains(self, domain: str) -> List[str]
    async def _check_certificate_transparency(self, domain: str) -> List[Dict]
```

## Data Structures

### Vulnerability Object
```python
{
    'id': str,                    # Unique vulnerability identifier
    'type': str,                  # Vulnerability type
    'severity': str,              # Critical, High, Medium, Low
    'description': str,           # Detailed description
    'url': str,                   # Affected URL
    'payload': str,               # Exploit payload
    'cvss_score': float,          # CVSS score
    'remediation': str,           # Remediation advice
    'source': str,                # Detection source
    'confidence': str,            # Confidence level
    'evidence': Dict              # Supporting evidence
}
```

### Scan Results Object
```python
{
    'target': str,                        # Target URL
    'scan_time': float,                   # Scan timestamp
    'vulnerabilities': List[Dict],        # Vulnerability list
    'tech_stack': List[str],             # Detected technologies
    'ai_insights': List[str],            # AI-generated insights
    'vulnerability_correlations': Dict,   # Attack chain analysis
    'owasp_report': Dict,                # OWASP compliance
    'pci_dss_report': Dict,              # PCI DSS compliance
    'security_gate': Dict,               # Security gate status
    'scan_stats': Dict,                  # Performance statistics
    'osint_intelligence': Dict,          # OSINT findings
    'proof_of_concepts': List[Dict],     # PoC exploits
    'autonomous_mission': Dict           # Autonomous agent results
}
```

### Configuration Object
```python
{
    'scan_profile': str,                 # Active profile
    'profiles': Dict,                    # Profile definitions
    'authentication': Dict,              # Auth configuration
    'custom_headers': Dict,              # Custom HTTP headers
    'proxy': Dict,                       # Proxy settings
    'wordlists': Dict,                   # Wordlist paths
    'webhook_url': str                   # Webhook URL
}
```

## Error Handling

### Custom Exceptions
```python
class HuginnScannerError(Exception):
    """Base exception for scanner errors"""
    pass

class ConfigurationError(HuginnScannerError):
    """Configuration-related errors"""
    pass

class ScanTimeoutError(HuginnScannerError):
    """Scan timeout errors"""
    pass

class AuthenticationError(HuginnScannerError):
    """Authentication-related errors"""
    pass
```

## Usage Examples

### Basic Scanning
```python
import asyncio
from app.tools.huginn_vuln_scanner import HuginnVulnScanner

async def basic_scan():
    scanner = HuginnVulnScanner('https://example.com')
    results = await scanner.scan()
    return results

results = asyncio.run(basic_scan())
```

### Advanced Configuration
```python
async def advanced_scan():
    scanner = HuginnVulnScanner('https://example.com', profile='aggressive')
    
    # Configure authentication
    scanner.config_manager.set_auth('login', username='admin', password='pass')
    
    # Set custom headers
    scanner.config_manager.config['custom_headers'] = {
        'Authorization': 'Bearer token123'
    }
    
    # Configure webhook
    scanner.webhook_notifier.set_webhook_url('https://hooks.slack.com/...')
    
    results = await scanner.scan()
    
    # Generate reports
    html_report = scanner.export_results('html')
    executive_summary = scanner.export_results('executive')
    
    return results, html_report, executive_summary
```

### Multi-Target Campaign
```python
from app.core.multi_target_orchestrator import MultiTargetOrchestrator

async def campaign_scan():
    orchestrator = MultiTargetOrchestrator()
    
    campaign = orchestrator.add_scan_campaign(
        'security_assessment',
        ['https://app1.com', 'https://app2.com'],
        profile='normal'
    )
    
    results = await orchestrator.execute_campaign('security_assessment')
    summary = orchestrator.generate_campaign_summary('security_assessment')
    
    return results, summary
```

## Integration Examples

### Flask Web Application
```python
from flask import Flask, request, jsonify
from app.tools.huginn_vuln_scanner import HuginnVulnScanner

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
async def scan_endpoint():
    data = request.get_json()
    target = data.get('target')
    profile = data.get('profile', 'normal')
    
    scanner = HuginnVulnScanner(target, profile=profile)
    results = await scanner.scan()
    
    return jsonify(results)
```

### Celery Task
```python
from celery import Celery
from app.tools.huginn_vuln_scanner import HuginnVulnScanner

app = Celery('huginn_scanner')

@app.task
async def scan_task(target_url, profile='normal'):
    scanner = HuginnVulnScanner(target_url, profile=profile)
    results = await scanner.scan()
    return results
```

---

*This API reference covers the core components and usage patterns of the Huginn Advanced Security Scanner. For additional examples and advanced usage, refer to the examples/ directory in the project repository.*