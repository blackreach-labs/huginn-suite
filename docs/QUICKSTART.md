# Huggin Scanner - Quick Start

## Installation

```bash
# Clone repository
git clone https://github.com/your-org/huggin
cd huggin

# Install dependencies
pip install -r requirements.txt

# Or install as package
pip install -e .
```

## Basic Usage

### 1. Simple Scan
```bash
python -m app.tools.huggin_vuln_scanner --target https://example.com
```

### 2. Aggressive Scan with Report
```bash
python -m app.tools.huggin_vuln_scanner \
  --target https://example.com \
  --profile aggressive \
  --format html \
  --output report.html
```

### 3. Python Script
```python
import asyncio
from app.tools.huggin_vuln_scanner import HugginVulnScanner

async def scan():
    scanner = HugginVulnScanner('https://example.com', profile='normal')
    results = await scanner.scan()
    
    print(f"Found {len(results['vulnerabilities'])} vulnerabilities")
    
    # Save report
    with open('report.html', 'w') as f:
        f.write(scanner.export_results('html'))

asyncio.run(scan())
```

## Scan Profiles

- **light**: Fast basic checks (20 concurrent, 5s timeout)
- **normal**: Balanced scan (50 concurrent, 10s timeout) 
- **aggressive**: Comprehensive scan (100 concurrent, 15s timeout)
- **insane**: All features including AI/ML (200 concurrent, 20s timeout)

## Key Features by Profile

| Feature | Light | Normal | Aggressive | Insane |
|---------|-------|--------|------------|--------|
| Basic Vulns | ✅ | ✅ | ✅ | ✅ |
| OSINT | ❌ | ✅ | ✅ | ✅ |
| API Testing | ❌ | ✅ | ✅ | ✅ |
| ML Prediction | ❌ | ❌ | ✅ | ✅ |
| Neural Networks | ❌ | ❌ | ❌ | ✅ |
| Quantum Fuzzing | ❌ | ❌ | ❌ | ✅ |
| Autonomous Agent | ❌ | ❌ | ❌ | ✅ |

## Output Formats

- `json`: Raw scan data
- `html`: Interactive report with evidence
- `executive`: Business summary
- `owasp`: OWASP Top 10 compliance
- `pci`: PCI DSS compliance

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    python -m app.tools.huggin_vuln_scanner \
      --target ${{ env.STAGING_URL }} \
      --profile normal \
      --format json \
      --output security-results.json
```

## Need Help?

- Check `README_USAGE.md` for detailed documentation
- See `examples/` directory for advanced usage
- Review configuration in `resources/config/scanner_config.yaml`