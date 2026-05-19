# app/core/flowise_detector.py
"""
Flowise CVE-2025-58434 Detector

Non-destructive verification-only scanner that:
1. Fingerprints the target to identify Flowise instances
2. Probes the forgot-password endpoint for tempToken leakage
3. Never attempts password changes or token use

CVE-2025-58434: Flowise password-reset endpoint leaks tempToken in response,
allowing unauthenticated account takeover.
"""
import requests
import re
from urllib.parse import urljoin
from dataclasses import dataclass, field
from typing import Optional, List
from app.core.logger import logger


@dataclass
class FlowiseScanResult:
    target: str
    detected: bool = False
    version: Optional[str] = None
    vulnerable: bool = False
    confidence: str = "low"
    details: str = ""
    leaked_fields: List[str] = field(default_factory=list)

    def to_finding(self) -> Optional[dict]:
        """Convert to standard vulnerability finding format."""
        if not self.vulnerable:
            return None
        return {
            'name': 'Flowise tempToken Leakage (CVE-2025-58434)',
            'cve': 'CVE-2025-58434',
            'severity': 'CRITICAL',
            'service': 'Flowise',
            'target': self.target,
            'version': self.version,
            'confidence': self.confidence,
            'description': (
                'The Flowise /api/v1/account/forgot-password endpoint leaks '
                'sensitive authentication tokens in its response body, enabling '
                'unauthenticated account takeover.'
            ),
            'evidence': self.leaked_fields,
            'details': self.details,
            'recommendation': (
                'Upgrade Flowise to a patched version. The forgot-password '
                'endpoint should not return tempToken or similar secrets in '
                'the HTTP response.'
            ),
        }


class FlowiseDetector:
    """Non-destructive Flowise CVE-2025-58434 scanner.
    
    Detection flow:
    1. Fingerprint target via known Flowise indicators
    2. If Flowise detected, probe forgot-password endpoint
    3. Flag only if sensitive fields are leaked in response
    4. Never performs actual password resets or uses tokens
    """

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Huginn-FlowiseScanner/1.0"
        })
        # Suppress TLS warnings for self-signed certs
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def scan(self, target: str) -> FlowiseScanResult:
        """Run full detection pipeline against target.
        
        Args:
            target: Base URL of the target (e.g., http://10.10.10.5:3000)
            
        Returns:
            FlowiseScanResult with detection and vulnerability status
        """
        result = FlowiseScanResult(target=target)

        try:
            # Step 1: Fingerprint
            result.detected, result.version = self._fingerprint(target)

            if not result.detected:
                result.details = "Flowise not identified on target"
                return result

            # Step 2: Check CVE-2025-58434
            vuln = self._check_cve_2025_58434(target)
            result.vulnerable = vuln["vulnerable"]
            result.confidence = vuln["confidence"]
            result.details = vuln["details"]
            result.leaked_fields = vuln.get("leaked_fields", [])

            return result

        except Exception as e:
            logger.error(f"Flowise scan error on {target}: {e}")
            result.details = f"Scan error: {e}"
            return result

    def _fingerprint(self, target: str):
        """Identify whether the target is running Flowise.
        
        Checks multiple indicators without authentication:
        - HTML/JS content containing 'flowise'
        - X-Powered-By header
        - Known API endpoints
        
        Returns:
            Tuple of (detected: bool, version: Optional[str])
        """
        indicator_paths = [
            "/",
            "/api/v1/chatflows",
            "/api/v1/ping",
        ]

        for path in indicator_paths:
            url = urljoin(target, path)
            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                text = resp.text.lower()
                if "flowise" in text:
                    version = self._extract_version(resp.text)
                    return True, version

                powered_by = resp.headers.get("x-powered-by", "").lower()
                if "flowise" in powered_by:
                    return True, None

            except requests.exceptions.RequestException:
                continue

        return False, None

    def _extract_version(self, text: str) -> Optional[str]:
        """Extract Flowise version from response content."""
        patterns = [
            r'version["\']?\s*:\s*["\']([^"\']+)',
            r'flowise[^\d]*(\d+\.\d+\.\d+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _check_cve_2025_58434(self, target: str) -> dict:
        """Probe forgot-password endpoint for tempToken leakage.
        
        Sends a POST with a non-existent test email to the forgot-password
        endpoint and inspects the response for leaked sensitive fields.
        
        This is non-destructive: even if the email existed, we never use
        any returned token.
        
        Returns:
            Dict with vulnerable, confidence, details, leaked_fields keys
        """
        endpoint = urljoin(target, "/api/v1/account/forgot-password")
        
        # Use a clearly-fake email that won't match real accounts
        test_payload = {"email": "security-test-nonexistent@example.invalid"}

        try:
            resp = self.session.post(
                endpoint,
                json=test_payload,
                timeout=self.timeout,
                verify=False
            )

            # Check if endpoint exists
            if resp.status_code == 404:
                return {
                    "vulnerable": False,
                    "confidence": "medium",
                    "details": "Forgot-password endpoint not found (404)",
                    "leaked_fields": []
                }

            # Parse response
            try:
                data = resp.json()
            except (ValueError, requests.exceptions.JSONDecodeError):
                return {
                    "vulnerable": False,
                    "confidence": "low",
                    "details": "Endpoint did not return JSON response",
                    "leaked_fields": []
                }

            # Check for leaked sensitive fields
            sensitive_fields = ["tempToken", "userId", "token", "resetToken", "secret"]
            leaked = [f for f in sensitive_fields if f in data]

            if leaked:
                return {
                    "vulnerable": True,
                    "confidence": "high",
                    "details": f"Sensitive fields exposed in response: {leaked}",
                    "leaked_fields": leaked
                }

            return {
                "vulnerable": False,
                "confidence": "medium",
                "details": "No token leakage observed in response",
                "leaked_fields": []
            }

        except requests.exceptions.ConnectionError:
            return {
                "vulnerable": False,
                "confidence": "low",
                "details": "Connection failed to forgot-password endpoint",
                "leaked_fields": []
            }
        except Exception as e:
            return {
                "vulnerable": False,
                "confidence": "low",
                "details": f"Probe error: {e}",
                "leaked_fields": []
            }
