"""
AV/Firewall Detection Scanner
Provides Web Application Firewall (WAF) detection capabilities.

This module has been refactored to contain only WAF detection logic.
Network firewall detection, evasion testing, and payload generation
are now handled by dedicated worker modules:
  - firewall_detector.py (FirewallDetectorWorker)
  - evasion_profiler.py (EvasionProfilerWorker)
  - payload_generator.py (PayloadGeneratorWorker)
  - ids_ips_detector.py (IDSIPSDetectorWorker)
"""

import socket
import logging
from typing import Dict, List, Optional, Any
import requests
from app.core.logger import logger

logger = logging.getLogger(__name__)


class AVFirewallScanner:
    """WAF detection scanner"""

    def __init__(self):
        self.timeout = 30
        self.ssl_verify = True

    def detect_waf(self, target: str, port: int = 80) -> Dict[str, Any]:
        """Detect Web Application Firewall"""
        results = {
            'target': target,
            'port': port,
            'waf_detected': False,
            'waf_type': None,
            'indicators': [],
            'error': None
        }

        try:
            # Test basic HTTP request
            url = f"http://{target}:{port}"
            if port == 443:
                url = f"https://{target}:{port}"

            # Send test requests to detect WAF
            test_payloads = [
                "/?id=1'",  # SQL injection test
                "/?q=<script>alert(1)</script>",  # XSS test
                "/?file=../../../etc/passwd",  # Path traversal test
            ]

            for payload in test_payloads:
                try:
                    response = requests.get(url + payload, timeout=10, verify=self.ssl_verify)

                    # Check response headers for WAF indicators
                    waf_headers = {
                        'cloudflare': ['cf-ray', 'cloudflare'],
                        'akamai': ['akamai', 'x-akamai'],
                        'aws-waf': ['x-amzn-requestid', 'x-amz-cf-id'],
                        'f5-bigip': ['f5-bigip', 'x-waf-event'],
                        'imperva': ['x-iinfo', 'incap_ses'],
                        'sucuri': ['x-sucuri-id', 'sucuri'],
                        'barracuda': ['barra', 'x-barracuda'],
                        'fortinet': ['fortigate', 'x-fw']
                    }

                    for waf_name, indicators in waf_headers.items():
                        for indicator in indicators:
                            for header, value in response.headers.items():
                                if indicator.lower() in header.lower() or indicator.lower() in value.lower():
                                    results['waf_detected'] = True
                                    results['waf_type'] = waf_name
                                    results['indicators'].append(f"Header: {header}: {value}")

                    # Check response body for WAF indicators
                    if response.status_code in [403, 406, 429, 501, 503]:
                        waf_body_indicators = [
                            'blocked', 'forbidden', 'access denied', 'security',
                            'firewall', 'waf', 'protection', 'threat'
                        ]

                        for indicator in waf_body_indicators:
                            if indicator in response.text.lower():
                                results['waf_detected'] = True
                                results['indicators'].append(f"Body contains: {indicator}")
                                break

                    if results['waf_detected']:
                        break

                except requests.RequestException:
                    continue

        except Exception as e:
            results['error'] = str(e)
            logger.error(f"WAF detection error for {target}:{port} - {e}")

        return results


# Global scanner instance
av_firewall_scanner = AVFirewallScanner()
