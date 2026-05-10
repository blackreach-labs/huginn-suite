# app/tools/scan_plugins/waf_plugin.py

class WAFPlugin:
    def __init__(self):
        self.name = "WAF Detection"
    
    def scan(self, url, response, session):
        """Detect Web Application Firewall"""
        try:
            # Test with malicious payload
            test_url = f"{url}?test=<script>alert(1)</script>"
            test_response = session.get(test_url, timeout=5, verify=self.ssl_verify)
            
            waf_indicators = {
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'AWS WAF': ['aws', 'x-amzn-requestid'],
                'Akamai': ['akamai', 'x-akamai'],
                'Incapsula': ['incapsula', 'x-iinfo'],
                'ModSecurity': ['mod_security', 'modsecurity'],
                'F5 BIG-IP': ['f5-bigip', 'x-wa-info'],
                'Barracuda': ['barracuda', 'barra'],
                'Sucuri': ['sucuri', 'x-sucuri']
            }
            
            detected_waf = []
            headers_str = str(test_response.headers).lower()
            content_str = test_response.text.lower()
            
            for waf_name, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator in headers_str or indicator in content_str:
                        detected_waf.append(waf_name)
                        break
            
            return {
                'detected_waf': detected_waf,
                'status_code': test_response.status_code,
                'blocked': test_response.status_code in [403, 406, 429, 503]
            }
            
        except Exception as e:
            return {'error': str(e)}