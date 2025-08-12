# app/tools/waf_detector.py

class WAFDetector:
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                'content': ['cloudflare', 'attention required'],
                'status_codes': [403, 503]
            },
            'AWS WAF': {
                'headers': ['x-amzn-requestid', 'x-amzn-trace-id'],
                'content': ['aws', 'request blocked'],
                'status_codes': [403]
            },
            'Akamai': {
                'headers': ['x-akamai-transformed', 'x-akamai-request-id'],
                'content': ['akamai', 'reference #'],
                'status_codes': [403]
            },
            'Incapsula': {
                'headers': ['x-iinfo', 'x-cdn'],
                'content': ['incapsula', 'request unsuccessful'],
                'status_codes': [403]
            },
            'ModSecurity': {
                'headers': ['mod_security'],
                'content': ['mod_security', 'not acceptable'],
                'status_codes': [406, 403]
            },
            'F5 BIG-IP': {
                'headers': ['x-wa-info', 'bigipserver'],
                'content': ['f5', 'the requested url was rejected'],
                'status_codes': [403]
            },
            'Barracuda': {
                'headers': ['barra'],
                'content': ['barracuda', 'you have been blocked'],
                'status_codes': [403]
            },
            'Sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'content': ['sucuri', 'access denied'],
                'status_codes': [403]
            }
        }
    
    def detect(self, normal_response, test_response=None):
        """Detect WAF based on response patterns"""
        detected_wafs = []
        
        # Use test response if available, otherwise normal response
        response_to_check = test_response if test_response else normal_response
        
        headers_str = str(response_to_check.headers).lower()
        content_str = response_to_check.text.lower()
        status_code = response_to_check.status_code
        
        for waf_name, signatures in self.waf_signatures.items():
            score = 0
            
            # Check headers
            for header in signatures['headers']:
                if header.lower() in headers_str:
                    score += 2
            
            # Check content
            for content_sig in signatures['content']:
                if content_sig.lower() in content_str:
                    score += 2
            
            # Check status codes
            if status_code in signatures['status_codes']:
                score += 1
            
            # If we have a test response and it's different from normal
            if test_response and test_response.status_code != normal_response.status_code:
                score += 1
            
            if score >= 2:  # Threshold for detection
                detected_wafs.append({
                    'name': waf_name,
                    'confidence': min(100, score * 25)
                })
        
        return {
            'detected': len(detected_wafs) > 0,
            'wafs': detected_wafs,
            'status_change': test_response.status_code != normal_response.status_code if test_response else False
        }