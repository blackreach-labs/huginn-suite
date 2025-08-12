import re
from urllib.parse import urlparse

class IDORDetector:
    """Detect Insecure Direct Object Reference patterns"""
    
    def __init__(self):
        self.numeric_pattern = re.compile(r'/(\d+)(?:/|$)')
        self.uuid_pattern = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)', re.IGNORECASE)
        self.hash_pattern = re.compile(r'/([a-f0-9]{32,64})(?:/|$)', re.IGNORECASE)
    
    def analyze_endpoints(self, parameters, discovered_paths=None):
        """Identify IDOR-vulnerable endpoint patterns"""
        findings = []
        idor_patterns = []
        
        # Analyze form actions and discovered paths
        all_urls = set()
        
        # Add form actions
        for url, forms in parameters.items():
            all_urls.add(url)
            for form in forms:
                all_urls.add(form['action'])
        
        # Add discovered paths if available
        if discovered_paths:
            all_urls.update(discovered_paths)
        
        for url in all_urls:
            parsed = urlparse(url)
            path = parsed.path
            
            # Check for numeric IDs
            numeric_matches = self.numeric_pattern.findall(path)
            if numeric_matches:
                idor_patterns.append({
                    'url': url,
                    'pattern': 'numeric_id',
                    'ids': numeric_matches,
                    'template': re.sub(r'/\d+', '/{id}', path)
                })
            
            # Check for UUIDs
            uuid_matches = self.uuid_pattern.findall(path)
            if uuid_matches:
                idor_patterns.append({
                    'url': url,
                    'pattern': 'uuid',
                    'ids': uuid_matches,
                    'template': re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', path, flags=re.IGNORECASE)
                })
            
            # Check for hash-like IDs
            hash_matches = self.hash_pattern.findall(path)
            if hash_matches:
                idor_patterns.append({
                    'url': url,
                    'pattern': 'hash_id',
                    'ids': hash_matches,
                    'template': re.sub(r'/[a-f0-9]{32,64}', '/{hash}', path, flags=re.IGNORECASE)
                })
        
        if idor_patterns:
            # Group by pattern type
            numeric_count = len([p for p in idor_patterns if p['pattern'] == 'numeric_id'])
            uuid_count = len([p for p in idor_patterns if p['pattern'] == 'uuid'])
            hash_count = len([p for p in idor_patterns if p['pattern'] == 'hash_id'])
            
            findings.append({
                'type': 'IDOR Attack Surface',
                'severity': 'MEDIUM',
                'description': f'Found {len(idor_patterns)} endpoints with ID parameters (Numeric: {numeric_count}, UUID: {uuid_count}, Hash: {hash_count})',
                'patterns': idor_patterns[:10],  # Show first 10
                'recommendation': 'Implement proper authorization checks for all ID-based endpoints'
            })
        
        return findings