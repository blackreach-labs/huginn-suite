#!/usr/bin/env python3
import requests
import json
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

# Import connection pool
try:
    from app.core.connection_pool import connection_pool
    from app.core.proxy_manager import proxy_manager
except ImportError:
    connection_pool = None
    proxy_manager = None

def api_discovery(target, port=80, https=False, wordlist=None):
    protocol = "https" if https else "http"
    base_url = f"{protocol}://{target}:{port}"
    
    if not wordlist:
        endpoints = ["api", "v1", "v2", "rest", "graphql", "swagger", "docs", "admin", "users", "auth", "login"]
    else:
        with open(wordlist, 'r') as f:
            endpoints = [line.strip() for line in f if line.strip()]
    
    print(f"[*] API endpoint discovery on {base_url}")
    found_apis = []
    
    def check_endpoint(endpoint):
        paths = [f"/{endpoint}", f"/api/{endpoint}", f"/api/v1/{endpoint}", f"/api/v2/{endpoint}"]
        
        for path in paths:
            url = base_url + path
            try:
                # Apply rate limiting
                try:
                    from app.core.rate_limiter import rate_limiter
                    rate_limiter.wait_if_needed('api_enum')
                except ImportError:
                    pass
                
                # Use connection pool if available
                if connection_pool:
                    session = connection_pool.get_session(f"api_{target}")
                    proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
                    response = session.get(url, timeout=3, verify=False, proxies=proxies)
                else:
                    proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
                    response = requests.get(url, timeout=3, verify=False, proxies=proxies)
                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('content-type', '').lower()
                    if 'json' in content_type or 'api' in content_type:
                        print(f"[+] API endpoint: {url} - Status: {response.status_code}")
                        found_apis.append(url)
                        
                        # Try to parse JSON response
                        try:
                            data = response.json()
                            if isinstance(data, dict) and len(str(data)) < 200:
                                print(f"    Response: {data}")
                        except:
                            pass
            except:
                pass
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_endpoint, endpoints)
    
    return found_apis

def test_api_methods(url):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
    print(f"[*] Testing HTTP methods on {url}")
    
    for method in methods:
        try:
            # Use connection pool if available
            if connection_pool:
                session = connection_pool.get_session("api_methods")
                proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
                response = session.request(method, url, timeout=3, verify=False, proxies=proxies)
            else:
                proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
                response = requests.request(method, url, timeout=3, verify=False, proxies=proxies)
            if response.status_code != 405:  # Method not allowed
                print(f"[+] {method} {url} - Status: {response.status_code}")
        except:
            pass

def test_api_auth(url):
    print(f"[*] Testing authentication bypass on {url}")
    
    # Test common auth bypasses
    headers_list = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"Authorization": "Bearer test"},
        {"X-API-Key": "test"},
        {"Admin": "true"},
        {"Role": "admin"}
    ]
    
    for headers in headers_list:
        try:
            # Use connection pool if available
            if connection_pool:
                session = connection_pool.get_session("api_auth")
                proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
                response = session.get(url, headers=headers, timeout=3, verify=False, proxies=proxies)
            else:
                proxies = proxy_manager.get_proxy_dict() if proxy_manager else {}
                response = requests.get(url, headers=headers, timeout=3, verify=False, proxies=proxies)
            if response.status_code == 200:
                print(f"[+] Potential bypass with headers: {headers}")
        except:
            pass

def main():
    parser = argparse.ArgumentParser(description="API Enumeration Tool")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=80, help="Port number")
    parser.add_argument("--https", action="store_true", help="Use HTTPS")
    parser.add_argument("--wordlist", help="API endpoint wordlist")
    parser.add_argument("--methods", action="store_true", help="Test HTTP methods")
    parser.add_argument("--auth-bypass", action="store_true", help="Test auth bypass")
    
    args = parser.parse_args()
    
    # Discover API endpoints
    found_apis = api_discovery(args.target, args.port, args.https, args.wordlist)
    
    if not found_apis:
        print("[-] No API endpoints found")
        return
    
    # Test methods on found APIs
    if args.methods:
        for api_url in found_apis[:3]:  # Limit to first 3
            test_api_methods(api_url)
    
    # Test auth bypass
    if args.auth_bypass:
        for api_url in found_apis[:3]:  # Limit to first 3
            test_api_auth(api_url)

if __name__ == "__main__":
    main()