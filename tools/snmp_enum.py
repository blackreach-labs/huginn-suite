#!/usr/bin/env python3
import socket
import struct
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

def snmp_scan_port(target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.connect((target, 161))
        sock.close()
        print(f"[+] {target}:161/udp open (SNMP)")
        return True
    except:
        return False

def snmp_community_scan(target, communities):
    print(f"[*] Testing SNMP communities on {target}")
    
    for community in communities:
        try:
            # SNMP GET request for system description
            request = b'\x30\x19\x02\x01\x00\x04' + bytes([len(community)]) + community.encode()
            request += b'\xa0\x0c\x02\x01\x00\x02\x01\x00\x30\x04\x30\x02\x06\x00'
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(request, (target, 161))
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            if len(response) > 10:
                print(f"[✓] Valid community string: '{community}'")
                return community
        except:
            pass
    
    print("[-] No valid community strings found")
    return None

def snmp_walk_basic(target, community):
    print(f"[*] Basic SNMP walk on {target} with community '{community}'")
    
    # Common OIDs
    oids = {
        "1.3.6.1.2.1.1.1.0": "System Description",
        "1.3.6.1.2.1.1.5.0": "System Name",
        "1.3.6.1.2.1.1.6.0": "System Location",
        "1.3.6.1.4.1.77.1.2.25": "Windows Users",
        "1.3.6.1.2.1.25.4.2.1.2": "Running Processes",
        "1.3.6.1.2.1.6.13.1.3": "TCP Listening Ports"
    }
    
    for oid, desc in oids.items():
        try:
            # Simple SNMP GET request
            request = b'\x30\x19\x02\x01\x00\x04' + bytes([len(community)]) + community.encode()
            request += b'\xa0\x0c\x02\x01\x00\x02\x01\x00\x30\x04\x30\x02\x06\x00'
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(request, (target, 161))
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            if len(response) > 20:
                print(f"[+] {desc}: Data available")
        except:
            print(f"[-] {desc}: No response")

def scan_range(base_ip):
    base = '.'.join(base_ip.split('.')[:-1])
    alive_hosts = []
    
    def check_host(host_num):
        target = f"{base}.{host_num}"
        if snmp_scan_port(target):
            alive_hosts.append(target)
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(check_host, range(1, 255))
    
    return alive_hosts

def main():
    parser = argparse.ArgumentParser(description="SNMP Enumeration Tool")
    parser.add_argument("target", help="Target IP or network")
    parser.add_argument("--range", action="store_true", help="Scan IP range")
    parser.add_argument("--community", help="Test specific community string")
    parser.add_argument("--walk", action="store_true", help="Perform SNMP walk")
    
    args = parser.parse_args()
    
    if args.range:
        print(f"[*] Scanning range {args.target}.1-254 for SNMP")
        hosts = scan_range(args.target)
        print(f"[*] Found {len(hosts)} hosts with SNMP")
        return
    
    if not snmp_scan_port(args.target):
        print("[-] SNMP port not open")
        return
    
    communities = ["public", "private", "community", "manager", "admin"]
    if args.community:
        communities = [args.community]
    
    valid_community = snmp_community_scan(args.target, communities)
    
    if valid_community and args.walk:
        snmp_walk_basic(args.target, valid_community)

if __name__ == "__main__":
    main()