#!/usr/bin/env python3
import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

def scan_db_ports(target):
    db_ports = {
        1433: "MSSQL",
        3306: "MySQL", 
        5432: "PostgreSQL",
        1521: "Oracle",
        27017: "MongoDB",
        6379: "Redis",
        5984: "CouchDB"
    }
    
    open_ports = []
    
    for port, service in db_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                print(f"[+] {port}/tcp open ({service})")
                open_ports.append((port, service))
        except:
            pass
    
    return open_ports

def test_mssql(target, port=1433):
    print(f"[*] Testing MSSQL on {target}:{port}")
    
    # Test for blank SA password
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # Send basic connection packet
        packet = b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00'
        sock.send(packet)
        response = sock.recv(1024)
        
        if len(response) > 8:
            print("[+] MSSQL server responded")
        
        sock.close()
    except Exception as e:
        print(f"[-] MSSQL test failed: {e}")

def test_mysql(target, port=3306):
    print(f"[*] Testing MySQL on {target}:{port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # Read initial handshake
        response = sock.recv(1024)
        if len(response) > 5 and response[4] == 10:  # Protocol version 10
            print("[+] MySQL server detected")
            
            # Extract server version
            version_start = 5
            version_end = response.find(b'\x00', version_start)
            if version_end > version_start:
                version = response[version_start:version_end].decode('ascii', errors='ignore')
                print(f"[+] MySQL version: {version}")
        
        sock.close()
    except Exception as e:
        print(f"[-] MySQL test failed: {e}")

def test_mongodb(target, port=27017):
    print(f"[*] Testing MongoDB on {target}:{port}")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
        
        # Send isMaster command
        packet = b'\x3a\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x17\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00'
        sock.send(packet)
        response = sock.recv(1024)
        
        if len(response) > 16:
            print("[+] MongoDB server responded")
        
        sock.close()
    except Exception as e:
        print(f"[-] MongoDB test failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Database Enumeration Tool")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--detailed", action="store_true", help="Detailed database probing")
    
    args = parser.parse_args()
    
    print(f"[*] Scanning database ports on {args.target}")
    open_ports = scan_db_ports(args.target)
    
    if not open_ports:
        print("[-] No database ports found")
        return
    
    if args.detailed:
        for port, service in open_ports:
            if service == "MSSQL":
                test_mssql(args.target, port)
            elif service == "MySQL":
                test_mysql(args.target, port)
            elif service == "MongoDB":
                test_mongodb(args.target, port)

if __name__ == "__main__":
    main()