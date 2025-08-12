#!/usr/bin/env python3
import socket
import struct
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

class SMBEnum:
    def __init__(self, target, timeout=3):
        self.target = target
        self.timeout = timeout

    def check_smb_ports(self):
        """Check if SMB/NetBIOS ports are open"""
        ports = [139, 445]
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    service = "NetBIOS" if port == 139 else "SMB"
                    print(f"[+] {port}/tcp open ({service})")
            except:
                pass
        
        return open_ports

    def netbios_name_query(self):
        """NetBIOS name service query"""
        try:
            # NetBIOS Name Service query packet
            query = b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            query += b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(query, (self.target, 137))
            
            response, addr = sock.recvfrom(1024)
            sock.close()
            
            if len(response) > 56:
                names = []
                num_names = response[56]
                
                for i in range(num_names):
                    offset = 57 + (i * 18)
                    if offset + 16 <= len(response):
                        name = response[offset:offset+15].decode('ascii', errors='ignore').strip()
                        name_type = response[offset+15]
                        if name:
                            names.append((name, name_type))
                
                return names
        except:
            pass
        return []

    def smb_negotiate(self):
        """SMB protocol negotiation"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, 445))
            
            # SMB negotiate request
            negotiate = b'\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00\x18S\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00'
            negotiate += b'\x00b\x00\x02PC NETWORK PROGRAM 1.0\x00\x02LANMAN1.0\x00\x02Windows for Workgroups 3.1a\x00\x02LM1.2X002\x00\x02LANMAN2.1\x00\x02NT LM 0.12\x00'
            
            sock.send(negotiate)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 47:
                # Extract OS info from response
                os_info = response[47:].split(b'\x00')[0].decode('ascii', errors='ignore')
                return os_info
        except:
            pass
        return None

def scan_range(base_ip, start=1, end=254):
    """Scan IP range for SMB services"""
    base = '.'.join(base_ip.split('.')[:-1])
    alive_hosts = []
    
    def check_host(host_num):
        target = f"{base}.{host_num}"
        scanner = SMBEnum(target, timeout=2)
        open_ports = scanner.check_smb_ports()
        if open_ports:
            alive_hosts.append(target)
            print(f"[+] {target} - SMB/NetBIOS detected")
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(check_host, range(start, end + 1))
    
    return alive_hosts

def main():
    parser = argparse.ArgumentParser(description="SMB Enumeration Tool")
    parser.add_argument("target", help="Target IP or network range")
    parser.add_argument("--range", action="store_true", help="Scan IP range")
    parser.add_argument("--netbios", action="store_true", help="NetBIOS name query")
    parser.add_argument("--os-detect", action="store_true", help="SMB OS detection")
    
    args = parser.parse_args()
    
    if args.range:
        print(f"[*] Scanning range {args.target}.1-254 for SMB/NetBIOS")
        hosts = scan_range(args.target)
        print(f"\n[*] Found {len(hosts)} hosts with SMB/NetBIOS")
        return
    
    scanner = SMBEnum(args.target)
    
    print(f"[*] Scanning {args.target} for SMB/NetBIOS")
    open_ports = scanner.check_smb_ports()
    
    if not open_ports:
        print("[-] No SMB/NetBIOS ports open")
        return
    
    if args.netbios or not (args.os_detect):
        print("\n[*] Performing NetBIOS name query...")
        names = scanner.netbios_name_query()
        if names:
            print("[+] NetBIOS names:")
            for name, name_type in names:
                service = {0x00: "Workstation", 0x20: "File Server"}.get(name_type, f"Type {name_type:02x}")
                print(f"    {name:<15} {service}")
        else:
            print("[-] No NetBIOS names found")
    
    if args.os_detect or not (args.netbios):
        print("\n[*] Attempting SMB OS detection...")
        os_info = scanner.smb_negotiate()
        if os_info:
            print(f"[+] OS: {os_info}")
        else:
            print("[-] Could not detect OS")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)