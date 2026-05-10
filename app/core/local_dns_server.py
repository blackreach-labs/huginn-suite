# app/core/local_dns_server.py
import socket
import struct
import threading
import json
import os
from typing import Dict, List, Optional
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.logger import logger
from app.core.license_manager import license_manager

class LocalDNSServer(QObject):
    """Local DNS server for Professional and Enterprise licenses"""
    
    status_changed = pyqtSignal(str, bool)  # message, is_running
    
    def __init__(self, port: int = 53530):
        super().__init__()
        self.port = port
        self.running = False
        self.socket = None
        self.thread = None
        self.records_file = os.path.join("resources", "config", "local_dns_records.json")
        self.records = {}
        self.load_records()
        
    def is_licensed(self) -> bool:
        """Check if user has Professional or Enterprise license"""
        license_info = license_manager.get_license_info()
        return license_info.get("licensed", False) and \
               license_info.get("license_type") in ["Professional", "Enterprise"]
    
    def start_server(self) -> bool:
        """Start the local DNS server"""
        if not self.is_licensed():
            self.status_changed.emit("Local DNS requires Professional or Enterprise license", False)
            return False
            
        if self.running:
            return True
            
        # Try multiple ports if default fails
        ports_to_try = [self.port, 53531, 53532, 53533, 53534]
        
        for port in ports_to_try:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.bind(('127.0.0.1', port))
                self.port = port  # Update to working port
                self.running = True
                
                self.thread = threading.Thread(target=self._server_loop, daemon=True)
                self.thread.start()
                
                logger.info(f"Local DNS server started on port {self.port}")
                self.status_changed.emit(f"Local DNS server started on port {self.port}", True)
                return True
                
            except Exception as e:
                if self.socket:
                    self.socket.close()
                    self.socket = None
                continue
        
        logger.error("Failed to start DNS server: No available ports")
        self.status_changed.emit("Failed to start DNS server: No available ports", False)
        return False
    
    def stop_server(self):
        """Stop the local DNS server"""
        if not self.running:
            return
            
        self.running = False
        if self.socket:
            self.socket.close()
            
        logger.info("Local DNS server stopped")
        self.status_changed.emit("Local DNS server stopped", False)
    
    def _server_loop(self):
        """Main server loop"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(512)
                response = self._handle_query(data)
                if response:
                    self.socket.sendto(response, addr)
            except Exception as e:
                if self.running:
                    logger.error(f"DNS server error: {e}")
    
    def _handle_query(self, data: bytes) -> Optional[bytes]:
        """Handle DNS query and return response"""
        try:
            if len(data) < 12:
                return None
                
            # Parse DNS header
            header = struct.unpack('!HHHHHH', data[:12])
            query_id = header[0]
            flags = header[1]
            qdcount = header[2]
            
            # Only handle standard queries
            if (flags >> 15) != 0 or qdcount != 1:
                return None
                
            # Parse question section
            offset = 12
            domain_parts = []
            
            while offset < len(data):
                if offset >= len(data):
                    break
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if offset + 1 + length > len(data):
                    break
                domain_parts.append(data[offset+1:offset+1+length].decode('utf-8', errors='ignore'))
                offset += 1 + length
            
            if offset + 4 > len(data):
                return None
                
            domain = '.'.join(domain_parts).lower()
            qtype = struct.unpack('!H', data[offset:offset+2])[0]
            qclass = struct.unpack('!H', data[offset+2:offset+4])[0]
            
            # Check if we have a record for this domain
            record = self.records.get(domain)
            if not record:
                return self._build_nxdomain_response(data, query_id)
                
            # Build response
            response = bytearray()
            
            # DNS Header
            response.extend(struct.pack('!HHHHHH', 
                query_id,     # ID
                0x8180,       # Flags: Response, Authoritative, No error
                1,            # Questions
                1,            # Answers
                0,            # Authority RRs
                0             # Additional RRs
            ))
            
            # Question section (copy from original)
            response.extend(data[12:offset+4])
            
            # Answer section
            answer_added = False
            if qtype == 1 and 'A' in record:  # A record
                ip = record['A'][0]  # Use first A record
                response.extend(self._build_answer(domain, 1, ip))
                answer_added = True
            elif qtype == 28 and 'AAAA' in record:  # AAAA record
                ip = record['AAAA'][0]  # Use first AAAA record
                response.extend(self._build_answer(domain, 28, ip))
                answer_added = True
            elif qtype == 5 and 'CNAME' in record:  # CNAME record
                cname = record['CNAME'][0]  # Use first CNAME record
                response.extend(self._build_answer(domain, 5, cname))
                answer_added = True
            
            if not answer_added:
                return self._build_nxdomain_response(data, query_id)
            
            return bytes(response)
            
        except Exception as e:
            logger.error(f"Error handling DNS query: {e}")
            return self._build_nxdomain_response(data, query_id) if 'query_id' in locals() else None
    
    def _build_answer(self, domain: str, qtype: int, value: str) -> bytes:
        """Build DNS answer section"""
        answer = bytearray()
        
        # Domain name (compressed pointer to question)
        answer.extend(b'\xc0\x0c')
        
        # Type, class, TTL, data length placeholder
        if qtype == 1:  # A record
            try:
                ip_bytes = socket.inet_aton(value)
                answer.extend(struct.pack('!HHIH', qtype, 1, 300, 4))
                answer.extend(ip_bytes)
            except Exception:
                return b''
        elif qtype == 28:  # AAAA record
            try:
                ip_bytes = socket.inet_pton(socket.AF_INET6, value)
                answer.extend(struct.pack('!HHIH', qtype, 1, 300, 16))
                answer.extend(ip_bytes)
            except Exception:
                return b''
        elif qtype == 5:  # CNAME record
            cname_bytes = self._encode_domain(value)
            answer.extend(struct.pack('!HHIH', qtype, 1, 300, len(cname_bytes)))
            answer.extend(cname_bytes)
            
        return bytes(answer)
    
    def _encode_domain(self, domain: str) -> bytes:
        """Encode domain name for DNS"""
        encoded = bytearray()
        for part in domain.split('.'):
            if len(part) > 63:  # DNS label length limit
                part = part[:63]
            encoded.append(len(part))
            encoded.extend(part.encode('utf-8', errors='ignore'))
        encoded.append(0)
        return bytes(encoded)
    
    def _build_nxdomain_response(self, original_query: bytes, query_id: int) -> bytes:
        """Build NXDOMAIN response for non-existent domains"""
        try:
            # Find end of question section
            offset = 12
            while offset < len(original_query):
                length = original_query[offset]
                if length == 0:
                    offset += 5  # Skip null byte + qtype + qclass
                    break
                offset += 1 + length
            
            response = bytearray()
            # DNS Header with NXDOMAIN
            response.extend(struct.pack('!HHHHHH',
                query_id,     # ID
                0x8183,       # Flags: Response, Authoritative, NXDOMAIN
                1,            # Questions
                0,            # Answers
                0,            # Authority RRs
                0             # Additional RRs
            ))
            
            # Copy question section
            response.extend(original_query[12:offset])
            
            return bytes(response)
        except Exception:
            return b''
    
    def add_record(self, domain: str, record_type: str, value: str) -> bool:
        """Add DNS record"""
        if not self.is_licensed():
            return False
            
        domain = domain.lower()
        if domain not in self.records:
            self.records[domain] = {}
        if record_type not in self.records[domain]:
            self.records[domain][record_type] = []
            
        if value not in self.records[domain][record_type]:
            self.records[domain][record_type].append(value)
            self.save_records()
            logger.info(f"Added DNS record: {domain} {record_type} {value}")
            self.status_changed.emit(f"Added DNS record: {domain} {record_type} {value}", self.running)
            return True
        return False
    
    def remove_record(self, domain: str, record_type: str, value: str = None) -> bool:
        """Remove DNS record"""
        if not self.is_licensed():
            return False
            
        domain = domain.lower()
        if domain not in self.records:
            return False
            
        if record_type not in self.records[domain]:
            return False
            
        if value:
            if value in self.records[domain][record_type]:
                self.records[domain][record_type].remove(value)
                if not self.records[domain][record_type]:
                    del self.records[domain][record_type]
                if not self.records[domain]:
                    del self.records[domain]
                self.save_records()
                logger.info(f"Removed DNS record: {domain} {record_type} {value}")
                self.status_changed.emit(f"Removed DNS record: {domain} {record_type} {value}", self.running)
                return True
        else:
            del self.records[domain][record_type]
            if not self.records[domain]:
                del self.records[domain]
            self.save_records()
            logger.info(f"Removed all DNS records: {domain} {record_type}")
            self.status_changed.emit(f"Removed all DNS records: {domain} {record_type}", self.running)
            return True
        return False
    
    def get_records(self) -> Dict:
        """Get all DNS records"""
        return self.records.copy()
    
    def clear_records(self):
        """Clear all DNS records"""
        if not self.is_licensed():
            return
            
        self.records.clear()
        self.save_records()
        logger.info("Cleared all DNS records")
        self.status_changed.emit("Cleared all DNS records", self.running)
    
    def save_records(self):
        """Save records to file"""
        try:
            with open(self.records_file, 'w') as f:
                json.dump(self.records, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save DNS records: {e}")
    
    def load_records(self):
        """Load records from file"""
        try:
            if os.path.exists(self.records_file):
                with open(self.records_file, 'r') as f:
                    self.records = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load DNS records: {e}")
            self.records = {}

# Global DNS server instance
local_dns_server = LocalDNSServer()