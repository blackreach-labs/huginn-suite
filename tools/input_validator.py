#!/usr/bin/env python3
import re
import ipaddress
import urllib.parse

class InputValidator:
    @staticmethod
    def validate_ip(ip_str):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port):
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_hostname(hostname):
        """Validate hostname format"""
        if len(hostname) > 253:
            return False
        pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
        return bool(pattern.match(hostname))
    
    @staticmethod
    def validate_url(url):
        """Validate URL format"""
        try:
            result = urllib.parse.urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename to prevent path traversal"""
        # Remove path separators and dangerous characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '', filename)
        sanitized = re.sub(r'\.\.', '', sanitized)
        return sanitized[:255]  # Limit length
    
    @staticmethod
    def validate_hash(hash_value, hash_type=None):
        """Validate hash format"""
        if not hash_value or not isinstance(hash_value, str):
            return False
        
        hash_patterns = {
            'md5': r'^[a-fA-F0-9]{32}$',
            'sha1': r'^[a-fA-F0-9]{40}$',
            'sha256': r'^[a-fA-F0-9]{64}$',
            'sha512': r'^[a-fA-F0-9]{128}$',
            'ntlm': r'^[a-fA-F0-9]{32}$'
        }
        
        if hash_type and hash_type.lower() in hash_patterns:
            return bool(re.match(hash_patterns[hash_type.lower()], hash_value))
        
        # Generic validation - check if it's hex and reasonable length
        return bool(re.match(r'^[a-fA-F0-9]{16,128}$', hash_value))
    
    @staticmethod
    def validate_command_safe(command):
        """Validate command for safe execution"""
        dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '<', '>', '"', "'"]
        return not any(char in command for char in dangerous_chars)