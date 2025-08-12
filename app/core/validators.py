# app/core/validators.py
import re
import os
import ipaddress
import urllib.parse
from pathlib import Path
from typing import Tuple, List, Optional, Union

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class SecurityValidator:
    """Security-focused validation methods"""
    
    @staticmethod
    def is_safe_path(path: str, base_dir: str) -> bool:
        """Check if path is safe (no directory traversal)"""
        try:
            base_path = Path(base_dir).resolve()
            target_path = Path(base_dir, path).resolve()
            return target_path.is_relative_to(base_path)
        except (ValueError, OSError):
            return False
    
    @staticmethod
    def validate_file_upload(file_path: str, allowed_extensions: List[str], 
                           max_size_mb: int = 10) -> Tuple[bool, str]:
        """Validate uploaded file"""
        try:
            path = Path(file_path)
            
            # Check extension
            if path.suffix.lower() not in allowed_extensions:
                return False, f"File type not allowed. Allowed: {allowed_extensions}"
            
            # Check size
            if path.stat().st_size > max_size_mb * 1024 * 1024:
                return False, f"File too large (max {max_size_mb}MB)"
            
            return True, "File is valid"
            
        except Exception as e:
            return False, f"File validation error: {str(e)}"

class InputValidator:
    """Handles input validation and sanitization"""
    
    @staticmethod
    def validate_domain(domain):
        """
        Validates domain format and prevents injection attacks
        Returns: (is_valid: bool, error_message: str)
        """
        if not domain or not isinstance(domain, str):
            return False, "Domain cannot be empty"
        
        # Remove whitespace and convert to lowercase
        domain = domain.strip().lower()
        
        # Check length
        if len(domain) > 253:
            return False, "Domain name too long (max 253 characters)"
        
        if len(domain) < 1:
            return False, "Domain name too short"
        
        # Check for valid domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(domain_pattern, domain):
            return False, "Invalid domain format"
        
        # Check for suspicious characters that could indicate injection
        suspicious_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$', '(', ')']
        if any(char in domain for char in suspicious_chars):
            return False, "Domain contains invalid characters"
        
        return True, domain
    
    @staticmethod
    def validate_wordlist_path(path):
        """
        Validates wordlist file path and accessibility
        Returns: (is_valid: bool, error_message: str, absolute_path: str)
        """
        if not path or not isinstance(path, str):
            return False, "Wordlist path cannot be empty", None
        
        try:
            # Convert to Path object for better handling
            wordlist_path = Path(path)
            
            # Check if file exists
            if not wordlist_path.exists():
                return False, f"Wordlist file not found: {path}", None
            
            # Check if it's a file (not directory)
            if not wordlist_path.is_file():
                return False, f"Path is not a file: {path}", None
            
            # Check file extension
            if not wordlist_path.suffix.lower() == '.txt':
                return False, "Wordlist must be a .txt file", None
            
            # Check file size (prevent extremely large files)
            file_size = wordlist_path.stat().st_size
            max_size = 100 * 1024 * 1024  # 100MB limit
            if file_size > max_size:
                return False, f"Wordlist file too large (max 100MB): {file_size/1024/1024:.1f}MB", None
            
            # Check if file is readable
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    # Try to read first line to verify format
                    first_line = f.readline()
                    if not first_line:
                        return False, "Wordlist file is empty", None
            except UnicodeDecodeError:
                return False, "Wordlist file contains invalid characters", None
            except PermissionError:
                return False, "Permission denied reading wordlist file", None
            
            return True, "Valid wordlist file", str(wordlist_path.absolute())
            
        except Exception as e:
            return False, f"Error validating wordlist: {str(e)}", None
    
    @staticmethod
    def validate_record_types(record_types):
        """
        Validates DNS record types selection
        Returns: (is_valid: bool, error_message: str, validated_types: list)
        """
        if not record_types:
            return False, "At least one record type must be selected", None
        
        valid_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR']
        validated_types = []
        
        for record_type in record_types:
            if not isinstance(record_type, str):
                return False, f"Invalid record type format: {record_type}", None
            
            record_type = record_type.upper().strip()
            if record_type not in valid_types:
                return False, f"Unsupported record type: {record_type}", None
            
            if record_type not in validated_types:
                validated_types.append(record_type)
        
        return True, "Valid record types", validated_types
    
    @staticmethod
    def sanitize_filename(filename):
        """
        Sanitizes filename for safe file operations
        Returns: sanitized filename string
        """
        if not filename:
            return "unnamed"
        
        # Remove or replace invalid filename characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing whitespace and dots
        filename = filename.strip(' .')
        
        # Limit length
        if len(filename) > 200:
            filename = filename[:200]
        
        # Ensure it's not empty after sanitization
        if not filename:
            filename = "unnamed"
        
        return filename
    
    @staticmethod
    def validate_scan_parameters(params: dict) -> Tuple[bool, str, Optional[dict]]:
        """Validate scan parameters comprehensively"""
        validated_params = {}
        errors = []
        
        # Validate target
        if 'target' in params:
            target = params['target']
            if not target:
                errors.append("Target is required")
            else:
                # Try as domain first, then IP
                is_valid_domain, domain_msg, clean_domain = InputValidator.validate_domain(target)
                if is_valid_domain:
                    validated_params['target'] = clean_domain
                    validated_params['target_type'] = 'domain'
                else:
                    is_valid_ip, ip_msg, clean_ip = InputValidator.validate_ip_address(target)
                    if is_valid_ip:
                        validated_params['target'] = clean_ip
                        validated_params['target_type'] = 'ip'
                    else:
                        errors.append(f"Invalid target: {domain_msg}, {ip_msg}")
        
        # Validate ports if present
        if 'ports' in params and params['ports']:
            is_valid, port_msg, port_list = InputValidator.validate_port_range(params['ports'])
            if is_valid:
                validated_params['ports'] = port_list
            else:
                errors.append(port_msg)
        
        # Validate wordlist if present
        if 'wordlist' in params and params['wordlist']:
            is_valid, wl_msg, wl_path = InputValidator.validate_wordlist_path(params['wordlist'])
            if is_valid:
                validated_params['wordlist'] = wl_path
            else:
                errors.append(wl_msg)
        
        if errors:
            return False, "; ".join(errors), None
        
        return True, "Parameters validated successfully", validated_params
    
    @staticmethod
    def validate_ip_address(ip_str: str) -> Tuple[bool, str, Optional[str]]:
        """Validate IP address (IPv4 or IPv6)"""
        if not ip_str or not isinstance(ip_str, str):
            return False, "IP address cannot be empty", None
        
        ip_str = ip_str.strip()
        
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            # Check for private/reserved addresses in security contexts
            if ip_obj.is_private:
                return True, f"Valid private IP address: {ip_str}", str(ip_obj)
            elif ip_obj.is_loopback:
                return True, f"Valid loopback IP address: {ip_str}", str(ip_obj)
            else:
                return True, f"Valid public IP address: {ip_str}", str(ip_obj)
        except ValueError as e:
            return False, f"Invalid IP address: {str(e)}", None
    
    @staticmethod
    def validate_port_range(port_str: str) -> Tuple[bool, str, Optional[List[int]]]:
        """Validate port range specification"""
        if not port_str or not isinstance(port_str, str):
            return False, "Port range cannot be empty", None
        
        port_str = port_str.strip()
        ports = []
        
        try:
            # Split by comma for multiple ranges/ports
            parts = [p.strip() for p in port_str.split(',') if p.strip()]
            
            for part in parts:
                if '-' in part:
                    # Range specification
                    start_str, end_str = part.split('-', 1)
                    start_port = int(start_str.strip())
                    end_port = int(end_str.strip())
                    
                    if start_port < 1 or end_port > 65535:
                        return False, "Port numbers must be between 1 and 65535", None
                    
                    if start_port > end_port:
                        return False, f"Invalid range: {start_port}-{end_port}", None
                    
                    # Limit range size to prevent resource exhaustion
                    if end_port - start_port > 10000:
                        return False, "Port range too large (max 10000 ports)", None
                    
                    ports.extend(range(start_port, end_port + 1))
                else:
                    # Single port
                    port = int(part)
                    if port < 1 or port > 65535:
                        return False, "Port numbers must be between 1 and 65535", None
                    ports.append(port)
            
            # Remove duplicates and sort
            ports = sorted(list(set(ports)))
            
            # Limit total number of ports
            if len(ports) > 10000:
                return False, "Too many ports specified (max 10000)", None
            
            return True, f"Valid port range: {len(ports)} ports", ports
            
        except ValueError as e:
            return False, f"Invalid port specification: {str(e)}", None
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, str, Optional[str]]:
        """Validate URL format and security"""
        if not url or not isinstance(url, str):
            return False, "URL cannot be empty", None
        
        url = url.strip()
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check for valid scheme
            if parsed.scheme not in ['http', 'https']:
                return False, "URL must use HTTP or HTTPS protocol", None
            
            # Check for valid hostname
            if not parsed.hostname:
                return False, "URL must contain a valid hostname", None
            
            # Security checks
            suspicious_patterns = [
                'javascript:', 'data:', 'file:', 'ftp:',
                '<script', '</script>', 'eval(', 'alert('
            ]
            
            url_lower = url.lower()
            for pattern in suspicious_patterns:
                if pattern in url_lower:
                    return False, f"URL contains suspicious content: {pattern}", None
            
            return True, "Valid URL", url
            
        except Exception as e:
            return False, f"Invalid URL: {str(e)}", None
    
    @staticmethod
    def sanitize_command_input(input_str: str) -> str:
        """Sanitize input for command execution"""
        if not input_str:
            return ""
        
        # Remove dangerous characters for command injection
        dangerous_chars = ['|', '&', ';', '$', '`', '(', ')', '<', '>', '"', "'"]
        sanitized = input_str
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        # Remove excessive whitespace
        sanitized = ' '.join(sanitized.split())
        
        return sanitized.strip()
    
    @staticmethod
    def validate_network_range(network_str: str) -> Tuple[bool, str, Optional[str]]:
        """Validate network range (CIDR notation)"""
        if not network_str or not isinstance(network_str, str):
            return False, "Network range cannot be empty", None
        
        network_str = network_str.strip()
        
        try:
            network = ipaddress.ip_network(network_str, strict=False)
            
            # Check network size limits
            if network.num_addresses > 65536:  # /16 for IPv4
                return False, "Network range too large (max /16 for IPv4)", None
            
            return True, f"Valid network range: {network}", str(network)
            
        except ValueError as e:
            return False, f"Invalid network range: {str(e)}", None