# app/tools/encoders.py
import base64
import re
import urllib.parse

def decode_javascript_obfuscation(js_content):
    """Attempt to decode obfuscated JavaScript"""
    decoded_content = []
    
    # Look for common obfuscation patterns
    patterns = [
        # String.fromCharCode patterns
        r'String\.fromCharCode\(([^)]+)\)',
        # Hex encoded strings
        r'\\x([0-9a-fA-F]{2})',
        # Unicode encoded strings
        r'\\u([0-9a-fA-F]{4})',
        # Base64 patterns in JS
        r'atob\(["\']([A-Za-z0-9+/=]+)["\']\)'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, js_content)
        for match in matches:
            try:
                if 'fromCharCode' in pattern:
                    # Decode character codes
                    codes = [int(x.strip()) for x in match.split(',') if x.strip().isdigit()]
                    decoded = ''.join(chr(code) for code in codes if 0 <= code <= 127)
                    if decoded and len(decoded) > 3:
                        decoded_content.append(decoded)
                
                elif '\\x' in pattern:
                    # Decode hex
                    decoded = bytes.fromhex(match).decode('utf-8', errors='ignore')
                    if decoded and len(decoded) > 3:
                        decoded_content.append(decoded)
                
                elif '\\u' in pattern:
                    # Decode unicode
                    decoded = chr(int(match, 16))
                    if decoded and ord(decoded) < 127:
                        decoded_content.append(decoded)
                
                elif 'atob' in pattern:
                    # Decode base64
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if decoded and len(decoded) > 3:
                        decoded_content.append(decoded)
                        
            except (ValueError, UnicodeDecodeError):
                continue
    
    return decoded_content

def detect_and_decode(string_data):
    """Detect and decode various encoding schemes"""
    results = []
    
    # Base64 detection and decoding
    if len(string_data) > 4 and len(string_data) % 4 == 0:
        try:
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', string_data):
                decoded = base64.b64decode(string_data).decode('utf-8', errors='ignore')
                if all(ord(c) < 127 for c in decoded) and len(decoded) > 3:
                    results.append(('Base64', decoded))
        except:
            pass
    
    # URL encoding detection
    if '%' in string_data:
        try:
            decoded = urllib.parse.unquote(string_data)
            if decoded != string_data and len(decoded) > 3:
                results.append(('URL Encoded', decoded))
        except:
            pass
    
    # Hex encoding detection
    if re.match(r'^[0-9a-fA-F]+$', string_data) and len(string_data) % 2 == 0:
        try:
            decoded = bytes.fromhex(string_data).decode('utf-8', errors='ignore')
            if all(ord(c) < 127 for c in decoded) and len(decoded) > 3:
                results.append(('Hex', decoded))
        except:
            pass
    
    # ROT13 detection
    try:
        import codecs
        decoded = codecs.decode(string_data, 'rot13')
        if decoded != string_data and len(decoded) > 3:
            results.append(('ROT13', decoded))
    except:
        pass
    
    return results