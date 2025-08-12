# app/core/obfuscation_engine.py
import base64
import urllib.parse
import re
import binascii
import codecs
try:
    from pygments import highlight
    from pygments.lexers import JavascriptLexer, PowerShellLexer, get_lexer_by_name
    from pygments.formatters import HtmlFormatter
    PYGMENTS_AVAILABLE = True
except ImportError:
    PYGMENTS_AVAILABLE = False

class ObfuscationEngine:
    @staticmethod
    def obfuscate(text, method):
        """Obfuscate text using specified method"""
        if method == "Base64 Encode":
            return base64.b64encode(text.encode()).decode()
        elif method == "URL Encode":
            return urllib.parse.quote(text)
        elif method == "PowerShell Base64":
            b64 = base64.b64encode(text.encode('utf-16le')).decode()
            return f"powershell -EncodedCommand {b64}"
        elif method == "JavaScript CharCode":
            char_codes = [str(ord(c)) for c in text]
            return f"String.fromCharCode({','.join(char_codes)})"
        elif method == "JavaScript Packer":
            # Simple JavaScript packer simulation
            hex_text = text.encode().hex()
            return f"eval(unescape('{urllib.parse.quote(text)}'))"
        elif method == "ROT13":
            return codecs.encode(text, 'rot13')
        elif method == "Hex Encode":
            return text.encode().hex()
        else:
            return text
    
    @staticmethod
    def deobfuscate(text, method):
        """Deobfuscate text using specified method"""
        try:
            if method == "Base64 Decode":
                return base64.b64decode(text).decode()
            elif method == "URL Decode":
                return urllib.parse.unquote(text)
            elif method == "PowerShell Decode":
                # Extract base64 from PowerShell command
                b64_match = re.search(r'-EncodedCommand\s+([A-Za-z0-9+/=]+)', text)
                if b64_match:
                    return base64.b64decode(b64_match.group(1)).decode('utf-16le')
                return base64.b64decode(text).decode('utf-16le')
            elif method == "JavaScript Decode":
                # Extract char codes
                char_match = re.search(r'String\.fromCharCode\(([0-9,\s]+)\)', text)
                if char_match:
                    codes = [int(x.strip()) for x in char_match.group(1).split(',')]
                    return ''.join(chr(code) for code in codes)
                return urllib.parse.unquote(text)
            elif method == "ROT13":
                return codecs.decode(text, 'rot13')
            elif method == "Hex Decode":
                return bytes.fromhex(text).decode()
            else:
                return text
        except Exception as e:
            raise Exception(f"Deobfuscation failed: {str(e)}")
    
    @staticmethod
    def auto_detect_and_decode(text, format_output=False):
        """Auto-detect obfuscation type and decode"""
        results = []
        
        # Base64 detection
        if ObfuscationEngine._is_base64(text):
            try:
                decoded = base64.b64decode(text).decode()
                confidence = 0.9 if len(decoded) > 0 and all(ord(c) < 128 for c in decoded) else 0.6
                if format_output:
                    formatted = f"<div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 8px; margin: 5px 0; word-wrap: break-word;'>{decoded}</div>"
                    results.append(("Base64", formatted, confidence))
                else:
                    results.append(("Base64", decoded, confidence))
            except:
                pass
        
        # URL encoding detection
        if '%' in text:
            try:
                decoded = urllib.parse.unquote(text)
                if decoded != text:
                    confidence = 0.8
                    if format_output:
                        formatted = f"<div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 8px; margin: 5px 0; word-wrap: break-word;'>{decoded}</div>"
                        results.append(("URL Encoding", formatted, confidence))
                    else:
                        results.append(("URL Encoding", decoded, confidence))
            except:
                pass
        
        # Hex encoding detection
        if ObfuscationEngine._is_hex(text):
            try:
                decoded = bytes.fromhex(text).decode()
                confidence = 0.7
                if format_output:
                    formatted = f"<div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 8px; margin: 5px 0; word-wrap: break-word;'>{decoded}</div>"
                    results.append(("Hex Encoding", formatted, confidence))
                else:
                    results.append(("Hex Encoding", decoded, confidence))
            except:
                pass
        
        # JavaScript CharCode detection
        char_match = re.search(r'String\.fromCharCode\(([0-9,\s]+)\)', text)
        if char_match:
            try:
                codes = [int(x.strip()) for x in char_match.group(1).split(',')]
                decoded = ''.join(chr(code) for code in codes)
                confidence = 0.9
                if format_output:
                    formatted = f"<div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 8px; margin: 5px 0; word-wrap: break-word;'>{decoded}</div>"
                    results.append(("JavaScript CharCode", formatted, confidence))
                else:
                    results.append(("JavaScript CharCode", decoded, confidence))
            except:
                pass
        
        # JavaScript packed code detection (eval function with packed parameters)
        js_packed_match = re.search(r'eval\(function\(p,a,c,k,e,d\)\{.*?\}\(.*?\)\)', text, re.DOTALL)
        if js_packed_match:
            try:
                # Extract the packed JavaScript and attempt to decode it
                packed_code = js_packed_match.group(0)
                decoded = ObfuscationEngine._unpack_javascript(packed_code)
                confidence = 0.95
                if format_output and PYGMENTS_AVAILABLE:
                    # Use pygments for JavaScript syntax highlighting
                    formatter = HtmlFormatter(style='monokai', noclasses=True, cssclass='highlight')
                    highlighted = highlight(decoded, JavascriptLexer(), formatter)
                    results.append(("JavaScript Packed", highlighted, confidence))
                elif format_output:
                    formatted = f"<div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 8px; margin: 5px 0; word-wrap: break-word;'><pre>{decoded}</pre></div>"
                    results.append(("JavaScript Packed", formatted, confidence))
                else:
                    results.append(("JavaScript Packed", decoded, confidence))
            except:
                pass
        
        # PowerShell EncodedCommand detection
        ps_match = re.search(r'-EncodedCommand\s+([A-Za-z0-9+/=]+)', text)
        if ps_match:
            try:
                decoded = base64.b64decode(ps_match.group(1)).decode('utf-16le')
                confidence = 0.95
                if format_output and PYGMENTS_AVAILABLE:
                    # Use pygments for PowerShell syntax highlighting
                    formatter = HtmlFormatter(style='monokai', noclasses=True, cssclass='highlight')
                    highlighted = highlight(decoded, PowerShellLexer(), formatter)
                    results.append(("PowerShell EncodedCommand", highlighted, confidence))
                elif format_output:
                    formatted = f"<div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 8px; margin: 5px 0; word-wrap: break-word;'><pre>{decoded}</pre></div>"
                    results.append(("PowerShell EncodedCommand", formatted, confidence))
                else:
                    results.append(("PowerShell EncodedCommand", decoded, confidence))
            except:
                pass
        
        return results
    
    @staticmethod
    def _is_base64(text):
        """Check if text looks like base64"""
        if len(text) % 4 != 0:
            return False
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
        return bool(base64_pattern.match(text)) and len(text) > 4
    
    @staticmethod
    def _is_hex(text):
        """Check if text looks like hex"""
        hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
        return bool(hex_pattern.match(text)) and len(text) % 2 == 0 and len(text) > 4
    
    @staticmethod
    def _unpack_javascript(packed_code):
        """Unpack JavaScript packed code"""
        # Extract the packed string and parameters
        match = re.search(r"\('(.*?)',(\d+),(\d+),'(.*?)'\.(.*?)\)\)$", packed_code)
        if not match:
            return "Could not parse packed JavaScript"
        
        p, a, c, k_string, split_method = match.groups()
        a, c = int(a), int(c)
        
        # Parse keyword array
        k = k_string.split('|')
        
        # Unpack the code
        result = p
        for i in range(c):
            if i < len(k) and k[i]:
                # Convert number to base-36 representation
                if i < 10:
                    token = str(i)
                elif i < 36:
                    token = chr(ord('a') + i - 10)
                else:
                    token = chr(ord('A') + i - 36)
                
                # Replace tokens
                result = re.sub(r'\b' + re.escape(token) + r'\b', k[i], result)
        
        # Extract just the JavaScript functions, removing wrapper code
        js_match = re.search(r'(function \w+.*?)(?=function|$)', result, re.DOTALL)
        if js_match:
            clean_js = js_match.group(1)
            # Find all function definitions
            functions = re.findall(r'function \w+\([^)]*\)\{[^}]*(?:\{[^}]*\}[^}]*)*\}', result)
            if functions:
                return '\n\n'.join(functions)
        
        return result