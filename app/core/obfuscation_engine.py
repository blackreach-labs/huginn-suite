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
        elif method == "ASCII Encode":
            return ' '.join(str(ord(c)) for c in text)
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
            elif method == "ASCII Decode":
                # Handle space-separated ASCII values
                ascii_values = text.strip().split()
                return ''.join(chr(int(val)) for val in ascii_values)
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
        
        # ASCII encoding detection (space-separated numbers)
        if ObfuscationEngine._is_ascii_encoded(text):
            try:
                ascii_values = text.strip().split()
                decoded = ''.join(chr(int(val)) for val in ascii_values)
                confidence = 0.8
                if format_output:
                    formatted = f"<div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 8px; margin: 5px 0; word-wrap: break-word;'>{decoded}</div>"
                    results.append(("ASCII Encoding", formatted, confidence))
                else:
                    results.append(("ASCII Encoding", decoded, confidence))
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
    def _is_ascii_encoded(text):
        """Check if text looks like ASCII-encoded (space-separated numbers)"""
        try:
            parts = text.strip().split()
            if len(parts) < 2:  # Need at least 2 numbers to be considered ASCII encoded
                return False
            for part in parts:
                val = int(part)
                if val < 32 or val > 126:  # Printable ASCII range
                    return False
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _bytes_to_bitstring(b: bytes) -> str:
        """Return a string of '0'/'1' bits for the given bytes."""
        return ''.join(f"{byte:08b}" for byte in b)

    @staticmethod
    def _bitstring_to_bytes(bits: str) -> bytes:
        """Convert a bitstring (length multiple of 8) back to bytes."""
        if len(bits) % 8 != 0:
            bits = bits[:(len(bits) // 8) * 8]
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

    @staticmethod
    def embed_in_emojis(carrier: str, secret: str) -> str:
        """
        Hide `secret` inside `carrier` (a string of emoji or other characters)
        by inserting zero-width characters after carrier characters.
        Returns the stego string.
        Usage note: carrier should be at least 1 character long. If secret is
        longer than can be evenly distributed, remaining bits are appended after carrier end.
        """
        if not carrier:
            raise ValueError("Carrier string must not be empty")

        ZWSP = '\u200B'   # maps to bit '0'
        ZWNJ = '\u200C'   # maps to bit '1'
        ZWJ  = '\u200D'   # used as wrapper/marker around bit-chunks

        secret_bytes = secret.encode('utf-8')
        length = len(secret_bytes)
        # 32-bit length header (big-endian)
        length_header = length.to_bytes(4, byteorder='big')
        header_bits = ObfuscationEngine._bytes_to_bitstring(length_header)
        payload_bits = ObfuscationEngine._bytes_to_bitstring(secret_bytes)
        bitstream = header_bits + payload_bits

        # Distribute bitstream across carrier characters
        n = len(carrier)
        if len(bitstream) == 0:
            return carrier  # nothing to hide

        chunk_size = (len(bitstream) + n - 1) // n  # ceil division
        parts = []
        for i, ch in enumerate(carrier):
            start = i * chunk_size
            chunk_bits = bitstream[start:start + chunk_size]
            if chunk_bits:
                mapped = ''.join(ZWSP if b == '0' else ZWNJ for b in chunk_bits)
                wrapped = ZWJ + mapped + ZWJ
                parts.append(ch + wrapped)
            else:
                parts.append(ch)

        # append remainder if any (shouldn't happen often, but safe)
        tail_start = n * chunk_size
        if tail_start < len(bitstream):
            chunk_bits = bitstream[tail_start:]
            mapped = ''.join(ZWSP if b == '0' else ZWNJ for b in chunk_bits)
            wrapped = ZWJ + mapped + ZWJ
            parts.append(wrapped)

        return ''.join(parts)

    @staticmethod
    def extract_from_emojis(stego: str) -> str:
        """
        Extract hidden secret from a string produced by embed_in_emojis.
        Returns the decoded UTF-8 string.
        Raises ValueError if no hidden data found or if extraction fails.
        """
        if not stego:
            raise ValueError("Input is empty")

        import re
        # Pattern: ZWJ (then one or more ZWSP or ZWNJ) then ZWJ
        # direct characters used for clarity
        pattern = re.compile(r'\u200D([\u200B\u200C]+)\u200D')
        matches = pattern.findall(stego)
        if not matches:
            raise ValueError("No hidden data found")

        # Rebuild bitstream in order of appearance
        bit_chunks = []
        for inner in matches:
            bits = ''.join('0' if ch == '\u200B' else '1' for ch in inner)
            bit_chunks.append(bits)
        bitstream = ''.join(bit_chunks)

        # First 32 bits are length in bytes (big-endian)
        if len(bitstream) < 32:
            raise ValueError("Hidden data too short to contain header")

        length_bits = bitstream[:32]
        payload_bits = bitstream[32:]
        length = int(length_bits, 2)

        needed_bits = length * 8
        if len(payload_bits) < needed_bits:
            raise ValueError("Hidden data truncated or corrupted")

        payload_relevant = payload_bits[:needed_bits]
        payload_bytes = ObfuscationEngine._bitstring_to_bytes(payload_relevant)
        try:
            return payload_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # If decoding fails, return raw bytes repr (or raise)
            raise ValueError("Extracted bytes are not valid UTF-8")
    
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