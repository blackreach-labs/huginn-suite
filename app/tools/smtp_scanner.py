# app/tools/smtp_scanner.py
import socket
import os
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class SMTPWorkerSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)

class SMTPWorker(QRunnable):
    def __init__(self, target, port=25, domain="", helo_name="test.local", wordlist_path=None):
        super().__init__()
        self.target = target
        self.port = port
        self.domain = domain
        self.helo_name = helo_name
        self.wordlist_path = wordlist_path
        self.signals = SMTPWorkerSignals()
        self.is_running = True
    
    def run(self):
        try:
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Starting SMTP enumeration on {self.target}:{self.port}...</p><br>")
            
            results = {}
            
            # Check SMTP connection
            if self._check_smtp_connection(results):
                # Enumerate users
                self._enumerate_users(results)
            
            self.signals.results.emit(results)
            self.signals.output.emit(f"<p style='color: #00FF41;'>SMTP enumeration completed.</p><br>")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Error: {str(e)}</p><br>")
        finally:
            self.signals.finished.emit()
    
    def _check_smtp_connection(self, results):
        """Check SMTP connection and get banner"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Connecting to SMTP server...</p><br>")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, self.port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.signals.output.emit(f"<p style='color: #00FF41;'>SMTP Banner: {banner.strip()}</p><br>")
            results['banner'] = banner.strip()
            
            # Send HELO
            sock.send(f"HELO {self.helo_name}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            self.signals.output.emit(f"<p>HELO Response: {response.strip()}</p><br>")
            
            sock.close()
            return True
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>SMTP connection failed: {str(e)}</p><br>")
            return False
    
    def _enumerate_users(self, results):
        """Enumerate SMTP users using VRFY command"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Enumerating SMTP users...</p><br>")
            
            # Load wordlist
            usernames = []
            if self.wordlist_path and os.path.exists(self.wordlist_path):
                with open(self.wordlist_path, 'r') as f:
                    usernames = [line.strip() for line in f if line.strip()]
            else:
                usernames = ['admin', 'administrator', 'root', 'test', 'user', 'guest', 'mail', 'postmaster']
            
            valid_users = []
            for username in usernames[:20]:  # Limit to first 20
                if not self.is_running:
                    break
                    
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.target, self.port))
                    
                    # Skip banner
                    sock.recv(1024)
                    
                    # Send VRFY command
                    sock.send(f"VRFY {username}\r\n".encode())
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if "250" in response or "252" in response:
                        valid_users.append(username)
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Valid user: {username}</p><br>")
                    
                    sock.close()
                    
                except:
                    pass
            
            if valid_users:
                results['valid_users'] = valid_users
                self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(valid_users)} valid users</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No valid users found or VRFY disabled</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>User enumeration failed: {str(e)}</p><br>")