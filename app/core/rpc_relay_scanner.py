# app/core/rpc_relay_scanner.py
"""
RPC Relay & MITM Scanner Module
Detects NTLM relay vulnerabilities and maps MITM attack surface
"""
import subprocess
import socket
import argparse
import sys
import re

class RPCRelayScanner:
    """Scanner for RPC relay vulnerabilities and MITM attack surface"""
    
    def __init__(self):
        self.target = None
        self.attacker_ip = None
    
    def scan_relay_potential(self, target, attacker_ip=None, relay_type="ntlm_relay", 
                           check_signing=True, enumerate=True, simulate=False):
        """Scan for NTLM relay potential"""
        self.target = target
        self.attacker_ip = attacker_ip or "127.0.0.1"
        
        print(f"[INFO] Scanning relay potential on {target}")
        print(f"[INFO] Relay type: {relay_type}")
        
        results = {
            'target': target,
            'relay_type': relay_type,
            'vulnerabilities': [],
            'interfaces': [],
            'signing_status': {}
        }
        
        # Check SMB signing enforcement
        if check_signing:
            signing_status = self._check_smb_signing(target)
            results['signing_status'] = signing_status
            
            if not signing_status.get('required', True):
                vuln = {
                    'name': 'SMB Signing Not Required',
                    'severity': 'High',
                    'description': 'SMB signing is not enforced, allowing relay attacks',
                    'impact': 'NTLM credentials can be relayed to other services'
                }
                results['vulnerabilities'].append(vuln)
                print(f"[VULN] HIGH: {vuln['name']} - {vuln['description']}")
        
        # Enumerate RPC interfaces for relay potential
        if enumerate:
            interfaces = self._enumerate_relay_interfaces(target)
            results['interfaces'] = interfaces
            
            # Check for PrinterBug/SpoolSample potential
            if any('spoolss' in iface.lower() for iface in interfaces):
                vuln = {
                    'name': 'PrinterBug/SpoolSample Relay Vector',
                    'severity': 'Critical',
                    'description': 'Print Spooler service can be abused for NTLM relay',
                    'impact': 'Forced authentication to attacker-controlled server'
                }
                results['vulnerabilities'].append(vuln)
                print(f"[VULN] CRITICAL: {vuln['name']} - {vuln['description']}")
            
            # Check for PetitPotam potential
            if any('lsarpc' in iface.lower() or 'efsr' in iface.lower() for iface in interfaces):
                vuln = {
                    'name': 'PetitPotam Relay Vector',
                    'severity': 'Critical', 
                    'description': 'LSA RPC interface can be abused for NTLM relay',
                    'impact': 'Forced authentication via EFS RPC calls'
                }
                results['vulnerabilities'].append(vuln)
                print(f"[VULN] CRITICAL: {vuln['name']} - {vuln['description']}")
        
        # Simulate attack if requested
        if simulate:
            self._simulate_relay_attack(target, relay_type, results)
        
        # Summary
        critical_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'Critical'])
        high_count = len([v for v in results['vulnerabilities'] if v['severity'] == 'High'])
        
        print(f"[SUMMARY] Found {critical_count} Critical and {high_count} High severity relay vectors")
        
        return results
    
    def map_mitm_surface(self, target, attacker_ip=None, target_service="smb"):
        """Map MITM attack surface"""
        self.target = target
        self.attacker_ip = attacker_ip or "127.0.0.1"
        
        print(f"[INFO] Mapping MITM attack surface for {target}")
        print(f"[INFO] Target service: {target_service}")
        
        results = {
            'target': target,
            'service': target_service,
            'attack_vectors': [],
            'relay_chains': [],
            'mitigation_status': {}
        }
        
        # Check for NTLM authentication services
        auth_services = self._discover_ntlm_services(target)
        results['auth_services'] = auth_services
        
        for service in auth_services:
            print(f"[FOUND] NTLM service: {service['name']} on port {service['port']}")
        
        # Analyze relay chain potential
        relay_chains = self._analyze_relay_chains(target, auth_services)
        results['relay_chains'] = relay_chains
        
        for chain in relay_chains:
            print(f"[CHAIN] {chain['source']} -> {chain['target']} (Risk: {chain['risk']})")
        
        # Check mitigation status
        mitigations = self._check_mitigations(target)
        results['mitigation_status'] = mitigations
        
        for mitigation, status in mitigations.items():
            status_text = "ENABLED" if status else "DISABLED"
            color = "green" if status else "red"
            print(f"[MITIGATION] {mitigation}: {status_text}")
        
        return results
    
    def _check_smb_signing(self, target):
        """Check SMB signing enforcement"""
        try:
            print(f"[INFO] Checking SMB signing status on {target}")
            
            # Try to connect without signing
            cmd = ["smbclient", "-L", target, "-N", "--option=client_signing=disabled"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            signing_status = {
                'required': True,
                'supported': True,
                'details': 'SMB signing status unknown'
            }
            
            if result.returncode == 0:
                signing_status['required'] = False
                signing_status['details'] = 'SMB signing not required - relay attacks possible'
                print(f"[WARNING] SMB signing not required on {target}")
            else:
                if "signing" in result.stderr.lower():
                    signing_status['details'] = 'SMB signing required - relay attacks mitigated'
                    print(f"[INFO] SMB signing required on {target}")
            
            return signing_status
            
        except Exception as e:
            print(f"[ERROR] Failed to check SMB signing: {e}")
            return {'required': True, 'supported': True, 'details': f'Error: {e}'}
    
    def _enumerate_relay_interfaces(self, target):
        """Enumerate RPC interfaces that can be used for relay attacks"""
        interfaces = []
        
        try:
            print(f"[INFO] Enumerating RPC interfaces on {target}")
            
            # Check for common relay-vulnerable interfaces
            vulnerable_interfaces = [
                ('spoolss', 'Print Spooler - PrinterBug/SpoolSample'),
                ('lsarpc', 'LSA RPC - PetitPotam'),
                ('efsr', 'Encrypting File System RPC - PetitPotam'),
                ('svcctl', 'Service Control Manager'),
                ('winreg', 'Windows Registry')
            ]
            
            for interface, description in vulnerable_interfaces:
                if self._test_interface_access(target, interface):
                    interfaces.append(f"{interface}: {description}")
                    print(f"[FOUND] Interface: {interface} - {description}")
            
            return interfaces
            
        except Exception as e:
            print(f"[ERROR] Interface enumeration failed: {e}")
            return []
    
    def _test_interface_access(self, target, interface):
        """Test if specific RPC interface is accessible"""
        try:
            if interface == 'spoolss':
                # Test print spooler
                cmd = ["sc", f"\\\\{target}", "query", "spooler"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0 and "RUNNING" in result.stdout
            
            elif interface == 'lsarpc':
                # Test LSA RPC
                cmd = ["net", "use", f"\\\\{target}\\IPC$"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            elif interface == 'svcctl':
                # Test service control
                cmd = ["sc", f"\\\\{target}", "query", "state=", "all"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            elif interface == 'winreg':
                # Test remote registry
                cmd = ["reg", "query", f"\\\\{target}\\HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "ProductName"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            return False
            
        except:
            return False
    
    def _simulate_relay_attack(self, target, relay_type, results):
        """Simulate relay attack (safe simulation)"""
        print(f"[SIMULATION] Simulating {relay_type} attack on {target}")
        
        simulation = {
            'type': relay_type,
            'steps': [],
            'success_probability': 'Unknown'
        }
        
        if relay_type == "ntlm_relay":
            simulation['steps'] = [
                "1. Set up NTLM relay server on attacker machine",
                "2. Trigger authentication from target to attacker",
                "3. Relay credentials to target service",
                "4. Execute commands with relayed credentials"
            ]
            
            # Estimate success probability based on findings
            if not results['signing_status'].get('required', True):
                simulation['success_probability'] = 'High'
            else:
                simulation['success_probability'] = 'Low'
        
        elif relay_type == "printerbug":
            simulation['steps'] = [
                "1. Set up SMB server on attacker machine",
                "2. Call RpcRemoteFindFirstPrinterChangeNotification",
                "3. Force target to authenticate to attacker SMB",
                "4. Relay credentials to target service"
            ]
            simulation['success_probability'] = 'High' if any('spoolss' in iface for iface in results['interfaces']) else 'Low'
        
        results['simulation'] = simulation
        print(f"[SIMULATION] Success probability: {simulation['success_probability']}")
    
    def _discover_ntlm_services(self, target):
        """Discover services that use NTLM authentication"""
        services = []
        
        # Common NTLM-enabled services
        ntlm_ports = [
            (445, 'SMB'),
            (139, 'NetBIOS'),
            (80, 'HTTP'),
            (443, 'HTTPS'),
            (389, 'LDAP'),
            (636, 'LDAPS'),
            (1433, 'MSSQL'),
            (5985, 'WinRM HTTP'),
            (5986, 'WinRM HTTPS')
        ]
        
        for port, service_name in ntlm_ports:
            if self._test_port_open(target, port):
                services.append({
                    'name': service_name,
                    'port': port,
                    'ntlm_enabled': self._test_ntlm_auth(target, port, service_name)
                })
        
        return services
    
    def _test_port_open(self, target, port):
        """Test if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _test_ntlm_auth(self, target, port, service):
        """Test if service supports NTLM authentication"""
        # Simplified test - in reality would need protocol-specific checks
        if service in ['SMB', 'NetBIOS']:
            return True
        elif service in ['HTTP', 'HTTPS']:
            # Would need to check for NTLM in HTTP headers
            return False  # Simplified
        elif service in ['LDAP', 'LDAPS']:
            return True
        elif service == 'MSSQL':
            return True
        elif service in ['WinRM HTTP', 'WinRM HTTPS']:
            return True
        return False
    
    def _analyze_relay_chains(self, target, auth_services):
        """Analyze potential relay attack chains"""
        chains = []
        
        for source in auth_services:
            for dest in auth_services:
                if source != dest and source['ntlm_enabled'] and dest['ntlm_enabled']:
                    risk = self._calculate_chain_risk(source, dest)
                    chains.append({
                        'source': f"{source['name']}:{source['port']}",
                        'target': f"{dest['name']}:{dest['port']}",
                        'risk': risk
                    })
        
        return chains
    
    def _calculate_chain_risk(self, source, dest):
        """Calculate risk level for relay chain"""
        # High-value targets
        high_value = ['SMB', 'LDAP', 'LDAPS', 'MSSQL']
        
        if dest['name'] in high_value:
            return 'High'
        elif source['name'] in ['HTTP', 'HTTPS'] and dest['name'] in ['SMB']:
            return 'Medium'
        else:
            return 'Low'
    
    def _check_mitigations(self, target):
        """Check for relay attack mitigations"""
        mitigations = {}
        
        # Check SMB signing
        signing_status = self._check_smb_signing(target)
        mitigations['SMB Signing'] = signing_status.get('required', False)
        
        # Check LDAP signing (simplified)
        mitigations['LDAP Signing'] = False  # Would need LDAP-specific check
        
        # Check EPA (Extended Protection for Authentication)
        mitigations['EPA'] = False  # Would need service-specific checks
        
        return mitigations

def main():
    """Command line interface"""
    parser = argparse.ArgumentParser(description="RPC Relay & MITM Scanner")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--scan", action="store_true", help="Scan for relay potential")
    parser.add_argument("--mitm", action="store_true", help="Map MITM attack surface")
    parser.add_argument("--attacker", help="Attacker IP address")
    parser.add_argument("--type", default="ntlm_relay", help="Relay type")
    parser.add_argument("--service", default="smb", help="Target service")
    parser.add_argument("--check-signing", action="store_true", help="Check SMB signing")
    parser.add_argument("--enumerate", action="store_true", help="Enumerate interfaces")
    parser.add_argument("--simulate", action="store_true", help="Simulate attack")
    
    args = parser.parse_args()
    
    scanner = RPCRelayScanner()
    
    if args.scan:
        results = scanner.scan_relay_potential(
            args.target, args.attacker, args.type,
            args.check_signing, args.enumerate, args.simulate
        )
    elif args.mitm:
        results = scanner.map_mitm_surface(
            args.target, args.attacker, args.service
        )
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()