# app/tools/snmp_scanner.py
import subprocess
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from ..core.snmp_data_collector import create_snmp_collector
from app.core.html_utils import h
from app.core.logger import logger

class SNMPWorkerSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)

class SNMPWorker(QRunnable):
    def __init__(self, target, version="2c", scan_type="Basic Info", communities=None, tenant_id="default"):
        super().__init__()
        self.target = target
        self.version = version
        self.scan_type = scan_type
        self.communities = communities or ["public", "private", "community"]
        self.tenant_id = tenant_id
        self.signals = SNMPWorkerSignals()
        self.is_running = True
        self.data_collector = create_snmp_collector(tenant_id)
    
    def run(self):
        try:
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Starting SNMP enumeration on {h(self.target)}...</p><br>")
            
            # Start scan in centralized data
            scan_id = self.data_collector.start_snmp_scan(self.target, "snmp_scanner")
            
            results = {}
            total_results = 0
            
            # Test communities
            valid_communities = self._test_communities(results)
            
            if valid_communities:
                # Collect valid communities
                self.data_collector.collect_community_strings(self.target, valid_communities)
                total_results += len(valid_communities)
                
                valid_community = valid_communities[0]  # Use first valid community
                
                # Perform enumeration based on scan type
                if self.scan_type in ["Basic Info", "Full Enumeration"]:
                    system_info = self._get_system_info(results, valid_community)
                    if system_info:
                        self.data_collector.collect_system_info(self.target, system_info)
                        total_results += 1
                
                if self.scan_type in ["Users", "Full Enumeration"]:
                    users = self._get_users(results, valid_community)
                    if users:
                        self.data_collector.collect_users(self.target, users)
                        total_results += len(users)
                
                if self.scan_type in ["Network", "Full Enumeration"]:
                    interfaces = self._get_network_info(results, valid_community)
                    if interfaces:
                        self.data_collector.collect_network_interfaces(self.target, interfaces)
                        total_results += len(interfaces)
            
            # Complete scan
            self.data_collector.complete_snmp_scan(total_results)
            
            self.signals.results.emit(results)
            self.signals.output.emit(f"<p style='color: #00FF41;'>SNMP enumeration completed. {total_results} results collected.</p><br>")
            
        except Exception as e:
            self.data_collector.complete_snmp_scan(0, str(e))
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Error: {h(str(e))}</p><br>")
        finally:
            self.signals.finished.emit()
    
    def _test_communities(self, results):
        """Test SNMP communities"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Testing SNMP communities...</p><br>")
            
            valid_communities = []
            
            for community in self.communities:
                if not self.is_running:
                    break
                    
                try:
                    # Use snmpget to test community
                    cmd = ["snmpget", "-v", self.version, "-c", community, self.target, "1.3.6.1.2.1.1.1.0"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0 and "No Such Object" not in result.stdout:
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Valid community: {h(community)}</p><br>")
                        valid_communities.append(community)
                        
                except Exception as _exc:
                    # Try with Windows netsh or basic UDP check
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            
            if valid_communities:
                results['valid_communities'] = valid_communities
                return valid_communities
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No valid SNMP communities found or SNMP tools not available</p><br>")
                return []
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Community testing failed: {h(str(e))}</p><br>")
            return []
    
    def _get_system_info(self, results, community):
        """Get system information"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Getting system information...</p><br>")
            
            system_info = {}
            
            # System description OID
            cmd = ["snmpget", "-v", self.version, "-c", community, self.target, "1.3.6.1.2.1.1.1.0"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                system_desc = result.stdout.strip()
                system_info['system_description'] = system_desc
                results['system_description'] = system_desc
                self.signals.output.emit(f"<p>System: {h(system_desc)}</p><br>")
                return system_info
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>Could not retrieve system information</p><br>")
                return None
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>System info retrieval failed: {h(str(e))}</p><br>")
            return None
    
    def _get_users(self, results, community):
        """Get user information"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Getting user information...</p><br>")
            
            # User table OID (if available)
            cmd = ["snmpwalk", "-v", self.version, "-c", community, self.target, "1.3.6.1.4.1.77.1.2.25"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                users = result.stdout.strip().split('\n')
                results['users'] = users
                self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(users)} user entries</p><br>")
                return users
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No user information available</p><br>")
                return []
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>User enumeration failed: {h(str(e))}</p><br>")
            return []
    
    def _get_network_info(self, results, community):
        """Get network information"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Getting network information...</p><br>")
            
            # Interface table OID
            cmd = ["snmpwalk", "-v", self.version, "-c", community, self.target, "1.3.6.1.2.1.2.2.1.2"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout.strip():
                interfaces = result.stdout.strip().split('\n')
                results['interfaces'] = interfaces
                self.signals.output.emit(f"<p style='color: #00FF41;'>Found {len(interfaces)} network interfaces</p><br>")
                return interfaces
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No network information available</p><br>")
                return []
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Network enumeration failed: {h(str(e))}</p><br>")
            return []