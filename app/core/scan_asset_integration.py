# app/core/scan_asset_integration.py
from PyQt6.QtCore import QObject, pyqtSignal
from app.core.asset_manager import asset_manager
from datetime import datetime
import re
from app.core.logger import logger

class ScanAssetIntegrator(QObject):
    """Integrates scan results with asset inventory"""
    
    asset_updated = pyqtSignal(str, str)  # tenant_id, asset_id
    
    def __init__(self):
        super().__init__()
        self.tenant_id = self.get_current_tenant()
        if not self.tenant_id or self.tenant_id == '':
            self.tenant_id = 'default'
    
    def get_current_tenant(self):
        """Get current tenant from main window if available"""
        try:
            # Try to get from main window first
            from PyQt6.QtWidgets import QApplication
            app = QApplication.instance()
            if app:
                # Look for main window with current_profile_name
                for widget in app.allWidgets():
                    if hasattr(widget, 'current_profile_name') and widget.current_profile_name:
                        print(f"Found profile from main window: {widget.current_profile_name}")
                        return widget.current_profile_name
                
                # Look for any widget with profile information
                for widget in app.allWidgets():
                    if hasattr(widget, 'profile_name') and widget.profile_name:
                        print(f"Found profile from widget: {widget.profile_name}")
                        return widget.profile_name
                    
                    # Check for profile combo box
                    if hasattr(widget, 'currentText') and 'profile' in str(type(widget)).lower():
                        profile_text = widget.currentText()
                        if profile_text and profile_text != 'Select Profile':
                            print(f"Found profile from combo box: {profile_text}")
                            return profile_text
            
            # Try to get from global state or settings
            try:
                from PyQt6.QtCore import QSettings
                settings = QSettings('Huginn', 'SecurityFramework')
                last_profile = settings.value('last_profile', 'default')
                if last_profile and last_profile != 'default':
                    print(f"Found profile from settings: {last_profile}")
                    return last_profile
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            # Fallback to engagement manager DB
            try:
                from app.core.feature_gap_integration import FeatureGapIntegration
                eng_manager = FeatureGapIntegration.engines.engagement_manager
                if eng_manager and eng_manager.active_engagement_id:
                    print(f"Found profile from engagement manager: {eng_manager.active_engagement_id}")
                    return eng_manager.active_engagement_id
            except Exception:
                pass
            
            print("No profile found, using default")
            return 'default'
        except Exception as e:
            print(f"Error getting tenant: {e}")
            return 'default'
    
    def process_ping_sweep_results(self, results):
        """Process ping sweep results and update assets"""
        if not isinstance(results, dict):
            return
        
        # Update tenant ID for current session
        self.tenant_id = self.get_current_tenant()
        if not self.tenant_id or self.tenant_id == '':
            self.tenant_id = 'default'
        
        for ip, data in results.items():
            if isinstance(data, dict) and data.get('status') == 'up':
                asset_id = asset_manager.add_or_update_asset(
                    tenant_id=self.tenant_id,
                    ip_address=ip,
                    status='DISCOVERED',
                    confidence=25,
                    metadata={'discovery_method': 'ping_sweep', 'response_time': data.get('response_time')}
                )
                if asset_id:
                    self.asset_updated.emit(self.tenant_id, asset_id)
    
    def process_enhanced_scan_results(self, results, service_detection=False, os_detection=False):
        """Process enhanced scan results with detailed OS and service information"""
        if not isinstance(results, dict):
            return
        
        # Update tenant ID for current session
        self.tenant_id = self.get_current_tenant()
        
        for ip, data in results.items():
            if isinstance(data, dict):
                # Extract enhanced information
                open_ports_data = data.get('open_ports', [])
                os_data = data.get('os_detection', {})
                
                # Build detailed services string with confidence
                services_list = []
                for port_info in open_ports_data:
                    port = port_info.get('port', 'unknown')
                    service = port_info.get('service', 'unknown')
                    confidence = port_info.get('confidence', 'medium')
                    protocol = port_info.get('protocol', 'tcp')
                    tls_version = port_info.get('tls_version', '')
                    
                    service_str = f"{port}/{protocol}:{service}"
                    if confidence != 'medium':
                        service_str += f"({confidence})"
                    if tls_version:
                        service_str += f"[{tls_version}]"
                    services_list.append(service_str)
                
                # Check if this is a web server (has port 80 or 443)
                is_web_server = any(p.get('port') in [80, 443] for p in open_ports_data)
                metadata = {'enhanced_scan': True, 'os_detection': os_detection, 'service_detection': service_detection}
                if is_web_server:
                    metadata['server_type'] = 'web_server'
                
                # Update asset with enhanced information
                print(f"Updating asset {ip} with enhanced scan data for tenant {self.tenant_id}")
                
                # Convert confidence to numeric value
                confidence_map = {'low': 30, 'medium': 60, 'high': 90}
                confidence_val = os_data.get('confidence', 'medium') if os_detection else 'medium'
                numeric_confidence = confidence_map.get(confidence_val, 60)
                
                asset_manager.add_or_update_asset(
                    tenant_id=self.tenant_id,
                    ip_address=ip,
                    hostname=data.get('hostname', ''),
                    os_type=os_data.get('os', '') if os_detection else '',
                    open_ports=[{'port': p['port'], 'protocol': p.get('protocol', 'tcp')} for p in open_ports_data],
                    services=[{
                        'port': p['port'],
                        'service': p['service'],
                        'protocol': p.get('protocol', 'tcp'),
                        'banner': p.get('banner', ''),
                        'confidence': p.get('confidence', 'medium'),
                        **(({'tls_version': p['tls_version']} if p.get('tls_version') else {}))
                    } for p in open_ports_data],
                    status='ANALYZED',
                    confidence=numeric_confidence,
                    metadata=metadata
                )
                print(f"Asset {ip} updated successfully")
    
    def process_port_scan_results(self, results):
        """Process port scan results and update assets"""
        if not isinstance(results, dict):
            return
        
        for ip, data in results.items():
            if isinstance(data, dict):
                open_ports = []
                services = []
                
                # Extract port information
                if 'open_ports' in data:
                    for port_info in data['open_ports']:
                        if isinstance(port_info, dict):
                            open_ports.append({
                                'port': port_info.get('port'),
                                'protocol': port_info.get('protocol', 'tcp'),
                                'state': port_info.get('state', 'open')
                            })
                            
                            # If service info is available
                            if port_info.get('service'):
                                services.append({
                                    'port': port_info.get('port'),
                                    'service': port_info.get('service'),
                                    'version': port_info.get('version', ''),
                                    'protocol': port_info.get('protocol', 'tcp')
                                })
                
                # Determine OS hints from ports
                os_hints = self._analyze_os_from_ports(open_ports)
                
                asset_data = {
                    'tenant_id': self.tenant_id,
                    'ip_address': ip,
                    'status': 'IDENTIFIED',
                    'confidence': 50,
                    'open_ports': open_ports,
                    'metadata': {'discovery_method': 'port_scan'}
                }
                
                if services:
                    asset_data['services'] = services
                    asset_data['confidence'] = 60
                
                if os_hints:
                    asset_data['os_type'] = os_hints['os_type']
                    asset_data['confidence'] = max(asset_data['confidence'], os_hints['confidence'])
                
                asset_id = asset_manager.add_or_update_asset(**asset_data)
                if asset_id:
                    self.asset_updated.emit(self.tenant_id, asset_id)
    
    def process_dns_results(self, results):
        """Process DNS enumeration results and update assets"""
        if not isinstance(results, dict):
            return
        
        for domain, record_types in results.items():
            if isinstance(record_types, dict):
                # Extract A records (IP addresses)
                if 'A' in record_types:
                    for ip in record_types['A']:
                        if self._is_valid_ip(ip):
                            # Check if we already have an asset with this IP
                            existing_asset = asset_manager.get_asset_by_ip(self.tenant_id, ip)
                            
                            # Merge hostname information with existing IP asset
                            asset_id = asset_manager.add_or_update_asset(
                                tenant_id=self.tenant_id,
                                ip_address=ip,
                                hostname=domain,
                                status='DISCOVERED' if not existing_asset else existing_asset.get('status', 'DISCOVERED'),
                                confidence=max(30, existing_asset.get('confidence', 0) if existing_asset else 30),
                                metadata={
                                    'discovery_method': 'dns_enum', 
                                    'domain': domain,
                                    'dns_resolved': True
                                }
                            )
                            if asset_id:
                                self.asset_updated.emit(self.tenant_id, asset_id)
    
    def process_service_detection_results(self, results):
        """Process service detection results and update assets"""
        if not isinstance(results, dict):
            return
        
        for ip, data in results.items():
            if isinstance(data, dict):
                services = []
                os_info = {}
                
                # Extract service information
                if 'services' in data:
                    for service in data['services']:
                        if isinstance(service, dict):
                            services.append({
                                'port': service.get('port'),
                                'service': service.get('name', service.get('service')),
                                'version': service.get('version', ''),
                                'product': service.get('product', ''),
                                'protocol': service.get('protocol', 'tcp')
                            })
                
                # Extract OS information
                if 'os_info' in data:
                    os_data = data['os_info']
                    if isinstance(os_data, dict):
                        os_info = {
                            'os_type': os_data.get('name', os_data.get('os_type', 'Unknown')),
                            'os_version': os_data.get('version', ''),
                            'confidence': min(90, max(70, os_data.get('accuracy', 70)))
                        }
                
                asset_data = {
                    'tenant_id': self.tenant_id,
                    'ip_address': ip,
                    'status': 'IDENTIFIED',
                    'confidence': 70,
                    'services': services,
                    'metadata': {'discovery_method': 'service_detection'}
                }
                
                if os_info:
                    asset_data.update(os_info)
                    asset_data['status'] = 'KNOWN' if os_info['confidence'] > 80 else 'IDENTIFIED'
                
                asset_id = asset_manager.add_or_update_asset(**asset_data)
                if asset_id:
                    self.asset_updated.emit(self.tenant_id, asset_id)
    
    def process_smb_results(self, results):
        """Process SMB enumeration results and update assets"""
        if not isinstance(results, dict):
            return
        
        # Update tenant ID for current session
        self.tenant_id = self.get_current_tenant()
        if not self.tenant_id or self.tenant_id == '':
            self.tenant_id = 'default'
        
        # Extract target IP from results
        target_ip = results.get('target_ip')
        if not target_ip:
            return
        
        services = []
        metadata = {'discovery_method': 'smb_enum'}
        
        # Extract SMB ports
        if 'smb_ports' in results:
            for port_info in results['smb_ports']:
                port_num = 445 if '445' in port_info else 139
                services.append({
                    'port': port_num,
                    'service': 'smb',
                    'version': 'SMB/CIFS',
                    'protocol': 'tcp',
                    'state': 'open'
                })
        
        # Extract SMB shares (both standard and brute force)
        all_shares = []
        if 'shares' in results:
            all_shares.extend(results['shares'])
        if 'bruteforce_shares' in results:
            all_shares.extend(results['bruteforce_shares'])
        
        if all_shares:
            metadata['shares_found'] = len(all_shares)
            metadata['share_list'] = all_shares[:10]
            
            # Add SMB service if not already added
            if not any(s.get('service') == 'smb' for s in services):
                services.append({
                    'port': 445,
                    'service': 'smb',
                    'version': 'SMB/CIFS',
                    'protocol': 'tcp',
                    'state': 'open'
                })
        
        asset_data = {
            'tenant_id': self.tenant_id,
            'ip_address': target_ip,
            'os_type': 'Windows',  # SMB typically indicates Windows
            'status': 'IDENTIFIED',
            'confidence': 70,
            'services': services,
            'metadata': metadata
        }
        
        print(f"Updating asset {target_ip} with SMB scan data for tenant {self.tenant_id}")
        
        asset_id = asset_manager.add_or_update_asset(**asset_data)
        if asset_id:
            print(f"Asset {target_ip} updated successfully with SMB data")
            self.asset_updated.emit(self.tenant_id, asset_id)
        else:
            print(f"Failed to update asset {target_ip} with SMB data")
    
    def process_rpc_results(self, results):
        """Process RPC enumeration results and update assets"""
        if not isinstance(results, dict):
            return
        
        # Update tenant ID for current session
        self.tenant_id = self.get_current_tenant()
        if not self.tenant_id or self.tenant_id == '':
            self.tenant_id = 'default'
        
        # Extract target IP from results (try both 'target' and 'target_ip')
        target_ip = results.get('target') or results.get('target_ip')
        if not target_ip:
            return
        

        
        services = []
        os_info = {}
        metadata = {'discovery_method': 'rpc_enum'}
        
        # Extract RPC services
        if 'rpc_endpoints' in results:
            for endpoint in results['rpc_endpoints']:
                if isinstance(endpoint, dict):
                    services.append({
                        'port': endpoint.get('port', 135),
                        'service': 'rpc',
                        'version': endpoint.get('version', ''),
                        'protocol': endpoint.get('protocol', 'tcp'),
                        'uuid': endpoint.get('uuid', '')
                    })
        
        # Extract Windows services
        if 'services' in results:
            for service in results['services']:
                if isinstance(service, dict):
                    services.append({
                        'port': 'N/A',
                        'service': service.get('name', 'Windows Service'),
                        'version': service.get('display_name', ''),
                        'protocol': 'rpc',
                        'state': service.get('state', 'unknown')
                    })
        
        # Extract vulnerabilities
        vulnerabilities = []
        if 'rpc_vulnerabilities' in results:
            for vuln in results['rpc_vulnerabilities']:
                vulnerabilities.append({
                    'id': vuln.get('cve', vuln.get('name', 'unknown')),
                    'name': vuln.get('name', 'Unknown RPC Vulnerability'),
                    'severity': vuln.get('severity', 'unknown').lower(),
                    'description': vuln.get('description', ''),
                    'cvss': vuln.get('cvss_score', 0)
                })
        
        # Extract shares information
        if 'shares' in results:
            metadata['shares_found'] = len(results['shares'])
            metadata['share_list'] = [{
                'name': share.get('name', 'Unknown'),
                'type': share.get('type', 'Unknown'),
                'permissions': share.get('permissions', 'Unknown')
            } for share in results['shares'][:10]]
        
        # Extract OS information from registry
        if 'registry' in results and 'os_info' in results['registry']:
            os_data = results['registry']['os_info']
            if isinstance(os_data, dict):
                os_info = {
                    'os_type': 'Windows',
                    'os_version': os_data.get('ProductName', ''),
                    'confidence': 85
                }
                metadata['registry_access'] = True
        
        asset_data = {
            'tenant_id': self.tenant_id,
            'ip_address': target_ip,
            'status': 'ANALYZED' if vulnerabilities else 'IDENTIFIED',
            'confidence': 85 if vulnerabilities else 75,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'metadata': metadata
        }
        
        if os_info:
            asset_data.update(os_info)
            asset_data['status'] = 'KNOWN'
            asset_data['confidence'] = 90
        
        asset_id = asset_manager.add_or_update_asset(**asset_data)
        if asset_id:
            self.asset_updated.emit(self.tenant_id, asset_id)
    
    def process_http_results(self, results):
        """Process HTTP enumeration results and update assets"""
        if not isinstance(results, dict):
            return
        
        # Update tenant ID for current session
        self.tenant_id = self.get_current_tenant()
        if not self.tenant_id or self.tenant_id == '':
            self.tenant_id = 'default'
        
        # Extract target from results
        target = results.get('target')
        if not target:
            return
        
        # Use resolved IP if provided, otherwise extract from URL
        if 'resolved_ip' in results and 'original_hostname' in results:
            ip = results['resolved_ip']
            fqdn = results['original_hostname']
            hostname = fqdn.split('.')[0]  # Extract host part from FQDN
        else:
            # Extract IP from target URL or use hostname
            ip = self._extract_ip_from_url(target)
            hostname = self._extract_hostname_from_url(target)
            fqdn = hostname  # FQDN is the resolved address from HTTP scan
        
        # If no IP, try to use hostname as identifier
        if not ip and not hostname:
            return
        
        services = []
        metadata = {'discovery_method': 'http_enum', 'target_url': target}
        
        # Extract server information
        if 'server' in results:
            port = 443 if 'https' in target else 80
            services.append({
                'port': port,
                'service': 'https' if 'https' in target else 'http',
                'version': results['server'],
                'protocol': 'tcp'
            })
        
        # Extract discovered directories/files
        if 'directories' in results:
            metadata['directories_found'] = len(results['directories'])
            metadata['directory_list'] = [d.get('path', '') for d in results['directories'][:10]]
        
        if 'known_files' in results:
            metadata['files_found'] = len(results['known_files'])
            metadata['file_list'] = results['known_files'][:10]
        
        # Extract source code findings and convert to vulnerabilities
        source_vulnerabilities = []
        if 'source_findings' in results:
            metadata['source_findings_count'] = len(results['source_findings'])
            metadata['source_findings'] = results['source_findings'][:10]
            
            # Convert source findings to vulnerability format for inventory
            for finding in results['source_findings']:
                severity = 'Medium'  # Default severity
                if any(keyword in finding.lower() for keyword in ['critical', 'dangerous', 'rce', 'execution']):
                    severity = 'Critical'
                elif any(keyword in finding.lower() for keyword in ['high', 'security', 'credential', 'api key']):
                    severity = 'High'
                elif any(keyword in finding.lower() for keyword in ['low', 'information']):
                    severity = 'Low'
                
                source_vulnerabilities.append({
                    'id': f"source_{abs(hash(finding))}",
                    'name': finding,
                    'severity': severity,
                    'description': f'Source code analysis finding: {finding}',
                    'cvss': {'Critical': 9.0, 'High': 7.0, 'Medium': 5.0, 'Low': 3.0}.get(severity, 5.0),
                    'source': 'HTTP Source Code Analysis'
                })
            
            # Extract detailed findings for inventory
            detailed_findings = results.get('detailed_findings', {})
            if detailed_findings:
                metadata['detailed_source_findings'] = {}
                for finding_type, findings in detailed_findings.items():
                    if isinstance(findings, list) and findings:
                        metadata['detailed_source_findings'][finding_type] = findings[:5]  # Limit to 5 per type
        
        # Extract top risk findings for Security section
        security_findings = []
        if 'risk_assessment' in results:
            risk_data = results['risk_assessment']
            metadata['risk_level'] = risk_data.get('risk_level', 'Unknown')
            metadata['risk_score'] = risk_data.get('risk_score', 0)
            if risk_data.get('high_risk_findings'):
                metadata['high_risk_findings'] = risk_data['high_risk_findings'][:5]
            
            # Extract top findings for Security section
            if 'top_findings' in risk_data:
                for finding in risk_data['top_findings']:
                    security_findings.append({
                        'name': finding['name'],
                        'score': finding['score'],
                        'count': finding['count'],
                        'context': finding['context'],
                        'category': finding['category']
                    })
                metadata['top_risk_findings'] = security_findings
        
        # Extract vulnerability data (from Huginn Scanner) - only if we have server info
        vulnerabilities = source_vulnerabilities.copy()  # Start with source code vulnerabilities
        if 'vulnerabilities' in results and 'server' in results and results['server'] != 'Unknown':
            print(f"[DEBUG] Scanner returned {len(results['vulnerabilities'])} vulnerabilities")
            for vuln in results['vulnerabilities']:
                # Generate a unique ID for the vulnerability if not present
                vuln_id = vuln.get('id', vuln.get('cve', f"vuln_{abs(hash(str(vuln)))}"))
                vuln_name = vuln.get('type', vuln.get('name', 'Unknown Vulnerability'))
                vuln_severity = vuln.get('severity', 'unknown').upper()
                vuln_description = vuln.get('description', '')
                
                vulnerabilities.append({
                    'id': vuln_id,
                    'name': vuln_name,
                    'severity': vuln_severity,
                    'description': vuln_description,
                    'cvss': vuln.get('cvss_score', vuln.get('cvss', 0)),
                    'url': vuln.get('url', ''),
                    'evidence': vuln.get('evidence', ''),
                    'recommendation': vuln.get('recommendation', 'Review and remediate this vulnerability')
                })
            metadata['vulnerabilities_found'] = len(vulnerabilities)
            print(f"[DEBUG] Clean results has {len(vulnerabilities)} vulnerabilities")
            
            # Only add HTTPS check if we successfully connected to an HTTP service
            if target.startswith('http://') and not any(v.get('name') == 'No HTTPS Encryption' for v in vulnerabilities):
                vulnerabilities.append({
                    'id': 'no_https',
                    'name': 'No HTTPS Encryption',
                    'severity': 'HIGH',
                    'description': f'Site {hostname or ip or target} not using HTTPS - all traffic transmitted in plaintext',
                    'cvss': 7.4,
                    'url': target,
                    'evidence': 'HTTP protocol detected',
                    'recommendation': 'Implement HTTPS encryption for all web traffic'
                })
                metadata['vulnerabilities_found'] = len(vulnerabilities)
        
        # Extract technology stack
        if 'tech_stack' in results:
            metadata['tech_stack'] = results['tech_stack']
            
            # Extract specific technology information
            if isinstance(results['tech_stack'], dict):
                if 'web_server' in results['tech_stack']:
                    metadata['web_server'] = results['tech_stack']['web_server']
                if 'framework' in results['tech_stack']:
                    metadata['framework'] = results['tech_stack']['framework']
                if 'detected_technologies' in results['tech_stack']:
                    metadata['detected_technologies'] = results['tech_stack']['detected_technologies']
        
        # Extract security score
        if 'security_score' in results:
            metadata['security_score'] = results['security_score']
        
        # Extract content discovery results
        if 'content_discovery' in results:
            content_data = results['content_discovery']
            if isinstance(content_data, dict):
                if 'discovered_paths' in content_data:
                    metadata['content_paths_found'] = len(content_data['discovered_paths'])
                if 'sensitive_findings' in content_data:
                    metadata['sensitive_content_count'] = len(content_data['sensitive_findings'])
        
        # Determine OS hints from server header
        os_hints = self._analyze_os_from_http(results)
        
        # Check if this is a web server (has port 80 or 443)
        is_web_server = any(s.get('port') in [80, 443] for s in services)
        if is_web_server:
            metadata['server_type'] = 'web_server'
        
        # Always use IP as primary identifier if available from DNS resolution
        if ip:
            primary_identifier = ip
            asset_hostname = hostname
        elif hostname and self._is_valid_ip(hostname):
            # Hostname is actually an IP
            primary_identifier = hostname
            asset_hostname = ''
        else:
            # Try to resolve hostname to IP for consistent asset identification
            resolved_ip = self._resolve_hostname_to_ip(hostname)
            if resolved_ip:
                primary_identifier = resolved_ip
                asset_hostname = hostname
            else:
                primary_identifier = hostname
                asset_hostname = hostname
        
        asset_data = {
            'tenant_id': self.tenant_id,
            'ip_address': primary_identifier,
            'hostname': asset_hostname,
            'fqdn': fqdn,
            'status': 'ANALYZED' if vulnerabilities else 'IDENTIFIED',
            'confidence': 85 if vulnerabilities else 60,
            'services': services,
            'vulnerabilities': vulnerabilities,
            'security_findings': security_findings,
            'metadata': metadata
        }
        
        if os_hints:
            asset_data['os_type'] = os_hints['os_type']
            asset_data['confidence'] = max(asset_data['confidence'], os_hints['confidence'])
        
        print(f"Updating asset {primary_identifier} with HTTP scan data for tenant {self.tenant_id}")
        print(f"[DEBUG] Scan completed with {len(vulnerabilities)} vulnerabilities")
        if 'source_findings' in results:
            print(f"[DEBUG] Source code analysis found {len(results['source_findings'])} findings")
        if 'risk_assessment' in results:
            risk_level = results['risk_assessment'].get('risk_level', 'Unknown')
            risk_score = results['risk_assessment'].get('risk_score', 0)
            print(f"[DEBUG] Risk assessment: {risk_level} (Score: {risk_score})")
        
        asset_id = asset_manager.add_or_update_asset(**asset_data)
        if asset_id:
            print(f"Asset {primary_identifier} updated successfully")
            if 'source_findings' in results:
                print(f"Asset includes {len(results['source_findings'])} source code findings")
            self.asset_updated.emit(self.tenant_id, asset_id)
        else:
            print(f"Failed to update asset {primary_identifier}")
    
    def process_vulnerability_results(self, results):
        """Process vulnerability scan results and update assets"""
        if not isinstance(results, dict):
            return
        
        for ip, data in results.items():
            if isinstance(data, dict) and 'vulnerabilities' in data:
                vulnerabilities = []
                
                for vuln in data['vulnerabilities']:
                    if isinstance(vuln, dict):
                        vulnerabilities.append({
                            'id': vuln.get('id', vuln.get('cve', 'Unknown')),
                            'name': vuln.get('name', vuln.get('title', 'Unknown Vulnerability')),
                            'severity': vuln.get('severity', 'unknown').lower(),
                            'description': vuln.get('description', ''),
                            'cvss': vuln.get('cvss', 0)
                        })
                
                if vulnerabilities:
                    asset_id = asset_manager.add_or_update_asset(
                        tenant_id=self.tenant_id,
                        ip_address=ip,
                        status='KNOWN',
                        confidence=95,
                        vulnerabilities=vulnerabilities,
                        metadata={'discovery_method': 'vulnerability_scan'}
                    )
                    if asset_id:
                        self.asset_updated.emit(self.tenant_id, asset_id)
    
    def _analyze_os_from_ports(self, open_ports):
        """Analyze OS type from open ports"""
        if not open_ports:
            return None
        
        port_numbers = [p.get('port') for p in open_ports if p.get('port')]
        
        # Windows indicators
        windows_ports = [135, 139, 445, 3389, 5985, 5986]
        windows_score = sum(1 for port in port_numbers if port in windows_ports)
        
        # Linux indicators
        linux_ports = [22, 25, 53, 80, 443, 993, 995]
        linux_score = sum(1 for port in port_numbers if port in linux_ports)
        
        # Router/Network device indicators
        router_ports = [23, 80, 161, 443, 8080]
        router_score = sum(1 for port in port_numbers if port in router_ports)
        
        if windows_score >= 2:
            return {'os_type': 'Windows', 'confidence': min(80, 40 + windows_score * 10)}
        elif linux_score >= 2 and 22 in port_numbers:
            return {'os_type': 'Linux', 'confidence': min(75, 35 + linux_score * 8)}
        elif router_score >= 2 and (23 in port_numbers or 161 in port_numbers):
            return {'os_type': 'Router', 'confidence': min(70, 30 + router_score * 10)}
        
        return None
    
    def _analyze_os_from_http(self, results):
        """Analyze OS type from HTTP server headers"""
        server = results.get('server', '').lower()
        
        if 'iis' in server or 'microsoft' in server:
            return {'os_type': 'Windows', 'confidence': 70}
        elif 'apache' in server and 'ubuntu' in server:
            return {'os_type': 'Linux', 'confidence': 65}
        elif 'nginx' in server:
            return {'os_type': 'Linux', 'confidence': 60}
        elif 'lighttpd' in server:
            return {'os_type': 'Linux', 'confidence': 55}
        
        return None
    
    def _is_valid_ip(self, ip_str):
        """Check if string is a valid IP address"""
        try:
            parts = ip_str.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _extract_ip_from_url(self, url):
        """Extract IP address from URL"""
        # Remove protocol
        url = url.replace('http://', '').replace('https://', '')
        
        # Remove path
        url = url.split('/')[0]
        
        # Remove port
        url = url.split(':')[0]
        
        # Check if it's already an IP
        if self._is_valid_ip(url):
            return url
        
        # Try to resolve hostname to IP
        return self._resolve_hostname_to_ip(url)
    
    def _extract_hostname_from_url(self, url):
        """Extract hostname from URL"""
        # Remove protocol
        url = url.replace('http://', '').replace('https://', '')
        
        # Remove path
        url = url.split('/')[0]
        
        # Remove port
        url = url.split(':')[0]
        
        # Return hostname (could be IP or domain name)
        return url
    
    def _resolve_hostname_to_ip(self, hostname):
        """Resolve hostname to IP address"""
        try:
            import socket
            return socket.gethostbyname(hostname)
        except:
            return None

# Global instance
scan_asset_integrator = ScanAssetIntegrator()