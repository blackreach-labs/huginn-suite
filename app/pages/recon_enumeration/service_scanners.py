# app/pages/recon_enumeration/service_scanners.py

class ServiceScannersMixin:
    """Mixin for service enumeration scanners"""
    
    def run_service_scan(self, tool_key):
        """Route service scan to appropriate method based on tool key"""
        target_input = getattr(self, f"{tool_key}_target_input", None)
        if not target_input:
            return
        
        target = target_input.text().strip()
        if not target:
            self.status_updated.emit(f"Please enter a target for {tool_key} enumeration")
            return
        
        # Set scanning state and button
        setattr(self, f"{tool_key}_scanning", True)
        run_button = getattr(self, f"{tool_key}_run_button", None)
        if run_button:
            if hasattr(run_button, 'start_scan'):
                run_button.start_scan()
            else:
                run_button.setText("Stop")
        
        # Show progress widget
        progress_widget = getattr(self, f"{tool_key}_progress_widget", None)
        if progress_widget:
            progress_widget.setVisible(True)
            progress_widget.reset_progress()
        
        # Route to appropriate service method
        if tool_key == 'http_enum':
            self.run_http_enumeration(target, tool_key)
        elif tool_key == 'rpc_enum':
            # Get RPC-specific parameters
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            scan_type = "Basic Info"
            auth_type = "Anonymous"
            username = ""
            password = ""
            ntlm_hash = ""
            domain = ""
            ticket_path = ""
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                scan_type = controls['rpc_scan_type'].currentText() if 'rpc_scan_type' in controls else "Basic Info"
                auth_type = controls['rpc_auth_combo'].currentText() if 'rpc_auth_combo' in controls else "Anonymous"
                username = controls['rpc_username'].text() if 'rpc_username' in controls else ""
                password = controls['rpc_password'].text() if 'rpc_password' in controls else ""
                ntlm_hash = controls['rpc_ntlm_hash'].text() if 'rpc_ntlm_hash' in controls else ""
                domain = controls['rpc_domain'].text() if 'rpc_domain' in controls else ""
                ticket_path = controls['rpc_ticket_path'].text() if 'rpc_ticket_path' in controls else ""
            
            self.run_rpc_enumeration(target, tool_key, scan_type, auth_type, username, password, ntlm_hash, domain, ticket_path)
        elif tool_key == 'smb_enum':
            # Get SMB-specific parameters
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            scan_type = "Basic Info"
            auth_type = "Anonymous"
            domain = ""
            username = ""
            password = ""
            wordlist_path = None
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                scan_type = controls['smb_scan_type'].currentText() if 'smb_scan_type' in controls else "Basic Info"
                auth_type = controls['smb_auth_combo'].currentText() if 'smb_auth_combo' in controls else "Anonymous"
                domain = controls['smb_domain'].text() if 'smb_domain' in controls else ""
                username = controls['smb_username'].text() if 'smb_username' in controls else ""
                password = controls['smb_password'].text() if 'smb_password' in controls else ""
                wordlist_path = controls['smb_wordlist'].currentData() if 'smb_wordlist' in controls else None
            
            # Set current scan type and switch to appropriate terminal
            setattr(self, f"{tool_key}_current_scan_type", scan_type)
            
            # Switch to the correct terminal view for this scan type
            if hasattr(self, 'switch_smb_scan_view'):
                self.switch_smb_scan_view(tool_key, scan_type)
            
            self.run_smb_enumeration(target, tool_key, scan_type, auth_type, domain, username, password, wordlist_path)
        elif tool_key == 'smtp_enum':
            self.run_smtp_enumeration(target, tool_key)
        elif tool_key == 'snmp_enum':
            self.run_snmp_enumeration(target, tool_key)
        elif tool_key == 'ldap_enum':
            self.run_ldap_enumeration(target, tool_key)
        elif tool_key == 'api_enum':
            self.run_api_enumeration(target, tool_key)
        elif tool_key == 'db_enum':
            self.run_db_enumeration(target, tool_key)
        elif tool_key == 'ike_enum':
            self.run_ike_enumeration(target, tool_key)
        elif tool_key == 'av_detect':
            self.run_av_detection(target, tool_key)
        elif tool_key == 'ssh_enum':
            self.run_ssh_enumeration(target, tool_key)
        else:
            # Fallback for unknown service types
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] Unknown service type: {tool_key}</p><br>")
            self.on_service_scan_finished(tool_key)
    
    def run_http_enumeration(self, target, tool_key):
        """Run HTTP enumeration using actual working implementation"""
        try:
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            scan_type = "Fingerprinting"
            preset = "Manual"
            wordlist_path = None
            extensions = []
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                scan_type = controls['http_scan_type'].currentText() if 'http_scan_type' in controls else "Fingerprinting"
                preset = controls['http_preset'].currentText() if 'http_preset' in controls else "Manual"
                wordlist_path = controls['http_wordlist'].currentData() if 'http_wordlist' in controls else None
                
                # Get extensions for directory enumeration
                if scan_type in ("Directory Enum", "Full Scan"):
                    # Read from checkable combobox controls
                    from app.core.control_panel_factory import CheckableComboBox
                    for control_name in ('ext_web', 'ext_frontend', 'ext_config', 'ext_backup'):
                        if control_name in controls and isinstance(controls[control_name], CheckableComboBox):
                            extensions.extend(controls[control_name].getCheckedItems())
            
            # Set current scan type and switch to appropriate terminal
            setattr(self, f"{tool_key}_current_scan_type", scan_type)
            
            # Switch to the correct terminal view for this scan type
            if hasattr(self, 'switch_http_scan_view'):
                self.switch_http_scan_view(tool_key, scan_type)
            
            # Clear the terminal for this scan type
            terminals = getattr(self, f"{tool_key}_terminals", {})
            if scan_type in terminals and terminals[scan_type] is not None:
                terminal = terminals[scan_type]
                terminal.clear()
            
            self.append_http_output(tool_key, scan_type, f"<p style='color: #00BFFF;'>[HTTP SCAN] Starting {scan_type} on {target}</p><br>")
            
            # Use actual HTTP scanner
            from app.tools.http_scanner import HTTPEnumWorker
            from PyQt6.QtCore import QThreadPool
            
            # Get current tenant from main window
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            
            # Check for listener configuration
            listener_id = None
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                if 'enable_listener' in controls and controls['enable_listener'].isChecked():
                    if 'listener_combo' in controls:
                        listener_data = controls['listener_combo'].currentData()
                        if listener_data:
                            listener_id = listener_data
                            self.append_http_output(tool_key, scan_type, f"<p style='color: #00FF41;'>[DEBUG] Using listener: {listener_id}</p><br>")
                        else:
                            self.append_http_output(tool_key, scan_type, f"<p style='color: #FFAA00;'>[DEBUG] Listener enabled but no data found</p><br>")
                    else:
                        self.append_http_output(tool_key, scan_type, f"<p style='color: #FFAA00;'>[DEBUG] Listener enabled but combo not found</p><br>")
                else:
                    pass  # Listener not enabled - no debug message
            
            worker = HTTPEnumWorker(
                target=target,
                scan_type=scan_type,
                wordlist_path=wordlist_path,
                extensions=extensions,
                preset=preset,
                auth_method=None,
                username="",
                password="",
                auth_headers={},
                auth_cookies={},
                tenant_id=tenant_id,
                listener_id=listener_id
            )
            
            # Connect signals
            worker.signals.output.connect(lambda text: self.append_http_output(tool_key, scan_type, text))
            worker.signals.finished.connect(lambda: self.on_http_scan_finished(tool_key, scan_type))
            worker.signals.results.connect(lambda results: self.store_http_results(tool_key, scan_type, results))
            worker.signals.results_ready.connect(lambda results: self.handle_http_realtime_results(tool_key, scan_type, results))
            # Connect progress signals for Directory Enum, Enterprise Scripts, and Full Scan
            if scan_type in ["Directory Enum", "VHost Brute", "Enterprise Scripts", "Full Scan"]:
                worker.signals.progress_start.connect(lambda total, msg: self.start_http_progress(tool_key, total, msg))
                worker.signals.progress_update.connect(lambda current, found, msg: self.update_http_progress(tool_key, current, found, msg))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except Exception as e:
            # Set current scan type for error handling
            setattr(self, f"{tool_key}_current_scan_type", scan_type)
            self.append_http_output(tool_key, scan_type, f"<p style='color: #FF6B6B;'>[ERROR] Failed to start HTTP scan: {e}</p><br>")
            self.on_http_scan_finished(tool_key, scan_type)
    
    def simulate_http_results(self, scan_type, target):
        """Simulate HTTP scan results based on scan type (fallback only)"""
        if scan_type == "Fingerprinting":
            return {
                'server': 'Apache/2.4.41',
                'status_code': 200,
                'known_files': [
                    {'path': '/robots.txt', 'status': 200},
                    {'path': '/sitemap.xml', 'status': 200}
                ],
                'crawl_data': {
                    target: {
                        'title': 'Sample Website',
                        'server': 'Apache/2.4.41',
                        'status': 200
                    }
                }
            }
        elif scan_type == "Directory Enum":
            return {
                'directories': [
                    {'path': 'admin', 'status': 403},
                    {'path': 'images', 'status': 200},
                    {'path': 'css', 'status': 200}
                ]
            }
        elif scan_type == "Source Code":
            return {
                'detailed_findings': {
                    'HTML comments found': ['<!-- TODO: Remove debug info -->', '<!-- Version 2.1 -->'],
                    'Email Addresses': ['admin@example.com', 'support@example.com']
                },
                'raw_html': '<html><!-- Sample HTML --><body><p>Contact: admin@example.com</p></body></html>'
            }
        else:
            return {'status': f'{scan_type} completed', 'target': target}
    
    def run_rpc_enumeration(self, target, tool_key, scan_type, auth_type, username, password, ntlm_hash, domain, ticket_path):
        """Run RPC enumeration using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.rpc_scanner import RPCWorker
            
            # Get current tenant from main window
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            
            # Create RPC worker with same parameters as enumeration page
            worker = RPCWorker(
                target=target,
                scan_type=scan_type,
                auth_type=auth_type,
                username=username,
                password=password,
                ntlm_hash=ntlm_hash,
                service_name="",  # Add service_name parameter
                tenant_id=tenant_id
            )
            
            # Connect signals like other service scanners
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_rpc_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_rpc_results(tool_key, results))
            
            # Connect progress signals for real-time progress bar updates
            worker.signals.progress_start.connect(lambda total, msg: self.start_rpc_progress(tool_key, total, msg))
            worker.signals.progress_update.connect(lambda current, found, msg: self.update_rpc_progress(tool_key, current, found, msg))
            
            # Connect table and graph data signals if available
            if hasattr(worker.signals, 'table_data'):
                worker.signals.table_data.connect(lambda data: self.update_rpc_table_view(tool_key, data))
            if hasattr(worker.signals, 'graph_data'):
                worker.signals.graph_data.connect(lambda data: self.update_rpc_tree_view(tool_key, data))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except Exception as e:
            self.append_service_output(tool_key, f"<p style='color: #FF6B6B;'>[ERROR] Failed to start RPC scan: {e}</p><br>")
            self.on_rpc_scan_finished(tool_key)
    
    def run_smb_enumeration(self, target, tool_key, scan_type, auth_type, domain, username, password, wordlist_path=None):
        """Run SMB enumeration using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.smb_scanner import SMBWorker
            
            # Get current tenant from main window
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            
            # Create SMB worker with exact same parameters as enumeration page
            worker = SMBWorker(
                target=target,
                scan_type=scan_type,
                auth_type=auth_type,
                domain=domain,
                username=username,
                password=password,
                wordlist_path=wordlist_path,
                tenant_id=tenant_id
            )
            
            # Connect signals exactly like enumeration page
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_smb_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_smb_results(tool_key, results))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] SMB scanner not available, using simulation</p><br>")
            results = {
                'shares': [{'name': 'IPC$', 'type': 'IPC'}, {'name': 'ADMIN$', 'type': 'DISK'}],
                'auth_type': auth_type,
                'target': target
            }
            self.store_smb_results(tool_key, results)
            self.on_smb_scan_finished(tool_key)
    
    def run_smtp_enumeration(self, target, tool_key):
        """Run SMTP enumeration using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.smtp_scanner import SMTPWorker
            
            self.append_service_output(tool_key, f"<p style='color: #00BFFF;'>[SMTP SCAN] Starting enumeration for {target}</p><br>")
            
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            port = "25"
            domain = ""
            helo_name = "test.local"
            wordlist_path = None
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                port = controls['smtp_port'].text() if 'smtp_port' in controls else "25"
                domain = controls['smtp_domain'].text() if 'smtp_domain' in controls else ""
                helo_name = controls['smtp_helo'].text() if 'smtp_helo' in controls else "test.local"
                wordlist_path = controls['smtp_wordlist'].currentData() if 'smtp_wordlist' in controls else None
            
            # Create SMTP worker with same parameters as enumeration page
            worker = SMTPWorker(
                target=target,
                port=int(port),
                domain=domain,
                helo_name=helo_name,
                wordlist_path=wordlist_path
            )
            
            # Connect signals like enumeration page
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_service_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_service_results(tool_key, results))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] SMTP scanner not available, using simulation</p><br>")
            results = {
                'smtp_port': port,
                'domain': domain,
                'helo_name': helo_name,
                'status': 'SMTP enumeration completed (simulated)'
            }
            self.store_service_results(tool_key, results)
            self.on_service_scan_finished(tool_key)
    
    def run_snmp_enumeration(self, target, tool_key):
        """Run SNMP enumeration using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.snmp_scanner import SNMPWorker
            
            self.append_service_output(tool_key, f"<p style='color: #00BFFF;'>[SNMP SCAN] Starting enumeration for {target}</p><br>")
            
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            version = "2c"
            scan_type = "Basic Info"
            communities = "public,private,community"
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                version = controls['snmp_version'].currentText() if 'snmp_version' in controls else "2c"
                scan_type = controls['snmp_scan_type'].currentText() if 'snmp_scan_type' in controls else "Basic Info"
                communities = controls['snmp_communities'].text() if 'snmp_communities' in controls else "public,private,community"
            
            # Get current tenant from main window
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            
            # Create SNMP worker with same parameters as enumeration page
            worker = SNMPWorker(
                target=target,
                version=version,
                scan_type=scan_type,
                communities=communities.split(','),
                tenant_id=tenant_id
            )
            
            # Connect signals like enumeration page
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_service_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_service_results(tool_key, results))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] SNMP scanner not available, using simulation</p><br>")
            results = {
                'version': version,
                'scan_type': scan_type,
                'communities': communities.split(','),
                'status': 'SNMP enumeration completed (simulated)'
            }
            self.store_service_results(tool_key, results)
            self.on_service_scan_finished(tool_key)
    
    def run_ldap_enumeration(self, target, tool_key):
        """Run LDAP enumeration using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.ldap_scanner import LDAPWorker
            
            self.append_service_output(tool_key, f"<p style='color: #00BFFF;'>[LDAP SCAN] Starting enumeration for {target}</p><br>")
            
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            port = "389"
            scan_type = "Basic Info"
            base_dn = ""
            use_ssl = False
            auth_type = "Anonymous"
            username = ""
            password = ""
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                port = controls['ldap_port'].text() if 'ldap_port' in controls else "389"
                scan_type = controls['ldap_scan_type'].currentText() if 'ldap_scan_type' in controls else "Basic Info"
                base_dn = controls['ldap_base_dn'].text() if 'ldap_base_dn' in controls else ""
                use_ssl = controls['ldap_ssl_checkbox'].isChecked() if 'ldap_ssl_checkbox' in controls else False
                auth_type = controls['ldap_auth_type'].currentText() if 'ldap_auth_type' in controls else "Anonymous"
                username = controls['ldap_username'].text() if 'ldap_username' in controls else ""
                password = controls['ldap_password'].text() if 'ldap_password' in controls else ""
            
            # Get current tenant from main window
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            
            # Create LDAP worker with same parameters as enumeration page
            worker = LDAPWorker(
                target=target,
                port=int(port),
                use_ssl=use_ssl,
                scan_type=scan_type,
                auth_type=auth_type,
                username=username,
                password=password,
                base_dn=base_dn,
                tenant_id=tenant_id
            )
            
            # Connect signals like enumeration page
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_service_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_service_results(tool_key, results))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] LDAP scanner not available, using simulation</p><br>")
            results = {
                'port': port,
                'scan_type': scan_type,
                'base_dn': base_dn,
                'ssl_enabled': use_ssl,
                'status': 'LDAP enumeration completed (simulated)'
            }
            self.store_service_results(tool_key, results)
            self.on_service_scan_finished(tool_key)
    
    def run_api_enumeration(self, target, tool_key):
        """Run API enumeration using HTTP scanner with API-focused settings"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.http_scanner import HTTPEnumWorker
            import os
            
            self.append_service_output(tool_key, f"<p style='color: #00BFFF;'>[API SCAN] Starting enumeration for {target}</p><br>")
            
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            scan_type = "Basic Discovery"
            preset = "API-focused"
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                scan_type = controls['api_scan_type'].currentText() if 'api_scan_type' in controls else "Basic Discovery"
                preset = controls['api_preset'].currentText() if 'api_preset' in controls else "API-focused"
            
            # Use API wordlist if available
            api_wordlist = os.path.join(getattr(self.main_window, 'project_root', ''), "resources", "wordlists", "http_enum", "api.txt")
            
            # Create HTTP worker with API-focused settings
            worker = HTTPEnumWorker(
                target=target,
                scan_type="Fingerprinting",
                wordlist_path=api_wordlist if os.path.exists(api_wordlist) else None,
                extensions=['.json', '.xml', '.php', '.asp', '.aspx'],
                preset=preset,
                auth_method=None,
                username="",
                password="",
                auth_headers={},
                auth_cookies={}
            )
            
            # Connect signals like enumeration page
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_service_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_service_results(tool_key, results))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] HTTP scanner not available, using simulation</p><br>")
            results = {
                'scan_type': scan_type,
                'preset': preset,
                'endpoints_found': ['/api/v1', '/rest', '/graphql'],
                'status': 'API enumeration completed (simulated)'
            }
            self.store_service_results(tool_key, results)
            self.on_service_scan_finished(tool_key)
    
    def run_db_enumeration(self, target, tool_key):
        """Run database enumeration using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.db_utils import DatabaseEnumWorker
            
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            db_type = "mssql"
            port = "1433"
            scan_type = "Basic Info"
            username = ""
            password = ""
            custom_query = ""
            oracle_sid = "DB11g"
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                db_type = controls['db_type_combo'].currentText().lower() if 'db_type_combo' in controls else "mssql"
                port = controls['db_port'].text() if 'db_port' in controls else ("1433" if db_type == "mssql" else "1521")
                scan_type = controls['db_scan_type'].currentText() if 'db_scan_type' in controls else "Basic Info"
                auth_type = controls['db_auth_combo'].currentText() if 'db_auth_combo' in controls else "None"
                username = controls['db_username'].text() if 'db_username' in controls and auth_type != "None" else ""
                password = controls['db_password'].text() if 'db_password' in controls and auth_type != "None" else ""
                custom_query = controls['db_custom_query'].text() if 'db_custom_query' in controls else ""
                oracle_sid = controls['oracle_sid'].text() if 'oracle_sid' in controls else "DB11g"
            
            # Set current scan type and switch to appropriate terminal
            setattr(self, f"{tool_key}_current_scan_type", scan_type)
            
            # Switch to the correct terminal view for this scan type
            if hasattr(self, 'switch_db_scan_view'):
                self.switch_db_scan_view(tool_key, scan_type)
            
            self.append_service_output(tool_key, f"<p style='color: #00BFFF;'>[DB SCAN] Starting {scan_type} on {target}:{port} ({db_type.upper()})</p><br>")
            
            # Create database worker with same parameters as enumeration page
            worker = DatabaseEnumWorker(
                target=target,
                db_type=db_type,
                scan_type=scan_type,
                port=int(port),
                username=username if username else None,
                password=password if password else None,
                custom_query=custom_query if custom_query else None,
                oracle_sid=oracle_sid,
                output_callback=lambda text: self.safe_append_db_output(tool_key, text),
                results_callback=lambda results: self.store_service_results(tool_key, results)
            )
            
            # Connect signals safely
            try:
                worker.signals.finished.connect(lambda: self.on_service_scan_finished(tool_key))
                worker.signals.error.connect(lambda error: self.append_service_output(tool_key, f"<p style='color: #FF6B6B;'>[ERROR] {error}</p><br>"))
                if hasattr(worker.signals, 'results'):
                    worker.signals.results.connect(lambda results: self.store_service_results(tool_key, results))
            except Exception as e:
                print(f"Signal connection error: {e}")
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] Database scanner not available, using simulation</p><br>")
            results = {
                'db_type': db_type,
                'port': port,
                'scan_type': scan_type,
                'status': 'Database enumeration completed (simulated)'
            }
            self.store_service_results(tool_key, results)
            self.on_service_scan_finished(tool_key)
        except Exception as e:
            self.append_service_output(tool_key, f"<p style='color: #FF6B6B;'>[ERROR] Failed to start database scan: {e}</p><br>")
            self.on_service_scan_finished(tool_key)
    
    def run_ike_enumeration(self, target, tool_key):
        """Run IKE enumeration using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.ike_worker import IKEWorker
            
            self.append_service_output(tool_key, f"<p style='color: #00BFFF;'>[IKE SCAN] Starting enumeration for {target}</p><br>")
            
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            port = "500"
            scan_type = "Basic Info"
            aggressive_mode = True
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                port = controls['ike_port'].text() if 'ike_port' in controls else "500"
                scan_type = controls['ike_scan_type'].currentText() if 'ike_scan_type' in controls else "Basic Info"
                aggressive_mode = controls['ike_aggressive_mode'].isChecked() if 'ike_aggressive_mode' in controls else True
            
            # Create IKE worker with same parameters as enumeration page
            worker = IKEWorker(
                target=target,
                port=int(port),
                scan_type=scan_type,
                aggressive_mode=aggressive_mode
            )
            
            # Connect signals like enumeration page
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_service_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_service_results(tool_key, results))
            worker.signals.error.connect(lambda error: self.append_service_output(tool_key, f"<p style='color: #FF6B6B;'>[ERROR] {error}</p><br>"))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] IKE scanner not available, using simulation</p><br>")
            results = {
                'port': port,
                'scan_type': scan_type,
                'aggressive_mode': aggressive_mode,
                'status': 'IKE enumeration completed (simulated)'
            }
            self.store_service_results(tool_key, results)
            self.on_service_scan_finished(tool_key)
        except Exception as e:
            self.append_service_output(tool_key, f"<p style='color: #FF6B6B;'>[ERROR] Failed to start IKE scan: {e}</p><br>")
            self.on_service_scan_finished(tool_key)
    
    def run_av_detection(self, target, tool_key):
        """Run AV/Firewall detection using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.av_worker import AVFirewallWorker
            
            self.append_service_output(tool_key, f"<p style='color: #00BFFF;'>[AV DETECTION] Starting detection for {target}</p><br>")
            
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            detection_type = "WAF Detection"
            port = "80"
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                detection_type = controls['av_detection_type'].currentText() if 'av_detection_type' in controls else "WAF Detection"
                port = controls['av_port'].text() if 'av_port' in controls else "80"
            
            # Create AV/Firewall worker
            worker = AVFirewallWorker(
                target=target,
                detection_type=detection_type,
                port=int(port)
            )
            
            # Connect signals like enumeration page
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_service_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_service_results(tool_key, results))
            worker.signals.error.connect(lambda error: self.append_service_output(tool_key, f"<p style='color: #FF6B6B;'>[ERROR] {error}</p><br>"))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] AV scanner not available, using simulation</p><br>")
            results = {
                'detection_type': detection_type,
                'target': target,
                'port': port,
                'status': 'Detection completed (simulated)'
            }
            self.store_service_results(tool_key, results)
            self.on_service_scan_finished(tool_key)
        except Exception as e:
            self.append_service_output(tool_key, f"<p style='color: #FF6B6B;'>[ERROR] Failed to start AV detection: {e}</p><br>")
            self.on_service_scan_finished(tool_key)
    
    def run_ssh_enumeration(self, target, tool_key):
        """Run SSH enumeration using actual working implementation"""
        try:
            from PyQt6.QtCore import QThreadPool
            from app.tools.ssh_scanner import SSHWorker
            
            self.append_service_output(tool_key, f"<p style='color: #00BFFF;'>[SSH SCAN] Starting enumeration for {target}</p><br>")
            
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            port = "22"
            scan_type = "Enumeration"
            auth_type = "Anonymous"
            username = ""
            password = ""
            key_path = ""
            wordlist_path = None
            
            if control_panel and hasattr(control_panel, 'controls'):
                controls = control_panel.controls
                port = controls['ssh_port'].text() if 'ssh_port' in controls else "22"
                scan_type = controls['ssh_scan_type'].currentText() if 'ssh_scan_type' in controls else "Enumeration"
                auth_type = controls['ssh_auth_type'].currentText() if 'ssh_auth_type' in controls else "Anonymous"
                username = controls['ssh_username'].text() if 'ssh_username' in controls else ""
                password = controls['ssh_password'].text() if 'ssh_password' in controls else ""
                key_path = controls['ssh_key_path'].text() if 'ssh_key_path' in controls else ""
                wordlist_path = controls['ssh_wordlist'].currentData() if 'ssh_wordlist' in controls else None
            
            # Get current tenant from main window
            tenant_id = getattr(self.main_window, 'current_profile_name', 'default')
            
            # Set current scan type and switch to appropriate terminal
            setattr(self, f"{tool_key}_current_scan_type", scan_type)
            
            # Switch to the correct terminal view for this scan type
            if hasattr(self, 'on_ssh_scan_type_changed'):
                self.on_ssh_scan_type_changed(tool_key, scan_type)
            
            # Create SSH worker
            worker = SSHWorker(
                target=target,
                port=int(port),
                scan_type=scan_type,
                auth_type=auth_type,
                username=username,
                password=password,
                key_path=key_path,
                wordlist_path=wordlist_path,
                tenant_id=tenant_id
            )
            
            # Connect signals
            worker.signals.output.connect(lambda text: self.append_service_output(tool_key, text))
            worker.signals.finished.connect(lambda: self.on_service_scan_finished(tool_key))
            worker.signals.results.connect(lambda results: self.store_service_results(tool_key, results))
            
            # Connect table and graph data signals if available
            if hasattr(worker.signals, 'table_data'):
                worker.signals.table_data.connect(lambda data: self.update_ssh_table_view(tool_key, data))
            if hasattr(worker.signals, 'graph_data'):
                worker.signals.graph_data.connect(lambda data: self.update_ssh_tree_view(tool_key, data))
            
            # Store worker reference
            setattr(self, f"{tool_key}_worker", worker)
            
            # Start worker
            QThreadPool.globalInstance().start(worker)
            
        except ImportError:
            # Fallback to simulation if scanner not available
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[WARNING] SSH scanner not available, using simulation</p><br>")
            results = {
                'port': "22",
                'scan_type': "Enumeration",
                'auth_type': "Anonymous",
                'status': 'SSH enumeration completed (simulated)'
            }
            self.store_service_results(tool_key, results)
            self.on_service_scan_finished(tool_key)
        except Exception as e:
            self.append_service_output(tool_key, f"<p style='color: #FF6B6B;'>[ERROR] Failed to start SSH scan: {e}</p><br>")
            self.on_service_scan_finished(tool_key)
    
    # Helper methods for service enumeration completion
    def on_rpc_scan_finished(self, tool_key):
        """Handle RPC scan completion"""
        # Update views with final results
        results = getattr(self, f"{tool_key}_results", {})
        if results:
            self.update_rpc_table_view(tool_key, results.get('table_data', {}))
            self.update_rpc_tree_view(tool_key, results.get('graph_data', {}))
        
        self.on_service_scan_finished(tool_key)
    
    def on_smb_scan_finished(self, tool_key):
        """Handle SMB scan completion"""
        self.on_service_scan_finished(tool_key)
    
    def on_http_scan_finished(self, tool_key, scan_type):
        """Handle HTTP scan completion"""
        # Reset scanning state
        setattr(self, f"{tool_key}_scanning", False)
        
        # Reset run button state
        run_button = getattr(self, f"{tool_key}_run_button", None)
        if run_button:
            if hasattr(run_button, 'stop_scan'):
                run_button.stop_scan()
            else:
                run_button.setText("Run")
            run_button.setEnabled(True)
        
        # Keep progress bar visible for completion
        progress_widget = getattr(self, f"{tool_key}_progress_widget", None)
        if progress_widget and hasattr(progress_widget, 'finish_progress'):
            progress_widget.finish_progress()
        
        # Enable export button if results exist
        export_button = getattr(self, f"{tool_key}_export_button", None)
        if export_button:
            results = getattr(self, f"{tool_key}_results", None)
            if results:
                export_button.setEnabled(True)
    
    def on_service_scan_finished(self, tool_key):
        """Generic service scan completion handler"""
        # Reset scanning state
        setattr(self, f"{tool_key}_scanning", False)
        
        # Reset run button state
        run_button = getattr(self, f"{tool_key}_run_button", None)
        if run_button:
            if hasattr(run_button, 'stop_scan'):
                run_button.stop_scan()
            else:
                run_button.setText("Run")
            run_button.setEnabled(True)
        
        # Hide progress widget
        progress_widget = getattr(self, f"{tool_key}_progress_widget", None)
        if progress_widget:
            progress_widget.setVisible(False)
            if hasattr(progress_widget, 'finish_progress'):
                progress_widget.finish_progress()
        
        # Enable export button if results exist
        export_button = getattr(self, f"{tool_key}_export_button", None)
        if export_button:
            results = getattr(self, f"{tool_key}_results", None)
            if results:
                export_button.setEnabled(True)
    
    def store_rpc_results(self, tool_key, results):
        """Store RPC scan results"""
        setattr(self, f"{tool_key}_results", results)
        
        # Update table and tree views with results data
        if results:
            self.update_rpc_table_view(tool_key, results.get('table_data', {}))
            self.update_rpc_tree_view(tool_key, results.get('graph_data', {}))
    
    def store_smb_results(self, tool_key, results):
        """Store SMB scan results"""
        setattr(self, f"{tool_key}_results", results)
    
    def store_http_results(self, tool_key, scan_type, results):
        """Store HTTP scan results and update views"""
        if not hasattr(self, f"{tool_key}_results"):
            setattr(self, f"{tool_key}_results", {})
        results_dict = getattr(self, f"{tool_key}_results")
        results_dict[scan_type] = results
        
        # Update graph/table views with results data
        if 'crawl_data' in results:
            self.update_http_graph_view(tool_key, scan_type, results['crawl_data'])
        if scan_type == "Directory Enum":
            if 'directories' in results:
                self.update_http_tree_view(tool_key, scan_type, results['directories'])
        elif scan_type == "Source Code":
            # Source Code uses crawl_data for graph view
            if 'crawl_data' in results:
                self.update_http_graph_view(tool_key, scan_type, results['crawl_data'])
        elif scan_type == "Full Scan":
            # Full Scan uses table data for table view
            if hasattr(results, 'full_scan_table_data') or 'full_scan_table_data' in results:
                table_data = getattr(results, 'full_scan_table_data', results.get('full_scan_table_data', []))
                self.update_http_full_scan_table(tool_key, scan_type, table_data)
            elif 'crawl_data' in results:
                self.update_http_graph_view(tool_key, scan_type, results['crawl_data'])
        elif scan_type == "Enterprise Scripts":
            # Always update Enterprise Scripts view with available data
            crawl_data = results.get('crawl_data', {})
            if crawl_data:
                self.update_http_graph_view(tool_key, scan_type, crawl_data)
            elif 'enterprise_results' in results:
                # Build crawl_data from enterprise_results if not present
                enterprise_data = results['enterprise_results']
                if enterprise_data:
                    from app.tools.http_scanner import HTTPEnumWorker
                    worker = HTTPEnumWorker(target="", scan_type="Enterprise Scripts")
                    worker._build_enterprise_tree(enterprise_data)
                    if hasattr(worker, 'crawl_tree_data'):
                        results['crawl_data'] = worker.crawl_tree_data
                        self.update_http_graph_view(tool_key, scan_type, worker.crawl_tree_data)
            # Always force an update to ensure UI refreshes
            self.update_http_graph_view(tool_key, scan_type, results.get('crawl_data', {}))
    
    def store_service_results(self, tool_key, results):
        """Store generic service results"""
        setattr(self, f"{tool_key}_results", results)
        
        # Update table and tree views for database enumeration
        if tool_key == 'db_enum':
            self.update_db_table_view(tool_key, results)
    
    def update_rpc_table_view(self, tool_key, table_data):
        """Update RPC table view with scan data"""
        if not table_data:
            return
        
        try:
            from PyQt6.QtWidgets import QTableWidgetItem
            
            # Get the table for current scan type
            tables = getattr(self, f"{tool_key}_tables", {})
            current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Basic Info")
            table = tables.get(current_scan_type)
            
            if not table:
                return
            
            # Clear existing data
            table.setRowCount(0)
            
            # Populate with services data (most common)
            if 'services' in table_data:
                services = table_data['services']
                table.setColumnCount(3)
                table.setHorizontalHeaderLabels(["Service Name", "Display Name", "State"])
                
                for i, service in enumerate(services):
                    table.insertRow(i)
                    table.setItem(i, 0, QTableWidgetItem(service.get('Service Name', '')))
                    table.setItem(i, 1, QTableWidgetItem(service.get('Display Name', '')))
                    table.setItem(i, 2, QTableWidgetItem(service.get('State', '')))
            
            # Add RPC endpoints if available
            elif 'rpc_endpoints' in table_data:
                endpoints = table_data['rpc_endpoints']
                table.setColumnCount(4)
                table.setHorizontalHeaderLabels(["Protocol", "UUID", "Port", "Description"])
                
                for i, endpoint in enumerate(endpoints):
                    table.insertRow(i)
                    table.setItem(i, 0, QTableWidgetItem(endpoint.get('Protocol', '')))
                    table.setItem(i, 1, QTableWidgetItem(endpoint.get('UUID', '')))
                    table.setItem(i, 2, QTableWidgetItem(str(endpoint.get('Port', ''))))
                    table.setItem(i, 3, QTableWidgetItem(endpoint.get('Description', '')))
            
            # Add network endpoints if available
            elif 'endpoints' in table_data:
                endpoints = table_data['endpoints']
                table.setColumnCount(4)
                table.setHorizontalHeaderLabels(["Port", "Service", "Protocol", "Status"])
                
                for i, endpoint in enumerate(endpoints):
                    table.insertRow(i)
                    table.setItem(i, 0, QTableWidgetItem(str(endpoint.get('Port', ''))))
                    table.setItem(i, 1, QTableWidgetItem(endpoint.get('Service', '')))
                    table.setItem(i, 2, QTableWidgetItem(endpoint.get('Protocol', '')))
                    table.setItem(i, 3, QTableWidgetItem(endpoint.get('Status', '')))
            
            table.resizeColumnsToContents()
            
        except Exception as e:
            print(f"DEBUG: Error updating RPC table view: {e}")
    
    def update_rpc_tree_view(self, tool_key, graph_data):
        """Update RPC tree view with scan data"""
        if not graph_data:
            return
        
        try:
            from PyQt6.QtWidgets import QTreeWidgetItem
            
            # Get the tree for current scan type
            trees = getattr(self, f"{tool_key}_trees", {})
            current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Basic Info")
            tree = trees.get(current_scan_type)
            
            if not tree:
                return
            
            # Clear existing data
            tree.clear()
            
            # Populate tree with hierarchical data
            for category, data in graph_data.items():
                if isinstance(data, dict) and 'count' in data:
                    # Create category item
                    category_item = QTreeWidgetItem(tree, [category, str(data['count']), data.get('details', '')])
                    
                    # Add children if available
                    if 'children' in data:
                        for child_name, child_data in data['children'].items():
                            if isinstance(child_data, dict) and 'count' in child_data:
                                child_item = QTreeWidgetItem(category_item, [
                                    child_name, 
                                    str(child_data['count']), 
                                    child_data.get('details', '')
                                ])
                            else:
                                child_item = QTreeWidgetItem(category_item, [child_name, "1", str(child_data)])
                    
                    category_item.setExpanded(True)
            
            tree.resizeColumnToContents(0)
            tree.resizeColumnToContents(1)
            
        except Exception as e:
            print(f"DEBUG: Error updating RPC tree view: {e}")
    
    def append_http_output(self, tool_key, scan_type, text):
        """Append HTTP output to the correct terminal"""
        terminals = getattr(self, f"{tool_key}_terminals", {})
        if scan_type in terminals and terminals[scan_type] is not None:
            terminal = terminals[scan_type]
            # Apply theme-specific font styling
            current_theme = getattr(self.main_window, 'current_theme', 'dark_blue')
            font_family = 'Share Tech Mono' if current_theme == 'matrix' else 'Neuropol X'
            
            if not text.startswith('<div style="font-family:'):
                text = f'<div style="font-family: {font_family}, monospace;">{text}</div>'
            
            terminal.insertHtml(text)
            
            # Scroll to bottom with delay
            from PyQt6.QtCore import QTimer
            QTimer.singleShot(10, lambda: terminal.verticalScrollBar().setValue(
                terminal.verticalScrollBar().maximum()
            ))
        else:
            # Set current scan type and fallback to service output
            setattr(self, f"{tool_key}_current_scan_type", scan_type)
            self.append_service_output(tool_key, text)
    
    def append_service_output(self, tool_key, text):
        """Append text to service terminal output"""
        terminal = None
        
        # Handle HTTP, RPC, SMB, SSH, and DB with multiple terminals (stored in dictionary)
        if tool_key in ["http_enum", "rpc_enum", "smb_enum", "ssh_enum", "db_enum"]:
            terminals = getattr(self, f"{tool_key}_terminals", {})
            if tool_key == "http_enum":
                current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Fingerprinting")
                terminal = terminals.get(current_scan_type)
            elif tool_key == "rpc_enum":
                current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Basic Info")
                terminal = terminals.get(current_scan_type)
            elif tool_key == "smb_enum":
                current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Basic Info")
                terminal = terminals.get(current_scan_type)
            elif tool_key == "ssh_enum":
                current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Enumeration")
                terminal = terminals.get(current_scan_type)
            elif tool_key == "db_enum":
                current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Basic Info")
                terminal = terminals.get(current_scan_type)
            
            # Fallback to any available terminal if current type not found
            if not terminal and terminals:
                terminal = next(iter(terminals.values()))
        else:
            # Handle other services with single terminal
            terminal = getattr(self, f"{tool_key}_terminal", None)
        
        if terminal and hasattr(terminal, 'insertHtml'):
            try:
                # Apply theme-specific font styling
                current_theme = getattr(self.main_window, 'current_theme', 'dark_blue')
                font_family = 'Share Tech Mono' if current_theme == 'matrix' else 'Neuropol X'
                
                if not text.startswith('<div style="font-family:'):
                    text = f'<div style="font-family: {font_family}, monospace;">{text}</div>'
                
                terminal.insertHtml(text)
                terminal.verticalScrollBar().setValue(terminal.verticalScrollBar().maximum())
                
            except Exception as e:
                # Fallback to console if terminal operations fail
                print(f"SERVICE OUTPUT [{tool_key}]: {text.strip()} (Terminal error: {e})")
        else:
            # Fallback to console for debugging
            print(f"SERVICE OUTPUT [{tool_key}]: {text.strip()}")
    
    def update_db_table_view(self, tool_key, results):
        """Update database table view with scan results"""
        try:
            from PyQt6.QtWidgets import QTableWidgetItem, QTreeWidgetItem
            
            tables = getattr(self, f"{tool_key}_tables", {})
            trees = getattr(self, f"{tool_key}_trees", {})
            current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Basic Info")
            table = tables.get(current_scan_type)
            tree = trees.get(current_scan_type)
            
            # Update table view
            if table:
                table.setRowCount(0)
                table.setColumnCount(3)
                table.setHorizontalHeaderLabels(["Property", "Value", "Details"])
                
                row = 0
                
                # Add basic info
                if 'db_type' in results:
                    table.insertRow(row)
                    table.setItem(row, 0, QTableWidgetItem("Database Type"))
                    table.setItem(row, 1, QTableWidgetItem(results['db_type'].upper()))
                    table.setItem(row, 2, QTableWidgetItem(f"{results['target']}:{results['port']}"))
                    row += 1
                
                # Add accessibility status
                if 'accessible' in results:
                    table.insertRow(row)
                    table.setItem(row, 0, QTableWidgetItem("Service Status"))
                    status = "Accessible" if results.get('accessible') else "Not Accessible"
                    table.setItem(row, 1, QTableWidgetItem(status))
                    table.setItem(row, 2, QTableWidgetItem(results.get('error', '')))
                    row += 1
                
                # Add server info if available
                if 'server_info' in results:
                    server_info = results['server_info']
                    for key, value in server_info.items():
                        table.insertRow(row)
                        table.setItem(row, 0, QTableWidgetItem(key.replace('_', ' ').title()))
                        table.setItem(row, 1, QTableWidgetItem(str(value)))
                        table.setItem(row, 2, QTableWidgetItem("Server Information"))
                        row += 1
                
                # Add security findings
                if 'security_findings' in results:
                    for finding in results['security_findings']:
                        table.insertRow(row)
                        table.setItem(row, 0, QTableWidgetItem("Security Finding"))
                        table.setItem(row, 1, QTableWidgetItem(finding.get('finding', '')))
                        table.setItem(row, 2, QTableWidgetItem(f"Severity: {finding.get('severity', 'Unknown')}"))
                        row += 1
                
                # Add info from scripts scan
                if 'info' in results:
                    for key, value in results['info'].items():
                        table.insertRow(row)
                        table.setItem(row, 0, QTableWidgetItem(key.replace('_', ' ').title()))
                        table.setItem(row, 1, QTableWidgetItem(str(value)))
                        table.setItem(row, 2, QTableWidgetItem("Database Information"))
                        row += 1
                
                table.resizeColumnsToContents()
            
            # Update tree view
            if tree:
                tree.clear()
                
                # Create main database node
                db_type = results.get('db_type', 'Database').upper()
                target = results.get('target', 'Unknown')
                port = results.get('port', 'Unknown')
                main_item = QTreeWidgetItem(tree, [f"{db_type} Database", "1", f"{target}:{port}"])
                
                # Add server information
                if 'server_info' in results:
                    server_item = QTreeWidgetItem(main_item, ["Server Information", str(len(results['server_info'])), ""])
                    for key, value in results['server_info'].items():
                        QTreeWidgetItem(server_item, [key.replace('_', ' ').title(), str(value), ""])
                    server_item.setExpanded(True)
                
                # Add security findings
                if 'security_findings' in results:
                    security_item = QTreeWidgetItem(main_item, ["Security Findings", str(len(results['security_findings'])), ""])
                    for finding in results['security_findings']:
                        severity = finding.get('severity', 'Unknown')
                        finding_text = finding.get('finding', '')
                        QTreeWidgetItem(security_item, [finding_text, severity, finding.get('description', '')])
                    security_item.setExpanded(True)
                
                # Add database info
                if 'info' in results:
                    info_item = QTreeWidgetItem(main_item, ["Database Information", str(len(results['info'])), ""])
                    for key, value in results['info'].items():
                        QTreeWidgetItem(info_item, [key.replace('_', ' ').title(), str(value), ""])
                    info_item.setExpanded(True)
                
                # Add vulnerabilities
                if 'vulnerabilities' in results:
                    vuln_item = QTreeWidgetItem(main_item, ["Vulnerabilities", str(len(results['vulnerabilities'])), ""])
                    for vuln in results['vulnerabilities']:
                        severity = vuln.get('severity', 'Unknown')
                        finding_text = vuln.get('finding', '')
                        QTreeWidgetItem(vuln_item, [finding_text, severity, vuln.get('description', '')])
                    vuln_item.setExpanded(True)
                
                main_item.setExpanded(True)
                tree.resizeColumnToContents(0)
                tree.resizeColumnToContents(1)
            
        except Exception as e:
            print(f"Error updating DB table view: {e}")
    
    def handle_http_realtime_results(self, tool_key, scan_type, results):
        """Handle real-time HTTP enumeration results"""
        try:
            if 'crawl_data' in results:
                self.update_http_graph_view(tool_key, scan_type, results['crawl_data'])
            # Handle Enterprise Scripts results - always process both data types
            if scan_type == "Enterprise Scripts":
                crawl_data = results.get('crawl_data', {})
                if crawl_data:
                    self.update_http_graph_view(tool_key, scan_type, crawl_data)
                # Also handle enterprise_results if present
                if 'enterprise_results' in results and not crawl_data:
                    enterprise_data = results['enterprise_results']
                    if enterprise_data:
                        from app.tools.http_scanner import HTTPEnumWorker
                        worker = HTTPEnumWorker(target="", scan_type="Enterprise Scripts")
                        worker._build_enterprise_tree(enterprise_data)
                        if hasattr(worker, 'crawl_tree_data'):
                            crawl_data = worker.crawl_tree_data
                            self.update_http_graph_view(tool_key, scan_type, crawl_data)
                # Force update even with empty data to clear previous results
                if not crawl_data:
                    self.update_http_graph_view(tool_key, scan_type, {})
            # Handle Full Scan table data
            elif scan_type == "Full Scan":
                if 'full_scan_table_data' in results:
                    table_data = results['full_scan_table_data']
                    self.update_http_full_scan_table(tool_key, scan_type, table_data)
        except Exception as e:
            print(f"DEBUG: Error handling HTTP realtime results: {e}")
    
    def start_http_progress(self, tool_key, total, message):
        """Start HTTP progress bar"""
        progress_widget = getattr(self, f"{tool_key}_progress_widget", None)
        if progress_widget and hasattr(progress_widget, 'start_progress'):
            progress_widget.start_progress(total, message)
    
    def update_http_progress(self, tool_key, current, found, message):
        """Update HTTP progress bar"""
        progress_widget = getattr(self, f"{tool_key}_progress_widget", None)
        if progress_widget and hasattr(progress_widget, 'update_progress'):
            progress_widget.update_progress(current, found, message)
    
    def start_rpc_progress(self, tool_key, total, message):
        """Start RPC progress bar"""
        progress_widget = getattr(self, f"{tool_key}_progress_widget", None)
        if progress_widget and hasattr(progress_widget, 'start_progress'):
            progress_widget.start_progress(total, message)
    
    def update_rpc_progress(self, tool_key, current, found, message):
        """Update RPC progress bar"""
        progress_widget = getattr(self, f"{tool_key}_progress_widget", None)
        if progress_widget and hasattr(progress_widget, 'update_progress'):
            progress_widget.update_progress(current, found, message)
    
    def update_http_graph_view(self, tool_key, scan_type, crawl_data):
        """Update HTTP graph view with crawl data"""
        try:
            tables = getattr(self, f"{tool_key}_tables", {})
            if scan_type in tables:
                graph_widget = tables[scan_type]
                if hasattr(graph_widget, 'update_from_crawl_data'):
                    graph_widget.update_from_crawl_data(crawl_data, scan_type)
        except Exception as e:
            print(f"DEBUG: Error updating HTTP graph view: {e}")
    
    def update_http_tree_view(self, tool_key, scan_type, directories):
        """Update HTTP tree view with directory data for Directory Enum"""
        try:
            from PyQt6.QtWidgets import QTreeWidgetItem, QTableWidgetItem
            
            # Update tree view (graph view)
            tables = getattr(self, f"{tool_key}_tables", {})
            if scan_type in tables:
                tree = tables[scan_type]
                if hasattr(tree, 'clear'):  # It's a tree widget
                    tree.clear()
                    
                    # Group directories by status code
                    status_groups = {}
                    for directory in directories:
                        status = directory.get('status', 200)
                        if status not in status_groups:
                            status_groups[status] = []
                        status_groups[status].append(directory)
                    
                    # Create tree structure
                    for status, dirs in status_groups.items():
                        status_item = QTreeWidgetItem(tree, [f"Status {status}", str(len(dirs)), ""])
                        for directory in dirs:
                            path = directory.get('path', '')
                            size = directory.get('size', 0)
                            size_str = f"{size:,} bytes" if size else "Unknown"
                            QTreeWidgetItem(status_item, [f"/{path}", size_str, ""])
                        status_item.setExpanded(True)
                    
                    tree.resizeColumnToContents(0)
                    tree.resizeColumnToContents(1)
            
            # Update table view (separate table for Directory Enum)
            dir_table = getattr(self, f"{tool_key}_dir_table", None)
            if dir_table and hasattr(dir_table, 'setRowCount'):
                dir_table.setRowCount(0)
                for i, directory in enumerate(directories):
                    dir_table.insertRow(i)
                    dir_table.setItem(i, 0, QTableWidgetItem(directory.get('path', '')))
                    dir_table.setItem(i, 1, QTableWidgetItem(str(directory.get('status', ''))))
                    size = directory.get('size', 0)
                    size_str = f"{size:,} bytes" if size else "Unknown"
                    dir_table.setItem(i, 2, QTableWidgetItem(size_str))
                dir_table.resizeColumnsToContents()
                
        except Exception as e:
            print(f"DEBUG: Error updating HTTP tree view: {e}")
    
    def update_http_full_scan_table(self, tool_key, scan_type, table_data):
        """Update Full Scan table view with comprehensive scan data"""
        try:
            from PyQt6.QtWidgets import QTableWidgetItem
            
            tables = getattr(self, f"{tool_key}_tables", {})
            if scan_type in tables:
                table = tables[scan_type]
                if hasattr(table, 'setRowCount'):  # It's a table widget
                    table.setRowCount(0)
                    
                    # Populate table with Full Scan data
                    for i, row_data in enumerate(table_data):
                        table.insertRow(i)
                        for j, cell_data in enumerate(row_data):
                            table.setItem(i, j, QTableWidgetItem(str(cell_data)))
                    
                    table.resizeColumnsToContents()
                    
        except Exception as e:
            print(f"DEBUG: Error updating Full Scan table: {e}")
    
    def update_ssh_tree_view(self, tool_key, graph_data):
        """Update SSH tree view with scan data"""
        if not graph_data:
            return
        
        try:
            from PyQt6.QtWidgets import QTreeWidgetItem
            
            # Get the tree for current scan type
            trees = getattr(self, f"{tool_key}_trees", {})
            current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Enumeration")
            tree = trees.get(current_scan_type)
            
            if not tree:
                return
            
            # Clear existing data
            tree.clear()
            
            # Populate tree with hierarchical SSH data
            for category, data in graph_data.items():
                if isinstance(data, dict) and 'count' in data:
                    # Create category item
                    category_item = QTreeWidgetItem(tree, [category, str(data['count']), data.get('details', '')])
                    
                    # Add children if available
                    if 'children' in data:
                        for child_name, child_data in data['children'].items():
                            if isinstance(child_data, dict) and 'count' in child_data:
                                child_item = QTreeWidgetItem(category_item, [
                                    child_name, 
                                    str(child_data['count']), 
                                    child_data.get('details', '')
                                ])
                                
                                # Add grandchildren if available
                                if 'children' in child_data:
                                    for grandchild_name, grandchild_data in child_data['children'].items():
                                        if isinstance(grandchild_data, dict) and 'count' in grandchild_data:
                                            QTreeWidgetItem(child_item, [
                                                grandchild_name,
                                                str(grandchild_data['count']),
                                                grandchild_data.get('details', '')
                                            ])
                                        else:
                                            QTreeWidgetItem(child_item, [grandchild_name, "1", str(grandchild_data)])
                            else:
                                child_item = QTreeWidgetItem(category_item, [child_name, "1", str(child_data)])
                    
                    category_item.setExpanded(True)
            
            tree.resizeColumnToContents(0)
            tree.resizeColumnToContents(1)
            
        except Exception as e:
            print(f"DEBUG: Error updating SSH tree view: {e}")
    
    def update_ssh_table_view(self, tool_key, table_data):
        """Update SSH table view with scan data"""
        if not table_data:
            return
        
        try:
            from PyQt6.QtWidgets import QTableWidgetItem
            
            # Get the table for current scan type
            tables = getattr(self, f"{tool_key}_tables", {})
            current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Enumeration")
            table = tables.get(current_scan_type)
            
            if not table:
                return
            
            # Clear existing data
            table.setRowCount(0)
            
            # Handle different SSH data types
            if 'ssh_banners' in table_data:
                banners = table_data['ssh_banners']
                table.setColumnCount(4)
                table.setHorizontalHeaderLabels(["Target", "Port", "Banner", "Status"])
                
                for i, banner in enumerate(banners):
                    table.insertRow(i)
                    table.setItem(i, 0, QTableWidgetItem(banner.get('Target', '')))
                    table.setItem(i, 1, QTableWidgetItem(str(banner.get('Port', ''))))
                    table.setItem(i, 2, QTableWidgetItem(banner.get('Banner', '')))
                    table.setItem(i, 3, QTableWidgetItem(banner.get('Status', '')))
            
            table.resizeColumnsToContents()
            
        except Exception as e:
            print(f"DEBUG: Error updating SSH table view: {e}")
    
    def safe_append_db_output(self, tool_key, text):
        """Safely append database output with minimal processing"""
        try:
            if not text.endswith('<br>'):
                text += '<br>'
            self.append_service_output(tool_key, text)
        except Exception as e:
            print(f"DB OUTPUT ERROR: {e}")
    
    def on_http_oob_changed(self, tool_key, enabled, listener_id):
        """Handle HTTP OOB listener enable/disable"""
        if enabled and listener_id:
            self.append_service_output(tool_key, f"<p style='color: #00FF41;'>[OOB] Enabled output to listener {listener_id}</p><br>")
            # Store OOB settings for use in HTTP scanner
            setattr(self, f"{tool_key}_oob_enabled", True)
            setattr(self, f"{tool_key}_oob_listener", listener_id)
        else:
            self.append_service_output(tool_key, f"<p style='color: #FFAA00;'>[OOB] Disabled output to listener</p><br>")
            setattr(self, f"{tool_key}_oob_enabled", False)
            setattr(self, f"{tool_key}_oob_listener", None)