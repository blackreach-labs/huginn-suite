# app/pages/recon_enumeration/service_field_visibility.py
import os
from app.core.logger import logger

class ServiceFieldVisibilityMixin:
    """Mixin for service field visibility management"""
    
    def setup_service_field_interactions(self, tool_key, controls):
        """Setup field interactions based on tool type"""
        if not hasattr(controls, 'controls'):
            return
            
        control_widgets = controls.controls
        
        # RPC enumeration field interactions
        if tool_key == 'rpc_enum' and 'rpc_auth_combo' in control_widgets:
            control_widgets['rpc_auth_combo'].currentTextChanged.connect(
                lambda auth_type: self.toggle_rpc_auth_fields(tool_key, auth_type)
            )
            control_widgets['rpc_scan_type'].currentTextChanged.connect(
                lambda scan_type: self.on_rpc_scan_type_changed(tool_key, scan_type)
            )
        
        # SMB enumeration field interactions
        elif tool_key == 'smb_enum' and 'smb_auth_combo' in control_widgets:
            control_widgets['smb_auth_combo'].currentTextChanged.connect(
                lambda auth_type: self.toggle_smb_auth_fields(tool_key, auth_type)
            )
            if 'smb_scan_type' in control_widgets:
                control_widgets['smb_scan_type'].currentTextChanged.connect(
                    lambda scan_type: self.on_smb_scan_type_changed(tool_key, scan_type)
                )
        
        # HTTP enumeration field interactions
        elif tool_key == 'http_enum' and 'http_scan_type' in control_widgets:
            control_widgets['http_scan_type'].currentTextChanged.connect(
                lambda scan_type: self.on_http_scan_type_changed(tool_key, scan_type)
            )
            if 'http_auth_method' in control_widgets:
                control_widgets['http_auth_method'].currentTextChanged.connect(
                    lambda auth_method: self.toggle_http_auth_fields(tool_key, auth_method)
                )
            if 'http_preset' in control_widgets:
                control_widgets['http_preset'].currentTextChanged.connect(
                    lambda preset: self.on_http_preset_changed(tool_key, preset)
                )
            if 'http_cred_manager_btn' in control_widgets:
                control_widgets['http_cred_manager_btn'].clicked.connect(
                    lambda: self.load_captured_sessions(tool_key)
                )
            if 'enable_listener' in control_widgets:
                control_widgets['enable_listener'].stateChanged.connect(
                    lambda state: self.toggle_http_listener_row(tool_key, state)
                )
            if 'add_listener_btn' in control_widgets:
                control_widgets['add_listener_btn'].clicked.connect(
                    lambda: self.show_add_listener_dialog(tool_key)
                )
            # Populate existing listeners and refresh periodically
            self.populate_existing_listeners(tool_key, control_widgets)
            
            # Set up timer to refresh listeners periodically
            from PyQt6.QtCore import QTimer
            refresh_timer = QTimer()
            refresh_timer.timeout.connect(lambda: self.safe_populate_listeners(tool_key, control_widgets))
            refresh_timer.start(5000)  # Refresh every 5 seconds
            setattr(self, f"{tool_key}_listener_refresh_timer", refresh_timer)
        
        # Database enumeration field interactions
        elif tool_key == 'db_enum' and 'db_type_combo' in control_widgets:
            control_widgets['db_type_combo'].currentTextChanged.connect(
                lambda db_type: self.toggle_db_fields(tool_key, db_type)
            )
            if 'db_scan_type' in control_widgets:
                control_widgets['db_scan_type'].currentTextChanged.connect(
                    lambda scan_type: self.on_db_scan_type_changed(tool_key, scan_type)
                )
            if 'db_auth_combo' in control_widgets:
                control_widgets['db_auth_combo'].currentTextChanged.connect(
                    lambda auth_type: self.toggle_db_auth_fields(tool_key, auth_type)
                )
            if 'db_cred_manager_btn' in control_widgets:
                control_widgets['db_cred_manager_btn'].clicked.connect(
                    lambda: self.open_db_credential_manager(tool_key)
                )
        
        # LDAP enumeration field interactions
        elif tool_key == 'ldap_enum':
            if 'ldap_scan_type' in control_widgets:
                control_widgets['ldap_scan_type'].currentTextChanged.connect(
                    lambda scan_type: self.on_ldap_scan_type_changed(tool_key, scan_type)
                )
            if 'ldap_auth_combo' in control_widgets:
                control_widgets['ldap_auth_combo'].currentTextChanged.connect(
                    lambda auth_type: self.toggle_ldap_auth_fields(tool_key, auth_type)
                )
        
        # AV/Firewall detection field interactions
        elif tool_key == 'av_detect' and 'av_detection_type' in control_widgets:
            control_widgets['av_detection_type'].currentTextChanged.connect(
                lambda detection_type: self.toggle_av_fields(tool_key, detection_type)
            )
        
        # SNMP enumeration field interactions
        elif tool_key == 'snmp_enum' and 'snmp_version' in control_widgets:
            control_widgets['snmp_version'].currentTextChanged.connect(
                lambda version: self.toggle_snmp_fields(tool_key, version)
            )
        
        # SSH enumeration field interactions
        elif tool_key == 'ssh_enum' and 'ssh_auth_type' in control_widgets:
            control_widgets['ssh_auth_type'].currentTextChanged.connect(
                lambda auth_type: self.toggle_ssh_auth_fields(tool_key, auth_type)
            )
            if 'ssh_scan_type' in control_widgets:
                control_widgets['ssh_scan_type'].currentTextChanged.connect(
                    lambda scan_type: self.on_ssh_scan_type_changed(tool_key, scan_type)
                )
    
    def toggle_rpc_auth_fields(self, tool_key, auth_type):
        """Toggle RPC authentication fields based on method selection"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            row_visibility = {
                'Domain:': auth_type in ["Credentials", "Pass-the-Hash", "Kerberos Ticket", "Kerberos Password"],
                'Username:': auth_type in ["Credentials", "Pass-the-Hash", "Kerberos Ticket", "Kerberos Password"],
                'Password:': auth_type in ["Credentials", "Kerberos Password"],
                'NTLM Hash:': auth_type == "Pass-the-Hash",
                'Ticket File:': auth_type == "Kerberos Ticket",
                'Credentials:': auth_type != "Anonymous"
            }
            
            for row_label, should_show in row_visibility.items():
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        widget = control_panel.row_widgets[row_label]
                        if should_show:
                            widget.setVisible(True)
                            if widget.parent() is None:
                                control_panel.layout().addWidget(widget)
                        else:
                            widget.setVisible(False)
                            control_panel.layout().removeWidget(widget)
                            widget.setParent(None)
                    except RuntimeError as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
    
    def toggle_smb_auth_fields(self, tool_key, auth_type):
        """Toggle SMB authentication fields based on method selection"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        show_creds = (auth_type != "Anonymous")
        
        # Show/hide credential fields
        if 'smb_username' in controls and controls['smb_username'] is not None:
            try:
                controls['smb_username'].setVisible(show_creds)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'smb_password' in controls and controls['smb_password'] is not None:
            try:
                controls['smb_password'].setVisible(show_creds)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'smb_domain' in controls and controls['smb_domain'] is not None:
            try:
                controls['smb_domain'].setVisible(show_creds)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            row_visibility = {
                'Domain:': show_creds,
                'Username:': show_creds,
                'Password:': show_creds,
                'Credentials:': show_creds
            }
            
            for row_label, should_show in row_visibility.items():
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        control_panel.row_widgets[row_label].setVisible(should_show)
                        if not should_show:
                            control_panel.row_widgets[row_label].setMaximumHeight(0)
                            control_panel.row_widgets[row_label].setMinimumHeight(0)
                        else:
                            control_panel.row_widgets[row_label].setMaximumHeight(30)
                            control_panel.row_widgets[row_label].setMinimumHeight(26)
                    except RuntimeError as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
            
            # Recalculate panel height
            self._recalculate_smb_panel_height(tool_key)
    
    def _recalculate_http_panel_height(self, tool_key):
        """Recalculate HTTP control panel height based on all currently visible rows"""
        self._recalculate_panel_height(tool_key)

    def _recalculate_smb_panel_height(self, tool_key):
        """Recalculate SMB control panel height based on all currently visible rows"""
        self._recalculate_panel_height(tool_key)

    def _recalculate_panel_height(self, tool_key):
        """Recalculate control panel height based on all currently visible rows"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'row_widgets'):
            return
        
        try:
            visible_count = 0
            for row_label, row_widget in control_panel.row_widgets.items():
                if row_widget is not None and row_widget.isVisible():
                    visible_count += 1
            needed_height = visible_count * 30 + 4
            control_panel.setFixedHeight(needed_height)
            control_panel.setMaximumHeight(needed_height)
        except RuntimeError:
            pass

    def on_http_scan_type_changed(self, tool_key, scan_type):
        """Handle HTTP scan type change to show/hide relevant fields"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
        
        controls = control_panel.controls
        
        # Define field visibility based on scan type
        if scan_type == "Fingerprinting":
            show_wordlist = False
            show_extensions = False
            show_preset = False
            show_auth = False
        elif scan_type == "Source Code":
            show_wordlist = False
            show_extensions = False
            show_preset = False
            show_auth = False
        elif scan_type == "Crawler":
            show_wordlist = False
            show_extensions = False
            show_preset = False  # Crawler doesn't use presets
            show_auth = True     # Crawler supports authentication
        elif scan_type == "Directory Enum":
            show_wordlist = True
            show_extensions = True
            show_preset = True
            show_auth = True
        elif scan_type == "Enterprise Scripts":
            show_wordlist = False
            show_extensions = False
            show_preset = False
            show_auth = False
        elif scan_type == "VHost Brute":
            show_wordlist = True
            show_extensions = False
            show_preset = False
            show_auth = False
        elif scan_type == "Huginn Scan":
            show_wordlist = False
            show_extensions = False
            show_preset = False
            show_auth = False
            # Launch Huginn Advanced Scanner
            self.launch_huginn_scanner(tool_key)
        elif scan_type == "Full Scan":
            show_wordlist = True
            show_extensions = True
            show_preset = True
            show_auth = True
        else:
            # Default to showing all fields
            show_wordlist = True
            show_extensions = True
            show_preset = True
            show_auth = True
        
        # Toggle field visibility with safety check
        if 'http_wordlist' in controls and controls['http_wordlist'] is not None:
            try:
                controls['http_wordlist'].setVisible(show_wordlist)
            except RuntimeError as _exc:
                pass  # Widget has been deleted
                logger.debug("Suppressed exception", exc_info=True)
        if 'http_preset' in controls and controls['http_preset'] is not None:
            try:
                controls['http_preset'].setVisible(show_preset)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Toggle listener options based on scan type
        self.toggle_http_listener_options(tool_key, scan_type)
        
        # Authentication method field
        if 'http_auth_method' in controls and controls['http_auth_method'] is not None:
            try:
                controls['http_auth_method'].setVisible(show_auth)
                # Reset to None when hiding auth fields
                if not show_auth:
                    controls['http_auth_method'].setCurrentText("None")
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Username and password fields are controlled by auth method, not scan type
        # They should remain hidden unless Basic Auth is specifically selected
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            # Extensions are only shown when preset is "Manual" AND scan type needs them
            current_preset = "Manual"
            if 'http_preset' in controls:
                try:
                    current_preset = controls['http_preset'].currentText()
                except RuntimeError:
                    pass
            show_extensions_rows = show_extensions and (current_preset == "Manual")
            
            row_visibility_map = {
                'Preset:': show_preset,
                'Extensions:': show_extensions_rows,
                'Wordlist:': show_wordlist,
                'Auth Method:': show_auth,
                'Login URL:': False,  # Hidden by default, shown only when Form-Based Auth selected
                'Username:': False,  # Hidden by default, shown only when Basic Auth or Form-Based Auth selected
                'Password:': False,  # Hidden by default, shown only when Basic Auth or Form-Based Auth selected
                'Credentials:': False  # Hidden by default, shown only when Session Replay selected
            }
            
            for row_label, should_show in row_visibility_map.items():
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        row_widget = control_panel.row_widgets[row_label]
                        if should_show:
                            row_widget.setVisible(True)
                            row_widget.setMaximumHeight(30)
                            row_widget.setMinimumHeight(26)
                        else:
                            row_widget.setVisible(False)
                            row_widget.setMaximumHeight(0)
                            row_widget.setMinimumHeight(0)
                    except RuntimeError as _exc:
                        pass  # Widget has been deleted
                        logger.debug("Suppressed exception", exc_info=True)
            
            # Recalculate panel height based on all visible rows
            self._recalculate_http_panel_height(tool_key)
        
        # Store current scan type first
        setattr(self, f"{tool_key}_current_scan_type", scan_type)
        
        # Update view buttons based on scan type
        self.update_http_view_buttons(tool_key, scan_type)
        
        # Switch to the appropriate terminal for this scan type
        self.switch_http_scan_view(tool_key, scan_type)
        
        # Reset view to text when switching scan types
        setattr(self, f"current_{tool_key}_view", "text")
        text_view_btn = getattr(self, f"{tool_key}_text_view_btn", None)
        if text_view_btn:
            text_view_btn.setChecked(True)
        
        # Uncheck other view buttons
        graph_view_btn = getattr(self, f"{tool_key}_graph_view_btn", None)
        table_view_btn = getattr(self, f"{tool_key}_table_view_btn", None)
        if graph_view_btn:
            graph_view_btn.setChecked(False)
        if table_view_btn:
            table_view_btn.setChecked(False)
    
    def toggle_http_listener_row(self, tool_key, state):
        """Toggle HTTP listener row visibility based on checkbox state"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'row_widgets'):
            return
        
        show_listener = (state == 2)  # Qt.CheckState.Checked
        
        # Toggle listener row visibility
        if 'Listener:' in control_panel.row_widgets:
            listener_row = control_panel.row_widgets['Listener:']
            if listener_row:
                try:
                    listener_row.setVisible(show_listener)
                    if show_listener:
                        listener_row.setMaximumHeight(30)
                        listener_row.setMinimumHeight(26)
                    else:
                        listener_row.setMaximumHeight(0)
                        listener_row.setMinimumHeight(0)
                except RuntimeError as _exc:
                    pass  # Widget has been deleted
                    logger.debug("Suppressed exception", exc_info=True)
        
        # Recalculate panel height
        self._recalculate_http_panel_height(tool_key)
    
    def toggle_http_listener_options(self, tool_key, scan_type):
        """Toggle HTTP listener options based on scan type"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
        
        controls = control_panel.controls
        
        # Show listener checkbox for scan types that support OOB testing
        show_listener = scan_type == "Fingerprinting"
        
        if 'enable_listener' in controls and controls['enable_listener'] is not None:
            try:
                controls['enable_listener'].setVisible(show_listener)
                if not show_listener:
                    controls['enable_listener'].setChecked(False)
                else:
                    # Refresh listeners when showing the option
                    self.populate_existing_listeners(tool_key, controls)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
    
    def show_add_listener_dialog(self, tool_key):
        """Show dialog to add new listener"""
        try:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QPushButton, QLineEdit
            import socket
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Add Listener")
            dialog.setModal(True)
            dialog.resize(400, 250)
            
            layout = QVBoxLayout(dialog)
            
            # Listener type selection
            type_layout = QHBoxLayout()
            type_layout.addWidget(QLabel("Listener Type:"))
            type_combo = QComboBox()
            type_combo.addItems(["netcat", "http", "dns", "powershell"])
            type_layout.addWidget(type_combo)
            layout.addLayout(type_layout)
            
            # Port input
            port_layout = QHBoxLayout()
            port_layout.addWidget(QLabel("Port:"))
            port_input = QLineEdit()
            port_input.setText("4444")
            port_layout.addWidget(port_input)
            layout.addLayout(port_layout)
            
            # IP address input
            ip_layout = QHBoxLayout()
            ip_layout.addWidget(QLabel("Listening IP:"))
            ip_input = QLineEdit()
            # Get adapter IP address
            try:
                hostname = socket.gethostname()
                adapter_ip = socket.gethostbyname(hostname)
                ip_input.setText(adapter_ip)
            except:
                ip_input.setText("0.0.0.0")
            ip_layout.addWidget(ip_input)
            layout.addLayout(ip_layout)
            
            # Buttons
            button_layout = QHBoxLayout()
            add_btn = QPushButton("Add")
            cancel_btn = QPushButton("Cancel")
            button_layout.addWidget(add_btn)
            button_layout.addWidget(cancel_btn)
            layout.addLayout(button_layout)
            
            # Connect buttons
            cancel_btn.clicked.connect(dialog.reject)
            add_btn.clicked.connect(lambda: self.add_listener(dialog, type_combo.currentText(), port_input.text(), ip_input.text(), tool_key))
            
            dialog.exec()
            
        except Exception as e:
            self.status_updated.emit(f"Error opening listener dialog: {e}")
    
    def add_listener(self, dialog, listener_type, port, ip_address, tool_key):
        """Add new listener"""
        if not port:
            port = "4444"  # Default port
        if not ip_address:
            ip_address = "0.0.0.0"
        
        try:
            from app.core.listener_manager import listener_manager
            
            # Create listener using listener_manager
            listener_id = listener_manager.create_listener(int(port), listener_type, ip_address)
            success = listener_manager.start_listener(listener_id)
            
            if success:
                # Update the listener combo box
                control_panel = getattr(self, f"{tool_key}_control_panel", None)
                if control_panel and hasattr(control_panel, 'controls'):
                    # Refresh the entire dropdown
                    self.populate_existing_listeners(tool_key, control_panel.controls)
                
                self.status_updated.emit(f"Added {listener_type} listener on {ip_address}:{port}")
                dialog.accept()
            else:
                self.status_updated.emit(f"Failed to start {listener_type} listener on {ip_address}:{port}")
        except Exception as e:
            self.status_updated.emit(f"Error creating listener: {e}")
    
    def safe_populate_listeners(self, tool_key, control_widgets):
        """Safely populate listeners with widget validation"""
        try:
            if 'listener_combo' not in control_widgets:
                return
            
            listener_combo = control_widgets['listener_combo']
            
            # Check if widget is still valid
            if listener_combo is None:
                return
            
            # Try to access the widget to see if it's still alive
            listener_combo.count()
            
            # If we get here, widget is valid - populate it
            self.populate_existing_listeners(tool_key, control_widgets)
            
        except (RuntimeError, AttributeError):
            # Widget has been deleted or is invalid - stop the timer
            timer_attr = f"{tool_key}_listener_refresh_timer"
            if hasattr(self, timer_attr):
                timer = getattr(self, timer_attr)
                if timer:
                    timer.stop()
                    delattr(self, timer_attr)
    
    def populate_existing_listeners(self, tool_key, control_widgets):
        """Populate listener dropdown with existing listeners"""
        if 'listener_combo' not in control_widgets:
            return
        
        listener_combo = control_widgets['listener_combo']
        
        # Validate widget before accessing
        try:
            listener_combo.clear()
        except RuntimeError:
            return  # Widget has been deleted
        
        # Get active listeners from listener_manager
        try:
            from app.core.listener_manager import listener_manager
            active_listeners = listener_manager.get_active_listeners()
            
            if active_listeners:
                for listener in active_listeners:
                    listener_id = listener['id']
                    listener_type = listener['type']
                    port = listener['port']
                    display_text = f"{listener_id} ({listener_type}:{port})"
                    listener_combo.addItem(display_text, listener_id)
                listener_combo.setEnabled(True)
            else:
                listener_combo.addItem("No listeners available")
                listener_combo.setEnabled(False)
                
        except ImportError:
            # Fallback if listener_manager not available
            listener_combo.addItem("No listeners available")
            listener_combo.setEnabled(False)
        except RuntimeError as _exc:
            # Widget was deleted during operation
            pass
            logger.debug("Suppressed exception", exc_info=True)
    
    def on_http_oob_checkbox_changed(self, tool_key, state):
        """Handle OOB checkbox state change"""
        enabled = (state == 2)  # Qt.CheckState.Checked
        
        listener_combo = getattr(self, f"{tool_key}_listener_combo", None)
        listener_input = getattr(self, f"{tool_key}_listener_input", None)
        
        try:
            if listener_combo:
                listener_combo.setVisible(enabled)
        except RuntimeError as _exc:
            pass  # Widget has been deleted
            logger.debug("Suppressed exception", exc_info=True)
        
        try:
            if listener_input:
                listener_input.setVisible(enabled)
        except RuntimeError as _exc:
            pass  # Widget has been deleted
            logger.debug("Suppressed exception", exc_info=True)
    
    def switch_http_scan_view(self, tool_key, scan_type):
        """Switch HTTP results view to the appropriate scan type"""
        results_stack = getattr(self, f"{tool_key}_results_stack", None)
        terminals = getattr(self, f"{tool_key}_terminals", {})
        tables = getattr(self, f"{tool_key}_tables", {})
        
        if not results_stack or scan_type not in terminals:
            return
        
        # Clear and rebuild stack with current scan type views
        while results_stack.count() > 0:
            widget = results_stack.widget(0)
            results_stack.removeWidget(widget)
        
        # Always add the terminal for this scan type
        if scan_type in terminals:
            results_stack.addWidget(terminals[scan_type])  # Text view
        
        # Add second view only if scan type supports it (not Crawler)
        if scan_type in tables and scan_type != "Crawler":
            results_stack.addWidget(tables[scan_type])     # Table/Graph view
        elif scan_type == "Crawler" and scan_type in tables:
            # For Crawler, only add the tree view (no table option)
            results_stack.addWidget(tables[scan_type])     # Tree view only
        
        # Set current view based on what's available
        current_view = getattr(self, f"current_{tool_key}_view", "text")
        if current_view == "text" or results_stack.count() == 1:
            results_stack.setCurrentIndex(0)  # Text view
        elif current_view in ["graph", "table"] and results_stack.count() > 1:
            results_stack.setCurrentIndex(1)  # Second view
    
    def on_http_preset_changed(self, tool_key, preset):
        """Handle HTTP preset change to show/hide extension fields"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
        
        # Only show extensions when preset is "Manual" and scan type requires them
        current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Fingerprinting")
        needs_extensions = current_scan_type in ("Directory Enum", "Full Scan")
        show_extensions = needs_extensions and (preset == "Manual")
        
        # Hide/show extension rows (now a single row with grouped dropdowns)
        if hasattr(control_panel, 'row_widgets'):
            ext_rows = ['Extensions:']
            for row_label in ext_rows:
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        row_widget = control_panel.row_widgets[row_label]
                        if show_extensions:
                            row_widget.setVisible(True)
                            row_widget.setMaximumHeight(30)
                            row_widget.setMinimumHeight(26)
                        else:
                            row_widget.setVisible(False)
                            row_widget.setMaximumHeight(0)
                            row_widget.setMinimumHeight(0)
                    except RuntimeError as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
            
            # Recalculate panel height based on all visible rows
            self._recalculate_http_panel_height(tool_key)
        

    
    def update_http_view_buttons(self, tool_key, scan_type):
        """Update HTTP view buttons based on scan type"""
        # Show/hide table view button based on scan type
        table_view_btn = getattr(self, f"{tool_key}_table_view_btn", None)
        graph_view_btn = getattr(self, f"{tool_key}_graph_view_btn", None)
        
        if table_view_btn:
            # Hide table view for Fingerprinting, Source Code, Crawler, VHost Brute, and Enterprise Scripts scan types
            table_view_btn.setVisible(scan_type not in ["Fingerprinting", "Source Code", "Crawler", "VHost Brute", "Enterprise Scripts"])
        
        # Update graph button text based on scan type
        if graph_view_btn:
            if scan_type in ["Fingerprinting", "Source Code", "Crawler"]:
                # These scan types use tree/graph views
                if not graph_view_btn.icon().isNull():
                    pass  # Keep icon
                else:
                    graph_view_btn.setText("Tree" if scan_type == "Crawler" else "Graph")
            else:
                # Other scan types might use different second views
                if not graph_view_btn.icon().isNull():
                    pass  # Keep icon
                else:
                    graph_view_btn.setText("Graph")
    
    def switch_http_scan_view(self, tool_key, scan_type):
        """Switch HTTP results view to the appropriate scan type"""
        results_stack = getattr(self, f"{tool_key}_results_stack", None)
        terminals = getattr(self, f"{tool_key}_terminals", {})
        tables = getattr(self, f"{tool_key}_tables", {})
        
        if not results_stack or scan_type not in terminals:
            return
        
        # Clear and rebuild stack with current scan type views
        while results_stack.count() > 0:
            widget = results_stack.widget(0)
            results_stack.removeWidget(widget)
        
        if scan_type in terminals:
            results_stack.addWidget(terminals[scan_type])  # Text view
        if scan_type in tables:
            results_stack.addWidget(tables[scan_type])     # Table/Graph view
            # For Directory Enum, add separate table view
            if scan_type == "Directory Enum":
                dir_table = getattr(self, f"{tool_key}_dir_table", None)
                if dir_table:
                    results_stack.addWidget(dir_table)         # Table view
        
        # Set current view to text by default
        results_stack.setCurrentIndex(0)
        current_view = getattr(self, f"current_{tool_key}_view", "text")
        if current_view == "graph" and scan_type in tables:
            results_stack.setCurrentIndex(1)
        elif current_view == "table" and scan_type == "Directory Enum" and results_stack.count() > 2:
            results_stack.setCurrentIndex(2)  # Table view for Directory Enum
        elif current_view == "table" and scan_type in tables:
            results_stack.setCurrentIndex(1)
    
    def toggle_http_auth_fields(self, tool_key, auth_method):
        """Toggle HTTP authentication fields based on method selection"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        
        # Determine which fields to show based on auth method
        show_basic = (auth_method == "Basic Auth")
        show_form = (auth_method == "Form-Based Auth")
        show_session = (auth_method == "Session Replay")
        show_captured = (auth_method == "Captured Sessions")
        
        # Show/hide individual controls
        if 'http_username' in controls and controls['http_username'] is not None:
            try:
                controls['http_username'].setVisible(show_basic or show_form)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'http_password' in controls and controls['http_password'] is not None:
            try:
                controls['http_password'].setVisible(show_basic or show_form)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'http_login_url' in controls and controls['http_login_url'] is not None:
            try:
                controls['http_login_url'].setVisible(show_form)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            auth_row_visibility = {
                'Login URL:': show_form,
                'Username:': show_basic or show_form,
                'Password:': show_basic or show_form,
                'Credentials:': show_session or show_captured
            }
            
            for row_label, should_show in auth_row_visibility.items():
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        row_widget = control_panel.row_widgets[row_label]
                        if should_show:
                            row_widget.setVisible(True)
                            row_widget.setMaximumHeight(30)
                            row_widget.setMinimumHeight(26)
                        else:
                            row_widget.setVisible(False)
                            row_widget.setMaximumHeight(0)
                            row_widget.setMinimumHeight(0)
                    except RuntimeError as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
        
        # Update Credentials button text for Captured Sessions
        if 'http_cred_manager_btn' in controls and controls['http_cred_manager_btn'] is not None:
            try:
                if show_captured:
                    controls['http_cred_manager_btn'].setText("🍪 Load Captured Session Tokens")
                    controls['http_cred_manager_btn'].setVisible(True)
                elif show_session:
                    controls['http_cred_manager_btn'].setText("📋 Load from Credential Manager")
                    controls['http_cred_manager_btn'].setVisible(True)
                else:
                    controls['http_cred_manager_btn'].setVisible(False)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Recalculate panel height to accommodate newly visible/hidden rows
        self._recalculate_http_panel_height(tool_key)
    
    def load_captured_sessions(self, tool_key):
        """Load captured session tokens from the HTTP Interceptor's session harvester"""
        from PyQt6.QtWidgets import (QMessageBox, QDialog, QVBoxLayout, QHBoxLayout,
                                     QLabel, QPushButton, QTableWidget, QTableWidgetItem,
                                     QHeaderView, QAbstractItemView)
        from PyQt6.QtCore import Qt
        
        # Find the CurlWidget instance to access its session harvester
        session_harvester = None
        try:
            # Navigate up to the main window to find the HTTP Interceptor
            main_window = self
            while main_window.parent():
                main_window = main_window.parent()
            
            # Search for CurlWidget in the widget tree
            from app.widgets.curl_widget import CurlWidget
            curl_widgets = main_window.findChildren(CurlWidget)
            if curl_widgets:
                session_harvester = curl_widgets[0].session_harvester
        except Exception:
            pass
        
        if not session_harvester or not session_harvester.tokens:
            QMessageBox.information(
                self, "No Captured Sessions",
                "No session tokens have been captured yet.\n\n"
                "To capture sessions:\n"
                "1. Go to HTTP Interceptor\n"
                "2. Start the proxy\n"
                "3. Browse the target application\n"
                "4. Session tokens will be automatically harvested"
            )
            return
        
        # Get session/JWT/CSRF tokens (the useful ones for auth)
        auth_tokens = [
            t for t in session_harvester.tokens.values()
            if t.category in ('session', 'jwt', 'csrf')
        ]
        
        if not auth_tokens:
            QMessageBox.information(
                self, "No Auth Tokens",
                "Captured traffic contains no session/JWT/CSRF tokens.\n"
                "Browse authenticated pages to capture auth tokens."
            )
            return
        
        # Build a selection dialog with clickable session rows
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Captured Session Tokens")
        dialog.setModal(True)
        dialog.resize(650, 420)
        dialog.setStyleSheet("""
            QDialog {
                background-color: rgba(20, 25, 35, 240);
                border: 1px solid rgba(100, 200, 255, 80);
                border-radius: 8px;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(10)
        
        # Title
        title = QLabel("🍪 Captured Session Tokens")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Instructions
        instructions = QLabel("Select the sessions to load as authentication for the HTTP crawler scan.")
        instructions.setStyleSheet("color: #AAAAAA; font-size: 9pt;")
        instructions.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(instructions)
        
        # Session table
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["", "Type", "Name", "Domain", "Value Preview"])
        table.setRowCount(len(auth_tokens))
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(15, 20, 30, 200);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                gridline-color: rgba(100, 200, 255, 30);
            }
            QTableWidget::item {
                padding: 4px 8px;
            }
            QTableWidget::item:selected {
                background-color: rgba(100, 200, 255, 80);
                color: #FFFFFF;
            }
            QTableWidget::item:hover {
                background-color: rgba(100, 200, 255, 40);
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
                font-weight: bold;
                padding: 5px;
                border: none;
            }
        """)
        
        # Category icons/colors
        category_display = {
            'session': ('🔑', '#00FF41'),
            'jwt': ('🎫', '#FFD700'),
            'csrf': ('🛡️', '#FF6B6B'),
        }
        
        for i, token in enumerate(auth_tokens):
            icon, color = category_display.get(token.category, ('❓', '#AAAAAA'))
            
            # Checkbox-style icon column
            icon_item = QTableWidgetItem(icon)
            icon_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_item.setFlags(icon_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            table.setItem(i, 0, icon_item)
            
            # Type
            type_item = QTableWidgetItem(token.category.upper())
            type_item.setForeground(Qt.GlobalColor.white)
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            table.setItem(i, 1, type_item)
            
            # Name
            name_item = QTableWidgetItem(token.name)
            name_item.setForeground(Qt.GlobalColor.white)
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            table.setItem(i, 2, name_item)
            
            # Domain
            domain_item = QTableWidgetItem(token.domain)
            domain_item.setForeground(Qt.GlobalColor.white)
            domain_item.setFlags(domain_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            table.setItem(i, 3, domain_item)
            
            # Value preview (truncated for security)
            value_preview = token.value[:40] + "..." if len(token.value) > 40 else token.value
            value_item = QTableWidgetItem(value_preview)
            value_item.setForeground(Qt.GlobalColor.white)
            value_item.setFlags(value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            value_item.setToolTip(f"Full value: {token.value[:100]}{'...' if len(token.value) > 100 else ''}")
            table.setItem(i, 4, value_item)
        
        # Auto-resize columns
        header = table.horizontalHeader()
        table.setColumnWidth(0, 35)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(table)
        
        # Select All / Deselect All row
        select_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("Select All")
        select_all_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 200, 255, 60);
                border: 1px solid rgba(100, 200, 255, 120);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 12px;
                font-size: 9pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 100);
            }
        """)
        select_all_btn.clicked.connect(table.selectAll)
        select_layout.addWidget(select_all_btn)
        
        deselect_btn = QPushButton("Deselect All")
        deselect_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 100, 100, 60);
                border: 1px solid rgba(150, 150, 150, 120);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 12px;
                font-size: 9pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 100, 100, 100);
            }
        """)
        deselect_btn.clicked.connect(table.clearSelection)
        select_layout.addWidget(deselect_btn)
        
        select_layout.addStretch()
        
        # Selection count label
        selection_label = QLabel(f"{len(auth_tokens)} token(s) available")
        selection_label.setStyleSheet("color: #AAAAAA; font-size: 9pt;")
        select_layout.addWidget(selection_label)
        
        layout.addLayout(select_layout)
        
        # Update selection count on change
        def update_selection_count():
            selected_rows = set(idx.row() for idx in table.selectedIndexes())
            selection_label.setText(f"{len(selected_rows)} of {len(auth_tokens)} token(s) selected")
        
        table.itemSelectionChanged.connect(update_selection_count)
        
        # Action buttons
        btn_layout = QHBoxLayout()
        
        load_btn = QPushButton("⚡ Load Selected Sessions")
        load_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(50, 150, 50, 150);
                border: 2px solid #32CD32;
                border-radius: 5px;
                color: #FFFFFF;
                font-weight: bold;
                padding: 8px 16px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(50, 180, 50, 200);
            }
        """)
        btn_layout.addWidget(load_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(100, 100, 100, 150);
                border: 2px solid #666666;
                border-radius: 5px;
                color: #FFFFFF;
                font-weight: bold;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: rgba(120, 120, 120, 180);
            }
        """)
        cancel_btn.clicked.connect(dialog.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
        
        # Load button action
        def on_load_selected():
            selected_rows = sorted(set(idx.row() for idx in table.selectedIndexes()))
            if not selected_rows:
                QMessageBox.warning(dialog, "No Selection", "Please select at least one session token to load.")
                return
            
            # Build auth headers and cookies from selected tokens
            auth_cookies = {}
            auth_headers = {}
            
            for row in selected_rows:
                token = auth_tokens[row]
                if token.source == 'cookie':
                    auth_cookies[token.name] = token.value
                elif token.source == 'header':
                    if 'bearer' in token.name.lower():
                        auth_headers['Authorization'] = f"Bearer {token.value}"
                    else:
                        auth_headers[token.name] = token.value
                elif token.source == 'body' and token.category == 'jwt':
                    auth_headers['Authorization'] = f"Bearer {token.value}"
            
            # Store on the control panel for the scanner to pick up
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            if control_panel:
                control_panel.captured_auth_cookies = auth_cookies
                control_panel.captured_auth_headers = auth_headers
            
            dialog.accept()
            
            # Show brief confirmation
            loaded_count = len(selected_rows)
            QMessageBox.information(
                self, "Sessions Loaded",
                f"✓ Loaded {loaded_count} session token(s) into HTTP crawler auth.\n\n"
                f"Cookies: {len(auth_cookies)}\n"
                f"Headers: {len(auth_headers)}"
            )
        
        load_btn.clicked.connect(on_load_selected)
        
        # Pre-select all rows by default
        table.selectAll()
        update_selection_count()
        
        dialog.exec()
    
    def on_ldap_scan_type_changed(self, tool_key, scan_type):
        """Handle LDAP scan type change to show/hide auth fields"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'row_widgets'):
            return
        
        # Show auth fields for Authenticated Enum and Full Scan
        show_auth = (scan_type in ["Authenticated Enum", "Full Scan"])
        
        if 'Auth:' in control_panel.row_widgets and control_panel.row_widgets['Auth:'] is not None:
            try:
                row_widget = control_panel.row_widgets['Auth:']
                row_widget.setVisible(show_auth)
                if show_auth:
                    row_widget.setMaximumHeight(30)
                    row_widget.setMinimumHeight(26)
                else:
                    row_widget.setMaximumHeight(0)
                    row_widget.setMinimumHeight(0)
            except RuntimeError:
                pass
        
        # If hiding auth, also hide username/password
        if not show_auth:
            for row_label in ['Username:', 'Password:']:
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        row_widget = control_panel.row_widgets[row_label]
                        row_widget.setVisible(False)
                        row_widget.setMaximumHeight(0)
                        row_widget.setMinimumHeight(0)
                    except RuntimeError:
                        pass
        else:
            # Re-apply auth field visibility based on current auth type
            if hasattr(control_panel, 'controls') and 'ldap_auth_combo' in control_panel.controls:
                try:
                    current_auth = control_panel.controls['ldap_auth_combo'].currentText()
                    self.toggle_ldap_auth_fields(tool_key, current_auth)
                except RuntimeError:
                    pass
        
        # Recalculate panel height
        self._recalculate_panel_height(tool_key)
    
    def toggle_ldap_auth_fields(self, tool_key, auth_type):
        """Toggle LDAP authentication fields based on auth type selection"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'row_widgets'):
            return
        
        show_creds = (auth_type != "Anonymous")
        
        for row_label in ['Username:', 'Password:']:
            if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                try:
                    row_widget = control_panel.row_widgets[row_label]
                    row_widget.setVisible(show_creds)
                    if show_creds:
                        row_widget.setMaximumHeight(30)
                        row_widget.setMinimumHeight(26)
                    else:
                        row_widget.setMaximumHeight(0)
                        row_widget.setMinimumHeight(0)
                except RuntimeError:
                    pass
        
        # Also toggle control visibility
        if hasattr(control_panel, 'controls'):
            for ctrl_name in ['ldap_username', 'ldap_password']:
                if ctrl_name in control_panel.controls and control_panel.controls[ctrl_name] is not None:
                    try:
                        control_panel.controls[ctrl_name].setVisible(show_creds)
                    except RuntimeError:
                        pass
        
        # Recalculate panel height
        self._recalculate_panel_height(tool_key)
    
    def toggle_db_fields(self, tool_key, db_type):
        """Toggle database fields based on database type selection"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        show_oracle_sid = (db_type.upper() == "ORACLE")
        
        # Show/hide Oracle SID field
        if 'oracle_sid' in controls and controls['oracle_sid'] is not None:
            try:
                controls['oracle_sid'].setVisible(show_oracle_sid)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Update default port based on database type
        if 'db_port' in controls and controls['db_port'] is not None:
            try:
                port_defaults = {
                    'MSSQL': '1433',
                    'MYSQL': '3306',
                    'MARIADB': '3306',
                    'ORACLE': '1521',
                    'POSTGRESQL': '5432'
                }
                default_port = port_defaults.get(db_type.upper(), '1433')
                controls['db_port'].setText(default_port)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Update authentication options based on database type
        if 'db_auth_combo' in controls and controls['db_auth_combo'] is not None:
            try:
                auth_combo = controls['db_auth_combo']
                current_auth = auth_combo.currentText()
                auth_combo.clear()
                
                # Database-specific authentication types
                if db_type.upper() == 'POSTGRESQL':
                    auth_options = ["None", "SCRAM-SHA-256", "MD5", "Plain Password", "Kerberos", "Windows", "Certificate"]
                elif db_type.upper() in ['MYSQL', 'MARIADB']:
                    auth_options = ["None", "mysql_native_password", "caching_sha2_password", "PAM/LDAP/Kerberos"]
                elif db_type.upper() == 'MSSQL':
                    auth_options = ["None", "Windows Auth", "SQL Server Auth"]
                elif db_type.upper() == 'ORACLE':
                    auth_options = ["None", "Database Auth", "External Auth", "Password File Auth"]
                else:
                    auth_options = ["None"]
                
                auth_combo.addItems(auth_options)
                
                # Try to restore previous selection if it exists in new options
                if current_auth in auth_options:
                    auth_combo.setCurrentText(current_auth)
                else:
                    auth_combo.setCurrentText("None")
                    
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            if 'Oracle SID:' in control_panel.row_widgets and control_panel.row_widgets['Oracle SID:'] is not None:
                try:
                    row_widget = control_panel.row_widgets['Oracle SID:']
                    row_widget.setVisible(show_oracle_sid)
                    if show_oracle_sid:
                        row_widget.setMaximumHeight(30)
                        row_widget.setMinimumHeight(26)
                    else:
                        row_widget.setMaximumHeight(0)
                        row_widget.setMinimumHeight(0)
                except RuntimeError as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
        
        # Recalculate panel height
        self._recalculate_panel_height(tool_key)
    
    def toggle_db_auth_fields(self, tool_key, auth_type):
        """Toggle database authentication fields based on method selection"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        
        # Define field visibility based on auth type
        show_domain = (auth_type in ["Windows Auth", "Windows", "External Auth"])
        show_creds = (auth_type not in ["None", "Certificate"])
        
        # Show/hide individual controls
        if 'db_domain' in controls and controls['db_domain'] is not None:
            try:
                controls['db_domain'].setVisible(show_domain)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'db_username' in controls and controls['db_username'] is not None:
            try:
                controls['db_username'].setVisible(show_creds)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'db_password' in controls and controls['db_password'] is not None:
            try:
                controls['db_password'].setVisible(show_creds)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'password_label' in controls and controls['password_label'] is not None:
            try:
                controls['password_label'].setVisible(show_creds)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'db_cred_manager_btn' in controls and controls['db_cred_manager_btn'] is not None:
            try:
                controls['db_cred_manager_btn'].setVisible(show_creds)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            row_visibility = {
                'Domain:': show_domain,
                'Username:': show_creds,
                'Credentials:': show_creds
            }
            
            for row_label, should_show in row_visibility.items():
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        row_widget = control_panel.row_widgets[row_label]
                        if should_show:
                            row_widget.setVisible(True)
                            row_widget.setMaximumHeight(30)
                            row_widget.setMinimumHeight(26)
                        else:
                            row_widget.setVisible(False)
                            row_widget.setMaximumHeight(0)
                            row_widget.setMinimumHeight(0)
                    except RuntimeError as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
        
        # Recalculate panel height
        self._recalculate_panel_height(tool_key)
    
    def toggle_av_fields(self, tool_key, detection_type):
        """Toggle AV/Firewall detection specific fields"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        show_payload = (detection_type == "AV Payload Gen")
        
        if 'av_payload_type' in controls and controls['av_payload_type'] is not None:
            try:
                controls['av_payload_type'].setVisible(show_payload)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            if 'Payload:' in control_panel.row_widgets and control_panel.row_widgets['Payload:'] is not None:
                try:
                    control_panel.row_widgets['Payload:'].setVisible(show_payload)
                except RuntimeError as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
    
    def toggle_snmp_fields(self, tool_key, version):
        """Toggle SNMP fields based on version selection"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        show_v3_auth = (version == "3")
        
        # Show/hide SNMP v3 authentication fields
        v3_fields = ['snmp_username', 'snmp_auth_protocol', 'snmp_auth_password', 'snmp_priv_protocol', 'snmp_priv_password']
        for field in v3_fields:
            if field in controls and controls[field] is not None:
                try:
                    controls[field].setVisible(show_v3_auth)
                except RuntimeError as _exc:
                    pass
                    logger.debug("Suppressed exception", exc_info=True)
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            v3_rows = ['Username:', 'Auth Protocol:', 'Auth Password:', 'Priv Protocol:', 'Priv Password:']
            for row_label in v3_rows:
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        control_panel.row_widgets[row_label].setVisible(show_v3_auth)
                    except RuntimeError as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
    
    def toggle_ssh_auth_fields(self, tool_key, auth_type):
        """Toggle SSH authentication fields based on method selection"""
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if not control_panel or not hasattr(control_panel, 'controls'):
            return
            
        controls = control_panel.controls
        
        # Define field visibility based on auth type
        show_username = auth_type in ["Password", "Key File", "Bruteforce"]
        show_password = auth_type in ["Password", "Bruteforce"]
        show_key_path = auth_type == "Key File"
        show_wordlist = auth_type == "Bruteforce"
        
        # Show/hide individual controls
        if 'ssh_username' in controls and controls['ssh_username'] is not None:
            try:
                controls['ssh_username'].setVisible(show_username)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'ssh_password' in controls and controls['ssh_password'] is not None:
            try:
                controls['ssh_password'].setVisible(show_password)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'ssh_key_path' in controls and controls['ssh_key_path'] is not None:
            try:
                controls['ssh_key_path'].setVisible(show_key_path)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        if 'ssh_wordlist' in controls and controls['ssh_wordlist'] is not None:
            try:
                controls['ssh_wordlist'].setVisible(show_wordlist)
            except RuntimeError as _exc:
                pass
                logger.debug("Suppressed exception", exc_info=True)
        
        # Hide/show rows if available
        if hasattr(control_panel, 'row_widgets'):
            row_visibility = {
                'Username:': show_username,
                'Password:': show_password,
                'Key Path:': show_key_path,
                'Wordlist:': show_wordlist
            }
            
            for row_label, should_show in row_visibility.items():
                if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                    try:
                        row_widget = control_panel.row_widgets[row_label]
                        if should_show:
                            row_widget.setVisible(True)
                            row_widget.setMaximumHeight(30)
                            row_widget.setMinimumHeight(26)
                        else:
                            row_widget.setVisible(False)
                            row_widget.setMaximumHeight(0)
                            row_widget.setMinimumHeight(0)
                    except RuntimeError as _exc:
                        pass
                        logger.debug("Suppressed exception", exc_info=True)
        
        # Recalculate panel height
        self._recalculate_panel_height(tool_key)
    
    def on_ssh_scan_type_changed(self, tool_key, scan_type):
        """Handle SSH scan type change to switch terminal views and hide auth fields"""
        setattr(self, f"{tool_key}_current_scan_type", scan_type)
        
        # Hide Auth Type field for non-authentication scan types
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if control_panel and hasattr(control_panel, 'row_widgets'):
            auth_row = control_panel.row_widgets.get('Auth Type:')
            if auth_row:
                show_auth = (scan_type in ["Enumeration", "Full Scan"])
                auth_row.setVisible(show_auth)
                if not show_auth:
                    auth_row.setMaximumHeight(0)
                    auth_row.setMinimumHeight(0)
                    # Also hide auth-dependent rows when auth is hidden
                    for row_label in ['Username:', 'Password:', 'Key Path:', 'Wordlist:']:
                        if row_label in control_panel.row_widgets and control_panel.row_widgets[row_label] is not None:
                            try:
                                row_widget = control_panel.row_widgets[row_label]
                                row_widget.setVisible(False)
                                row_widget.setMaximumHeight(0)
                                row_widget.setMinimumHeight(0)
                            except RuntimeError:
                                pass
                else:
                    auth_row.setMaximumHeight(30)
                    auth_row.setMinimumHeight(26)
                    # Re-apply auth field visibility based on current auth type
                    if hasattr(control_panel, 'controls') and 'ssh_auth_type' in control_panel.controls:
                        try:
                            current_auth = control_panel.controls['ssh_auth_type'].currentText()
                            self.toggle_ssh_auth_fields(tool_key, current_auth)
                        except RuntimeError:
                            pass
            
            # Recalculate panel height
            self._recalculate_panel_height(tool_key)
        
        # Update the results stack to show the correct terminal/table for this scan type
        results_stack = getattr(self, f"{tool_key}_results_stack", None)
        current_view = getattr(self, f"current_{tool_key}_view", "text")
        
        if not results_stack:
            return
        
        terminals = getattr(self, f"{tool_key}_terminals", {})
        tables = getattr(self, f"{tool_key}_tables", {})
        trees = getattr(self, f"{tool_key}_trees", {})
        
        # Clear and rebuild stack with current scan type views
        while results_stack.count() > 0:
            widget = results_stack.widget(0)
            results_stack.removeWidget(widget)
        
        if scan_type in terminals:
            results_stack.addWidget(terminals[scan_type])  # Text view
        if scan_type in trees:
            results_stack.addWidget(trees[scan_type])      # Tree view
        if scan_type in tables:
            results_stack.addWidget(tables[scan_type])     # Table view
        
        # Set correct view index based on current view (SSH only has text and graph)
        if current_view == "text":
            results_stack.setCurrentIndex(0)
        elif current_view == "graph":
            results_stack.setCurrentIndex(1)  # Tree view for SSH
    
    def on_smb_scan_type_changed(self, tool_key, scan_type):
        """Handle SMB scan type change to switch terminal views"""
        setattr(self, f"{tool_key}_current_scan_type", scan_type)
        
        # Show/hide wordlist row based on scan type
        control_panel = getattr(self, f"{tool_key}_control_panel", None)
        if control_panel and hasattr(control_panel, 'row_widgets'):
            show_wordlist = (scan_type == "Share Enumeration")
            if 'Wordlist:' in control_panel.row_widgets and control_panel.row_widgets['Wordlist:'] is not None:
                try:
                    row_widget = control_panel.row_widgets['Wordlist:']
                    row_widget.setVisible(show_wordlist)
                    if show_wordlist:
                        row_widget.setMaximumHeight(30)
                        row_widget.setMinimumHeight(26)
                    else:
                        row_widget.setMaximumHeight(0)
                        row_widget.setMinimumHeight(0)
                except RuntimeError:
                    pass
            
            # Also toggle the wordlist combobox control visibility
            if hasattr(control_panel, 'controls') and 'smb_wordlist' in control_panel.controls:
                try:
                    control_panel.controls['smb_wordlist'].setVisible(show_wordlist)
                except RuntimeError:
                    pass
            
            # Recalculate panel height
            self._recalculate_smb_panel_height(tool_key)
        
        # Update the results stack to show the correct terminal/table for this scan type
        results_stack = getattr(self, f"{tool_key}_results_stack", None)
        current_view = getattr(self, f"current_{tool_key}_view", "text")
        
        if not results_stack:
            return
        
        terminals = getattr(self, f"{tool_key}_terminals", {})
        tables = getattr(self, f"{tool_key}_tables", {})
        trees = getattr(self, f"{tool_key}_trees", {})
        
        # Clear and rebuild stack with current scan type views
        while results_stack.count() > 0:
            widget = results_stack.widget(0)
            results_stack.removeWidget(widget)
        
        if scan_type in terminals:
            results_stack.addWidget(terminals[scan_type])  # Text view
        if scan_type in trees:
            results_stack.addWidget(trees[scan_type])      # Tree view
        if scan_type in tables:
            results_stack.addWidget(tables[scan_type])     # Table view
        
        # Set correct view index based on current view
        if current_view == "text":
            results_stack.setCurrentIndex(0)
        elif current_view == "graph":
            results_stack.setCurrentIndex(1)  # Tree view for SMB
        elif current_view == "table":
            results_stack.setCurrentIndex(2)  # Table view for SMB
    
    def on_rpc_scan_type_changed(self, tool_key, scan_type):
        """Handle RPC scan type change to switch terminal views"""
        setattr(self, f"{tool_key}_current_scan_type", scan_type)
        
        # Update the results stack to show the correct terminal/table for this scan type
        results_stack = getattr(self, f"{tool_key}_results_stack", None)
        current_view = getattr(self, f"current_{tool_key}_view", "text")
        
        if not results_stack:
            return
        
        terminals = getattr(self, f"{tool_key}_terminals", {})
        tables = getattr(self, f"{tool_key}_tables", {})
        trees = getattr(self, f"{tool_key}_trees", {})
        
        # Clear and rebuild stack with current scan type views
        while results_stack.count() > 0:
            widget = results_stack.widget(0)
            results_stack.removeWidget(widget)
        
        if scan_type in terminals:
            results_stack.addWidget(terminals[scan_type])  # Text view
        if scan_type in trees:
            results_stack.addWidget(trees[scan_type])      # Tree view
        if scan_type in tables:
            results_stack.addWidget(tables[scan_type])     # Table view
        
        # Set correct view index based on current view
        if current_view == "text":
            results_stack.setCurrentIndex(0)
        elif current_view == "graph":
            results_stack.setCurrentIndex(1)  # Tree view for RPC
        elif current_view == "table":
            results_stack.setCurrentIndex(2)  # Table view for RPC
    
    def check_dns_target_type(self):
        """Check and validate DNS target type"""
        if not hasattr(self, 'dns_target_input'):
            return
            
        text = self.dns_target_input.text().strip()
        # Check if target looks like IP (3 octets with dots)
        import re
        ip_pattern = r'^(\d{1,3}\.){2,3}\d{1,3}'
        is_ip_like = bool(re.match(ip_pattern, text))
        
        if is_ip_like:
            # Enable PTR, disable and uncheck others
            if hasattr(self, 'ptr_checkbox'):
                self.ptr_checkbox.setEnabled(True)
                self.ptr_checkbox.setChecked(True)
            if hasattr(self, 'all_checkbox'):
                self.all_checkbox.setEnabled(False)
                self.all_checkbox.setChecked(False)
            if hasattr(self, 'dns_record_types'):
                for checkbox in self.dns_record_types.values():
                    checkbox.setEnabled(False)
                    checkbox.setChecked(False)
            # Hide method row when PTR is active
            if hasattr(self, 'method_row_layout'):
                for i in range(self.method_row_layout.count()):
                    item = self.method_row_layout.itemAt(i)
                    if item and item.widget():
                        item.widget().setVisible(False)
        else:
            # Enable others, disable PTR
            if hasattr(self, 'ptr_checkbox'):
                self.ptr_checkbox.setEnabled(False)
                self.ptr_checkbox.setChecked(False)
            if hasattr(self, 'all_checkbox'):
                self.all_checkbox.setEnabled(True)
            if hasattr(self, 'dns_record_types'):
                for checkbox in self.dns_record_types.values():
                    checkbox.setEnabled(True)
                # Set A record as default when switching from IP
                if text and not any(cb.isChecked() for cb in self.dns_record_types.values()):
                    self.dns_record_types['A'].setChecked(True)
            # Show method row when PTR is not active
            if hasattr(self, 'method_row_layout'):
                for i in range(self.method_row_layout.count()):
                    item = self.method_row_layout.itemAt(i)
                    if item and item.widget():
                        item.widget().setVisible(True)
                # Re-apply method visibility settings
                if hasattr(self, 'method_combo'):
                    self.toggle_method_options(self.method_combo.currentText())
    
    def toggle_all_records(self):
        """Toggle all DNS record types"""
        if not hasattr(self, 'all_checkbox') or not hasattr(self, 'dns_record_types'):
            return
            
        state = self.all_checkbox.isChecked()
        for checkbox in self.dns_record_types.values():
            checkbox.setChecked(state)
        if hasattr(self, 'ptr_checkbox') and self.ptr_checkbox.isEnabled():
            self.ptr_checkbox.setChecked(state)
    
    def update_all_checkbox(self):
        """Update all checkbox state"""
        if not hasattr(self, 'all_checkbox') or not hasattr(self, 'dns_record_types'):
            return
            
        all_checked = all(cb.isChecked() for cb in self.dns_record_types.values())
        if hasattr(self, 'ptr_checkbox') and self.ptr_checkbox.isEnabled():
            all_checked = all_checked and self.ptr_checkbox.isChecked()
        self.all_checkbox.setChecked(all_checked)
    
    def toggle_method_options(self, method):
        """Toggle DNS method options"""
        if not hasattr(self, 'wordlist_combo'):
            return
            
        is_wordlist = (method == "Wordlist")
        
        self.wordlist_combo.setVisible(is_wordlist)
        
        # Toggle bruteforce options visibility
        if hasattr(self, 'bruteforce_label'):
            self.bruteforce_label.setVisible(not is_wordlist)
        if hasattr(self, 'length_label'):
            self.length_label.setVisible(not is_wordlist)
        if hasattr(self, 'length_spinbox'):
            self.length_spinbox.setVisible(not is_wordlist)
        if hasattr(self, 'char_checkboxes'):
            for checkbox in self.char_checkboxes.values():
                checkbox.setVisible(not is_wordlist)
    
    def populate_dns_wordlists(self):
        """Populate DNS wordlist dropdown"""
        if not hasattr(self, 'wordlist_combo'):
            return
            
        self.wordlist_combo.addItem("Default subdomains", None)
        wordlist_dir = os.path.join(self.main_window.project_root, "resources", "wordlists")
        if os.path.exists(wordlist_dir):
            for filename in os.listdir(wordlist_dir):
                if filename.endswith(".txt"):
                    self.wordlist_combo.addItem(filename, os.path.join(wordlist_dir, filename))
        
        # Set default wordlist to subdomains-top1000.txt
        default_wordlist_path = os.path.join(wordlist_dir, "subdomains-top1000.txt")
        for i in range(self.wordlist_combo.count()):
            if self.wordlist_combo.itemData(i) == default_wordlist_path:
                self.wordlist_combo.setCurrentIndex(i)
                break
    
    def launch_huginn_scanner(self, tool_key):
        """Launch Huginn Advanced Scanner dialog"""
        try:
            from app.components.huginn_scanner_component import HuginnScannerComponent
            from PyQt6.QtWidgets import QDialog, QVBoxLayout
            
            # Get target from the HTTP target input
            target_input = getattr(self, f"{tool_key}_target_input", None)
            target = target_input.text().strip() if target_input else ""
            
            if not target:
                self.status_updated.emit("Please enter a target URL for Huginn scanner")
                return
            
            # Create dialog for Huginn scanner
            dialog = QDialog(self)
            dialog.setWindowTitle("🚀 Huginn Advanced Security Scanner")
            dialog.setModal(True)
            dialog.resize(1200, 800)
            
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(10, 10, 10, 10)
            
            # Create Huginn scanner component
            huginn_component = HuginnScannerComponent(dialog)
            
            # Pre-fill target if provided
            if target:
                huginn_component.target_input.setText(target)
            
            layout.addWidget(huginn_component)
            
            # Connect signals
            huginn_component.scan_completed.connect(lambda results: self.on_huginn_scan_completed(tool_key, results))
            
            self.status_updated.emit("Huginn Advanced Scanner opened")
            dialog.exec()
            
        except ImportError as e:
            self.status_updated.emit(f"Huginn scanner not available: {e}")
        except Exception as e:
            self.status_updated.emit(f"Error launching Huginn scanner: {e}")
    
    def on_huginn_scan_completed(self, tool_key, results):
        """Handle Huginn scan completion"""
        try:
            # Display results in the HTTP terminal
            current_scan_type = getattr(self, f"{tool_key}_current_scan_type", "Huginn Scan")
            
            vuln_count = len(results.get('vulnerabilities', []))
            
            # Use append_http_output if available, otherwise append_service_output
            if hasattr(self, 'append_http_output'):
                self.append_http_output(tool_key, current_scan_type, 
                    f"<p style='color: #00FF41;'>[HUGINN] Scan completed - {vuln_count} vulnerabilities found</p><br>")
            elif hasattr(self, 'append_service_output'):
                self.append_service_output(tool_key, 
                    f"<p style='color: #00FF41;'>[HUGINN] Scan completed - {vuln_count} vulnerabilities found</p><br>")
            
            # Store results if method available
            if hasattr(self, 'store_http_results'):
                self.store_http_results(tool_key, current_scan_type, results)
            
            # Enable export button
            export_button = getattr(self, f"{tool_key}_export_button", None)
            if export_button:
                export_button.setEnabled(True)
                
            self.status_updated.emit(f"Huginn scan completed - {vuln_count} vulnerabilities found")
            
        except Exception as e:
            self.status_updated.emit(f"Error processing Huginn results: {e}")
    

    
    def open_db_credential_manager(self, tool_key):
        """Open credential manager for database authentication"""
        try:
            from app.core.credential_manager import credential_manager
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout
            
            dialog = QDialog(self)
            dialog.setWindowTitle("Select Database Credentials")
            dialog.resize(400, 300)
            
            layout = QVBoxLayout(dialog)
            
            # Get database credentials
            db_creds = credential_manager.get_mssql_credentials()
            
            if not db_creds:
                from PyQt6.QtWidgets import QLabel
                layout.addWidget(QLabel("No database credentials found."))
                close_btn = QPushButton("Close")
                close_btn.clicked.connect(dialog.close)
                layout.addWidget(close_btn)
            else:
                # Create list of credentials
                cred_list = QListWidget()
                for cred in db_creds:
                    display_text = f"{getattr(cred, 'username', 'Unknown')} ({getattr(cred, 'type', 'Unknown')}) - {getattr(cred, 'description', 'No description')}"
                    cred_list.addItem(display_text)
                layout.addWidget(cred_list)
                
                # Buttons
                btn_layout = QHBoxLayout()
                select_btn = QPushButton("Select")
                cancel_btn = QPushButton("Cancel")
                
                def apply_credential():
                    current_row = cred_list.currentRow()
                    if current_row >= 0:
                        selected_cred = db_creds[current_row]
                        self.apply_db_credentials(tool_key, selected_cred)
                        dialog.accept()
                
                select_btn.clicked.connect(apply_credential)
                cancel_btn.clicked.connect(dialog.reject)
                
                btn_layout.addWidget(select_btn)
                btn_layout.addWidget(cancel_btn)
                layout.addLayout(btn_layout)
            
            dialog.exec()
            
        except Exception as e:
            print(f"Error opening credential manager: {e}")
            if hasattr(self, 'status_updated'):
                self.status_updated.emit(f"Error: {e}")
    
    def apply_db_credentials(self, tool_key, cred_data):
        """Apply selected database credentials to form fields"""
        try:
            control_panel = getattr(self, f"{tool_key}_control_panel", None)
            if not control_panel or not hasattr(control_panel, 'controls'):
                return
            
            controls = control_panel.controls
            
            # Apply credentials to fields
            if hasattr(cred_data, 'username') and 'db_username' in controls:
                controls['db_username'].setText(getattr(cred_data, 'username', ''))
            if hasattr(cred_data, 'password') and 'db_password' in controls:
                controls['db_password'].setText(getattr(cred_data, 'password', ''))
            if hasattr(cred_data, 'domain') and 'db_domain' in controls:
                controls['db_domain'].setText(getattr(cred_data, 'domain', ''))
            
            # Set auth type
            if 'db_auth_combo' in controls:
                cred_type = getattr(cred_data, 'type', '')
                if cred_type == 'Windows Auth':
                    controls['db_auth_combo'].setCurrentText('Windows Auth')
                elif cred_type == 'SQL Server Auth':
                    controls['db_auth_combo'].setCurrentText('MSSQL Auth')
            
            if hasattr(self, 'status_updated'):
                self.status_updated.emit(f"Applied credentials for {getattr(cred_data, 'username', 'user')}")
                
        except Exception as e:
            print(f"Error applying credentials: {e}")
    
    def switch_db_terminal(self, tool_key, scan_type):
        """Switch database terminal to the specified scan type"""
        try:
            results_stack = getattr(self, f"{tool_key}_results_stack", None)
            terminals = getattr(self, f"{tool_key}_terminals", {})
            tables = getattr(self, f"{tool_key}_tables", {})
            
            if not results_stack:
                return
            
            # Store current scan type
            setattr(self, f"{tool_key}_current_scan_type", scan_type)
            
            # Only switch if the scan type exists in terminals
            if scan_type in terminals:
                # Clear and rebuild stack with current scan type views
                while results_stack.count() > 0:
                    widget = results_stack.widget(0)
                    results_stack.removeWidget(widget)
                
                # Add terminal and table for this scan type
                results_stack.addWidget(terminals[scan_type])  # Text view
                if scan_type in tables:
                    results_stack.addWidget(tables[scan_type])     # Table view
                
                # Set current view to text by default
                results_stack.setCurrentIndex(0)
                current_view = getattr(self, f"current_{tool_key}_view", "text")
                if current_view == "table" and results_stack.count() > 1:
                    results_stack.setCurrentIndex(1)
        except Exception as e:
            print(f"Error in switch_db_terminal: {e}")
    
    def on_db_scan_type_changed(self, tool_key, scan_type):
        """Handle database scan type change to switch terminal views"""
        try:
            setattr(self, f"{tool_key}_current_scan_type", scan_type)
            self.switch_db_scan_view(tool_key, scan_type)
        except Exception as e:
            print(f"Error switching DB terminal: {e}")
    

    
    def on_http_oob_changed(self, tool_key, enabled, listener_id):
        """Handle OOB listener state change"""
        if enabled:
            self.status_updated.emit(f"OOB listener enabled for {tool_key}: {listener_id}")
        else:
            self.status_updated.emit(f"OOB listener disabled for {tool_key}")
    
    def apply_terminal_theme(self):
        """Apply theme-specific styling to DNS terminal"""
        if not hasattr(self, 'dns_terminal'):
            return
            
        # Get current theme from main window
        current_theme = getattr(self.main_window, 'current_theme', 'dark_blue')
        
        if current_theme == 'matrix':
            # Matrix theme with ShareTechMono font
            self.dns_terminal.setStyleSheet("""
                QTextEdit {
                    background-color: #000000;
                    color: #00FF41;
                    font-family: 'Share Tech Mono', monospace;
                    font-size: 11pt;
                    border: 1px solid #00FF41;
                    border-radius: 5px;
                    selection-background-color: #003300;
                }
            """)
        else:
            # Dark Blue theme with Neuropol font (default)
            self.dns_terminal.setStyleSheet("""
                QTextEdit {
                    background-color: #1E1E1E;
                    color: #DCDCDC;
                    font-family: 'Neuropol X', monospace;
                    font-size: 10pt;
                    border: 1px solid rgba(100, 200, 255, 100);
                    border-radius: 5px;
                    selection-background-color: #2D4F7C;
                }
            """)