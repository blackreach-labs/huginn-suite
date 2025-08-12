# app/widgets/remediation_widget.py
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from ..core.automated_remediation import create_remediation_engine, RemediationAction
from ..core.cross_scan_correlator import create_cross_scan_correlator

class RemediationWidget(QWidget):
    """Widget for displaying and managing automated remediation"""
    
    def __init__(self, tenant_id: str = "default"):
        super().__init__()
        self.tenant_id = tenant_id
        self.remediation_engine = create_remediation_engine(tenant_id)
        self.correlator = create_cross_scan_correlator(tenant_id)
        self.remediation_actions = []
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the remediation widget UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("🛠️ Automated Remediation")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50;")
        header_layout.addWidget(title)
        
        # Generate plan button
        generate_btn = QPushButton("🔄 Generate Plan")
        generate_btn.clicked.connect(self.generate_remediation_plan)
        generate_btn.setMaximumWidth(120)
        header_layout.addWidget(generate_btn)
        
        layout.addLayout(header_layout)
        
        # Statistics panel
        self.stats_widget = self.create_stats_widget()
        layout.addWidget(self.stats_widget)
        
        # Main content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Actions list
        left_panel = self.create_actions_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Details and scripts
        right_panel = self.create_details_panel()
        splitter.addWidget(right_panel)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
        # Generate initial plan
        self.generate_remediation_plan()
    
    def create_stats_widget(self) -> QWidget:
        """Create statistics overview widget"""
        widget = QFrame()
        widget.setFrameStyle(QFrame.Shape.Box)
        widget.setMaximumHeight(80)
        
        layout = QHBoxLayout(widget)
        
        self.total_actions_label = QLabel("Total Actions: 0")
        self.critical_actions_label = QLabel("Critical: 0")
        self.high_actions_label = QLabel("High: 0")
        self.estimated_time_label = QLabel("Est. Time: 0 min")
        self.risk_reduction_label = QLabel("Risk Reduction: 0%")
        
        # Style labels
        for label in [self.total_actions_label, self.critical_actions_label, 
                     self.high_actions_label, self.estimated_time_label, self.risk_reduction_label]:
            label.setStyleSheet("font-weight: bold; padding: 5px;")
        
        self.critical_actions_label.setStyleSheet("font-weight: bold; color: #e74c3c; padding: 5px;")
        self.high_actions_label.setStyleSheet("font-weight: bold; color: #f39c12; padding: 5px;")
        
        layout.addWidget(self.total_actions_label)
        layout.addWidget(QLabel("|"))
        layout.addWidget(self.critical_actions_label)
        layout.addWidget(self.high_actions_label)
        layout.addWidget(QLabel("|"))
        layout.addWidget(self.estimated_time_label)
        layout.addWidget(self.risk_reduction_label)
        layout.addStretch()
        
        return widget
    
    def create_actions_panel(self) -> QWidget:
        """Create remediation actions panel"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Panel title
        title = QLabel("🔧 Remediation Actions")
        title.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(title)
        
        # Actions tree
        self.actions_tree = QTreeWidget()
        self.actions_tree.setHeaderLabels([
            "Priority", "Action", "Type", "Time", "Risk Reduction"
        ])
        self.actions_tree.itemClicked.connect(self.on_action_selected)
        layout.addWidget(self.actions_tree)
        
        return widget
    
    def create_details_panel(self) -> QWidget:
        """Create details panel"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Tab widget for different views
        self.details_tabs = QTabWidget()
        
        # Action details tab
        self.details_tab = self.create_action_details_tab()
        self.details_tabs.addTab(self.details_tab, "📋 Details")
        
        # PowerShell script tab
        self.powershell_tab = self.create_script_tab("PowerShell")
        self.details_tabs.addTab(self.powershell_tab, "💻 PowerShell")
        
        # Bash script tab
        self.bash_tab = self.create_script_tab("Bash")
        self.details_tabs.addTab(self.bash_tab, "🐧 Bash")
        
        layout.addWidget(self.details_tabs)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        export_json_btn = QPushButton("📄 Export JSON")
        export_json_btn.clicked.connect(self.export_json)
        export_layout.addWidget(export_json_btn)
        
        export_ps_btn = QPushButton("💾 Save PowerShell")
        export_ps_btn.clicked.connect(self.export_powershell)
        export_layout.addWidget(export_ps_btn)
        
        export_bash_btn = QPushButton("💾 Save Bash")
        export_bash_btn.clicked.connect(self.export_bash)
        export_layout.addWidget(export_bash_btn)
        
        export_layout.addStretch()
        layout.addLayout(export_layout)
        
        return widget
    
    def create_action_details_tab(self) -> QWidget:
        """Create action details tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        layout.addWidget(self.details_text)
        
        return widget
    
    def create_script_tab(self, script_type: str) -> QWidget:
        """Create script tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        script_text = QTextEdit()
        script_text.setReadOnly(True)
        script_text.setFont(QFont("Consolas", 10))
        layout.addWidget(script_text)
        
        return widget
    
    def generate_remediation_plan(self):
        """Generate remediation plan from correlations"""
        try:
            # Get correlations
            correlations = self.correlator.correlate_all_findings(time_window_hours=24)
            
            # Generate remediation actions
            self.remediation_actions = self.remediation_engine.generate_remediation_plan(correlations)
            
            # Update UI
            self.update_statistics()
            self.update_actions_tree()
            self.update_scripts()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate remediation plan: {e}")
    
    def update_statistics(self):
        """Update statistics display"""
        total = len(self.remediation_actions)
        critical = len([a for a in self.remediation_actions if a.priority == 'Critical'])
        high = len([a for a in self.remediation_actions if a.priority == 'High'])
        
        # Calculate estimated time (convert to minutes)
        total_minutes = 0
        for action in self.remediation_actions:
            time_str = action.estimated_time
            if 'minute' in time_str:
                minutes = int(time_str.split()[0])
                total_minutes += minutes
        
        # Calculate average risk reduction
        avg_risk_reduction = sum(a.risk_reduction for a in self.remediation_actions) / len(self.remediation_actions) if self.remediation_actions else 0
        
        self.total_actions_label.setText(f"Total Actions: {total}")
        self.critical_actions_label.setText(f"Critical: {critical}")
        self.high_actions_label.setText(f"High: {high}")
        self.estimated_time_label.setText(f"Est. Time: {total_minutes} min")
        self.risk_reduction_label.setText(f"Risk Reduction: {avg_risk_reduction:.1f}/10")
    
    def update_actions_tree(self):
        """Update actions tree widget"""
        self.actions_tree.clear()
        
        for action in self.remediation_actions:
            item = QTreeWidgetItem([
                action.priority,
                action.title,
                action.action_type.replace('_', ' ').title(),
                action.estimated_time,
                f"{action.risk_reduction:.1f}/10"
            ])
            
            # Color code by priority
            if action.priority == 'Critical':
                item.setForeground(0, QColor('#e74c3c'))
            elif action.priority == 'High':
                item.setForeground(0, QColor('#f39c12'))
            elif action.priority == 'Medium':
                item.setForeground(0, QColor('#f1c40f'))
            
            # Store action data
            item.setData(0, Qt.ItemDataRole.UserRole, action)
            
            self.actions_tree.addTopLevelItem(item)
        
        # Resize columns
        for i in range(self.actions_tree.columnCount()):
            self.actions_tree.resizeColumnToContents(i)
    
    def update_scripts(self):
        """Update script tabs"""
        if not self.remediation_actions:
            return
        
        # Generate PowerShell script
        powershell_script = self.remediation_engine.generate_powershell_script(self.remediation_actions)
        powershell_widget = self.details_tabs.widget(1).findChild(QTextEdit)
        if powershell_widget:
            powershell_widget.setPlainText(powershell_script)
        
        # Generate Bash script
        bash_script = self.remediation_engine.generate_bash_script(self.remediation_actions)
        bash_widget = self.details_tabs.widget(2).findChild(QTextEdit)
        if bash_widget:
            bash_widget.setPlainText(bash_script)
    
    def on_action_selected(self, item, column):
        """Handle action selection"""
        action = item.data(0, Qt.ItemDataRole.UserRole)
        if action:
            self.display_action_details(action)
    
    def display_action_details(self, action: RemediationAction):
        """Display detailed action information"""
        details_html = f"""
        <h2>{action.title}</h2>
        <p><strong>Priority:</strong> <span style="color: {'#e74c3c' if action.priority == 'Critical' else '#f39c12' if action.priority == 'High' else '#f1c40f'}">{action.priority}</span></p>
        <p><strong>Type:</strong> {action.action_type.replace('_', ' ').title()}</p>
        <p><strong>Estimated Time:</strong> {action.estimated_time}</p>
        <p><strong>Risk Reduction:</strong> {action.risk_reduction}/10</p>
        
        <h3>Description</h3>
        <p>{action.description}</p>
        
        <h3>Commands</h3>
        <pre style="background-color: #f8f9fa; padding: 10px; border-radius: 5px;">
        """
        
        for command in action.commands:
            details_html += f"{command}\n"
        
        details_html += """
        </pre>
        
        <h3>Configuration Changes</h3>
        <pre style="background-color: #f8f9fa; padding: 10px; border-radius: 5px;">
        """
        
        import json
        details_html += json.dumps(action.config_changes, indent=2)
        
        details_html += """
        </pre>
        
        <h3>Verification Steps</h3>
        <ol>
        """
        
        for step in action.verification_steps:
            details_html += f"<li><code>{step}</code></li>"
        
        details_html += "</ol>"
        
        self.details_text.setHtml(details_html)
    
    def export_json(self):
        """Export remediation plan as JSON"""
        if not self.remediation_actions:
            QMessageBox.information(self, "Export", "No remediation actions to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Remediation Plan", 
            f"remediation_plan_{self.tenant_id}.json",
            "JSON Files (*.json)"
        )
        
        if filename:
            try:
                export_data = self.remediation_engine.export_remediation_plan(self.remediation_actions)
                with open(filename, 'w') as f:
                    f.write(export_data)
                QMessageBox.information(self, "Export", f"Remediation plan exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export: {e}")
    
    def export_powershell(self):
        """Export PowerShell script"""
        if not self.remediation_actions:
            QMessageBox.information(self, "Export", "No remediation actions to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save PowerShell Script", 
            f"remediation_{self.tenant_id}.ps1",
            "PowerShell Files (*.ps1)"
        )
        
        if filename:
            try:
                script = self.remediation_engine.generate_powershell_script(self.remediation_actions)
                with open(filename, 'w') as f:
                    f.write(script)
                QMessageBox.information(self, "Export", f"PowerShell script saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save script: {e}")
    
    def export_bash(self):
        """Export Bash script"""
        if not self.remediation_actions:
            QMessageBox.information(self, "Export", "No remediation actions to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Bash Script", 
            f"remediation_{self.tenant_id}.sh",
            "Shell Scripts (*.sh)"
        )
        
        if filename:
            try:
                script = self.remediation_engine.generate_bash_script(self.remediation_actions)
                with open(filename, 'w') as f:
                    f.write(script)
                QMessageBox.information(self, "Export", f"Bash script saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to save script: {e}")