# app/widgets/contextual_help_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QTextEdit, QScrollArea, QTabWidget)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QFont

class ContextualHelpWidget(QWidget):
    """Contextual help system that provides beginner-friendly explanations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_context = "general"
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the contextual help UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Header
        header = QLabel("💡 Contextual Help")
        header.setStyleSheet("font-size: 16pt; font-weight: bold; color: #64C8FF; margin-bottom: 10px;")
        layout.addWidget(header)
        
        # Tab widget for different help categories
        self.help_tabs = QTabWidget()
        self.help_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                background-color: rgba(0, 0, 0, 100);
            }
            QTabBar::tab {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                font-size: 10pt;
            }
            QTabBar::tab:selected {
                background-color: rgba(100, 200, 255, 100);
                color: #000000;
                font-weight: bold;
            }
        """)
        
        # Create help tabs
        self.create_methodology_tab()
        self.create_tools_tab()
        self.create_techniques_tab()
        self.create_troubleshooting_tab()
        
        layout.addWidget(self.help_tabs)
        
    def create_methodology_tab(self):
        """Create methodology explanation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 10px;
            }
        """)
        
        methodology_text = """
🎯 PENETRATION TESTING METHODOLOGY

The penetration testing process follows a structured approach to ensure comprehensive security assessment:

📋 1. ENGAGEMENT SETUP (Planning Phase)
• Define scope and objectives
• Gather target information
• Set up testing environment
• Review rules of engagement

🔍 2. RECONNAISSANCE (Information Gathering)
• Passive information gathering (OSINT)
• Active information gathering (scanning)
• Service enumeration and fingerprinting
• Vulnerability identification

💥 3. EXPLOITATION (Gaining Access)
• Exploit identified vulnerabilities
• Gain initial access to systems
• Establish persistent access
• Document proof of compromise

🔄 4. POST-EXPLOITATION (Maintaining Access)
• Privilege escalation
• Lateral movement
• Data collection and exfiltration
• Persistence mechanisms

📋 5. REPORTING (Documentation)
• Document all findings
• Assess business impact
• Provide remediation guidance
• Present results to stakeholders

💡 WHY THIS ORDER MATTERS:
Each phase builds upon the previous one. Reconnaissance provides targets for exploitation, 
exploitation provides access for post-exploitation activities, and all phases provide 
evidence for comprehensive reporting.

🎯 BEGINNER TIPS:
• Always get written authorization before testing
• Start with automated tools, then move to manual testing
• Document everything as you go
• Focus on high-impact vulnerabilities first
• Don't skip the reconnaissance phase - it's crucial!
        """
        
        content.setPlainText(methodology_text)
        layout.addWidget(content)
        
        self.help_tabs.addTab(tab, "📋 Methodology")
    
    def create_tools_tab(self):
        """Create tools explanation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 10px;
            }
        """)
        
        tools_text = """
🛠️ PENETRATION TESTING TOOLS GUIDE

🔍 RECONNAISSANCE TOOLS:

🌐 OSINT Collection
• Purpose: Gather public information about targets
• When to use: Beginning of every engagement
• What it finds: Email addresses, employee names, technologies, subdomains
• Beginner tip: Start here - it's passive and won't alert the target

📡 Port Scanning  
• Purpose: Discover open ports and services
• When to use: After identifying live hosts
• What it finds: Open ports, service versions, operating systems
• Beginner tip: Start with common ports, then expand to full range

🌐 DNS Enumeration
• Purpose: Discover subdomains and DNS records
• When to use: Early reconnaissance phase
• What it finds: Subdomains, mail servers, DNS misconfigurations
• Beginner tip: Use wordlists for subdomain brute-forcing

🎯 VULNERABILITY ASSESSMENT TOOLS:

🚀 Huginn Advanced Scanner
• Purpose: AI-powered comprehensive vulnerability scanning
• When to use: After service enumeration
• What it finds: Web app vulnerabilities, misconfigurations, security issues
• Beginner tip: Start with 'Normal' profile, review all findings

🌐 Web Application Testing
• Purpose: Manual testing of web applications
• When to use: After automated scanning
• What it finds: Business logic flaws, complex vulnerabilities
• Beginner tip: Focus on input validation and authentication

💥 EXPLOITATION TOOLS:

🔓 Web Exploits
• Purpose: Exploit web application vulnerabilities
• When to use: After confirming vulnerabilities
• What it does: Demonstrates impact of vulnerabilities
• Beginner tip: Always test in a controlled manner

🐚 Shell Management
• Purpose: Manage compromised systems
• When to use: After gaining initial access
• What it does: Maintains access, executes commands
• Beginner tip: Document all actions for reporting

📊 REPORTING TOOLS:

📋 Findings Management
• Purpose: Organize and document discoveries
• When to use: Throughout the engagement
• What it does: Tracks vulnerabilities, evidence, remediation
• Beginner tip: Document as you go, don't wait until the end

💡 TOOL SELECTION TIPS:
• Start with automated tools for broad coverage
• Use manual tools for deep analysis
• Always validate automated findings manually
• Choose tools based on discovered services
• Don't rely on a single tool - use multiple approaches
        """
        
        content.setPlainText(tools_text)
        layout.addWidget(content)
        
        self.help_tabs.addTab(tab, "🛠️ Tools")
    
    def create_techniques_tab(self):
        """Create techniques explanation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 10px;
            }
        """)
        
        techniques_text = """
🎯 PENETRATION TESTING TECHNIQUES

🔍 RECONNAISSANCE TECHNIQUES:

🌐 Passive Information Gathering
• Google dorking: site:target.com filetype:pdf
• Social media reconnaissance
• Public database searches
• Certificate transparency logs
• DNS record analysis

📡 Active Information Gathering  
• Port scanning with different techniques
• Service version detection
• OS fingerprinting
• Banner grabbing
• Network mapping

🎯 VULNERABILITY IDENTIFICATION:

🔍 Automated Scanning
• Use multiple scanners for coverage
• Configure scans based on discovered services
• Review and validate all findings
• Prioritize by severity and exploitability

🧪 Manual Testing
• Parameter fuzzing and injection testing
• Authentication and authorization bypass
• Business logic flaw identification
• Configuration review
• Source code analysis (if available)

💥 EXPLOITATION TECHNIQUES:

🌐 Web Application Exploitation
• SQL injection for database access
• Cross-site scripting (XSS) for client-side attacks
• Command injection for system access
• File inclusion for information disclosure
• Authentication bypass for unauthorized access

🖥️ System Exploitation
• Buffer overflow exploitation
• Privilege escalation techniques
• Service exploitation
• Kernel exploits
• Configuration exploitation

🔄 POST-EXPLOITATION TECHNIQUES:

🔑 Privilege Escalation
• Local privilege escalation
• Kernel exploits
• Service misconfigurations
• Scheduled task abuse
• Registry manipulation

🌐 Lateral Movement
• Credential harvesting
• Pass-the-hash attacks
• Kerberos attacks
• Network pivoting
• Service exploitation

💡 TECHNIQUE SELECTION TIPS:
• Match techniques to discovered services
• Start with low-risk techniques
• Escalate complexity based on findings
• Always consider detection avoidance
• Document all techniques used

🚨 ETHICAL CONSIDERATIONS:
• Only test authorized targets
• Minimize system impact
• Respect data privacy
• Follow responsible disclosure
• Maintain professional standards
        """
        
        content.setPlainText(techniques_text)
        layout.addWidget(content)
        
        self.help_tabs.addTab(tab, "🎯 Techniques")
    
    def create_troubleshooting_tab(self):
        """Create troubleshooting tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        content = QTextEdit()
        content.setReadOnly(True)
        content.setStyleSheet("""
            QTextEdit {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 50);
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 10px;
            }
        """)
        
        troubleshooting_text = """
🔧 TROUBLESHOOTING GUIDE

🚫 COMMON ISSUES AND SOLUTIONS:

❌ "No results found" or "Scan completed with 0 findings"
✅ Solutions:
• Check target is reachable (ping test)
• Verify correct URL format (http:// or https://)
• Try different scan profiles (Light → Normal → Aggressive)
• Check firewall/proxy settings
• Ensure target is actually vulnerable

❌ "Connection timeout" or "Network unreachable"
✅ Solutions:
• Verify target IP/domain is correct
• Check network connectivity
• Try different ports (80, 443, 8080, 8443)
• Disable VPN if causing issues
• Check DNS resolution

❌ "Authentication failed" or "Access denied"
✅ Solutions:
• Verify credentials are correct
• Check if account is locked
• Try different authentication methods
• Ensure proper domain format (DOMAIN\username)
• Check credential manager settings

❌ "Scan taking too long" or "Application hanging"
✅ Solutions:
• Reduce concurrent threads in settings
• Use lighter scan profiles
• Scan smaller target ranges
• Check system resources (CPU/Memory)
• Restart application if needed

❌ "False positives" or "Inaccurate results"
✅ Solutions:
• Manually verify all findings
• Use multiple tools for confirmation
• Check tool configuration
• Review scan parameters
• Cross-reference with other sources

🔍 DEBUGGING STEPS:

1️⃣ Check Basic Connectivity
• Ping target host
• Telnet to specific ports
• Use browser to access web services
• Verify DNS resolution

2️⃣ Review Configuration
• Check target scope settings
• Verify authentication credentials
• Review scan parameters
• Confirm tool selection

3️⃣ Analyze Results
• Look for patterns in failures
• Check log files for errors
• Review scan statistics
• Compare with expected results

4️⃣ Adjust Approach
• Try different tools
• Modify scan parameters
• Use alternative techniques
• Consult documentation

💡 PERFORMANCE OPTIMIZATION:

🚀 Speed Up Scans:
• Increase concurrent threads (if system allows)
• Use targeted port ranges
• Skip unnecessary checks
• Use faster scan profiles

🎯 Improve Accuracy:
• Use multiple verification methods
• Cross-reference findings
• Manual validation of results
• Review false positive patterns

📊 Resource Management:
• Monitor CPU and memory usage
• Close unnecessary applications
• Use appropriate scan intensity
• Schedule resource-intensive scans

🆘 WHEN TO SEEK HELP:
• Persistent technical issues
• Unexpected application behavior
• Complex network configurations
• Advanced exploitation scenarios
• Compliance and legal questions

Remember: Troubleshooting is part of the learning process!
        """
        
        content.setPlainText(troubleshooting_text)
        layout.addWidget(content)
        
        self.help_tabs.addTab(tab, "🔧 Troubleshooting")
    
    def set_context(self, context):
        """Set the current context for contextual help"""
        self.current_context = context
        # Could expand this to show context-specific help
    
    def show_context_help(self, tool_name):
        """Show help specific to a tool or technique"""
        # This could be expanded to show tool-specific help
        pass