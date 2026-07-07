# app/widgets/enhanced_help_panel.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QTextEdit, QTabWidget, QScrollArea,
                             QFrame, QSplitter)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QPixmap, QIcon

class EnhancedHelpPanel(QWidget):
    """Enhanced help panel with tool-specific documentation"""
    
    closed = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Huginn Help & Documentation")
        self.setWindowFlags(Qt.WindowType.Window)
        self.resize(1400, 900)
        self.setMinimumSize(1200, 800)
        
        self.setup_ui()
        self.load_help_content()
        
    def setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Huginn Help & Documentation")
        title_label.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        header_layout.addWidget(close_button)
        
        layout.addLayout(header_layout)
        
        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Tool list
        self.tool_list = QWidget()
        self.tool_list.setMinimumWidth(280)
        self.tool_list.setMaximumWidth(350)
        self.setup_tool_list()
        splitter.addWidget(self.tool_list)
        
        # Right panel - Help content
        self.help_tabs = QTabWidget()
        self.setup_help_tabs()
        splitter.addWidget(self.help_tabs)
        
        # Set splitter proportions for better space usage
        splitter.setSizes([300, 1100])  # Tool list: 300px, Help content: remaining space
        splitter.setStretchFactor(0, 0)  # Tool list doesn't stretch
        splitter.setStretchFactor(1, 1)  # Help content stretches
        
        layout.addWidget(splitter)
        
    def setup_tool_list(self):
        """Setup the tool list"""
        layout = QVBoxLayout(self.tool_list)
        
        list_label = QLabel("Tools")
        list_label.setStyleSheet("font-size: 14pt; font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(list_label)
        
        # Tool buttons
        tools = [
            ("DNS Enumeration", "dns"),
            ("Port Scanning", "port"),
            ("SMB Enumeration", "smb"),
            ("SMTP Enumeration", "smtp"),
            ("SNMP Enumeration", "snmp"),
            ("HTTP Enumeration", "http"),
            ("API Enumeration", "api"),
            ("RPC Enumeration", "rpc"),
            ("LDAP Enumeration", "ldap"),
            ("Database Enumeration", "db"),
            ("AV/Firewall Detection", "av_fw"),
            ("🔮 Runecraft Guide", "runecraft"),
            ("🚀 Huginn Scanner", "huginn_scanner"),
            ("🔐 Auth Workflows", "auth_workflows")
        ]
        
        for tool_name, tool_id in tools:
            button = QPushButton(tool_name)
            button.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 8px;
                    border: 1px solid #444;
                    background-color: #2a2a2a;
                    color: #FFFFFF;
                }
                QPushButton:hover {
                    background-color: #3a3a3a;
                    border-color: #64C8FF;
                }
                QPushButton:pressed {
                    background-color: #1a1a1a;
                }
            """)
            button.clicked.connect(lambda checked, tid=tool_id: self.show_tool_help(tid))
            layout.addWidget(button)
        
        layout.addStretch()
        
    def setup_help_tabs(self):
        """Setup help content tabs"""
        # Overview tab
        overview_content = QTextEdit()
        overview_content.setReadOnly(True)
        overview_content.setHtml(self.get_overview_content())
        self.help_tabs.addTab(overview_content, "Overview")
        
        # Tool Help tab
        self.tool_help_content = QTextEdit()
        self.tool_help_content.setReadOnly(True)
        self.help_tabs.addTab(self.tool_help_content, "Tool Help")
        
        # Keyboard Shortcuts tab
        shortcuts_content = QTextEdit()
        shortcuts_content.setReadOnly(True)
        shortcuts_content.setHtml(self.get_shortcuts_content())
        self.help_tabs.addTab(shortcuts_content, "Shortcuts")
        
        # Tips & Tricks tab
        tips_content = QTextEdit()
        tips_content.setReadOnly(True)
        tips_content.setHtml(self.get_tips_content())
        self.help_tabs.addTab(tips_content, "Tips & Tricks")
        
    def load_help_content(self):
        """Load help content"""
        self.help_data = {
            "dns": {
                "title": "DNS Enumeration",
                "description": "Comprehensive DNS reconnaissance and subdomain discovery",
                "features": [
                    "Subdomain enumeration with wordlists",
                    "Bruteforce subdomain discovery",
                    "Multiple DNS record types (A, CNAME, MX, TXT, NS, SRV)",
                    "PTR record enumeration for IP ranges",
                    "Zone transfer attempts",
                    "Custom DNS server support"
                ],
                "usage": [
                    "Enter target domain (e.g., example.com)",
                    "Select record types to query",
                    "Choose enumeration method (Wordlist or Bruteforce)",
                    "Configure DNS server (optional)",
                    "Click Run to start enumeration"
                ],
                "tips": [
                    "Use different wordlists for different target types",
                    "PTR enumeration works best with IP ranges",
                    "SRV records reveal service information",
                    "Zone transfers are rare but valuable"
                ]
            },
            "port": {
                "title": "Port Scanning",
                "description": "Network port discovery and service identification",
                "features": [
                    "TCP connect and SYN stealth scans",
                    "UDP port scanning",
                    "Service version detection",
                    "OS fingerprinting",
                    "Network sweep capabilities",
                    "Custom port ranges"
                ],
                "usage": [
                    "Enter target IP or range",
                    "Select scan type",
                    "Configure port range",
                    "Enable additional options (OS/Service detection)",
                    "Start scan"
                ],
                "tips": [
                    "SYN scans are stealthier but require privileges",
                    "UDP scans take longer but find different services",
                    "Service detection provides valuable information",
                    "Use timing options to avoid detection"
                ]
            },
            "smb": {
                "title": "SMB Enumeration",
                "description": "Windows SMB/NetBIOS service enumeration",
                "features": [
                    "Share enumeration and permissions",
                    "OS and version detection",
                    "NetBIOS information gathering",
                    "Vulnerability scanning (MS17-010, etc.)",
                    "Anonymous and authenticated access",
                    "Domain information extraction"
                ],
                "usage": [
                    "Enter target IP or hostname",
                    "Select scan type",
                    "Configure authentication (if needed)",
                    "Run enumeration"
                ],
                "tips": [
                    "Try anonymous access first",
                    "Check for null sessions",
                    "Look for writable shares",
                    "Enumerate users and groups when possible"
                ]
            },
            "runecraft": {
                "title": "🔮 Runecraft - Magical Payload Forge",
                "description": "Revolutionary dark magical interface for crafting advanced payloads by combining powerful runic components. Transform from mundane payload generation to mystical spell-crafting with Norse-inspired runes.",
                "features": [
                    "<b>🧙‍♂️ Payload Creation Wizard:</b> 9-step guided process covering payload type, platform, protocol, obfuscation, and evasion",
                    "<b>🔮 Runic Spell-Crafting:</b> Drag & drop Norse runes in 3x3 magical grid with synergy detection",
                    "<b>⚙️ Manual Code Interface:</b> Direct code editing with 13 advanced payload templates including reverse shells, beacons, and stagers",
                    "<b>5 Mystical Rune Categories:</b> Protocol (🔵), Authentication (🟡), Payload (🔴), Logic (🟢), Encoding (🟣)",
                    "<b>24 Ancient Norse Runes:</b> Each with unique symbols (Algiz, Thurisaz, Uruz, etc.) and specialized powers",
                    "<b>Advanced Payload Templates:</b> Reverse TCP shells, HTTP beacons, VBA macros, encoded PowerShell, Python stagers",
                    "<b>Cross-Platform Support:</b> Windows, Linux, macOS, Android with format-specific output (EXE, ELF, APK, scripts)",
                    "<b>Multi-Protocol Communication:</b> TCP, HTTP, HTTPS, DNS, ICMP with protocol-specific implementations",
                    "<b>Advanced Obfuscation:</b> Base64, XOR, AES, RC4 encoding with multi-layer support",
                    "<b>Evasion Techniques:</b> Anti-VM, anti-debug, execution delays, admin checks, sleep jitter",
                    "<b>Multi-Format Export:</b> Python, PowerShell, VBA, Bash, raw shellcode, executables",
                    "<b>Enterprise Arsenal:</b> Full rune library and advanced features unlocked with Enterprise license"
                ],
                "usage": [
                    "<b>Access Runecraft:</b> Navigate to EXPLOITATION → Web & App Exploits → 🔧 Runecraft tab",
                    "<b>Choose Your Method:</b> Select 🧙‍♂️ Wizard (guided), 🧙‍♂️ Rune Interface (drag-drop), or ⚙️ Manual Interface (code editing)",
                    "<b>Wizard Method:</b> Click 🧙‍♂️ Wizard button and follow 9 guided steps for payload creation",
                    "<b>Rune Method:</b> Drag runes from 🔮 Rune Library to ⚒️ Crafting Grid, watch for synergies, click 🔥 Forge Payload",
                    "<b>Manual Method:</b> Select payload type, configure target, click 🔧 Generate Template, edit code as needed",
                    "<b>Advanced Configuration:</b> Apply obfuscation, evasion techniques, and custom modifications",
                    "<b>Deploy Creation:</b> Export in preferred format (📋 Hex, 🐍 Python, 💾 Binary, PowerShell, VBA) for deployment"
                ],
                "tips": [
                    "<b>Wizard for Beginners:</b> Use the step-by-step wizard for guided payload creation with explanations",
                    "<b>Runes for Creativity:</b> Experiment with rune combinations to discover powerful synergies and unique payloads",
                    "<b>Manual for Precision:</b> Use manual interface for exact control and custom modifications",
                    "<b>Cross-Platform Strategy:</b> Select target OS first - affects available templates and output formats",
                    "<b>Protocol Selection:</b> TCP for speed, HTTP for stealth, DNS for covert channels",
                    "<b>Obfuscation Layers:</b> Combine multiple encoding methods (Base64 + XOR + AES) for maximum evasion",
                    "<b>Evasion Techniques:</b> Enable anti-VM and delays for production environments",
                    "<b>Template Customization:</b> Generated templates are starting points - modify for specific scenarios",
                    "<b>Rune Synergies:</b> Protocol+Payload=Network Strike, Auth+Encoding=Stealth Bypass, 4+ types=Legendary",
                    "<b>Output Format Strategy:</b> Python for flexibility, PowerShell for Windows, VBA for phishing, raw shellcode for injection",
                    "<b>Testing Workflow:</b> Generate payload → Test in lab → Apply additional obfuscation → Deploy",
                    "<b>Advanced Features:</b> Use custom code section in wizard or manual interface for specialized requirements"
                ]
            },
            "huginn_scanner": {
                "title": "🚀 Huginn Advanced Security Scanner",
                "description": "Revolutionary AI-powered vulnerability assessment tool combining traditional security testing with cutting-edge artificial intelligence and quantum-inspired algorithms for comprehensive security analysis.",
                "features": [
                    "<b>🧠 Neural Network Vulnerability Analysis:</b> Deep learning-based pattern recognition for advanced threat detection",
                    "<b>🔬 Quantum-Inspired Fuzzing:</b> Advanced payload generation using quantum computing concepts",
                    "<b>🤖 Autonomous Security Agent:</b> Self-directed penetration testing with 7-state AI agent",
                    "<b>📈 ML Vulnerability Prediction:</b> Machine learning-based vulnerability forecasting and risk assessment",
                    "<b>🎯 Advanced Exploitation:</b> Proof-of-concept exploit generation and validation",
                    "<b>📈 Compliance Reporting:</b> OWASP Top 10 and PCI DSS compliance assessment with executive dashboards",
                    "<b>🔍 OSINT Intelligence:</b> Comprehensive reconnaissance and intelligence gathering integration",
                    "<b>🛡️ WAF Evasion:</b> Advanced bypass techniques for web application firewalls",
                    "<b>⚡ Zero-Day Discovery:</b> Evolutionary fuzzing for unknown vulnerability discovery",
                    "<b>📊 Multi-threaded Scanning:</b> Intelligent rate limiting with memory-optimized operations"
                ],
                "usage": [
                    "<b>Access the Scanner:</b> Navigate to Reconnaissance & Enumeration → Service Enumeration → HTTP Service Enumeration → 🚀 Huginn Advanced Scanner",
                    "<b>Configure Target:</b> Enter target URL (https://example.com) in the target field",
                    "<b>Select Scan Profile:</b> Choose from Light (20 concurrent), Normal (50), Aggressive (100), or Insane (200) profiles",
                    "<b>Authentication Setup:</b> Configure credentials, headers, or session tokens if required",
                    "<b>Advanced Options:</b> Enable AI features, webhook notifications, custom headers, or proxy settings",
                    "<b>Start Scanning:</b> Click 'Start Scan' and monitor real-time progress with live vulnerability detection",
                    "<b>Review Results:</b> Analyze findings in interactive HTML report with evidence buttons",
                    "<b>Generate Reports:</b> Export in HTML, JSON, Executive, OWASP, or PCI compliance formats"
                ],
                "tips": [
                    "<b>Profile Selection:</b> Start with 'Normal' profile for balanced performance, use 'Insane' for maximum coverage",
                    "<b>Authentication:</b> Properly configure auth to access protected areas - supports multiple auth types",
                    "<b>AI Features:</b> Enable neural network analysis for advanced pattern detection and zero-day discovery",
                    "<b>Rate Limiting:</b> Adjust concurrent threads based on target capacity to avoid overwhelming servers",
                    "<b>Webhook Integration:</b> Set up Slack/Discord webhooks for real-time vulnerability alerts",
                    "<b>Custom Headers:</b> Add User-Agent, Authorization, or custom headers for specific testing scenarios",
                    "<b>Proxy Configuration:</b> Route traffic through Burp Suite or other proxies for additional analysis",
                    "<b>Report Formats:</b> Use HTML for detailed analysis, JSON for automation, Executive for management",
                    "<b>Evidence Collection:</b> Click evidence buttons in reports to view proof-of-concept exploits",
                    "<b>Compliance Mapping:</b> Generate OWASP Top 10 2021 and PCI DSS compliance reports for audits",
                    "<b>Session Management:</b> Save scan configurations and results for consistent testing workflows",
                    "<b>Memory Optimization:</b> Monitor memory usage during large scans and adjust settings accordingly"
                ]
            },
            "smtp": {
                "title": "SMTP Enumeration",
                "description": "Email server user enumeration and mail service reconnaissance",
                "features": [
                    "Multi-method user enumeration (VRFY, EXPN, RCPT TO)",
                    "Wordlist-based username testing",
                    "Custom port configuration (default 25)",
                    "Target domain specification for RCPT TO method",
                    "Configurable HELO/EHLO identifier",
                    "Mail server banner analysis",
                    "Automatic method fallback on failure"
                ],
                "usage": [
                    "Enter target mail server IP or hostname",
                    "Set the SMTP port (default: 25, or 587/465 for submission)",
                    "Enter target domain for RCPT TO testing (optional)",
                    "Configure HELO name (default: test.local)",
                    "Select a wordlist for username enumeration",
                    "Click Run to start enumeration"
                ],
                "tips": [
                    "VRFY is the fastest method but often disabled on modern servers",
                    "RCPT TO is the most reliable method and works on most servers",
                    "EXPN can reveal mailing list members if enabled",
                    "Use a targeted wordlist with common usernames for the organisation",
                    "Change the HELO name to something plausible to avoid detection",
                    "Try port 587 if port 25 is filtered"
                ]
            },
            "snmp": {
                "title": "SNMP Enumeration",
                "description": "Network device information gathering via Simple Network Management Protocol",
                "features": [
                    "SNMP version support (v1, v2c, v3)",
                    "Multiple scan types (Basic Info, Users, Processes, Software, Network, Full Enumeration)",
                    "Community string configuration and brute-forcing",
                    "Quick presets (Default and Extended community lists)",
                    "System information gathering (hostname, OS, uptime)",
                    "User and process enumeration",
                    "Network interface and routing table discovery",
                    "Installed software enumeration"
                ],
                "usage": [
                    "Enter target IP address",
                    "Select SNMP version (2c recommended for most devices)",
                    "Choose scan type (Basic Info for quick recon, Full Enumeration for comprehensive)",
                    "Configure community strings (default: public,private,community)",
                    "Use Quick presets to load Default or Extended community lists",
                    "Click Run to start enumeration"
                ],
                "tips": [
                    "Start with 'public' and 'private' community strings — they're still common",
                    "Full Enumeration takes longer but reveals users, processes, and installed software",
                    "Use the Extended preset for a broader community string brute-force",
                    "SNMP v3 requires credentials but provides encrypted communication",
                    "Network scan type reveals interfaces, routes, and ARP tables",
                    "Many IoT devices still use default SNMP communities"
                ]
            },
            "http": {
                "title": "HTTP Enumeration",
                "description": "Web server fingerprinting, directory enumeration, and content discovery",
                "features": [
                    "Multiple scan types (Fingerprinting, Source Code, Crawler, Directory Enum, Enterprise Scripts, Full Scan)",
                    "File extension selection by category (PHP, ASP, JSP, HTML, JS, Config, Backup)",
                    "Preset configurations (Manual, PHP Apps, API-focused, Login Pages, Backup Files, CMS Common)",
                    "Wordlist-based directory and file discovery with size options (Small, Medium, Large)",
                    "Listener integration for capturing callbacks",
                    "Authentication support (None, Basic Auth) with credential manager",
                    "Web server identification and technology stack detection",
                    "Security header analysis"
                ],
                "usage": [
                    "Enter target URL (e.g., http://target.com or https://target.com)",
                    "Select scan type from the dropdown",
                    "For Directory Enum: choose a preset or manually select file extensions",
                    "Select wordlist and size (Small/Medium/Large)",
                    "Configure authentication if the target requires login",
                    "Enable Listener if you need to capture out-of-band callbacks",
                    "Click Run to start the scan"
                ],
                "tips": [
                    "Start with Fingerprinting to identify the web server and technology stack",
                    "Use presets to quickly configure extension sets for common platforms",
                    "Backup Files preset finds .bak, .old, .tmp files that may contain sensitive data",
                    "Enable Config extensions (.env, .config, .conf) to find exposed configuration files",
                    "Crawler mode follows links to map the full site structure",
                    "Enterprise Scripts runs advanced checks including Nikto-style vulnerability tests",
                    "Use Basic Auth when testing authenticated areas of the application"
                ]
            },
            "api": {
                "title": "API Enumeration",
                "description": "REST API endpoint discovery, method testing, and vulnerability assessment",
                "features": [
                    "Multiple scan types (Basic Discovery, Gobuster Enum, HTTP Methods, Auth Bypass, Vulnerability Test, Full Scan)",
                    "Preset configurations (None, API-focused, Login Pages, Backup Files)",
                    "Wordlist size options (Small, Medium, Large)",
                    "Common API endpoint pattern detection (/api, /api/v1, /rest, /graphql, /swagger)",
                    "HTTP method testing (GET, POST, PUT, DELETE, PATCH, OPTIONS)",
                    "Authentication bypass testing",
                    "SQL injection and NoSQL injection testing",
                    "API versioning detection"
                ],
                "usage": [
                    "Enter target base URL (e.g., https://api.target.com)",
                    "Select scan type from the dropdown",
                    "Choose a preset for targeted endpoint patterns",
                    "Select wordlist size (Medium recommended for balanced coverage)",
                    "Select specific wordlist if needed",
                    "Click Run to start API enumeration"
                ],
                "tips": [
                    "Start with Basic Discovery to find API endpoints before deeper testing",
                    "Gobuster Enum uses wordlists for brute-force endpoint discovery",
                    "HTTP Methods testing reveals which verbs are accepted on each endpoint",
                    "Auth Bypass tests for common authentication weaknesses (missing auth, IDOR)",
                    "Check /swagger, /api-docs, and /graphql for self-documenting APIs",
                    "Vulnerability Test includes SQLi and NoSQLi checks on discovered parameters",
                    "Use the API-focused preset for comprehensive REST API wordlists"
                ]
            },
            "rpc": {
                "title": "RPC Enumeration",
                "description": "Windows RPC service enumeration for domain reconnaissance and user discovery",
                "features": [
                    "Multiple scan types (Basic Info, Full Enumeration, Vulnerability Scan, Complete Assessment)",
                    "Multiple authentication methods (Anonymous, Credentials, Pass-the-Hash, Kerberos Ticket, Kerberos Password)",
                    "Domain user and group enumeration",
                    "Server information gathering",
                    "NTLM hash authentication support",
                    "Kerberos ticket (.ccache) authentication",
                    "Credential Manager integration",
                    "Vulnerability scanning for RPC-related CVEs"
                ],
                "usage": [
                    "Enter target IP or hostname (typically a domain controller)",
                    "Select scan type (Basic Info for quick recon, Complete Assessment for full audit)",
                    "Choose authentication method from the Auth dropdown",
                    "For Credentials: enter domain, username, and password",
                    "For Pass-the-Hash: enter domain, username, and NTLM hash",
                    "For Kerberos Ticket: browse to your .ccache ticket file",
                    "Click Run to start enumeration"
                ],
                "tips": [
                    "Try Anonymous access first — many domain controllers allow null sessions",
                    "Pass-the-Hash is useful when you have NTLM hashes but not plaintext passwords",
                    "Full Enumeration reveals domain users, groups, and password policies",
                    "Use Kerberos authentication when you have a valid TGT from a compromised account",
                    "Vulnerability Scan checks for known RPC exploits (MS03-026, PrintNightmare, etc.)",
                    "Load credentials from the Credential Manager to avoid retyping across tools",
                    "Complete Assessment combines all scan types for a thorough audit"
                ]
            },
            "ldap": {
                "title": "LDAP Enumeration",
                "description": "LDAP directory service enumeration for Active Directory and other directory servers",
                "features": [
                    "Multiple scan types (Basic Info, Anonymous Enum, Authenticated Enum, Full Scan)",
                    "Configurable port (default 389, SSL/TLS on 636)",
                    "SSL/TLS toggle for encrypted connections",
                    "Base DN auto-detection when left empty",
                    "Anonymous bind enumeration",
                    "Authenticated enumeration with domain credentials",
                    "User, group, and computer object discovery",
                    "Domain policy and configuration extraction"
                ],
                "usage": [
                    "Enter target LDAP server IP or hostname",
                    "Set port (389 for standard, or check 'Use SSL/TLS' for port 636)",
                    "Select scan type from the dropdown",
                    "Enter Base DN (e.g., DC=domain,DC=com) or leave empty for auto-detection",
                    "For Authenticated Enum: enter username (DOMAIN\\user or user@domain.com) and password",
                    "Click Run to start enumeration"
                ],
                "tips": [
                    "Try Anonymous Enum first — many LDAP servers allow unauthenticated queries",
                    "Leave Base DN empty to let Huginn auto-detect it from the server's rootDSE",
                    "Authenticated Enum reveals far more objects (users, groups, GPOs, trusts)",
                    "Use SSL/TLS (port 636) when testing production environments to avoid credential interception",
                    "Full Scan combines anonymous and authenticated techniques for maximum coverage",
                    "Look for service accounts with weak passwords or no expiry in the results"
                ]
            },
            "db": {
                "title": "Database Enumeration",
                "description": "Multi-database service enumeration supporting MSSQL, MySQL, MariaDB, Oracle, and PostgreSQL",
                "features": [
                    "Support for 5 database types (MSSQL, MySQL, MariaDB, Oracle, PostgreSQL)",
                    "Multiple scan types (Basic Info, Scripts, Full Scan)",
                    "Automatic port detection per database type (1433, 3306, 1521, 5432)",
                    "Oracle SID configuration for targeted enumeration",
                    "Authentication support with username/password",
                    "Credential Manager integration",
                    "NSE script execution for vulnerability detection",
                    "Database version and configuration fingerprinting"
                ],
                "usage": [
                    "Enter target database server IP or hostname",
                    "Select database type from the dropdown (MSSQL, MySQL, MariaDB, Oracle, PostgreSQL)",
                    "Verify the port (auto-populated based on DB type, adjust if non-standard)",
                    "Select scan type (Basic Info for fingerprinting, Scripts for NSE checks, Full Scan for both)",
                    "Configure authentication if you have credentials (select auth method, enter username/password)",
                    "For Oracle: enter the SID (default: DB11g)",
                    "Click Run to start enumeration"
                ],
                "tips": [
                    "Basic Info reveals version, configuration, and available databases without credentials",
                    "Scripts mode runs NSE scripts that check for known vulnerabilities and misconfigurations",
                    "Default ports: MSSQL=1433, MySQL/MariaDB=3306, Oracle=1521, PostgreSQL=5432",
                    "Try common default credentials (sa/blank for MSSQL, root/blank for MySQL)",
                    "Oracle SID brute-forcing can reveal hidden database instances",
                    "Use the Credential Manager to load saved credentials across multiple database targets",
                    "Full Scan combines fingerprinting and vulnerability checks for comprehensive assessment"
                ]
            },
            "av_fw": {
                "title": "AV/Firewall Detection",
                "description": "Detect and profile network security devices (firewalls, WAFs, IDS/IPS) and generate AV evasion test payloads — all natively in Python with no external tools",
                "features": [
                    "<b>WAF Detection:</b> Identifies Web Application Firewalls by analyzing HTTP response headers and behaviors",
                    "<b>Firewall Detection:</b> Classifies ports as open/closed/filtered via TCP probes, detects stateful vs packet-filter firewalls",
                    "<b>Evasion Testing:</b> Tests 5 bypass techniques (source port, timing, window size, pattern, flag manipulation) against filtered ports",
                    "<b>AV Payload Gen:</b> Generates encoded test payloads (reverse_tcp, bind_tcp, cmd_exec) in multiple formats (raw, EXE, DLL, PowerShell)",
                    "<b>Full Detection:</b> Runs comprehensive firewall detection scan",
                    "Independent results per detection type — switching preserves output",
                    "Real-time progress bar with per-probe updates",
                    "No external dependencies (no nmap, no msfvenom) — pure Python sockets and struct packing"
                ],
                "usage": [
                    "Navigate to Service Enumeration → 🛡️ AV/FW tab",
                    "Enter target IP or hostname",
                    "Select detection type from the dropdown",
                    "<b>WAF Detection:</b> Set port (default 80) — detects Cloudflare, AWS WAF, ModSecurity, etc.",
                    "<b>Firewall Detection:</b> Port field hidden — automatically scans top 20 ports + ACK probe",
                    "<b>Evasion Test:</b> Port field hidden — establishes baseline then tests 5 evasion techniques",
                    "<b>AV Payload Gen:</b> Set port (LPORT for reverse shell) — generates encoded shellcode",
                    "Click Run to start the scan",
                    "Switch between Text and Table views for results"
                ],
                "tips": [
                    "Run Firewall Detection first to identify filtered ports, then use Evasion Test on those results",
                    "WAF Detection works best on port 80/443 where web applications are served",
                    "Firewall Detection confidence: >50% filtered = DETECTED, 20-50% = LIKELY, <20% = not detected",
                    "Stateful firewalls filter ephemeral ports too; packet-filters only block specific ports",
                    "Evasion Test uses a 1-second timeout and tests top 5 filtered ports to keep scans fast",
                    "AV Payload Gen uses the target IP as LHOST — set it to YOUR IP for reverse shells",
                    "Each detection type has its own terminal — results are preserved when switching types",
                    "Use Ctrl-L to clear only the current detection type's output",
                    "Export results as JSON/CSV/XML/HTML for reporting"
                ]
            },
            "auth_workflows": {
                "title": "🔐 Auth Workflows — Authentication Flow Analysis & Testing",
                "description": "Enterprise-grade authentication security testing module that captures, models, and tests authentication flows across all major protocols including OAuth 2.0, OIDC, NTLM, Kerberos, SAML 2.0, Forms-Based Auth, Certificate/mTLS, JWT, and API Keys.",
                "features": [
                    "<b>🎯 Flow Recording:</b> Protocol-aware proxy traffic capture with automatic detection of OAuth, NTLM, Kerberos, SAML, JWT, FBA, certificate auth, and API keys",
                    "<b>🧩 State Model:</b> Directed-graph visualization of authentication flows with protocol-specific node classification (challenge, callback, token_mint, assertion_consumer, etc.)",
                    "<b>⚡ 35+ Attack Mutations:</b> Protocol-specific security tests organized by category (Generic, OAuth2, OIDC, JWT, SAML, NTLM, FBA, API Key)",
                    "<b>🔐 Deep Token Analysis:</b> JWT decode with weak-secret brute-force, SAML assertion parsing, Kerberos ticket encryption analysis, NTLM message parsing, session cookie entropy",
                    "<b>📊 Automatic Vulnerability Detection:</b> 25+ security checks with CWE IDs covering all protocols",
                    "<b>OAuth 2.0 Testing:</b> State bypass, redirect_uri manipulation, PKCE bypass, scope escalation, implicit grant detection, code reuse",
                    "<b>OIDC Testing:</b> Nonce replay, audience confusion, id_token substitution, at_hash validation",
                    "<b>NTLM Testing:</b> NTLMv1 detection, relay risk assessment, downgrade attacks, hash extraction",
                    "<b>Kerberos Testing:</b> RC4/AES encryption detection (Kerberoasting risk), delegation analysis, ticket replay",
                    "<b>SAML Testing:</b> Signature stripping, assertion replay, XXE injection, attribute injection, XSW detection",
                    "<b>JWT Testing:</b> Algorithm none, signature stripping, claim tampering, KID injection, expiry bypass",
                    "<b>Session Analysis:</b> Cookie entropy measurement, HttpOnly/Secure/SameSite attribute checks, predictability detection",
                    "<b>HTML/JSON Export:</b> Professional reports with severity-colored vulnerability tables for client deliverables"
                ],
                "usage": [
                    "<b>Access:</b> Navigate to EXPLOITATION → Web & App Exploits → Auth Workflows tab",
                    "<b>Step 1 — Record:</b> Click 🔴 Start Recording, perform authentication in browser (via proxy), click ⏹️ Stop Recording",
                    "<b>Step 2 — Analyze:</b> Select flow in State Model tab, click 🏗️ Build Model to see flow graph and auto-detected security issues",
                    "<b>Step 3 — Test:</b> In Replay & Testing tab, choose: ▶️ Baseline (verify flow works), 🔒 Auto Security Test (protocol-appropriate), or 🛡️ Full Audit (all 35 mutations)",
                    "<b>Step 4 — Tokens:</b> In Token Analysis tab, click 🔍 Analyze Tokens for deep inspection of all captured tokens",
                    "<b>Step 5 — Report:</b> In Results tab, review all findings and export as HTML report or JSON",
                    "<b>Selective Testing:</b> Check specific mutation checkboxes in the Testing tab and click 🧪 Run Selected Mutations",
                    "<b>Import/Export:</b> Save flows to JSON for later analysis or share with team members"
                ],
                "tips": [
                    "<b>Record complete flows:</b> Include the full sequence from unauthenticated state through successful authentication",
                    "<b>Use Auto Security Test first:</b> It selects mutations based on detected protocols — most efficient approach",
                    "<b>Test multiple roles:</b> Record admin, user, and guest flows separately for differential analysis",
                    "<b>Check token entropy:</b> Tokens below 3.5 bits/char entropy are nearly always exploitable",
                    "<b>Look for NTLMv1:</b> If detected, it's a critical finding for any internal penetration test",
                    "<b>Verify PKCE:</b> Modern OAuth without PKCE is vulnerable to authorization code interception",
                    "<b>SAML signature checks:</b> Unsigned assertions are critical — always verify signature enforcement",
                    "<b>JWT weak secrets:</b> The analyzer tests 16 common passwords — a match is a critical finding",
                    "<b>Cookie attributes:</b> Missing HttpOnly + Secure + SameSite is a common finding worth reporting",
                    "<b>Watch for false positives:</b> WAF blocks on mutation tests may look like 'success' — verify manually",
                    "<b>Full Audit for comprehensive:</b> When time allows, run all 35 mutations for maximum coverage",
                    "<b>Export for reporting:</b> HTML export produces client-ready deliverables with severity colors"
                ]
            }
        }
        
    def show_tool_help(self, tool_id):
        """Show help for specific tool"""
        if tool_id in self.help_data:
            help_info = self.help_data[tool_id]
            
            html_content = f"""
            <h2 style="color: #64C8FF;">{help_info['title']}</h2>
            <p style="font-size: 12pt; margin-bottom: 20px;">{help_info['description']}</p>
            
            <h3 style="color: #87CEEB;">Features</h3>
            <ul>
            """
            
            for feature in help_info['features']:
                html_content += f"<li>{feature}</li>"
            
            html_content += """
            </ul>
            
            <h3 style="color: #87CEEB;">Usage</h3>
            <ol>
            """
            
            for step in help_info['usage']:
                html_content += f"<li>{step}</li>"
            
            html_content += """
            </ol>
            
            <h3 style="color: #87CEEB;">Tips</h3>
            <ul>
            """
            
            for tip in help_info['tips']:
                html_content += f"<li>{tip}</li>"
            
            html_content += "</ul>"
            
            self.tool_help_content.setHtml(html_content)
            self.help_tabs.setCurrentIndex(1)  # Switch to Tool Help tab
        
    def get_overview_content(self):
        """Get overview content"""
        return """
        <h2 style="color: #64C8FF;">Huginn Overview</h2>
        <p>Huginn is a comprehensive penetration testing toolkit with advanced enumeration capabilities.</p>
        
        <h3 style="color: #87CEEB;">Main Features</h3>
        <ul>
            <li><strong>DNS Enumeration:</strong> Subdomain discovery and DNS reconnaissance</li>
            <li><strong>Port Scanning:</strong> Network service discovery and identification</li>
            <li><strong>SMB Enumeration:</strong> Windows share and service enumeration</li>
            <li><strong>SMTP Enumeration:</strong> Email server user enumeration</li>
            <li><strong>SNMP Enumeration:</strong> Network device information gathering</li>
            <li><strong>HTTP Enumeration:</strong> Web server fingerprinting and directory discovery</li>
            <li><strong>API Enumeration:</strong> REST API endpoint discovery</li>
            <li><strong>🔮 Runecraft Forge:</strong> Magical payload crafting with Norse runic components</li>
            <li><strong>🚀 Huginn Scanner:</strong> AI-powered vulnerability assessment with neural network analysis</li>
            <li><strong>Advanced Reporting:</strong> Professional PDF and HTML reports</li>
        </ul>
        
        <h3 style="color: #87CEEB;">Getting Started</h3>
        <ol>
            <li>Select an enumeration tool from the left panel</li>
            <li>Enter your target (IP, domain, or range)</li>
            <li>Configure scan options</li>
            <li>Click Run to start the scan</li>
            <li>Export results when complete</li>
        </ol>
        
        <h3 style="color: #87CEEB;">Best Practices</h3>
        <ul>
            <li>Always ensure you have permission to scan targets</li>
            <li>Start with passive reconnaissance</li>
            <li>Use appropriate timing to avoid detection</li>
            <li>Document all findings thoroughly</li>
            <li>Verify results with multiple tools</li>
        </ul>
        
        <h3 style="color: #87CEEB;">🔮 Runecraft - Advanced Payload Crafting</h3>
        <p>Runecraft transforms traditional payload generation into an intuitive, magical experience:</p>
        <ul>
            <li><strong>Norse Runic System:</strong> 24 ancient symbols representing different payload components</li>
            <li><strong>Drag & Drop Interface:</strong> Visually combine runes in a 3x3 crafting grid</li>
            <li><strong>Synergy Detection:</strong> Automatic recognition of powerful rune combinations</li>
            <li><strong>Multi-Layer Payloads:</strong> Protocol + Auth + Payload + Logic + Encoding combinations</li>
            <li><strong>Enterprise Features:</strong> Full arsenal unlocked for advanced security testing</li>
        </ul>
        
        <div style="background-color: #1a1a2a; padding: 15px; border-left: 4px solid #64C8FF; margin: 10px 0;">
        <p><strong>🎆 Quick Runecraft Example:</strong></p>
        <p>1. Drag <strong>Raido (RPC)</strong> for protocol layer</p>
        <p>2. Add <strong>Nauthiz (NTLM)</strong> for authentication</p>
        <p>3. Include <strong>Fehu (Shellcode)</strong> for payload execution</p>
        <p>4. Apply <strong>Tiwaz (XOR)</strong> for encoding</p>
        <p>5. Forge into a complete RPC attack payload!</p>
        </div>
        """
        
    def get_shortcuts_content(self):
        """Get keyboard shortcuts content"""
        return """
        <h2 style="color: #64C8FF;">Keyboard Shortcuts</h2>
        
        <h3 style="color: #87CEEB;">Global Shortcuts</h3>
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
            <tr style="background-color: #2a2a2a;">
                <th>Shortcut</th>
                <th>Action</th>
            </tr>
            <tr><td>F1</td><td>Show this help panel</td></tr>
            <tr><td>F5</td><td>Run current scan</td></tr>
            <tr><td>F11</td><td>Toggle fullscreen</td></tr>
            <tr><td>Ctrl+E</td><td>Export results</td></tr>
            <tr><td>Ctrl+L</td><td>Clear output</td></tr>
            <tr><td>Ctrl+M</td><td>Minimize to tray</td></tr>
            <tr><td>Ctrl+Q</td><td>Quit application</td></tr>
            <tr><td>Ctrl+T</td><td>Open theme selector</td></tr>
            <tr><td>Escape</td><td>Go back/Cancel</td></tr>
        </table>
        
        <h3 style="color: #87CEEB;">Enumeration Shortcuts</h3>
        <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
            <tr style="background-color: #2a2a2a;">
                <th>Shortcut</th>
                <th>Action</th>
            </tr>
            <tr><td>Enter</td><td>Start scan (when in input field)</td></tr>
            <tr><td>Ctrl+Shift+R</td><td>Show running scans</td></tr>
            <tr><td>Ctrl+Shift+S</td><td>Open session manager</td></tr>
            <tr><td>Ctrl+R</td><td>Generate reports</td></tr>
        </table>
        """
        
    def get_tips_content(self):
        """Get tips and tricks content"""
        return """
        <h2 style="color: #64C8FF;">Tips & Tricks</h2>
        
        <h3 style="color: #87CEEB;">DNS Enumeration Tips</h3>
        <ul>
            <li><strong>Wordlist Selection:</strong> Use targeted wordlists for better results</li>
            <li><strong>Bruteforce Length:</strong> Start with 3-4 characters, increase if needed</li>
            <li><strong>Record Types:</strong> Always check SRV records for service discovery</li>
            <li><strong>PTR Records:</strong> Use IP ranges like 192.168.1.0 for reverse lookups</li>
        </ul>
        
        <h3 style="color: #87CEEB;">Port Scanning Tips</h3>
        <ul>
            <li><strong>Scan Types:</strong> Use SYN scans for stealth, TCP connect for reliability</li>
            <li><strong>Timing:</strong> Slower scans avoid detection but take longer</li>
            <li><strong>UDP Scanning:</strong> Takes time but finds different services</li>
            <li><strong>Service Detection:</strong> Provides valuable version information</li>
        </ul>
        
        <h3 style="color: #87CEEB;">SMB Enumeration Tips</h3>
        <ul>
            <li><strong>Anonymous Access:</strong> Try null sessions first</li>
            <li><strong>Share Permissions:</strong> Look for writable shares</li>
            <li><strong>Vulnerabilities:</strong> Check for MS17-010 and other SMB exploits</li>
            <li><strong>Domain Info:</strong> Extract user and group information</li>
        </ul>
        
        <h3 style="color: #87CEEB;">General Tips</h3>
        <ul>
            <li><strong>Multiple Views:</strong> Use text, graph, and table views for different perspectives</li>
            <li><strong>Export Options:</strong> Choose appropriate format for your needs</li>
            <li><strong>Session Management:</strong> Organize scans by project or target</li>
            <li><strong>Advanced Reporting:</strong> Generate professional reports for clients</li>
            <li><strong>Themes:</strong> Customize the interface to your preference</li>
        </ul>
        
        <h3 style="color: #87CEEB;">Performance Tips</h3>
        <ul>
            <li><strong>Threading:</strong> Adjust thread count based on target capacity</li>
            <li><strong>Timeouts:</strong> Increase timeouts for slow networks</li>
            <li><strong>Rate Limiting:</strong> Use slower rates to avoid detection</li>
            <li><strong>Memory Usage:</strong> Monitor memory usage during large scans</li>
        </ul>
        """
        
    def closeEvent(self, event):
        """Handle close event"""
        self.closed.emit()
        event.accept()