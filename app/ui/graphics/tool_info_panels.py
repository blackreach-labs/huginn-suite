# app/ui/graphics/tool_info_panels.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QFrame, QScrollArea, QGraphicsView, QGraphicsScene,
                             QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsTextItem)
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QRect
from PyQt6.QtGui import QPixmap, QPainter, QColor, QBrush, QPen, QFont

class ToolInfoPanel(QWidget):
    """Enhanced information panel for enumeration tools"""
    
    def __init__(self, tool_type, parent=None):
        super().__init__(parent)
        self.tool_type = tool_type
        self.setup_ui()
        self.create_tool_graphics()
        
    def setup_ui(self):
        """Setup basic UI structure"""
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(10, 10, 10, 10)
        
        # Title section
        self.title_frame = QFrame()
        self.title_frame.setFixedHeight(60)
        self.title_layout = QHBoxLayout(self.title_frame)
        
        self.tool_icon = QLabel()
        self.tool_icon.setFixedSize(48, 48)
        self.tool_icon.setStyleSheet("border: 2px solid #64C8FF; border-radius: 24px;")
        
        self.tool_title = QLabel()
        self.tool_title.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        
        self.title_layout.addWidget(self.tool_icon)
        self.title_layout.addWidget(self.tool_title)
        self.title_layout.addStretch()
        
        # Content area
        self.content_scroll = QScrollArea()
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_scroll.setWidget(self.content_widget)
        self.content_scroll.setWidgetResizable(True)
        
        self.layout.addWidget(self.title_frame)
        self.layout.addWidget(self.content_scroll)
        
    def create_tool_graphics(self):
        """Create tool-specific graphics and information"""
        graphics_map = {
            'dns': self.create_dns_graphics,
            'port': self.create_port_graphics,
            'smb': self.create_smb_graphics,
            'http': self.create_http_graphics,
            'smtp': self.create_smtp_graphics,
            'snmp': self.create_snmp_graphics,
            'api': self.create_api_graphics,
            'rpc': self.create_rpc_graphics
        }
        
        if self.tool_type in graphics_map:
            graphics_map[self.tool_type]()
        else:
            self.create_default_graphics()
            
    def create_dns_graphics(self):
        """Create DNS enumeration graphics"""
        self.tool_title.setText("DNS Enumeration")
        
        # DNS hierarchy visualization
        hierarchy_frame = self.create_section_frame("DNS Hierarchy")
        hierarchy_view = DNSHierarchyView()
        hierarchy_frame.layout().addWidget(hierarchy_view)
        
        # Query types explanation
        query_frame = self.create_section_frame("Record Types")
        query_info = self.create_info_text("""
        <b>A Records:</b> IPv4 address mapping<br>
        <b>AAAA Records:</b> IPv6 address mapping<br>
        <b>CNAME Records:</b> Canonical name aliases<br>
        <b>MX Records:</b> Mail exchange servers<br>
        <b>TXT Records:</b> Text information<br>
        <b>NS Records:</b> Name server delegation<br>
        <b>SRV Records:</b> Service location<br>
        <b>PTR Records:</b> Reverse DNS lookup
        """)
        query_frame.layout().addWidget(query_info)
        
        # Enumeration methods
        methods_frame = self.create_section_frame("Enumeration Methods")
        methods_info = self.create_info_text("""
        <b>Wordlist Enumeration:</b> Dictionary-based subdomain discovery<br>
        <b>Bruteforce:</b> Character-based subdomain generation<br>
        <b>Zone Transfer:</b> AXFR requests for zone data<br>
        <b>Wildcard Detection:</b> Automatic filtering of wildcard responses
        """)
        methods_frame.layout().addWidget(methods_info)
        
        self.content_layout.addWidget(hierarchy_frame)
        self.content_layout.addWidget(query_frame)
        self.content_layout.addWidget(methods_frame)
        
    def create_port_graphics(self):
        """Create port scanning graphics"""
        self.tool_title.setText("Port Scanning")
        
        # Port range visualization
        port_frame = self.create_section_frame("Port Ranges")
        port_view = PortRangeView()
        port_frame.layout().addWidget(port_view)
        
        # Scan types
        scan_frame = self.create_section_frame("Scan Types")
        scan_info = self.create_info_text("""
        <b>TCP Connect:</b> Full three-way handshake<br>
        <b>SYN Stealth:</b> Half-open scanning technique<br>
        <b>UDP Scan:</b> User Datagram Protocol scanning<br>
        <b>Service Detection:</b> Banner grabbing and fingerprinting<br>
        <b>OS Detection:</b> Operating system identification
        """)
        scan_frame.layout().addWidget(scan_info)
        
        # Common ports
        ports_frame = self.create_section_frame("Common Ports")
        ports_info = self.create_info_text("""
        <b>21:</b> FTP - File Transfer Protocol<br>
        <b>22:</b> SSH - Secure Shell<br>
        <b>23:</b> Telnet - Remote terminal<br>
        <b>25:</b> SMTP - Simple Mail Transfer<br>
        <b>53:</b> DNS - Domain Name System<br>
        <b>80:</b> HTTP - Web traffic<br>
        <b>443:</b> HTTPS - Secure web traffic<br>
        <b>3389:</b> RDP - Remote Desktop Protocol
        """)
        ports_frame.layout().addWidget(ports_info)
        
        self.content_layout.addWidget(port_frame)
        self.content_layout.addWidget(scan_frame)
        self.content_layout.addWidget(ports_frame)
        
    def create_smb_graphics(self):
        """Create SMB enumeration graphics"""
        self.tool_title.setText("SMB Enumeration")
        
        # SMB architecture
        arch_frame = self.create_section_frame("SMB Architecture")
        arch_view = SMBArchitectureView()
        arch_frame.layout().addWidget(arch_view)
        
        # Enumeration techniques
        enum_frame = self.create_section_frame("Enumeration Techniques")
        enum_info = self.create_info_text("""
        <b>Share Enumeration:</b> Discover available network shares<br>
        <b>Null Session:</b> Anonymous connection attempts<br>
        <b>User Enumeration:</b> Identify domain users and groups<br>
        <b>OS Fingerprinting:</b> Determine operating system version<br>
        <b>Vulnerability Scanning:</b> Check for known SMB exploits
        """)
        enum_frame.layout().addWidget(enum_info)
        
        # Security considerations
        security_frame = self.create_section_frame("Security Considerations")
        security_info = self.create_info_text("""
        <b>SMBv1 Vulnerabilities:</b> EternalBlue, MS17-010<br>
        <b>Authentication:</b> NTLM, Kerberos protocols<br>
        <b>Share Permissions:</b> Access control evaluation<br>
        <b>Signing Requirements:</b> Message integrity verification
        """)
        security_frame.layout().addWidget(security_info)
        
        self.content_layout.addWidget(arch_frame)
        self.content_layout.addWidget(enum_frame)
        self.content_layout.addWidget(security_frame)
        
    def create_http_graphics(self):
        """Create HTTP enumeration graphics"""
        self.tool_title.setText("HTTP/S Fingerprinting")
        
        # HTTP stack visualization
        stack_frame = self.create_section_frame("HTTP Protocol Stack")
        stack_view = HTTPStackView()
        stack_frame.layout().addWidget(stack_view)
        
        # Fingerprinting techniques
        finger_frame = self.create_section_frame("Fingerprinting Techniques")
        finger_info = self.create_info_text("""
        <b>Server Headers:</b> Identify web server software<br>
        <b>Directory Enumeration:</b> Discover hidden paths<br>
        <b>Technology Detection:</b> Framework and CMS identification<br>
        <b>SSL/TLS Analysis:</b> Certificate and cipher evaluation<br>
        <b>Security Headers:</b> HSTS, CSP, X-Frame-Options analysis
        """)
        finger_frame.layout().addWidget(finger_info)
        
        # Common vulnerabilities
        vuln_frame = self.create_section_frame("Common Web Vulnerabilities")
        vuln_info = self.create_info_text("""
        <b>Directory Traversal:</b> Path manipulation attacks<br>
        <b>Information Disclosure:</b> Sensitive data exposure<br>
        <b>Weak SSL/TLS:</b> Insecure cryptographic implementations<br>
        <b>Default Credentials:</b> Unchanged administrative passwords<br>
        <b>Outdated Software:</b> Unpatched web applications
        """)
        vuln_frame.layout().addWidget(vuln_info)
        
        self.content_layout.addWidget(stack_frame)
        self.content_layout.addWidget(finger_frame)
        self.content_layout.addWidget(vuln_frame)
        
    def create_smtp_graphics(self):
        """Create SMTP enumeration graphics"""
        self.tool_title.setText("SMTP Enumeration")
        
        # SMTP flow diagram
        flow_frame = self.create_section_frame("SMTP Communication Flow")
        flow_view = SMTPFlowView()
        flow_frame.layout().addWidget(flow_view)
        
        # Enumeration methods
        methods_frame = self.create_section_frame("User Enumeration Methods")
        methods_info = self.create_info_text("""
        <b>VRFY Command:</b> Verify if user exists on server<br>
        <b>EXPN Command:</b> Expand mailing list members<br>
        <b>RCPT TO:</b> Test recipient acceptance<br>
        <b>Banner Grabbing:</b> Server identification and version<br>
        <b>Relay Testing:</b> Open mail relay detection
        """)
        methods_frame.layout().addWidget(methods_info)
        
        # Security implications
        security_frame = self.create_section_frame("Security Implications")
        security_info = self.create_info_text("""
        <b>Information Disclosure:</b> Username enumeration risks<br>
        <b>Open Relays:</b> Spam and abuse potential<br>
        <b>Authentication Bypass:</b> Weak credential policies<br>
        <b>TLS Configuration:</b> Encryption and certificate validation
        """)
        security_frame.layout().addWidget(security_info)
        
        self.content_layout.addWidget(flow_frame)
        self.content_layout.addWidget(methods_frame)
        self.content_layout.addWidget(security_frame)
        
    def create_snmp_graphics(self):
        """Create SNMP enumeration graphics"""
        self.tool_title.setText("SNMP Enumeration")
        
        # SNMP architecture
        arch_frame = self.create_section_frame("SNMP Architecture")
        arch_view = SNMPArchitectureView()
        arch_frame.layout().addWidget(arch_view)
        
        # MIB information
        mib_frame = self.create_section_frame("Management Information Base (MIB)")
        mib_info = self.create_info_text("""
        <b>System Information:</b> 1.3.6.1.2.1.1 - Device details<br>
        <b>Network Interfaces:</b> 1.3.6.1.2.1.2 - Interface statistics<br>
        <b>Routing Table:</b> 1.3.6.1.2.1.4.21 - Network routes<br>
        <b>TCP Connections:</b> 1.3.6.1.2.1.6.13 - Active connections<br>
        <b>Running Processes:</b> 1.3.6.1.2.1.25.4.2 - Process list<br>
        <b>Installed Software:</b> 1.3.6.1.2.1.25.6.3 - Software inventory
        """)
        mib_frame.layout().addWidget(mib_info)
        
        # Community strings
        comm_frame = self.create_section_frame("Community String Security")
        comm_info = self.create_info_text("""
        <b>Default Communities:</b> public, private, community<br>
        <b>Read-Only Access:</b> Information disclosure risks<br>
        <b>Read-Write Access:</b> Configuration modification potential<br>
        <b>SNMPv3 Security:</b> Authentication and encryption features
        """)
        comm_frame.layout().addWidget(comm_info)
        
        self.content_layout.addWidget(arch_frame)
        self.content_layout.addWidget(mib_frame)
        self.content_layout.addWidget(comm_frame)
        
    def create_api_graphics(self):
        """Create API enumeration graphics"""
        self.tool_title.setText("API Enumeration")
        
        # API architecture
        api_frame = self.create_section_frame("API Architecture Types")
        api_view = APIArchitectureView()
        api_frame.layout().addWidget(api_view)
        
        # Enumeration techniques
        enum_frame = self.create_section_frame("Enumeration Techniques")
        enum_info = self.create_info_text("""
        <b>Endpoint Discovery:</b> Find available API endpoints<br>
        <b>HTTP Method Testing:</b> GET, POST, PUT, DELETE, PATCH<br>
        <b>Parameter Fuzzing:</b> Identify accepted parameters<br>
        <b>Authentication Bypass:</b> Test access controls<br>
        <b>Version Enumeration:</b> Discover API versions (v1, v2, v3)
        """)
        enum_frame.layout().addWidget(enum_info)
        
        # Common vulnerabilities
        vuln_frame = self.create_section_frame("OWASP API Security Top 10")
        vuln_info = self.create_info_text("""
        <b>Broken Authentication:</b> Weak authentication mechanisms<br>
        <b>Excessive Data Exposure:</b> Over-sharing of information<br>
        <b>Lack of Rate Limiting:</b> Resource consumption attacks<br>
        <b>Injection Attacks:</b> SQL, NoSQL, Command injection<br>
        <b>Security Misconfiguration:</b> Default or weak settings
        """)
        vuln_frame.layout().addWidget(vuln_info)
        
        self.content_layout.addWidget(api_frame)
        self.content_layout.addWidget(enum_frame)
        self.content_layout.addWidget(vuln_frame)
        
    def create_rpc_graphics(self):
        """Create RPC enumeration graphics"""
        self.tool_title.setText("RPC Enumeration")
        
        # RPC architecture
        rpc_frame = self.create_section_frame("RPC Architecture")
        rpc_view = RPCArchitectureView()
        rpc_frame.layout().addWidget(rpc_view)
        
        # Enumeration methods
        methods_frame = self.create_section_frame("Enumeration Methods")
        methods_info = self.create_info_text("""
        <b>Endpoint Mapper:</b> Port 135 service discovery<br>
        <b>NULL Session:</b> Anonymous connection attempts<br>
        <b>Domain Enumeration:</b> User and group discovery<br>
        <b>Share Enumeration:</b> Network resource identification<br>
        <b>Registry Access:</b> Remote registry enumeration
        """)
        methods_frame.layout().addWidget(methods_info)
        
        # Security considerations
        security_frame = self.create_section_frame("Security Considerations")
        security_info = self.create_info_text("""
        <b>Windows 11 Changes:</b> RemoteRegistry disabled by default<br>
        <b>UAC Token Filtering:</b> Administrative access restrictions<br>
        <b>Authentication Requirements:</b> Credential-based access<br>
        <b>Network Segmentation:</b> RPC endpoint filtering
        """)
        security_frame.layout().addWidget(security_info)
        
        self.content_layout.addWidget(rpc_frame)
        self.content_layout.addWidget(methods_frame)
        self.content_layout.addWidget(security_frame)
        
    def create_default_graphics(self):
        """Create default graphics for unknown tool types"""
        self.tool_title.setText("Enumeration Tool")
        
        default_frame = self.create_section_frame("Tool Information")
        default_info = self.create_info_text("""
        This enumeration tool provides comprehensive security assessment capabilities.
        Select specific options and configure parameters to begin scanning.
        """)
        default_frame.layout().addWidget(default_info)
        
        self.content_layout.addWidget(default_frame)
        
    def create_section_frame(self, title):
        """Create a section frame with title"""
        frame = QFrame()
        frame.setFrameStyle(QFrame.Shape.Box)
        frame.setStyleSheet("""
            QFrame {
                border: 1px solid #64C8FF;
                border-radius: 8px;
                margin: 5px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(frame)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            font-size: 14pt;
            font-weight: bold;
            color: #64C8FF;
            border: none;
            margin-bottom: 10px;
        """)
        layout.addWidget(title_label)
        
        return frame
        
    def create_info_text(self, text):
        """Create formatted information text"""
        label = QLabel(text)
        label.setWordWrap(True)
        label.setStyleSheet("""
            color: #DCDCDC;
            font-size: 11pt;
            line-height: 1.4;
            border: none;
        """)
        return label

# Visualization components for different tools
class DNSHierarchyView(QGraphicsView):
    """DNS hierarchy visualization"""
    
    def __init__(self):
        super().__init__()
        self.setFixedHeight(200)
        self.setup_scene()
        
    def setup_scene(self):
        scene = QGraphicsScene()
        
        # Create DNS hierarchy visualization
        # Root domain
        root = scene.addEllipse(150, 20, 100, 40, QPen(QColor("#64C8FF")), QBrush(QColor("#64C8FF")))
        root_text = scene.addText("Root (.)", QFont("Arial", 10))
        root_text.setPos(170, 30)
        root_text.setDefaultTextColor(QColor("white"))
        
        # TLD
        tld = scene.addEllipse(150, 80, 100, 40, QPen(QColor("#00FF41")), QBrush(QColor("#00FF41")))
        tld_text = scene.addText("TLD (.com)", QFont("Arial", 10))
        tld_text.setPos(165, 90)
        tld_text.setDefaultTextColor(QColor("black"))
        
        # Domain
        domain = scene.addEllipse(150, 140, 100, 40, QPen(QColor("#FFAA00")), QBrush(QColor("#FFAA00")))
        domain_text = scene.addText("Domain", QFont("Arial", 10))
        domain_text.setPos(175, 150)
        domain_text.setDefaultTextColor(QColor("black"))
        
        # Connect with lines
        scene.addLine(200, 60, 200, 80, QPen(QColor("#DCDCDC"), 2))
        scene.addLine(200, 120, 200, 140, QPen(QColor("#DCDCDC"), 2))
        
        self.setScene(scene)

class PortRangeView(QGraphicsView):
    """Port range visualization"""
    
    def __init__(self):
        super().__init__()
        self.setFixedHeight(150)
        self.setup_scene()
        
    def setup_scene(self):
        scene = QGraphicsScene()
        
        # Port ranges
        ranges = [
            (0, 1023, "Well-known", "#FF4444"),
            (1024, 49151, "Registered", "#FFAA00"),
            (49152, 65535, "Dynamic", "#00FF41")
        ]
        
        x_start = 20
        width = 360
        
        for i, (start, end, name, color) in enumerate(ranges):
            y = 20 + i * 40
            rect = scene.addRect(x_start, y, width, 30, QPen(QColor(color)), QBrush(QColor(color)))
            
            text = scene.addText(f"{name} ({start}-{end})", QFont("Arial", 9))
            text.setPos(x_start + 10, y + 5)
            text.setDefaultTextColor(QColor("white"))
        
        self.setScene(scene)

class SMBArchitectureView(QGraphicsView):
    """SMB architecture visualization"""
    
    def __init__(self):
        super().__init__()
        self.setFixedHeight(180)
        self.setup_scene()
        
    def setup_scene(self):
        scene = QGraphicsScene()
        
        # SMB layers
        layers = [
            ("Application", "#64C8FF"),
            ("SMB Protocol", "#00FF41"),
            ("NetBIOS", "#FFAA00"),
            ("TCP/IP", "#FF6666")
        ]
        
        for i, (layer, color) in enumerate(layers):
            y = 20 + i * 35
            rect = scene.addRect(100, y, 200, 30, QPen(QColor(color)), QBrush(QColor(color)))
            
            text = scene.addText(layer, QFont("Arial", 10))
            text.setPos(170, y + 5)
            text.setDefaultTextColor(QColor("white"))
        
        self.setScene(scene)

class HTTPStackView(QGraphicsView):
    """HTTP protocol stack visualization"""
    
    def __init__(self):
        super().__init__()
        self.setFixedHeight(160)
        self.setup_scene()
        
    def setup_scene(self):
        scene = QGraphicsScene()
        
        # HTTP stack layers
        layers = [
            ("HTTP/HTTPS", "#64C8FF"),
            ("TLS/SSL", "#00FF41"),
            ("TCP", "#FFAA00"),
            ("IP", "#FF6666")
        ]
        
        for i, (layer, color) in enumerate(layers):
            y = 20 + i * 30
            rect = scene.addRect(120, y, 160, 25, QPen(QColor(color)), QBrush(QColor(color)))
            
            text = scene.addText(layer, QFont("Arial", 9))
            text.setPos(170, y + 3)
            text.setDefaultTextColor(QColor("white"))
        
        self.setScene(scene)

class SMTPFlowView(QGraphicsView):
    """SMTP communication flow visualization"""
    
    def __init__(self):
        super().__init__()
        self.setFixedHeight(200)
        self.setup_scene()
        
    def setup_scene(self):
        scene = QGraphicsScene()
        
        # SMTP flow steps
        steps = [
            "HELO/EHLO",
            "MAIL FROM",
            "RCPT TO",
            "DATA",
            "QUIT"
        ]
        
        for i, step in enumerate(steps):
            x = 20 + i * 70
            rect = scene.addRect(x, 50, 60, 30, QPen(QColor("#64C8FF")), QBrush(QColor("#64C8FF")))
            
            text = scene.addText(step, QFont("Arial", 8))
            text.setPos(x + 5, 55)
            text.setDefaultTextColor(QColor("white"))
            
            if i < len(steps) - 1:
                scene.addLine(x + 60, 65, x + 70, 65, QPen(QColor("#DCDCDC"), 2))
        
        self.setScene(scene)

class SNMPArchitectureView(QGraphicsView):
    """SNMP architecture visualization"""
    
    def __init__(self):
        super().__init__()
        self.setFixedHeight(180)
        self.setup_scene()
        
    def setup_scene(self):
        scene = QGraphicsScene()
        
        # SNMP components
        components = [
            ("SNMP Manager", 50, 50, "#64C8FF"),
            ("SNMP Agent", 250, 50, "#00FF41"),
            ("MIB Database", 250, 120, "#FFAA00")
        ]
        
        for name, x, y, color in components:
            rect = scene.addRect(x, y, 100, 40, QPen(QColor(color)), QBrush(QColor(color)))
            
            text = scene.addText(name, QFont("Arial", 9))
            text.setPos(x + 10, y + 10)
            text.setDefaultTextColor(QColor("white"))
        
        # Connection lines
        scene.addLine(150, 70, 250, 70, QPen(QColor("#DCDCDC"), 2))
        scene.addLine(300, 90, 300, 120, QPen(QColor("#DCDCDC"), 2))
        
        self.setScene(scene)

class APIArchitectureView(QGraphicsView):
    """API architecture visualization"""
    
    def __init__(self):
        super().__init__()
        self.setFixedHeight(160)
        self.setup_scene()
        
    def setup_scene(self):
        scene = QGraphicsScene()
        
        # API types
        apis = [
            ("REST API", "#64C8FF"),
            ("GraphQL", "#00FF41"),
            ("SOAP", "#FFAA00")
        ]
        
        for i, (api_type, color) in enumerate(apis):
            x = 50 + i * 120
            rect = scene.addRect(x, 50, 100, 40, QPen(QColor(color)), QBrush(QColor(color)))
            
            text = scene.addText(api_type, QFont("Arial", 10))
            text.setPos(x + 20, y + 10)
            text.setDefaultTextColor(QColor("white"))
        
        self.setScene(scene)

class RPCArchitectureView(QGraphicsView):
    """RPC architecture visualization"""
    
    def __init__(self):
        super().__init__()
        self.setFixedHeight(200)
        self.setup_scene()
        
    def setup_scene(self):
        scene = QGraphicsScene()
        
        # RPC components
        client = scene.addRect(50, 50, 80, 40, QPen(QColor("#64C8FF")), QBrush(QColor("#64C8FF")))
        client_text = scene.addText("RPC Client", QFont("Arial", 9))
        client_text.setPos(60, 60)
        client_text.setDefaultTextColor(QColor("white"))
        
        server = scene.addRect(250, 50, 80, 40, QPen(QColor("#00FF41")), QBrush(QColor("#00FF41")))
        server_text = scene.addText("RPC Server", QFont("Arial", 9))
        server_text.setPos(260, 60)
        server_text.setDefaultTextColor(QColor("black"))
        
        # Endpoint mapper
        mapper = scene.addRect(150, 120, 80, 40, QPen(QColor("#FFAA00")), QBrush(QColor("#FFAA00")))
        mapper_text = scene.addText("Endpoint\nMapper", QFont("Arial", 8))
        mapper_text.setPos(160, 125)
        mapper_text.setDefaultTextColor(QColor("black"))
        
        # Connection lines
        scene.addLine(130, 70, 250, 70, QPen(QColor("#DCDCDC"), 2))
        scene.addLine(190, 90, 190, 120, QPen(QColor("#DCDCDC"), 2))
        
        self.setScene(scene)