# app/tools/port_utils.py
from PyQt6.QtCore import QThreadPool
from .port_scanner import PortScanWorker, NetworkSweepWorker, EnhancedPortScanWorker, Layer2SweepWorker, get_common_ports, get_top_ports

def run_port_scan(target, ports, output_callback, status_callback, finished_callback, results_callback, progress_callback=None, progress_start_callback=None):
    """Run TCP port scan on target"""
    worker = PortScanWorker(target, ports)
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker

def run_network_sweep(network_range, output_callback, status_callback, finished_callback, results_callback, progress_callback=None, progress_start_callback=None):
    """Run network sweep to discover alive hosts"""
    worker = NetworkSweepWorker(network_range)
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker



def parse_port_range(port_string):
    """Parse port range string into list of ports"""
    ports = []
    
    if not port_string.strip():
        raise ValueError("Port range cannot be empty")
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            # Range like 80-90 or 1-65535
            try:
                start, end = map(int, part.split('-', 1))
                if start > end:
                    raise ValueError(f"Invalid range: {part} (start > end)")
                if start < 1 or end > 65535:
                    raise ValueError(f"Port range must be 1-65535: {part}")
                
                # Allow full port range scanning
                ports.extend(range(start, end + 1))
            except ValueError as e:
                if "invalid literal" in str(e):
                    raise ValueError(f"Invalid port number in range: {part}")
                raise
        else:
            # Single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port must be 1-65535: {port}")
                ports.append(port)
            except ValueError:
                raise ValueError(f"Invalid port number: {part}")
    
    return sorted(list(set(ports)))  # Remove duplicates and sort

def parse_tcp_udp_ports(tcp_ports_text, udp_ports_text):
    """Parse separate TCP and UDP port ranges"""
    tcp_ports = []
    udp_ports = []
    
    if tcp_ports_text and tcp_ports_text.strip():
        try:
            tcp_ports = parse_port_range(tcp_ports_text)
        except ValueError:
            tcp_ports = []
    
    if udp_ports_text and udp_ports_text.strip():
        try:
            udp_ports = parse_port_range(udp_ports_text)
        except ValueError:
            udp_ports = []
    
    return tcp_ports, udp_ports

def categorize_services(open_ports):
    """Categorize services based on open ports"""
    categories = {
        'Web / HTTP(S) Services': [80, 443, 8000, 8080, 8081, 8086, 8443, 8880, 8888],
        'Remote Access / Tunneling / Admin': [22, 23, 2222, 3389, 500, 4500, 1194, 1723, 5040, 5050, 5900, 7680],
        'Email / Messaging': [25, 110, 143, 993, 995, 2525, 5671, 5672],
        'Database / Storage': [1433, 1521, 3306, 5432, 5984, 5987, 6378, 6379, 7474, 9000, 9042, 9200, 11211, 27017, 27018, 27019],
        'Dev / Internal Tools': [3000, 5000, 5001, 7000, 7001, 8200, 8500, 8787, 9001, 9090, 9093, 15672],
        'Directory / Auth Services': [88, 389, 636, 3268, 3269, 464],
        'Container / Cloud / K8s': [2375, 2376, 6443, 10250, 10255],
        'IoT / Multimedia / Misc': [161, 554, 1900, 2181, 5353, 5355, 8883]
    }
    
    found_services = {}
    for port in open_ports:
        for category, ports in categories.items():
            if port in ports:
                if category not in found_services:
                    found_services[category] = []
                found_services[category].append(port)
    
    return found_services

def get_service_description(port):
    """Get service description for a port"""
    service_map = {
        20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client', 80: 'HTTP', 88: 'Kerberos',
        110: 'POP3', 111: 'RPC', 135: 'RPC Endpoint', 137: 'NetBIOS Name',
        138: 'NetBIOS Datagram', 139: 'NetBIOS Session', 143: 'IMAP', 161: 'SNMP',
        389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 464: 'Kerberos Password',
        554: 'RTSP', 631: 'IPP', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 1900: 'UPnP',
        2181: 'Zookeeper', 2222: 'SSH Alt', 2375: 'Docker', 2376: 'Docker TLS',
        2525: 'SMTP Alt', 3000: 'Dev Server', 3268: 'LDAP GC', 3269: 'LDAP GC SSL',
        3306: 'MySQL', 3389: 'RDP', 3544: 'Teredo', 500: 'IKE', 5000: 'UPnP',
        5001: 'Commplex', 5040: 'Unknown', 5050: 'Yahoo Messenger',
        5432: 'PostgreSQL', 5671: 'AMQP SSL', 5672: 'AMQP', 5984: 'CouchDB',
        5985: 'WinRM HTTP', 5986: 'WinRM HTTPS', 5987: 'Unknown',
        6378: 'Redis Alt', 6379: 'Redis', 6443: 'Kubernetes API',
        7000: 'Cassandra', 7001: 'Cassandra SSL', 7474: 'Neo4j',
        7680: 'Pando Media', 8000: 'HTTP Alt', 8042: 'Unknown',
        8080: 'HTTP Proxy', 8081: 'HTTP Alt', 8086: 'InfluxDB',
        8200: 'Vault', 8443: 'HTTPS Alt', 8500: 'Consul', 8787: 'Unknown',
        8880: 'HTTP Alt', 8883: 'MQTT SSL', 8888: 'HTTP Alt',
        9000: 'SonarQube', 9001: 'Tor', 9042: 'Cassandra CQL',
        9090: 'Prometheus', 9093: 'Alertmanager', 9200: 'Elasticsearch',
        9220: 'Unknown', 9221: 'Unknown', 9222: 'Unknown', 9223: 'Unknown',
        9224: 'Unknown', 9225: 'Unknown', 9226: 'Unknown', 9227: 'Unknown',
        9228: 'Unknown', 9229: 'Unknown', 11211: 'Memcached',
        15672: 'RabbitMQ Mgmt', 27017: 'MongoDB', 27018: 'MongoDB Shard',
        27019: 'MongoDB Config'
    }
    return service_map.get(port, f'Port {port}')

def detect_server_type(open_ports):
    """Detect server type based on port combinations"""
    port_set = set(open_ports)
    
    # Windows Domain Controller - most specific first
    dc_ports = {53, 88, 135, 389, 445, 464, 636, 3268, 3269, 5985}
    if len(dc_ports.intersection(port_set)) >= 6:
        return "Windows Domain Controller"
    
    # Windows Server with AD services
    ad_ports = {88, 389, 636, 3268, 3269}
    win_ports = {135, 445}
    if len(ad_ports.intersection(port_set)) >= 3 and win_ports.issubset(port_set):
        return "Windows Active Directory Server"
    
    # Database servers
    if 1433 in port_set:
        return "Microsoft SQL Server"
    if 3306 in port_set:
        return "MySQL Database Server"
    if 5432 in port_set:
        return "PostgreSQL Database Server"
    if 1521 in port_set:
        return "Oracle Database Server"
    if {6379}.issubset(port_set):
        return "Redis Server"
    if {27017}.issubset(port_set):
        return "MongoDB Server"
    if {9200}.issubset(port_set):
        return "Elasticsearch Server"
    
    # Web servers
    web_ports = {80, 443}
    if web_ports.intersection(port_set):
        if win_ports.issubset(port_set):
            return "Windows Web Server (IIS)"
        elif 22 in port_set:
            return "Linux Web Server"
        else:
            return "Web Server"
    
    # Mail servers
    mail_ports = {25, 110, 143, 993, 995}
    if len(mail_ports.intersection(port_set)) >= 2:
        return "Mail Server"
    
    # File servers
    if {445, 139}.issubset(port_set) or {21}.issubset(port_set):
        return "File Server"
    
    # Network infrastructure
    if {161}.issubset(port_set):
        return "Network Device (SNMP)"
    if {554}.issubset(port_set):
        return "Media/Streaming Server"
    
    # Generic Windows/Linux detection
    if win_ports.issubset(port_set):
        return "Windows Server"
    elif 22 in port_set:
        return "Linux/Unix Server"
    
    return "Unknown"

def run_ip_range_port_scan(ip_range, ports, output_callback, status_callback, finished_callback, results_callback, progress_callback=None, progress_start_callback=None):
    """Run port scan on IP range"""
    from app.core.ip_range_parser import parse_ip_range
    
    # Parse IP range using proper parser
    ips = parse_ip_range(ip_range)
    if not ips:
        if status_callback:
            status_callback(f"Invalid IP range: {ip_range}")
        if output_callback:
            output_callback(f"<p style='color: #FF4500;'>[ERROR] Invalid IP range: {ip_range}</p><br>")
        if finished_callback:
            finished_callback()
        return None
    
    # Create worker for IP range scanning
    from .port_scanner import IPRangePortScanWorker
    worker = IPRangePortScanWorker(ips, ports)
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    QThreadPool.globalInstance().start(worker)
    return worker

def ping_sweep(target, output_callback, status_callback, finished_callback, results_callback=None, progress_callback=None, progress_start_callback=None, tenant_id="default"):
    """Run ping sweep to discover alive hosts"""
    worker = NetworkSweepWorker(target, timeout=1, tenant_id=tenant_id)
    worker.scan_type = 'ping_sweep'  # Set scan type for differentiation
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    if results_callback:
        worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    from PyQt6.QtCore import QThreadPool
    QThreadPool.globalInstance().start(worker)
    return worker

def huggin_sweep(target, output_callback, status_callback, finished_callback, results_callback=None, progress_callback=None, progress_start_callback=None, tenant_id="default"):
    """Run Huggin sweep (host discovery only - no port scanning)"""
    worker = NetworkSweepWorker(target, timeout=1, tenant_id=tenant_id)
    worker.scan_type = 'huggin_sweep'  # Set scan type for differentiation
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    if results_callback:
        worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    from PyQt6.QtCore import QThreadPool
    QThreadPool.globalInstance().start(worker)
    return worker

def enhanced_port_scan(target, ports, os_detection=False, service_detection=False, output_callback=None, status_callback=None, finished_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None, tenant_id="default"):
    """Run enhanced port scan with OS and service detection"""
    from app.core.ip_range_parser import parse_ip_range
    from .port_scanner import EnhancedPortScanWorker
    
    # Parse target IPs
    ips = parse_ip_range(target)
    if not ips:
        if status_callback:
            status_callback(f"Invalid target range: {target}")
        if output_callback:
            output_callback(f"<p style='color: #FF4500;'>[ERROR] Invalid target range: {target}</p><br>")
        if finished_callback:
            finished_callback()
        return None
    
    # Parse ports
    try:
        port_list = parse_port_range(ports)
        
        # Use single target or multiple targets based on parsed IPs
        if len(ips) == 1:
            target = ips[0]
        else:
            target = ips
            
        worker = EnhancedPortScanWorker(
            target, 
            tcp_ports=port_list,
            os_detection=os_detection,
            service_detection=service_detection,
            tenant_id=tenant_id
        )
        
        # Connect signals
        worker.signals.output.connect(output_callback)
        worker.signals.status.connect(status_callback)
        worker.signals.finished.connect(finished_callback)
        worker.signals.results_ready.connect(results_callback)
        
        if progress_callback:
            worker.signals.progress_update.connect(progress_callback)
        if progress_start_callback:
            worker.signals.progress_start.connect(progress_start_callback)
        
        QThreadPool.globalInstance().start(worker)
        return worker
        
    except ValueError as e:
        if status_callback:
            status_callback(f"Invalid port range: {e}")
        if output_callback:
            output_callback(f"<p style='color: #FF4500;'>[ERROR] {e}</p><br>")
        if finished_callback:
            finished_callback()
        return None

def enhanced_targeted_scan(target, ports, os_detection=False, service_detection=False, output_callback=None, status_callback=None, finished_callback=None, results_callback=None, progress_callback=None, progress_start_callback=None, tenant_id="default"):
    """Run enhanced targeted port scan with OS and service detection"""
    from app.core.ip_range_parser import parse_ip_range
    from .port_scanner import EnhancedPortScanWorker
    
    # Parse target IPs
    ips = parse_ip_range(target)
    if not ips:
        if status_callback:
            status_callback(f"Invalid target range: {target}")
        if output_callback:
            output_callback(f"<p style='color: #FF4500;'>[ERROR] Invalid target range: {target}</p><br>")
        if finished_callback:
            finished_callback()
        return None
    
    # Parse ports
    try:
        port_list = parse_port_range(ports)
        
        # Create enhanced worker
        worker = EnhancedPortScanWorker(
            ips[0] if len(ips) == 1 else ips,
            port_list,
            os_detection=os_detection,
            service_detection=service_detection,
            tenant_id=tenant_id
        )
        
        # Connect signals
        worker.signals.output.connect(output_callback)
        worker.signals.status.connect(status_callback)
        worker.signals.finished.connect(finished_callback)
        worker.signals.results_ready.connect(results_callback)
        
        if progress_callback:
            worker.signals.progress_update.connect(progress_callback)
        if progress_start_callback:
            worker.signals.progress_start.connect(progress_start_callback)
        
        from PyQt6.QtCore import QThreadPool
        QThreadPool.globalInstance().start(worker)
        return worker
        
    except ValueError as e:
        if status_callback:
            status_callback(f"Invalid port range: {e}")
        if output_callback:
            output_callback(f"<p style='color: #FF4500;'>[ERROR] {e}</p><br>")
        if finished_callback:
            finished_callback()
        return None

def layer2_sweep(target, output_callback, status_callback, finished_callback, results_callback=None, progress_callback=None, progress_start_callback=None, tenant_id="default"):
    """Run Layer 2 sweep using ARP, NDP, NetBIOS, and mDNS"""
    worker = Layer2SweepWorker(target, timeout=2, tenant_id=tenant_id)
    
    # Connect signals
    worker.signals.output.connect(output_callback)
    worker.signals.status.connect(status_callback)
    worker.signals.finished.connect(finished_callback)
    if results_callback:
        worker.signals.results_ready.connect(results_callback)
    
    if progress_callback:
        worker.signals.progress_update.connect(progress_callback)
    if progress_start_callback:
        worker.signals.progress_start.connect(progress_start_callback)
    
    from PyQt6.QtCore import QThreadPool
    QThreadPool.globalInstance().start(worker)
    return worker

def targeted_port_scan(target, ports, output_callback, status_callback, finished_callback, results_callback=None, progress_callback=None, progress_start_callback=None, tenant_id="default"):
    """Legacy targeted port scan - redirects to enhanced scan"""
    return enhanced_port_scan(target, ports, False, False, output_callback, status_callback, finished_callback, results_callback, progress_callback, progress_start_callback, tenant_id)