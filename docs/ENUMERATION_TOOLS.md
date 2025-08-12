# Enumeration Tools Documentation

This document provides detailed information about all enumeration tools available in Huggin.

## Overview

Huggin includes 8 comprehensive enumeration tools, each designed for specific network reconnaissance and security assessment tasks. All tools feature:

- **Multi-threaded scanning** for improved performance
- **Real-time progress tracking** with visual feedback
- **Multiple output formats** (JSON, CSV, XML, PDF reports)
- **Session management** for project organization
- **Result caching** to avoid redundant scans
- **Proxy support** for network routing
- **Rate limiting** to prevent target overload

## Tool Categories

### 1. DNS Enumeration
**Purpose**: Domain and subdomain reconnaissance
**Protocols**: DNS (UDP/TCP 53)

**Features**:
- Subdomain discovery using wordlists or bruteforce
- Multiple DNS record types (A, AAAA, CNAME, MX, TXT, NS, PTR)
- Automatic wildcard detection and filtering
- Zone transfer attempts (AXFR)
- PTR enumeration for IP ranges
- Custom DNS server support

**Use Cases**:
- Subdomain enumeration for attack surface mapping
- DNS infrastructure analysis
- Reverse DNS lookups for network mapping
- Zone transfer testing for misconfigurations

### 2. Port Scanning
**Purpose**: Network service discovery
**Protocols**: TCP

**Features**:
- TCP connect scanning with service detection
- Network sweep for host discovery
- Custom port ranges and common port lists
- Service banner grabbing
- Multi-threaded concurrent scanning

**Use Cases**:
- Open port identification
- Service enumeration
- Network mapping
- Attack surface assessment

### 3. RPC Enumeration
**Purpose**: Windows RPC service enumeration
**Protocols**: RPC (TCP 135)

**Features**:
- Domain user and group enumeration
- Anonymous and authenticated access
- Server information gathering
- Integration with rpcclient

**Use Cases**:
- Windows domain reconnaissance
- User account enumeration
- Domain controller analysis
- Privilege escalation preparation

### 4. SMB Enumeration
**Purpose**: SMB/NetBIOS service analysis
**Protocols**: SMB (TCP 445), NetBIOS (TCP 139)

**Features**:
- SMB share enumeration and permissions
- Operating system fingerprinting
- NetBIOS name resolution
- Vulnerability scanning (MS17-010, MS08-067)
- Multi-tool integration (smbclient, nbtscan, nmap)

**Use Cases**:
- Windows network enumeration
- Share discovery and access testing
- OS version identification
- SMB vulnerability assessment

### 5. SMTP Enumeration
**Purpose**: Email server user enumeration
**Protocols**: SMTP (TCP 25)

**Features**:
- Multi-method user enumeration (VRFY, EXPN, RCPT TO)
- Wordlist-based username testing
- Custom domain configuration
- Mail server banner analysis
- Automatic method fallback

**Use Cases**:
- Email user enumeration
- Mail server reconnaissance
- Social engineering preparation
- Email security assessment

### 6. SNMP Enumeration
**Purpose**: Network device information gathering
**Protocols**: SNMP (UDP 161)

**Features**:
- Community string brute-forcing
- MIB walking with specific OIDs
- System information gathering
- User and process enumeration
- Network interface discovery
- SNMP v1, v2c, and v3 support

**Use Cases**:
- Network device enumeration
- System information gathering
- Security configuration analysis
- Network topology mapping

### 7. HTTP/S Fingerprinting
**Purpose**: Web application reconnaissance
**Protocols**: HTTP (TCP 80), HTTPS (TCP 443)

**Features**:
- Web server identification and fingerprinting
- SSL/TLS certificate analysis
- Directory and file enumeration
- Security header analysis
- Technology stack detection
- Vulnerability scanning integration

**Use Cases**:
- Web application enumeration
- Technology identification
- SSL/TLS security assessment
- Hidden content discovery

### 8. API Enumeration
**Purpose**: API endpoint discovery and testing
**Protocols**: HTTP/HTTPS

**Features**:
- REST API endpoint discovery
- GraphQL and Swagger enumeration
- HTTP method testing
- Authentication bypass testing
- Vulnerability assessment (SQLi, NoSQLi)
- API versioning detection

**Use Cases**:
- API security assessment
- Endpoint discovery
- Authentication testing
- API vulnerability analysis

## Tool Integration

### External Tool Dependencies

**Linux/WSL Requirements**:
- `nmap` - Network scanning and service detection
- `smbclient` - SMB share enumeration
- `nbtscan` - NetBIOS name scanning
- `rpcclient` - RPC enumeration
- `snmp-utils` - SNMP enumeration
- `gobuster` - Directory and API enumeration
- `nikto` - Web vulnerability scanning

**Installation Commands**:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap smbclient nbtscan samba-common-bin snmp snmp-utils

# Optional tools
sudo apt install gobuster nikto

# Go-based tools
go install github.com/OJ/gobuster/v3@latest
```

### Python Dependencies
All enumeration tools use native Python libraries where possible:
- `requests` - HTTP/HTTPS communication
- `dnspython` - DNS operations
- `socket` - Network connectivity testing
- `ssl` - SSL/TLS certificate analysis
- `subprocess` - External tool integration

## Configuration Options

### Global Settings
- **Timeout values**: Configurable connection timeouts
- **Thread counts**: Adjustable concurrency levels
- **Rate limiting**: Requests per second control
- **Proxy settings**: HTTP/SOCKS proxy support
- **User agents**: Customizable HTTP user agents

### Tool-Specific Settings
- **DNS**: Custom DNS servers, record types, wildcard handling
- **Port Scanning**: Port ranges, scan types, service detection
- **SMB**: Authentication methods, share enumeration depth
- **SMTP**: Domain configuration, enumeration methods
- **SNMP**: Community strings, MIB OIDs, version support
- **HTTP**: Extensions, wordlists, security analysis
- **API**: Endpoint patterns, vulnerability testing depth

## Output Formats

### Real-time Output
- **Terminal-style display** with color coding
- **Progress indicators** for long-running scans
- **Status updates** and error reporting
- **Live result streaming** as discoveries are made

### Export Formats
- **JSON**: Structured data for programmatic processing
- **CSV**: Tabular data for spreadsheet analysis
- **XML**: Hierarchical data representation
- **PDF**: Professional reports with executive summaries
- **HTML**: Web-viewable reports with interactive elements

### Session Management
- **Project organization**: Group related scans by project
- **Scan history**: Persistent storage of all scan results
- **Result comparison**: Compare scans over time
- **Session export**: Export entire project data

## Best Practices

### Reconnaissance Workflow
1. **Start with DNS enumeration** to map the attack surface
2. **Perform port scanning** to identify services
3. **Use protocol-specific tools** based on discovered services
4. **Combine results** for comprehensive analysis
5. **Document findings** using session management

### Performance Optimization
- **Use appropriate thread counts** for target capacity
- **Enable rate limiting** to avoid detection
- **Cache results** to prevent redundant scans
- **Use proxy rotation** for large-scale enumeration

### Legal and Ethical Considerations
- **Only scan authorized targets**
- **Respect rate limits** and target capacity
- **Follow responsible disclosure** for vulnerabilities
- **Document authorization** for all scanning activities

## Troubleshooting

### Common Issues
- **Tool not found**: Install required external dependencies
- **Permission denied**: Run with appropriate privileges
- **Connection timeout**: Adjust timeout values or check connectivity
- **Rate limiting**: Reduce thread count or enable rate limiting

### Debug Information
- **Verbose logging** available for all tools
- **Error reporting** with detailed stack traces
- **Network connectivity testing** built into each tool
- **Tool availability checking** before execution

## Advanced Usage

### Custom Wordlists
- **Create custom wordlists** for specific targets
- **Import external wordlists** from security distributions
- **Merge wordlists** for comprehensive coverage
- **Wordlist statistics** and content preview

### Automation
- **Scan scheduling** for regular assessments
- **Template-based scanning** for consistent methodology
- **Multi-target scanning** for bulk assessments
- **Result correlation** across multiple scans

### Integration
- **Plugin system** for custom functionality
- **API integration** with external services
- **Threat intelligence** integration for IOC checking
- **Machine learning** pattern detection for anomaly analysis

This documentation provides a comprehensive overview of all enumeration capabilities in Huggin. For specific usage examples and detailed configuration options, refer to the individual tool documentation and built-in help system.