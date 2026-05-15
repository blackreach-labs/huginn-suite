# Huginn Framework - Complete Database Analysis

## Overview
The Huginn security framework utilizes **15 distinct SQLite databases** for different aspects of security assessment, data collection, and operational management. Each database serves a specific purpose in the comprehensive security testing workflow.

## Database Inventory

### 1. **centralized_scan_data.db** - Primary Data Hub
**Location**: `resources/centralized_scan_data.db`  
**Implementation**: `app/core/centralized_scan_data.py`  
**Purpose**: Central repository for all scan results with tenant isolation

**Key Features**:
- Multi-tenant data separation for enterprise deployments
- Real-time data collection from all 10+ service enumeration tools
- Smart deduplication using SHA256 hashing with count tracking
- Comprehensive scan metadata and session management
- Post-exploitation session and command tracking
- Performance-optimized with strategic indexing

**Tables**:
- `scan_data` - Individual scan results with deduplication
- `scan_metadata` - Scan session information and status
- `post_exploit_sessions` - Post-exploitation session tracking
- `post_exploit_commands` - Command execution history

**Data Types Supported**:
- RPC endpoints, services, vulnerabilities
- DNS subdomains, records, zone transfers
- Port scans, service detection, OS fingerprinting
- HTTP directories, vulnerabilities
- SMB shares, files
- Network endpoints and registry data

---

### 2. **proxy.db** - HTTP Traffic Database
**Location**: `resources/proxy.db`  
**Implementation**: `app/core/proxy_database.py`  
**Purpose**: HTTP/HTTPS traffic interception and analysis

**Key Features**:
- Real-time HTTP/HTTPS traffic capture
- Request/response storage with full headers and body
- Traffic statistics and analysis
- Integration with mitmproxy for SSL interception
- Performance metrics (response time, size tracking)

**Tables**:
- `requests` - Complete HTTP request/response pairs

**Use Cases**:
- Web application security testing
- API traffic analysis
- Authentication flow examination
- Session management testing

---

### 3. **vulnerability_findings.db** - Security Findings
**Location**: `resources/vulnerability_findings.db`  
**Implementation**: `app/core/vulnerability_database.py`  
**Purpose**: Centralized vulnerability collection and reporting

**Key Features**:
- Structured vulnerability data with CVE integration
- Severity classification and risk scoring
- Evidence collection and remediation tracking
- Session-based vulnerability grouping
- Advanced reporting capabilities

**Tables**:
- `vulnerabilities` - Individual vulnerability findings
- `scan_sessions` - Vulnerability scan sessions with statistics

**Vulnerability Categories**:
- RPC vulnerabilities and NTLM relay vectors
- RPC signing/sealing issues
- Service misconfigurations
- Authentication bypasses

---

### 4. **pentest_findings.db** - Penetration Testing Data
**Location**: `resources/pentest_findings.db`  
**Implementation**: `app/core/pentest_database.py`  
**Purpose**: Comprehensive penetration testing data management

**Key Features**:
- Target asset management with OS fingerprinting
- Service enumeration and version tracking
- Vulnerability correlation and risk assessment
- Credential storage and management
- Loot collection and evidence tracking

**Tables**:
- `targets` - Target systems and basic information
- `services` - Discovered services with version details
- `vulnerabilities` - Security vulnerabilities with impact assessment
- `credentials` - Harvested credentials and authentication data
- `loot` - Collected files, screenshots, and sensitive data

**Advanced Features**:
- Risk scoring algorithms
- Attack surface analysis
- Service-based vulnerability correlation
- Multi-source credential management

---

### 5. **breach_data.db** - Breach Intelligence
**Location**: `resources/breach_data.db`  
**Implementation**: `app/core/breach_database.py`  
**Purpose**: Data breach intelligence and credential lookup

**Key Features**:
- Email and domain breach lookup
- Password hash storage and analysis
- Breach source tracking and attribution
- Sample data for testing and demonstration

**Tables**:
- `breaches` - Breach records with email, domain, and credential data

**Sample Data Includes**:
- ExampleBreach2020, TestLeak2019, CompanyHack2021
- MD5 and SHA1 password hashes
- Plain text passwords for testing

---

### 6. **crawl.db** - Web Crawling Data
**Location**: `resources/crawl.db`  
**Implementation**: `app/core/crawl_database.py`  
**Purpose**: Web application crawling and discovery

**Key Features**:
- URL discovery and mapping
- Response code and content type tracking
- Crawl depth and parent URL relationships
- Performance metrics and timing data

**Tables**:
- `crawl_results` - Discovered URLs with metadata

**Crawl Metrics**:
- Domain-based organization
- Path analysis and directory structure
- Response time and content length tracking

---

### 7. **auth_workflows.db** - Authentication Analysis
**Location**: `resources/auth_workflows.db`  
**Implementation**: `app/core/auth_database.py`  
**Purpose**: Authentication workflow analysis and testing

**Key Features**:
- Authentication flow capture and analysis
- Token lifecycle management and entropy analysis
- Vulnerability detection in auth mechanisms
- State model generation for complex flows
- Test result correlation and reporting

**Tables**:
- `auth_flows` - Authentication workflow sessions
- `tokens` - Token analysis and security assessment
- `test_results` - Authentication security test results
- `vulnerabilities` - Auth-specific security issues
- `state_models` - Authentication state machine models

**Security Testing**:
- Token entropy and predictability analysis
- Authentication bypass detection
- Session management vulnerabilities
- Multi-step authentication flow analysis

---

### 8. **listeners.db** - C2 Listener Management
**Location**: `resources/listeners.db`  
**Implementation**: `app/core/listener_manager.py`  
**Purpose**: Command and control listener management

**Key Features**:
- Multi-transport listener support (HTTP, HTTPS, DNS, etc.)
- Session management with automatic expiry
- Audit logging for all listener activities
- Engagement-based isolation
- Plugin architecture for transport protocols

**Tables**:
- `listeners` - Active and historical listeners
- `sessions` - C2 sessions with fingerprinting
- `audit_logs` - Complete audit trail

**Transport Support**:
- HTTP/HTTPS listeners
- DNS tunneling
- Custom transport plugins
- Session fingerprinting and tracking

---

### 9. **exploits.db** - Exploit Database
**Location**: `resources/exploits.db` (implied)  
**Implementation**: `app/core/exploit_database.py`  
**Purpose**: Professional exploit database with CVE integration

**Key Features**:
- CVE database integration with NVD API
- Metasploit module mapping
- CVSS scoring and severity classification
- Service-specific exploit recommendations
- Automated exploit discovery and correlation

**Tables**:
- `exploits` - Exploit definitions with CVE data
- `exploit_categories` - Exploit classification system

**Integration Features**:
- National Vulnerability Database (NVD) synchronization
- Service version to exploit mapping
- Risk-based exploit prioritization
- Automated exploit report generation

---

### 10. **asset_inventory.db** - Asset Management
**Location**: `resources/asset_inventory.db`  
**Implementation**: Referenced in `app/pages/inventory_page.py`  
**Purpose**: Comprehensive asset inventory and management

**Key Features**:
- Multi-tenant asset isolation
- Asset discovery and classification
- Service and vulnerability correlation
- Asset lifecycle management
- Notes and metadata tracking

**Asset Categories**:
- Network devices and servers
- Web applications and services
- Domain controllers and infrastructure
- Discovered vs. identified vs. known assets

---

### 11. **scan_history.db** - Historical Scan Data
**Location**: `resources/scan_history.db`  
**Purpose**: Legacy scan results and historical data

**Key Features**:
- Historical scan result preservation
- Trend analysis and comparison
- Long-term data retention
- Legacy compatibility support

---

### 12. **scan_results.db** - Current Scan Results
**Location**: `resources/scan_results.db`  
**Purpose**: Current and recent scan result storage

**Key Features**:
- Active scan result management
- Quick access to recent findings
- Integration with reporting systems
- Export and analysis capabilities

---

### 13. **correlation.db** - Cross-Scan Correlation
**Location**: `resources/correlation.db`  
**Implementation**: `app/core/cross_scan_correlator.py`  
**Purpose**: Advanced correlation analysis across scan types

**Key Features**:
- Multi-scan type correlation analysis
- Attack chain identification
- Lateral movement opportunity detection
- Credential harvesting pattern recognition
- Network pivoting analysis

**Correlation Types**:
- Lateral movement opportunities
- Credential harvesting vectors
- Service exploitation chains
- Information disclosure patterns
- Network pivoting possibilities

---

### 14. **hash_lookup.db** - Hash Analysis
**Location**: `resources/hash_lookup.db`  
**Implementation**: `application/services/hash_lookup_service.py`  
**Purpose**: Password hash analysis and cracking support

**Key Features**:
- Multi-source hash lookup (local and online)
- Hash type identification and validation
- Database statistics and source tracking
- Integration with external hash databases

**Hash Sources**:
- Local hash databases
- Online API providers
- Custom hash collections
- Breach data integration

---

### 15. **header_mappings.db** - HTTP Header Analysis
**Location**: `resources/header_mappings.db`  
**Purpose**: HTTP header analysis and fingerprinting

**Key Features**:
- HTTP header pattern recognition
- Server fingerprinting capabilities
- Security header analysis
- Custom header mapping rules

---

## Database Architecture Patterns

### Connection Management
- **Database Pool**: `app/core/database_pool.py` provides thread-safe connection pooling
- **WAL Mode**: Write-Ahead Logging for improved concurrency
- **Performance Optimization**: Strategic indexing and query optimization
- **Connection Limits**: Configurable pool sizes and timeout handling

### Data Flow Architecture
```
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│ Service Scanners │───▶│ Data Collectors      │───▶│ Centralized Scan    │
│ • RPC/SMB/SMTP   │    │ • Structured Capture │    │     Database        │
│ • LDAP/SNMP/HTTP │    │ • Data Validation   │    │  (Multi-Tenant)     │
│ • DB/IKE/AV      │    │ • Format Conversion │    │                     │
└─────────────────┘    └──────────────────────┘    └─────────────────────┘
                                                              │
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│ Specialized DBs │◀───│ Data Processing      │◀───│   Data Processing   │
│ • Proxy Traffic  │    │ & Deduplication     │    │   & Deduplication   │
│ • Vulnerabilities│    │ (Smart Hashing)     │    │   (Smart Hashing)   │
│ • Auth Workflows │    │                     │    │                     │
└─────────────────┘    └──────────────────────┘    └─────────────────────┘
```

### Multi-Tenant Support
- **Tenant Isolation**: Complete data separation by tenant ID
- **Profile-Based Access**: Integration with user profile system
- **Data Export**: Tenant-specific data export capabilities
- **Cleanup Operations**: Automated old data cleanup per tenant

### Performance Optimizations
- **Strategic Indexing**: Optimized indexes for common query patterns
- **Connection Pooling**: Thread-safe database connection management
- **Batch Operations**: Efficient bulk data operations
- **Memory Management**: Optimized for large-scale scanning operations

## Integration Points

### Real-Time Updates
- **1-Second Refresh**: UI components update every second with live data
- **Event-Driven Architecture**: Database changes trigger UI updates
- **Progress Tracking**: Real-time scan progress and status updates

### Cross-Database Correlation
- **Unified Reporting**: Reports combine data from multiple databases
- **Attack Chain Analysis**: Correlation across different scan types
- **Risk Assessment**: Comprehensive risk scoring using all data sources

### Export and Reporting
- **Multiple Formats**: JSON, HTML, Markdown export support
- **Executive Summaries**: Business-friendly reporting
- **Technical Reports**: Detailed technical findings
- **Compliance Reports**: OWASP Top 10, PCI DSS compliance mapping

## Security Considerations

### Data Protection
- **Sensitive Data Handling**: Secure storage of credentials and findings
- **Hash-Based Deduplication**: SHA256 hashing for data integrity
- **Audit Trails**: Complete audit logging for all operations
- **Access Control**: Tenant-based access restrictions

### Operational Security
- **Automatic Cleanup**: Configurable data retention policies
- **Secure Deletion**: Proper data sanitization procedures
- **Backup Considerations**: Database backup and recovery procedures
- **Encryption**: Database encryption for sensitive deployments

## Maintenance and Operations

### Database Maintenance
- **Automatic Cleanup**: Built-in old data cleanup procedures
- **Index Maintenance**: Automatic index optimization
- **Statistics Updates**: Database statistics for query optimization
- **Health Monitoring**: Database health and performance monitoring

### Troubleshooting
- **Error Handling**: Comprehensive error handling and logging
- **Recovery Procedures**: Database recovery and repair procedures
- **Performance Tuning**: Query optimization and performance tuning
- **Monitoring Tools**: Database monitoring and alerting capabilities

## Future Enhancements

### Planned Improvements
- **Database Sharding**: Horizontal scaling for large deployments
- **Replication Support**: Master-slave replication for high availability
- **Advanced Analytics**: Machine learning integration for pattern detection
- **Cloud Integration**: Cloud database support for distributed deployments

### Scalability Considerations
- **Horizontal Scaling**: Multi-database deployment strategies
- **Load Balancing**: Database load balancing and distribution
- **Caching Layers**: Redis/Memcached integration for performance
- **Archive Strategies**: Long-term data archival and retrieval

---

## Summary

The Huginn framework employs a sophisticated multi-database architecture with **15 specialized databases** serving different aspects of security assessment:

1. **Primary Data Hub**: `centralized_scan_data.db` - Central repository with tenant isolation
2. **Traffic Analysis**: `proxy.db` - HTTP/HTTPS traffic interception
3. **Security Findings**: `vulnerability_findings.db` - Vulnerability management
4. **Penetration Testing**: `pentest_findings.db` - Comprehensive pentest data
5. **Breach Intelligence**: `breach_data.db` - Data breach lookup
6. **Web Crawling**: `crawl.db` - Web application discovery
7. **Authentication**: `auth_workflows.db` - Auth flow analysis
8. **C2 Management**: `listeners.db` - Command and control
9. **Exploit Database**: `exploits.db` - CVE and exploit management
10. **Asset Inventory**: `asset_inventory.db` - Asset management
11. **Scan History**: `scan_history.db` - Historical data
12. **Current Results**: `scan_results.db` - Active scan results
13. **Correlation**: `correlation.db` - Cross-scan analysis
14. **Hash Analysis**: `hash_lookup.db` - Password hash lookup
15. **Header Analysis**: `header_mappings.db` - HTTP fingerprinting

This architecture provides comprehensive data management for enterprise-grade security assessments with multi-tenant support, real-time updates, advanced correlation capabilities, and robust reporting systems.