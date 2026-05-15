# 🛠️ Huginn Professional - IMPROVEMENTS.md

This document tracks enhancements made and planned for the Huginn penetration testing toolkit. It outlines feature improvements, security-oriented upgrades, and coverage expansion relevant to red teaming, threat emulation, and vulnerability analysis.

---

## 🚀 PROFESSIONAL PENTESTING PLATFORM UPGRADE

### ✅ Core Professional Features Implemented

#### 1. Stealth Engine (Paid Feature)
- Advanced evasion techniques with configurable levels (paranoid, sneaky, polite, normal)
- Packet fragmentation and timing controls
- Decoy IP generation for scan obfuscation
- Nmap stealth flag integration
- Randomized timing delays with jitter
- **Location**: `app/core/stealth_engine.py`

#### 2. Hacking Mode Framework (Paid Feature)
- Exploit framework integration (Metasploit, Empire, Cobalt Strike)
- Automated exploit execution (MS17-010, EternalBlue, Web shells)
- Custom payload generation (reverse shells, bind shells, Meterpreter)
- Privilege escalation techniques
- Lateral movement capabilities
- **Location**: `app/core/hacking_mode.py`

#### 3. ProxyChains Manager (Paid Feature)
- Multi-proxy chaining support (HTTP, SOCKS4, SOCKS5)
- Tor integration with automatic configuration
- Dynamic, strict, and random chain types
- Proxy authentication support
- Automated proxychains config generation
- **Location**: `app/core/proxychains_manager.py`

#### 4. Professional Exploit Database (Paid Feature)
- CVE integration with National Vulnerability Database
- Automated exploit matching based on service detection
- Metasploit module mapping
- CVSS scoring and severity classification
- Risk assessment and exploit recommendations
- **Location**: `app/core/exploit_database.py`

#### 5. Post-Exploitation Framework (Paid Feature)
- Session management (reverse shells, Meterpreter, web shells)
- System enumeration automation
- Privilege escalation techniques
- Persistence establishment methods
- Lateral movement capabilities
- Data exfiltration techniques
- **Location**: `app/core/post_exploitation.py`

#### 6. License Management System
- Professional license validation
- Feature-based access control
- Trial license generation
- Expiry monitoring and warnings
- Encrypted license storage
- **Location**: `app/core/license_manager.py`

### 💰 Monetization Tiers

#### Free Tier
- Basic enumeration tools (DNS, Port, SMB, SMTP, SNMP, HTTP, API)
- Standard reporting (JSON, CSV, XML)
- Community support
- Basic vulnerability scanning

#### Professional Tier ($99/month)
- **Stealth Mode**: Advanced evasion and timing controls
- **ProxyChains**: Multi-proxy traffic routing
- **Basic Hacking Mode**: Limited exploit execution
- Priority support
- Advanced reporting templates

#### Enterprise Tier ($299/month)
- **Full Exploit Database**: CVE integration and automated matching
- **Post-Exploitation Framework**: Complete compromise workflow
- **Advanced Hacking Mode**: Full exploit framework integration
- **Custom API Integrations**: Shodan, VirusTotal, threat feeds
- Executive reporting and compliance templates
- Dedicated support channel

---

## 🔧 CORE FRAMEWORK IMPROVEMENTS

### ✅ Advanced Core Components Implemented

#### 1. HTTP Client & Proxy System
- **HTTP Client**: Unified HttpRequest/HttpResponse objects (`app/core/http_client.py`)
- **Proxy Engine**: Real-time HTTP/HTTPS traffic interception (`app/core/proxy_engine.py`)
- **Proxy Database**: SQLite-based traffic storage (`app/core/proxy_database.py`)
- **Connection Pool**: HTTP connection pooling and retry handling (`app/core/connection_pool.py`)
- **Rate Limiter**: Global rate limiting for scanning operations (`app/core/rate_limiter.py`)

#### 2. Advanced Scanning Framework
- **Advanced Directory Enumeration**: Recursive scanning with concurrent handling (`app/core/advanced_dir_enum.py`)
- **Certificate Transparency**: CT log searching capabilities (`app/core/cert_transparency.py`)
- **Distributed Scanning**: Multi-node scanning coordination (`app/core/distributed_scanning.py`)
- **Memory Manager**: Memory usage monitoring and optimization (`app/core/memory_manager.py`)
- **Scan Controller**: Scan process control with pause/resume (`app/core/scan_controller.py`)

#### 3. Intelligence & Analysis
- **ML Pattern Detection**: Machine learning-based pattern analysis (`app/core/ml_pattern_detection.py`)
- **Threat Intelligence**: IOC checking and feed integration (`app/core/threat_intelligence.py`)
- **Vulnerability Correlator**: Finding correlation and attack chain detection (`app/core/vulnerability_correlator.py`)
- **API Integration**: Shodan, VirusTotal, URLVoid integration (`app/core/api_integration.py`)

#### 4. Data Management
- **Cache Manager**: File-based caching with TTL support (`app/core/cache_manager.py`)
- **Scan Database**: SQLite database for scan history (`app/core/scan_database.py`)
- **Template Manager**: Scan template management system (`app/core/template_manager.py`)
- **Result Filter**: Advanced filtering and search capabilities (`app/core/result_filter.py`)

#### 5. Plugin & Extension System
- **Plugin Manager**: Dynamic plugin loading and execution (`app/core/plugin_manager.py`)
- **Base Worker**: Standard worker class for command execution (`app/core/base_worker.py`)

### ✅ Huginn Advanced Security Scanner
- **Revolutionary AI-powered vulnerability scanner** (`app/tools/huginn_vuln_scanner.py`)
- **Neural Network Vulnerability Analysis**: Deep learning pattern recognition
- **Quantum-Inspired Fuzzing**: Advanced payload generation
- **Autonomous Security Agent**: 7-state AI agent for self-directed testing
- **ML Vulnerability Prediction**: Machine learning-based forecasting
- **Advanced Exploitation**: PoC exploit generation and validation
- **Compliance Reporting**: OWASP Top 10 and PCI DSS assessment
- **OSINT Intelligence**: Comprehensive reconnaissance
- **WAF Evasion**: Advanced bypass techniques
- **Zero-Day Discovery**: Evolutionary fuzzing capabilities

### ✅ Scan Profiles & Integration
- **Light Profile**: Basic vulnerability checks (20 concurrent, 5s timeout)
- **Normal Profile**: Balanced comprehensive scan (50 concurrent, 10s timeout)
- **Aggressive Profile**: Full-spectrum testing (100 concurrent, 15s timeout)
- **Insane Profile**: All AI features enabled (200 concurrent, 20s timeout)
- **Seamless Integration**: Integrated into main application under Service Enumeration

### ✅ Advanced Authentication & Session Management
- **Auth Flow Recorder**: Authentication workflow recording (`app/core/auth_flow_recorder.py`)
- **Auth State Model**: State-based authentication modeling (`app/core/auth_state_model.py`)
- **Auth Replay Engine**: Authentication replay capabilities (`app/core/auth_replay_engine.py`)
- **Auth Token Analyzer**: Token analysis and validation (`app/core/auth_token_analyzer.py`)
- **Session Manager**: Session handling and management (`app/core/session_manager.py`)

### ✅ Cloud Security Testing
- **AWS Pentest Engine**: AWS-specific penetration testing (`app/core/aws_pentest_engine.py`)
- **Azure Pentest Engine**: Azure security assessment (`app/core/azure_pentest_engine.py`)
- **Cloud Enumeration**: Multi-cloud reconnaissance (`app/core/cloud_enumeration.py`)
- **AWS SAM Deployment**: Serverless application testing (`app/core/aws_sam_deployment.py`)

### ✅ Advanced Vulnerability Detection
- **SSTI Detector**: Server-Side Template Injection detection (`app/core/ssti_detector.py`)
- **Deserialization Detector**: Unsafe deserialization detection (`app/core/deserialization_detector.py`)
- **Business Logic Tester**: Business logic flaw detection (`app/core/business_logic_tester.py`)
- **API Security Tester**: API-specific vulnerability testing (`app/core/api_security_tester.py`)

### ✅ AI & Machine Learning Components
- **Neural Vulnerability Engine**: Advanced AI-powered analysis (`app/core/neural_vulnerability_engine.py`)
- **ML Vulnerability Predictor**: Predictive vulnerability analysis (`app/core/ml_vulnerability_predictor.py`)
- **AI Pattern Analyzer**: Intelligent pattern recognition (`app/core/ai_pattern_analyzer.py`)
- **Autonomous Agent**: Self-directed security testing (`app/core/autonomous_agent.py`)
- **Quantum Fuzzer**: Quantum-inspired fuzzing engine (`app/core/quantum_fuzzer.py`)
- **Zero Day Fuzzer**: Unknown vulnerability discovery (`app/core/zero_day_fuzzer.py`)

### ✅ Reporting & Documentation
- **Advanced Reporting**: Multi-format report generation (`app/core/advanced_reporting.py`)
- **Executive Summary**: Business-friendly reporting (`app/core/executive_summary.py`)
- **Compliance Reporter**: Regulatory compliance mapping (`app/core/compliance_reporter.py`)
- **PDF Generator**: Professional PDF report generation (`app/core/pdf_generator.py`)
- **Evidence Collector**: Automated evidence gathering (`app/core/evidence_collector.py`)

### ✅ Specialized Security Tools
- **Wireless Security**: WiFi security testing (`app/core/wireless_security.py`)
- **Social Engineering**: Social engineering toolkit (`app/core/social_engineering.py`)
- **Anti-Forensics**: Anti-forensics capabilities (`app/core/anti_forensics.py`)
- **Evasion Engine**: Advanced evasion techniques (`app/core/evasion_engine.py`)
- **Obfuscation Engine**: Payload obfuscation (`app/core/obfuscation_engine.py`)

---

## 🔧 RPC ENUMERATION IMPROVEMENTS

---

## ✅ Implemented Improvements

### 1. Structured Output for UI Integration
- Introduced a consistent JSON structure for scan results:
  ```json
  {
    "host": "192.168.1.10",
    "os": "Windows 11 Pro",
    "shares": ["C$", "inetpub"],
    "ports": [135, 139, 445],
    "rpc_interfaces": [
      "uuid: 1234-5678 svcctl",
      "uuid: 5678-90ab eventlog",
      ...
    ]
  }
  ```
- Enables seamless UI data binding for tables and visual graphs.
- Ensures output can be logged, exported, and reused in post-processing.

### 2. System Info Retrieval Improvements
- Primary method: Native Windows command `systeminfo` with optional credentials:
  ```bash
  systeminfo /s <target> /u <user> /p <password>
  ```
- Fallback: Registry-based OS info enumeration using:
  ```bash
  reg query \\<target>\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion /v ProductName
  ```
- Accounts for restricted UAC policies and disabled RemoteRegistry service.
- Annotates failures in the UI with actionable suggestions (e.g., enabling services, adjusting UAC).

### 3. Network Share Enumeration
- Executes the following logic:
  - Authenticated: `net use` to initiate IPC$ session
  - Listing: `net view \\target` to enumerate available shares
- Parses typical shares like `ADMIN$`, `C$`, and custom shares.
- Filters and formats output with annotations for accessibility or error states (e.g., access denied).

### 4. RPC Endpoint Mapping
- Added optional call to `rpcdump.py` to discover:
  - Active RPC endpoints
  - Interface UUIDs
  - Associated named pipes and bindings
- Top 10 most relevant interfaces shown in output (e.g., `svcctl`, `eventlog`, `spoolss`)
- Highlights potentially vulnerable interfaces
- Automatically detects and logs absence of `rpcdump.py` without crashing

### 5. Open RPC Port Scanner
- Performs direct TCP connectivity checks to commonly used RPC-related ports:
  - `135` – RPC Endpoint Mapper
  - `139` – NetBIOS Session Service
  - `445` – SMB
  - `1024–1026` – Dynamic RPC ports (legacy range)
- Results are recorded as a structured list and reported with appropriate visual cues

### 6. RPC Endpoint Mapping
- Added optional call to `rpcdump.py` to discover:
  - Active RPC endpoints
  - Interface UUIDs
  - Associated named pipes and bindings
- Top 10 most relevant interfaces shown in output (e.g., `svcctl`, `eventlog`, `spoolss`)
- Highlights potentially vulnerable interfaces
- Automatically detects and logs absence of `rpcdump.py` without crashing
- Integrated into structured output format with `rpc_interfaces` field

### 7. Authentication Modes
- Implemented NTLM hash-based authentication (pass-the-hash)
- Added NTLM hash field to UI controls
- Support for hash authentication in rpcdump and rpcclient calls
- Credential validation with feedback on success/failure
- UI toggle between password and hash authentication

### 8. Advanced Enumeration Modules - SAMR Interface
- `samr` interface enumeration via rpcclient:
  - Enumerate domain users (`enumdomusers`)
  - Enumerate domain groups (`enumdomgroups`)
  - Parse user/group names and RIDs
- Integrated into structured output with `domain_users` and `domain_groups` fields
- Limited results display (top 10 users, top 8 groups) for UI performance
- Requires authenticated access (username + password/hash)

### 9. Advanced Enumeration Modules - LSARPC Interface
- `lsarpc` interface enumeration via rpcclient:
  - Domain SID extraction (`lsaquery`)
  - Trust relationships enumeration (`lsaenumsid`)
  - Policy information retrieval
- Integrated into structured output with `lsa_info` field
- Displays domain SID and trust domain relationships
- Requires authenticated access for full functionality

### 10. Vulnerability Path Probing
- Interface exposure tests for known RPC-based exploits:
  - `spoolss` — PrintNightmare (CVE-2021-1675) detection
  - `efsr/lsarpc` — PetitPotam (CVE-2021-36942) NTLM relay path
  - `svcctl` — Service control interface abuse detection
- Severity classification (High/Medium/Low)
- Vulnerability descriptions and interface identification
- Integrated into structured output with `vulnerabilities` field

### 11. RID Cycling Logic
- Sequential RID enumeration for user discovery:
  - Tests common RIDs (500, 501, 502, 512, 513, etc.)
  - High-privileged RID identification (500, 512, 516, 518, 519)
  - Standard user RID enumeration (1000+)
- SID-to-name resolution via `lookupsids` command
- Privilege level classification (High/Standard)
- Integrated into structured output with `rid_users` field
- Limited to 15 results for performance

### 12. WKSSVC Interface Enumeration
- `wkssvc` interface enumeration via rpcclient:
  - Computer name and domain information
  - OS version and workstation details
  - Logged-in users enumeration
  - Network share count and accessibility
- Integrated into structured output with `workstation_info` field
- Fallback to share enumeration when direct WKSSVC fails

### 13. UI Enhancements
- Added scan type selection (Basic Info, Full Enumeration, Vulnerability Scan, Complete Assessment)
- Warning banners for Windows 11 compatibility issues:
  - RemoteRegistry service disabled notifications
  - UAC token filtering alerts
- Improved control layout with scan type categorization
- Enhanced visual feedback for different enumeration levels

### 14. Secrets / Hash Extraction (Privileged Only)
- Integrated with Impacket's `secretsdump.py` for credential extraction:
  - SAM database hash extraction
  - LSA secrets and DPAPI keys
  - Cached credentials retrieval
- Protected behind privilege confirmation prompt
- Secure handling - hashes not displayed in UI
- Integrated into structured output with `secrets` field
- Requires elevated access and explicit user consent

### 15. RPC Relay & MITM Mapping
- Detection of NTLM-authenticating RPC interfaces:
  - PrinterBug/SpoolSample relay potential (spoolss)
  - PetitPotam relay vectors (lsarpc/efsr)
  - Service control interface abuse (svcctl)
- SMB signing enforcement detection:
  - Identifies relay-vulnerable configurations
  - Warns when signing not enforced
- Risk assessment and relay potential scoring
- Integrated into structured output with `relay_info` field
- Comprehensive MITM attack surface analysis

---

## 🔜 NEXT PHASE IMPLEMENTATIONS

### 🎯 Critical Professional Features (Priority 1)

#### ✅ Web Application Security Scanner (COMPLETED)
- ✅ Huginn Advanced Security Scanner with AI-powered vulnerability detection
- ✅ Automated SQLi, XSS, CSRF detection via scan plugins
- ✅ OWASP Top 10 vulnerability assessment
- ✅ Custom payload injection testing
- ✅ Authentication bypass techniques
- ✅ Business logic flaw detection
- ✅ SSTI and deserialization vulnerability detection

#### ✅ Active Directory Enumeration (PARTIALLY COMPLETED)
- ✅ AD enumeration framework (`app/core/ad_enumeration.py`)
- ✅ RPC-based domain enumeration (SAMR, LSARPC interfaces)
- ✅ Domain user and group enumeration
- ✅ Trust relationship mapping
- 🔄 BloodHound integration for attack path analysis (IN PROGRESS)
- 🔄 Kerberoasting and ASREPRoasting (PLANNED)
- 🔄 Golden/Silver ticket detection (PLANNED)

#### ✅ Wireless Security Testing (COMPLETED)
- ✅ WiFi security testing framework (`app/core/wireless_security.py`)
- ✅ Network discovery and analysis
- ✅ WPA/WPA2/WPA3 assessment capabilities
- ✅ Evil twin attack simulation
- ✅ Bluetooth enumeration and exploitation

#### ✅ Social Engineering Toolkit (COMPLETED)
- ✅ Social engineering framework (`app/core/social_engineering.py`)
- ✅ Phishing campaign management
- ✅ Credential harvesting templates
- ✅ Email spoofing and analysis
- ✅ OSINT collection (Facebook, LinkedIn, Twitter scrapers)
- ✅ Human intelligence gathering

### ✅ Advanced Evasion Techniques (COMPLETED)

#### ✅ Anti-Forensics Module (COMPLETED)
- ✅ Anti-forensics framework (`app/core/anti_forensics.py`)
- ✅ Log clearing and timestamp manipulation
- ✅ Artifact removal and cleanup
- ✅ Memory dump evasion
- ✅ Network traffic obfuscation

#### ✅ Sandbox Evasion (COMPLETED)
- ✅ Evasion engine (`app/core/evasion_engine.py`)
- ✅ VM detection and bypass
- ✅ Analysis environment identification
- ✅ Behavioral evasion techniques
- ✅ Dynamic analysis countermeasures

#### ✅ EDR/AV Bypass (COMPLETED)
- ✅ Obfuscation engine (`app/core/obfuscation_engine.py`)
- ✅ Process hollowing techniques
- ✅ DLL injection methods
- ✅ Signature evasion
- ✅ Behavioral detection bypass
- ✅ AV/Firewall detection and bypass (`app/tools/av_firewall_scanner.py`)

### ✅ Professional Reporting Engine (COMPLETED)

#### ✅ Executive Dashboard (COMPLETED)
- ✅ Advanced reporting system (`app/core/advanced_reporting.py`)
- ✅ Risk metrics visualization
- ✅ Compliance mapping (NIST, ISO 27001, PCI-DSS) (`app/core/compliance_reporter.py`)
- ✅ Executive summary generation (`app/core/executive_summary.py`)
- ✅ ROI and business impact analysis
- ✅ PDF report generation (`app/core/pdf_generator.py`)

#### ✅ Automated Remediation (COMPLETED)
- ✅ Vulnerability correlation (`app/core/vulnerability_correlator.py`)
- ✅ Fix recommendations with priority scoring
- ✅ Patch management integration
- ✅ Vulnerability lifecycle tracking
- ✅ Remediation verification testing

#### ✅ Timeline Analysis (COMPLETED)
- ✅ Attack path visualization
- ✅ Kill chain mapping
- ✅ Threat actor behavior analysis
- ✅ Incident response integration
- ✅ Evidence collection (`app/core/evidence_collector.py`)

### 🔄 REMAINING ENHANCEMENTS (Priority 4)

#### Multi-Target Campaign Management
- ✅ Multi-target orchestrator (`app/core/multi_target_orchestrator.py`)
- ✅ Multi-target manager (`app/core/multi_target_manager.py`)
- ✅ Campaign coordination and reporting
- ✅ Distributed scanning capabilities

#### CI/CD Integration
- ✅ CI/CD integration framework (`app/core/cicd_integration.py`)
- ✅ Automated security testing in pipelines
- ✅ GitHub Actions and Jenkins integration
- ✅ Security gate enforcement

#### VPN & Network Management
- ✅ VPN manager (`app/core/vpn_manager.py`)
- ✅ OpenVPN client integration (`app/core/openvpn_client.py`)
- ✅ OVPN configuration parser (`app/core/openvpn_ovpn_parser.py`)
- ✅ Network routing and tunneling

#### Additional Enterprise Features
- ✅ Credential management (`app/core/credential_manager.py`, `app/core/secure_credential_manager.py`)
- ✅ Binary analysis (`app/core/binary_analyzer.py`)
- ✅ Dependency analysis (`app/core/dependency_analyzer.py`)
- ✅ Performance monitoring (`app/core/performance_monitor.py`)
- ✅ Notification management (`app/core/notification_manager.py`)
- ✅ System tray integration (`app/core/system_tray.py`)

### ✅ Specialized Scanners & Tools Implemented

#### Core Scanning Tools
- **DNS Scanner**: Advanced DNS enumeration (`app/tools/dns_scanner.py`)
- **Port Scanner**: Multi-threaded port scanning (`app/tools/port_scanner.py`)
- **HTTP Scanner**: Web application scanning (`app/tools/http_scanner.py`)
- **SMB Scanner**: SMB/CIFS enumeration (`app/tools/smb_scanner.py`)
- **RPC Scanner**: RPC service enumeration (`app/tools/rpc_scanner.py`)
- **SMTP Scanner**: Email server enumeration (`app/tools/smtp_scanner.py`)
- **SNMP Scanner**: SNMP service enumeration (`app/tools/snmp_scanner.py`)
- **LDAP Scanner**: Directory service enumeration (`app/tools/ldap_scanner.py`)
- **Database Scanner**: Database service scanning (`app/tools/db_scanner.py`)
- **API Scanner**: REST/GraphQL API testing (`app/tools/api_scanner.py`)
- **IKE Scanner**: IPSec/IKE enumeration (`app/tools/ike_scanner.py`)

#### Specialized Security Tools
- **WAF Detector**: Web Application Firewall detection (`app/tools/waf_detector.py`)
- **TLS Fingerprint**: SSL/TLS configuration analysis (`app/tools/tls_fingerprint.py`)
- **HTTP Fingerprint**: Web server fingerprinting (`app/tools/http_fingerprint.py`)
- **Enterprise Fingerprint**: Enterprise service detection (`app/tools/enterprise_fingerprint.py`)
- **AV/Firewall Scanner**: Security product detection (`app/tools/av_firewall_scanner.py`)
- **Nmap Scanner**: Nmap integration wrapper (`app/tools/nmap_scanner.py`)

#### Scan Plugins Framework
- **Base Plugin**: Plugin architecture foundation (`app/tools/scan_plugins/base_plugin.py`)
- **XSS Plugin**: Cross-Site Scripting detection (`app/tools/scan_plugins/xss_plugin.py`)
- **SSRF Plugin**: Server-Side Request Forgery testing (`app/tools/scan_plugins/ssrf_plugin.py`)
- **IDOR Plugin**: Insecure Direct Object Reference testing (`app/tools/scan_plugins/idor_plugin.py`)
- **CMS Plugin**: Content Management System detection (`app/tools/scan_plugins/cms_plugin.py`)
- **WAF Plugin**: WAF bypass techniques (`app/tools/scan_plugins/waf_plugin.py`)
- **Security Plugin**: General security testing (`app/tools/scan_plugins/security_plugin.py`)

### 🔐 RPC Enumeration Future Enhancements

### ✅ Kerberos Authentication (COMPLETED)
- ✅ Kerberos support via TGT/TGS or `.ccache` ticket usage (`app/core/kerberos_auth.py`)
- ✅ Ticket-based authentication for domain environments
- ✅ Password-based TGT acquisition with kinit
- ✅ Service ticket management for RPC services
- 🔄 Golden/Silver ticket detection and analysis (PLANNED)

### ✅ Advanced Secrets Extraction (COMPLETED)
- ✅ Native Windows secrets extraction (`app/core/secrets_extractor.py`)
- ✅ SAM database hash extraction using reg save
- ✅ LSA secrets and DPAPI keys extraction
- ✅ Cached credentials retrieval
- ✅ Secure handling - hashes not displayed in UI
- ✅ Registry-based extraction without external dependencies

### 📦 Advanced Secrets Extraction
- Integrate with Impacket’s `secretsdump.py` to pull sensitive data:
  - Cached credentials (LSA secrets)
  - SAM hashes
  - NTDS.dit on Domain Controllers
- Protect behind a privileged-use confirmation prompt
- Add logging and optional offline hash storage

### 🛡️ Vulnerability Path Probing
- Interface exposure tests for known RPC-based exploits:
  - `spoolss` — PrintNightmare (CVE-2021-1675)
  - `efsr` — PetitPotam NTLM relay path
  - `svcctl` — Abusable service creation
- Show warnings if vulnerable interfaces are bound on exposed ports
- Future: auto-detection of patches/hardening via registry or function call probing

### 📊 UI Enhancements
- Add expandable sections or tabs for:
  - RPC interfaces list
  - Per-share permission detail
  - Credential result states (e.g., Auth OK, Auth Denied)
- Show warning banners for typical Windows 11 issues:
  - RemoteRegistry disabled
  - UAC token filtering blocking remote systeminfo

### 🌐 RPC Relay & MITM Mapping
- Integrate detection of NTLM-authenticating RPC interfaces
- Output if services are susceptible to:
  - Responder relay
  - mitm6/NTLMv1 relay
- Future: simulate challenge flow to assess relayability


