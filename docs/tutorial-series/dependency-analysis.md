# Dependency Analysis — YouTube Tutorial Series

This document maps each video topic in the Huginn YouTube Tutorial Series to relevant source files, UI pages, external tool dependencies, prerequisite videos, and configuration prerequisites. Use this as a reference when writing individual video scripts.

---

## Table of Contents

- [Page-to-Phase Mapping](#page-to-phase-mapping)
- [Section 2 — Recon and Enumeration Tools](#section-2--recon-and-enumeration-tools)
- [Section 3 — OSINT and Intelligence Gathering](#section-3--osint-and-intelligence-gathering)
- [Section 4 — Vulnerability Scanning](#section-4--vulnerability-scanning)
- [Section 5 — Web Application Exploitation](#section-5--web-application-exploitation)
- [Section 6 — Network and OS Exploitation](#section-6--network-and-os-exploitation)
- [Section 7 — Stealth and Evasion](#section-7--stealth-and-evasion)
- [Section 8 — Post-Exploitation and Privilege Escalation](#section-8--post-exploitation-and-privilege-escalation)
- [Section 9 — Reporting and Documentation](#section-9--reporting-and-documentation)
- [Section 10 — Advanced Features and Workflows](#section-10--advanced-features-and-workflows)
- [Prerequisite Relationship Graph](#prerequisite-relationship-graph)
- [Configuration Prerequisites Summary](#configuration-prerequisites-summary)

---

## Page-to-Phase Mapping

The following table maps attack chain phases to their corresponding UI page files in `app/pages/`.

| Attack Chain Phase | UI Pages |
|---|---|
| Setup | `app/pages/attack_chain_home.py`, `app/pages/home_page.py`, `app/pages/global_settings_page.py` |
| Recon | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration_enhanced.py`, `app/pages/dns_enumeration_page.py`, `app/pages/osint_page.py`, `app/pages/network_discovery_page.py` |
| Scan | `app/pages/huginn_scanner_page.py`, `app/pages/vuln_scanning_page.py`, `app/pages/running_scans_page.py` |
| Exploit | `app/pages/web_exploits_page.py`, `app/pages/os_exploits_page.py`, `app/pages/db_attacks_page.py`, `app/pages/owasp_api_page.py` |
| Elevate | `app/pages/post_exploitation_page.py`, `app/pages/shell_management_page.py`, `app/pages/cracking_page.py`, `app/pages/session_info_page.py` |
| Report | `app/pages/findings_page.py`, `app/pages/centralized_dashboard_page.py` |
| Advanced | `app/pages/guided_workflow_page.py`, `app/pages/script_editor_page.py`, `app/pages/scripts_page.py`, `app/pages/inventory_page.py`, `app/pages/database_management_page.py` |

**Supporting infrastructure pages:**

| Purpose | File |
|---|---|
| Page registration/routing | `app/pages/page_registry.py` |
| Base page class | `app/pages/components/base_page.py` |
| Page factory | `app/pages/components/page_factory.py` |
| Plugin pages | `app/pages/components/plugin_page_factory.py` |
| Port scanning sub-module | `app/pages/recon_enumeration/port_scanning.py` |
| Service scanners | `app/pages/recon_enumeration/service_scanners.py` |
| Service UI components | `app/pages/recon_enumeration/service_ui_components.py` |
| Service field visibility | `app/pages/recon_enumeration/service_field_visibility.py` |
| Export controls | `app/pages/ui_components/export_controls.py` |
| Progress indicators | `app/pages/ui_components/progress_indicator.py` |
| Results viewer | `app/pages/ui_components/results_viewer.py` |
| Scan controls | `app/pages/ui_components/scan_controls.py` |
| Runecraft tab | `app/pages/exploitation/runecraft_tab.py` |
| Runecraft wizard | `app/pages/exploitation/runecraft_wizard.py` |

---

## Section 2 — Recon and Enumeration Tools

### Video 5: DNS Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/dns_resolver.py`, `app/core/dns_data_collector.py`, `app/core/dns_settings.py`, `app/core/enhanced_dns_worker.py`, `app/core/subdomain_engine.py`, `app/core/subdomain_enumerator.py` |
| UI Pages | `app/pages/dns_enumeration_page.py`, `app/pages/recon_enumeration_page.py` |
| Components | `app/components/dns_controls_component.py`, `app/components/dns_results_component.py` |
| Tools | `app/tools/dns_scanner.py`, `app/tools/dns_utils.py` |
| External Tools | `dig`, `nslookup`, `dnsrecon` (optional reference) |
| Prerequisite Videos | Video 3 (UI Navigation) |
| Config Prerequisites | Target domain name, DNS server configuration |

### Video 6: Port Scanning

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/port_data_collector.py`, `app/core/scanner_engine.py`, `app/core/ip_range_parser.py`, `app/core/rate_limiter.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/port_scanning.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | `app/components/network_sweep_component.py`, `app/components/scan_profiles_component.py` |
| Tools | `app/tools/port_scanner.py`, `app/tools/port_utils.py`, `app/tools/nmap_scanner.py` |
| External Tools | `nmap` |
| Prerequisite Videos | Video 3 (UI Navigation) |
| Config Prerequisites | Target IP or range, nmap installed |

### Video 7: SMB Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/smb_client.py`, `app/core/smb_data_collector.py`, `app/core/smb_diagnostics.py`, `app/core/smb_simple.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | (via recon_enumeration_page services) |
| Tools | `app/tools/smb_scanner.py`, `app/tools/smb_utils.py`, `app/tools/smb_proto.py`, `app/tools/smb_raw_proto.py`, `tools/smb_enum.py` |
| External Tools | `smbclient`, `enum4linux` (reference) |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 445) |
| Config Prerequisites | Target with SMB services (HTB/THM lab) |

### Video 8: SMTP Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | (SMTP logic integrated into data collectors) |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | (via recon_enumeration_page services) |
| Tools | `app/tools/smtp_scanner.py`, `app/tools/smtp_utils.py`, `tools/smtp_enum.py` |
| External Tools | `smtp-user-enum` (reference), `telnet` |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 25/587) |
| Config Prerequisites | Target with SMTP service (HTB/THM lab) |

### Video 9: SNMP Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/snmp_data_collector.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | (via recon_enumeration_page services) |
| Tools | `app/tools/snmp_scanner.py`, `app/tools/snmp_utils.py`, `tools/snmp_enum.py` |
| External Tools | `snmpwalk`, `onesixtyone` (reference) |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 161) |
| Config Prerequisites | Target with SNMP service, community strings |

### Video 10: HTTP/S Fingerprinting

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/http_data_collector.py`, `app/core/http_client.py`, `app/core/tech_fingerprinter.py`, `app/core/security_headers_analyzer.py`, `app/core/comprehensive_security_headers.py`, `app/core/tls_analyzer.py`, `app/core/advanced_ssl_analyzer.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | (via recon_enumeration_page services) |
| Tools | `app/tools/http_fingerprint.py`, `app/tools/http_scanner.py`, `app/tools/http_utils.py`, `app/tools/tls_fingerprint.py` |
| External Tools | `whatweb`, `wappalyzer` (reference) |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 80/443) |
| Config Prerequisites | Target with web server |

### Video 11: API Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/api_security_tester.py`, `app/core/api_integration.py`, `app/core/http_methods_enumerator.py`, `app/core/form_parameter_enumerator.py` |
| UI Pages | `app/pages/owasp_api_page.py`, `app/pages/recon_enumeration_page.py` |
| Components | `app/components/owasp_api/api_risk_details_component.py`, `app/components/owasp_api/api_risk_list_component.py` |
| Tools | `app/tools/api_enumerator.py`, `app/tools/api_scanner.py`, `app/tools/api_utils.py`, `app/tools/api_matcher.py`, `tools/api_enum.py` |
| External Tools | `curl`, `postman` (reference) |
| Prerequisite Videos | Video 10 (HTTP/S Fingerprinting) |
| Config Prerequisites | Target with API endpoints |

### Video 12: RPC Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/rpc_data_collector.py`, `app/core/rpc_enum.py`, `app/core/rpc_enumeration_engine.py`, `app/core/rpc_endpoint_mapper.py`, `app/core/rpc_service_enum.py`, `app/core/rpc_dcom_mapper.py`, `app/core/rpc_protocol.py`, `app/core/rpc_transport.py`, `app/core/rpc_http_transport.py`, `app/core/anonymous_rpc_enum.py`, `app/core/dcom_uuid_scanner.py`, `app/core/native_rpc_dump.py`, `app/core/windows_rpc_client.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | `app/components/rpc_relay_component.py` |
| Tools | `app/tools/rpc_scanner.py`, `app/tools/rpc_utils.py`, `app/tools/rpcdump.py` |
| External Tools | `rpcclient`, `impacket` (reference) |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 135/139/445) |
| Config Prerequisites | Windows target with RPC services (HTB/THM lab) |

### Video 13: LDAP Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/ldap_data_collector.py`, `app/core/ad_enumeration.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | (via recon_enumeration_page services) |
| Tools | `app/tools/ldap_scanner.py`, `app/tools/ldap_utils.py` |
| External Tools | `ldapsearch`, `ldapdomaindump` (reference) |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 389/636) |
| Config Prerequisites | Target with LDAP/AD services (HTB/THM lab) |

### Video 14: IKE/VPN Assessment

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/vpn_manager.py`, `app/core/openvpn_client.py`, `app/core/openvpn_ovpn_parser.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | (via recon_enumeration_page services) |
| Tools | `app/tools/ike_scanner.py`, `app/tools/ike_utils.py`, `app/tools/ike_worker.py` |
| External Tools | `ike-scan`, `strongswan` (reference) |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 500/4500) |
| Config Prerequisites | Target with IKE/IPsec services |

### Video 15: Database Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/mssql_client.py`, `app/core/database_utils.py`, `app/core/remote_database_connector.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py`, `app/pages/db_attacks_page.py` |
| Components | `app/components/db_attacks/database_enumeration_component.py` |
| Tools | `app/tools/db_scanner.py`, `app/tools/db_utils.py`, `tools/db_enum.py` |
| External Tools | `mssqlclient.py` (impacket), `mysql`, `psql` |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 1433/3306/5432) |
| Config Prerequisites | Target with database services (HTB/THM lab) |

### Video 16: AV/Firewall Detection

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/advanced_os_detection.py`, `app/core/enhanced_os_detection.py` |
| UI Pages | `app/pages/recon_enumeration_page.py`, `app/pages/recon_enumeration/service_scanners.py` |
| Components | (via recon_enumeration_page services) |
| Tools | `app/tools/av_firewall_scanner.py`, `app/tools/av_firewall_utils.py`, `app/tools/av_worker.py`, `app/tools/waf_detector.py` |
| External Tools | `nmap` (NSE scripts), `wafw00f` (reference) |
| Prerequisite Videos | Video 6 (Port Scanning) |
| Config Prerequisites | Target with firewall/AV (HTB/THM lab) |

---

## Section 3 — OSINT and Intelligence Gathering

### Video 17: Subdomain Discovery

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/subdomain_engine.py`, `app/core/subdomain_enumerator.py`, `app/core/passive_subdomain_worker.py`, `app/core/professional_subdomain_worker.py`, `app/core/passive_content_discovery.py` |
| UI Pages | `app/pages/osint_page.py` |
| Components | `app/components/cloud_discovery_component.py` |
| Tools | (integrated in core modules) |
| External Tools | `subfinder`, `amass` (reference) |
| Prerequisite Videos | Video 5 (DNS Enumeration) |
| Config Prerequisites | Target domain |

### Video 18: Certificate Transparency

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/cert_transparency.py`, `app/core/tls_analyzer.py`, `app/core/advanced_ssl_analyzer.py` |
| UI Pages | `app/pages/osint_page.py` |
| Components | `app/components/cloud_discovery_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (uses CT log APIs) |
| Prerequisite Videos | Video 17 (Subdomain Discovery) |
| Config Prerequisites | Target domain |

### Video 19: Breach Intelligence

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/breach_database.py`, `app/core/breach_intel_engine.py` |
| UI Pages | `app/pages/osint_page.py` |
| Components | `app/components/breach_analysis_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (uses breach database APIs) |
| Prerequisite Videos | Video 17 (Subdomain Discovery) |
| Config Prerequisites | **Enterprise tier license**, breach database API access |

### Video 20: People/Employee OSINT

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/people_intel_engine.py`, `app/core/osint_collector.py`, `app/core/osint_engines.py`, `app/core/osint_workers.py` |
| UI Pages | `app/pages/osint_page.py` |
| Components | `app/components/people_search_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (uses OSINT APIs) |
| Prerequisite Videos | Video 17 (Subdomain Discovery) |
| Config Prerequisites | Target organization name |

### Video 21: Social Media Intelligence

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/social_media_engine.py`, `app/core/facebook_scraper.py`, `app/core/twitter_scraper.py`, `app/core/linkedin_scraper.py` |
| UI Pages | `app/pages/osint_page.py` |
| Components | `app/components/social_media_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (uses social media APIs) |
| Prerequisite Videos | Video 20 (People/Employee OSINT) |
| Config Prerequisites | Target usernames/handles |

### Video 22: Threat Intelligence

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/threat_intel_engine.py`, `app/core/threat_intelligence.py` |
| UI Pages | `app/pages/osint_page.py` |
| Components | `app/components/threat_intelligence_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (uses threat intel APIs) |
| Prerequisite Videos | Video 17 (Subdomain Discovery) |
| Config Prerequisites | **Enterprise tier license**, VirusTotal API key, Shodan API key |

### Video 23: Infrastructure OSINT

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/cloud_enumeration.py`, `app/core/osint_collector.py`, `app/core/osint_engines.py` |
| UI Pages | `app/pages/osint_page.py` |
| Components | `app/components/infrastructure_osint_component.py`, `app/components/cloud_discovery_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (uses Shodan, Censys APIs) |
| Prerequisite Videos | Video 17 (Subdomain Discovery) |
| Config Prerequisites | Shodan API key, target IP ranges |

---

## Section 4 — Vulnerability Scanning

### Video 24: Scanner Overview and Profiles

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/scanner_engine.py`, `app/core/scan_controller.py`, `app/core/adaptive_scanner.py`, `app/core/intelligent_scan_orchestrator.py`, `app/core/scope_manager.py` |
| UI Pages | `app/pages/huginn_scanner_page.py`, `app/pages/vuln_scanning_page.py`, `app/pages/running_scans_page.py` |
| Components | `app/components/huginn_scanner_component.py`, `app/components/scan_profiles_component.py`, `app/components/scan_table_component.py` |
| Tools | `app/tools/enhanced_huginn_scanner.py`, `app/tools/huginn_vuln_scanner.py` |
| External Tools | None (internal scanner) |
| Prerequisite Videos | Video 6 (Port Scanning) |
| Config Prerequisites | Target IP/domain, scan profile selection |

### Video 25: Scan Configuration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/scan_controller.py`, `app/core/scan_registry.py`, `app/core/rate_limiter.py`, `app/core/scope_manager.py`, `app/core/config.py`, `app/core/huginn_config_manager.py` |
| UI Pages | `app/pages/huginn_scanner_page.py`, `app/pages/global_settings_page.py` |
| Components | `app/components/scan_profiles_component.py`, `app/components/scan_details_component.py` |
| Tools | `app/tools/enhanced_huginn_scanner.py` |
| External Tools | None |
| Prerequisite Videos | Video 24 (Scanner Overview) |
| Config Prerequisites | Target configuration, profile settings |

### Video 26: Results Interpretation

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/huginn_results_analyzer.py`, `app/core/evidence_collector.py`, `app/core/vulnerability_correlator.py`, `app/core/vulnerability_correlator_enhanced.py`, `app/core/cross_scan_correlator.py`, `app/core/result_comparator.py`, `app/core/result_filter.py` |
| UI Pages | `app/pages/huginn_scanner_page.py`, `app/pages/vuln_scanning_page.py` |
| Components | `app/components/scan_results_component.py`, `app/components/scan_details_component.py` |
| Tools | `app/tools/evidence_collector.py` |
| External Tools | None |
| Prerequisite Videos | Video 24 (Scanner Overview), Video 25 (Scan Configuration) |
| Config Prerequisites | Completed scan results |

### Video 27: AI-Powered Scanning

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/ai_pattern_analyzer.py`, `app/core/ai_payload_engine.py`, `app/core/ml_pattern_detection.py`, `app/core/ml_vulnerability_predictor.py`, `app/core/neural_vulnerability_engine.py`, `app/core/advanced_analytics_engine.py` |
| UI Pages | `app/pages/huginn_scanner_page.py`, `app/pages/vuln_scanning_page.py` |
| Components | `app/components/huginn_scanner_component.py` |
| Tools | `app/tools/enhanced_huginn_scanner.py` |
| External Tools | None (internal ML models) |
| Prerequisite Videos | Video 24 (Scanner Overview), Video 26 (Results Interpretation) |
| Config Prerequisites | **Enterprise tier license** |

---

## Section 5 — Web Application Exploitation

### Video 28: SQL Injection

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/basic_injection_tester.py`, `app/core/query_engine.py` |
| UI Pages | `app/pages/web_exploits_page.py`, `app/pages/db_attacks_page.py` |
| Components | `app/components/web_exploits_component.py`, `app/components/db_attacks/sql_injection_component.py` |
| Tools | `tools/web_exploits.py`, `tools/db_attacks.py` |
| External Tools | `sqlmap` (reference) |
| Prerequisite Videos | Video 10 (HTTP/S Fingerprinting), Video 24 (Scanner Overview) |
| Config Prerequisites | DVWA instance (security level: Low → High), lab access |

### Video 29: Cross-Site Scripting (XSS)

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/basic_injection_tester.py`, `app/core/form_analyzer.py` |
| UI Pages | `app/pages/web_exploits_page.py` |
| Components | `app/components/web_exploits_component.py` |
| Tools | `tools/web_exploits.py` |
| External Tools | None (browser-based verification) |
| Prerequisite Videos | Video 10 (HTTP/S Fingerprinting), Video 28 (SQL Injection) |
| Config Prerequisites | DVWA instance (security level: Low → High), lab access |

### Video 30: Server-Side Template Injection (SSTI)

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/ssti_detector.py`, `app/core/advanced_ssti_tester.py` |
| UI Pages | `app/pages/web_exploits_page.py` |
| Components | `app/components/web_exploits_component.py` |
| Tools | `tools/web_exploits.py` |
| External Tools | None |
| Prerequisite Videos | Video 28 (SQL Injection), Video 29 (XSS) |
| Config Prerequisites | THM room with SSTI vulnerability, lab access |

### Video 31: Command Injection

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/command_injection_tester.py` |
| UI Pages | `app/pages/web_exploits_page.py` |
| Components | `app/components/web_exploits_component.py` |
| Tools | `tools/web_exploits.py` |
| External Tools | None |
| Prerequisite Videos | Video 28 (SQL Injection) |
| Config Prerequisites | DVWA instance (Command Injection module), lab access |

### Video 32: Path Traversal

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/path_traversal_tester.py`, `app/core/content_discovery.py`, `app/core/directory_fuzzer.py`, `app/core/advanced_dir_enum.py` |
| UI Pages | `app/pages/web_exploits_page.py` |
| Components | `app/components/web_exploits_component.py` |
| Tools | `tools/web_exploits.py` |
| External Tools | None |
| Prerequisite Videos | Video 28 (SQL Injection) |
| Config Prerequisites | DVWA instance (File Inclusion module), lab access |

### Video 33: SSRF

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/ssrf_tester.py`, `app/core/redirect_ssrf_detector.py` |
| UI Pages | `app/pages/web_exploits_page.py` |
| Components | `app/components/web_exploits_component.py` |
| Tools | `tools/web_exploits.py` |
| External Tools | None |
| Prerequisite Videos | Video 10 (HTTP/S Fingerprinting), Video 28 (SQL Injection) |
| Config Prerequisites | THM room with SSRF vulnerability, lab access |

### Video 34: Deserialization Attacks

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/deserialization_detector.py`, `app/core/deserialization_tester.py` |
| UI Pages | `app/pages/web_exploits_page.py` |
| Components | `app/components/web_exploits_component.py` |
| Tools | `tools/web_exploits.py` |
| External Tools | `ysoserial` (reference) |
| Prerequisite Videos | Video 28 (SQL Injection), Video 30 (SSTI) |
| Config Prerequisites | THM room with deserialization vulnerability, lab access |

### Video 35: HTTP Interceptor

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/curl_interceptor.py`, `app/core/http_client.py`, `app/core/unified_request_handler.py`, `app/core/auth_flow_recorder.py`, `app/core/auth_replay_engine.py` |
| UI Pages | `app/pages/web_exploits_page.py` |
| Components | `app/components/http_interceptor_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (built-in proxy) |
| Prerequisite Videos | Video 10 (HTTP/S Fingerprinting) |
| Config Prerequisites | Browser proxy configuration, target web application |

---

## Section 6 — Network and OS Exploitation

### Video 36: SSH Brute-force and Vulnerability Scanning

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/ssh_bruteforce_worker.py`, `app/core/ssh_audit_engine.py`, `app/core/ssh_banner_parser.py`, `app/core/ssh_protocol.py`, `app/core/ssh_key_parser.py`, `app/core/ssh_data_collector.py` |
| UI Pages | `app/pages/os_exploits_page.py` |
| Components | `app/components/ssh_bruteforce_component.py`, `app/components/ssh_vuln_scanner_component.py` |
| Tools | `app/tools/ssh_scanner.py`, `app/tools/ssh_bruteforce_worker.py` |
| External Tools | `hydra` (reference), `ssh-audit` (reference) |
| Prerequisite Videos | Video 6 (Port Scanning — need open port 22) |
| Config Prerequisites | HTB/THM machine with SSH, wordlists |

### Video 37: Database Attacks

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/mssql_client.py`, `app/core/remote_database_connector.py`, `app/core/database_utils.py` |
| UI Pages | `app/pages/db_attacks_page.py` |
| Components | `app/components/db_attacks/database_enumeration_component.py`, `app/components/db_attacks/data_extraction_component.py`, `app/components/db_attacks/privilege_escalation_component.py`, `app/components/db_attacks/sql_injection_component.py` |
| Tools | `tools/db_attacks.py`, `app/tools/db_scanner.py` |
| External Tools | `mssqlclient.py` (impacket), `mysql` |
| Prerequisite Videos | Video 15 (Database Enumeration), Video 28 (SQL Injection) |
| Config Prerequisites | HTB/THM machine with database services, credentials |

### Video 38: RPC Relay and MITM

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/rpc_relay_scanner.py`, `app/core/rpc_relay_spoofer.py`, `app/core/ntlm_relay_client.py`, `app/core/rpc_lsa_sam_client.py`, `app/core/rpc_token_impersonation.py`, `app/core/rpc_service_impersonation.py`, `app/core/rpc_shell.py`, `app/core/rpc_payload_builder.py`, `app/core/rpc_vulnerability_scanner.py`, `app/core/lsarpc_client.py` |
| UI Pages | `app/pages/os_exploits_page.py` |
| Components | `app/components/rpc_relay_component.py` |
| Tools | `app/tools/rpc_scanner.py` |
| External Tools | `responder`, `ntlmrelayx` (impacket reference) |
| Prerequisite Videos | Video 12 (RPC Enumeration) |
| Config Prerequisites | **Professional tier license**, HTB/THM AD lab, network position for relay |

### Video 39: Exploit Database

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/exploit_database.py`, `app/core/exploit_generator.py`, `app/core/version_cve_mapper.py`, `app/core/vulnerability_database.py` |
| UI Pages | `app/pages/os_exploits_page.py` |
| Components | `app/components/os_exploits/vulnerability_scanner_component.py` |
| Tools | `tools/os_exploits.py` |
| External Tools | `searchsploit`, `metasploit` (reference) |
| Prerequisite Videos | Video 24 (Scanner Overview), Video 26 (Results Interpretation) |
| Config Prerequisites | **Enterprise tier license** (full database), vulnerability scan results with CVEs |

### Video 40: Hacking Mode

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/post_exploitation.py`, `app/core/shell_manager.py`, `app/core/listener_manager.py`, `app/core/session_manager.py` |
| UI Pages | `app/pages/os_exploits_page.py`, `app/pages/shell_management_page.py` |
| Components | `app/components/os_exploits/privilege_escalation_component.py`, `app/components/listener_integration.py` |
| Tools | `tools/os_exploits.py`, `app/components/scripts/exploitation_tools_component.py`, `app/components/scripts/reverse_shells_component.py` |
| External Tools | `metasploit`, `empire`, `cobalt-strike` (reference) |
| Prerequisite Videos | Video 39 (Exploit Database), Video 36 (SSH Brute-force) |
| Config Prerequisites | **Professional tier** (Basic) / **Enterprise tier** (Advanced), HTB/THM target, listener setup |

---

## Section 7 — Stealth and Evasion

### Video 41: Stealth Mode

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/stealth_config.py`, `app/core/stealth_engine.py`, `app/core/stealth_integration.py`, `app/core/evasion_engine.py`, `app/core/rate_limiter.py` |
| UI Pages | `app/pages/global_settings_page.py` |
| Components | (settings integrated into global settings) |
| Tools | `app/tools/stealth_scanner.py` |
| External Tools | None (internal configuration) |
| Prerequisite Videos | Video 6 (Port Scanning), Video 24 (Scanner Overview) |
| Config Prerequisites | **Professional tier license** |

### Video 42: ProxyChains

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/proxychains_manager.py`, `app/core/proxy_engine.py`, `app/core/proxy_manager.py`, `app/core/proxy_database.py` |
| UI Pages | `app/pages/global_settings_page.py` |
| Components | (settings integrated into global settings) |
| Tools | (integrated in core modules) |
| External Tools | `proxychains`, `proxychains-ng` |
| Prerequisite Videos | Video 41 (Stealth Mode) |
| Config Prerequisites | **Professional tier license**, proxy list (HTTP/SOCKS4/SOCKS5), proxychains installed |

### Video 43: Tor Integration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/proxychains_manager.py`, `app/core/proxy_engine.py` |
| UI Pages | `app/pages/global_settings_page.py` |
| Components | (settings integrated into global settings) |
| Tools | (integrated in core modules) |
| External Tools | `tor`, `torsocks` |
| Prerequisite Videos | Video 42 (ProxyChains) |
| Config Prerequisites | **Professional tier license**, Tor installed and configured |

### Video 44: AWS Infrastructure Deployment

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/aws_sam_deployment.py`, `app/core/aws_exploitation.py`, `app/core/aws_pentest_engine.py` |
| UI Pages | `app/pages/global_settings_page.py` |
| Components | (settings integrated into global settings) |
| Tools | (integrated in core modules) |
| External Tools | `aws-cli`, `terraform` (reference) |
| Prerequisite Videos | Video 41 (Stealth Mode), Video 42 (ProxyChains) |
| Config Prerequisites | **Professional tier license**, AWS account, AWS CLI configured, IAM credentials |

---

## Section 8 — Post-Exploitation and Privilege Escalation

### Video 45: Session Management

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/session_manager.py`, `app/core/session_harvester.py`, `app/core/shell_manager.py`, `app/core/listener_manager.py` |
| UI Pages | `app/pages/post_exploitation_page.py`, `app/pages/session_info_page.py`, `app/pages/shell_management_page.py` |
| Components | `app/components/session_info/session_management_component.py`, `app/components/session_info/session_overview_component.py`, `app/components/session_info/session_data_tables_component.py` |
| Tools | (integrated in core modules) |
| External Tools | `metasploit` (meterpreter sessions reference) |
| Prerequisite Videos | Video 40 (Hacking Mode) |
| Config Prerequisites | **Enterprise tier license**, established access to HTB/THM target |

### Video 46: Credential Harvesting

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/credential_manager.py`, `app/core/secure_credential_manager.py`, `app/core/lsass_dumper.py`, `app/core/samr_client.py`, `app/core/dcsync_client.py`, `app/core/secrets_extractor.py` |
| UI Pages | `app/pages/post_exploitation_page.py` |
| Components | (integrated into post-exploitation interface) |
| Tools | `tools/credential_manager.py` |
| External Tools | `mimikatz` (reference), `secretsdump.py` (impacket) |
| Prerequisite Videos | Video 45 (Session Management) |
| Config Prerequisites | **Enterprise tier license**, administrative access on target |

### Video 47: Persistence Techniques

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/post_exploitation.py`, `app/core/ssh_persistence.py`, `app/core/winreg_client.py`, `app/core/svcctl_client.py` |
| UI Pages | `app/pages/post_exploitation_page.py` |
| Components | `app/components/os_exploits/persistence_component.py` |
| Tools | `tools/os_exploits.py` |
| External Tools | `reg.exe`, `schtasks`, `systemctl` (reference) |
| Prerequisite Videos | Video 45 (Session Management), Video 46 (Credential Harvesting) |
| Config Prerequisites | **Enterprise tier license**, administrative access on target, HTB/THM lab |

### Video 48: Lateral Movement

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/ssh_lateral.py`, `app/core/post_exploitation.py`, `app/core/shell_manager.py` |
| UI Pages | `app/pages/post_exploitation_page.py` |
| Components | `app/components/os_exploits/lateral_movement_component.py` |
| Tools | `tools/os_exploits.py` |
| External Tools | `psexec.py` (impacket), `wmiexec.py` (impacket), `evil-winrm` (reference) |
| Prerequisite Videos | Video 46 (Credential Harvesting), Video 47 (Persistence) |
| Config Prerequisites | **Enterprise tier license**, harvested credentials, multi-host lab |

### Video 49: Active Directory Enumeration

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/ad_enumeration.py`, `app/core/ldap_data_collector.py`, `app/core/kerberos_auth.py` |
| UI Pages | `app/pages/post_exploitation_page.py` |
| Components | (integrated into post-exploitation interface) |
| Tools | `app/tools/ad_enum.py`, `app/tools/kerberos_tools.py` |
| External Tools | `bloodhound`, `sharphound`, `rubeus` (reference) |
| Prerequisite Videos | Video 13 (LDAP Enumeration), Video 46 (Credential Harvesting) |
| Config Prerequisites | **Enterprise tier license**, domain credentials, AD lab environment (HTB) |

---

## Section 9 — Reporting and Documentation

### Video 50: Findings Management

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/evidence_collector.py`, `app/core/centralized_reporting.py`, `app/core/centralized_scan_data.py`, `app/core/security_metrics.py` |
| UI Pages | `app/pages/findings_page.py` |
| Components | `app/components/findings/findings_list_component.py`, `app/components/findings/findings_details_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None |
| Prerequisite Videos | Video 26 (Results Interpretation) |
| Config Prerequisites | Completed scan results with findings |

### Video 51: Report Generation

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/advanced_reporting.py`, `app/core/enhanced_reporting.py`, `app/core/pdf_generator.py`, `app/core/pdf_report_generator.py`, `app/core/exporter.py`, `app/core/template_manager.py` |
| UI Pages | `app/pages/findings_page.py`, `app/pages/centralized_dashboard_page.py` |
| Components | `app/components/findings/advanced_reporting_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (internal report engine) |
| Prerequisite Videos | Video 50 (Findings Management) |
| Config Prerequisites | Populated findings database |

### Video 52: Executive Summary

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/executive_summary.py`, `app/core/advanced_analytics_engine.py`, `app/core/security_metrics.py` |
| UI Pages | `app/pages/centralized_dashboard_page.py` |
| Components | `app/components/findings/advanced_reporting_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None |
| Prerequisite Videos | Video 51 (Report Generation) |
| Config Prerequisites | **Enterprise tier license**, multiple scan results |

### Video 53: Compliance Reporting

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/compliance_mapper.py`, `app/core/compliance_reporter.py` |
| UI Pages | `app/pages/centralized_dashboard_page.py` |
| Components | `app/components/compliance_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None |
| Prerequisite Videos | Video 51 (Report Generation), Video 52 (Executive Summary) |
| Config Prerequisites | **Enterprise tier license**, compliance template selection (NIST/ISO/PCI-DSS) |

### Video 54: Trend Analysis

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/result_comparator.py`, `app/core/cross_scan_correlator.py`, `app/core/graph_engine.py`, `app/core/security_metrics.py` |
| UI Pages | `app/pages/centralized_dashboard_page.py` |
| Components | (integrated into dashboard) |
| Tools | (integrated in core modules) |
| External Tools | None |
| Prerequisite Videos | Video 50 (Findings Management), Video 51 (Report Generation) |
| Config Prerequisites | Multiple completed scans over time |

---

## Section 10 — Advanced Features and Workflows

### Video 55: Guided Mode

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/attack_chain_orchestrator.py`, `app/core/questionnaire_graph.py`, `app/core/questionnaire_neo4j.py` |
| UI Pages | `app/pages/guided_workflow_page.py`, `app/pages/attack_chain_home.py` |
| Components | `app/components/guided_workflow/workflow_navigation_component.py`, `app/components/guided_workflow/workflow_progress_component.py`, `app/components/guided_workflow/workflow_step_component.py`, `app/components/attack_chain/engagement_setup_component.py`, `app/components/attack_chain/mindmap_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None |
| Prerequisite Videos | Video 3 (UI Navigation), Video 24 (Scanner Overview) |
| Config Prerequisites | Target configured, engagement scope defined |

### Video 56: Runecraft Payload Builder

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/runecraft_engine.py`, `app/core/runecraft_payload_builder.py`, `app/core/obfuscation_engine.py`, `app/core/ai_payload_engine.py` |
| UI Pages | `app/pages/exploitation/runecraft_tab.py`, `app/pages/exploitation/runecraft_wizard.py` |
| Components | `app/components/runecraft_component.py`, `app/components/runecraft/runecraft_integration.py`, `app/components/scripts/reverse_shells_component.py`, `app/components/scripts/code_templates_component.py` |
| Tools | `app/tools/payload_builder.py` |
| External Tools | `msfvenom` (reference) |
| Prerequisite Videos | Video 40 (Hacking Mode) |
| Config Prerequisites | **Professional tier license**, lab target for payload testing |

### Video 57: Hash Cracking

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/crack_engine.py`, `app/core/gpu_crack_engine.py`, `app/core/hashcat_engine.py`, `app/core/wordlist_manager.py` |
| UI Pages | `app/pages/cracking_page.py` |
| Components | `app/components/cracking/attack_configuration_component.py`, `app/components/cracking/hash_analysis_component.py`, `app/components/cracking/hash_lookup_component.py`, `app/components/cracking/live_attacks_component.py`, `app/components/cracking/results_management_component.py`, `app/components/cracking/ssh_key_parser_component.py` |
| Tools | `tools/hash_cracker.py`, `tools/cracking_tools.py` |
| External Tools | `hashcat`, `john` (John the Ripper) |
| Prerequisite Videos | Video 46 (Credential Harvesting) |
| Config Prerequisites | **Professional tier license**, wordlists, GPU (optional for performance), hash samples |

### Video 58: Local DNS Server

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/local_dns_server.py`, `app/core/dns_settings.py` |
| UI Pages | `app/pages/global_settings_page.py` |
| Components | `app/components/dns_controls_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (built-in DNS server) |
| Prerequisite Videos | Video 5 (DNS Enumeration) |
| Config Prerequisites | **Professional tier license**, network configuration for DNS resolution |

### Video 59: Automation and Scheduling

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/scheduler.py`, `app/core/multi_target_manager.py`, `app/core/distributed_scanning.py` |
| UI Pages | `app/pages/running_scans_page.py`, `app/pages/global_settings_page.py` |
| Components | `app/components/automation_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None (internal scheduler) |
| Prerequisite Videos | Video 24 (Scanner Overview), Video 25 (Scan Configuration) |
| Config Prerequisites | **Professional tier license**, target list, schedule definition |

### Video 60: Multi-Target Campaigns

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/multi_target_coordinator.py`, `app/core/multi_target_manager.py`, `app/core/multi_target_orchestrator.py`, `app/core/distributed_scanning.py` |
| UI Pages | `app/pages/running_scans_page.py`, `app/pages/inventory_page.py` |
| Components | `app/components/automation_component.py`, `app/components/inventory_stats_component.py` |
| Tools | (integrated in core modules) |
| External Tools | None |
| Prerequisite Videos | Video 59 (Automation and Scheduling), Video 50 (Findings Management) |
| Config Prerequisites | **Enterprise tier license**, multiple target IPs, asset inventory |

### Video 61: Plugin System

| Category | Files / Dependencies |
|---|---|
| Core Modules | `app/core/plugin_manager.py` |
| UI Pages | `app/pages/components/plugin_page_factory.py`, `app/pages/script_editor_page.py`, `app/pages/scripts_page.py` |
| Components | `app/components/scripts/code_templates_component.py`, `app/components/scripts/exploitation_tools_component.py` |
| Tools | (plugin API) |
| External Tools | None |
| Prerequisite Videos | Video 55 (Guided Mode), Video 59 (Automation and Scheduling) |
| Config Prerequisites | **Enterprise tier license**, plugin development knowledge |

---

## Prerequisite Relationship Graph

The following diagram shows video prerequisite relationships. An arrow from Video A → Video B means A must be watched before B.

```
Section 1 (Existing)
  Video 3 (UI Navigation)
    ├── Video 5 (DNS Enumeration)
    │     ├── Video 17 (Subdomain Discovery)
    │     │     ├── Video 18 (Certificate Transparency)
    │     │     ├── Video 19 (Breach Intelligence)
    │     │     ├── Video 20 (People/Employee OSINT)
    │     │     │     └── Video 21 (Social Media Intelligence)
    │     │     ├── Video 22 (Threat Intelligence)
    │     │     └── Video 23 (Infrastructure OSINT)
    │     └── Video 58 (Local DNS Server)
    ├── Video 6 (Port Scanning)
    │     ├── Video 7 (SMB Enumeration)
    │     ├── Video 8 (SMTP Enumeration)
    │     ├── Video 9 (SNMP Enumeration)
    │     ├── Video 10 (HTTP/S Fingerprinting)
    │     │     ├── Video 11 (API Enumeration)
    │     │     ├── Video 28 (SQL Injection) ──┐
    │     │     │     ├── Video 29 (XSS)      │
    │     │     │     │     └── Video 30 (SSTI)│
    │     │     │     ├── Video 31 (Cmd Inj)   │
    │     │     │     ├── Video 32 (Path Trav) │
    │     │     │     ├── Video 33 (SSRF)      │
    │     │     │     └── Video 34 (Deser)     │
    │     │     └── Video 35 (HTTP Interceptor) │
    │     ├── Video 12 (RPC Enumeration)        │
    │     │     └── Video 38 (RPC Relay/MITM)   │
    │     ├── Video 13 (LDAP Enumeration)       │
    │     │     └── Video 49 (AD Enumeration)   │
    │     ├── Video 14 (IKE/VPN Assessment)     │
    │     ├── Video 15 (Database Enumeration)   │
    │     │     └── Video 37 (Database Attacks)─┘
    │     ├── Video 16 (AV/Firewall Detection)
    │     ├── Video 24 (Scanner Overview)
    │     │     ├── Video 25 (Scan Configuration)
    │     │     ├── Video 26 (Results Interpretation)
    │     │     │     └── Video 50 (Findings Management)
    │     │     │           ├── Video 51 (Report Generation)
    │     │     │           │     ├── Video 52 (Executive Summary)
    │     │     │           │     │     └── Video 53 (Compliance)
    │     │     │           │     └── Video 54 (Trend Analysis)
    │     │     │           └── Video 60 (Multi-Target Campaigns)
    │     │     ├── Video 27 (AI-Powered Scanning)
    │     │     └── Video 39 (Exploit Database)
    │     │           └── Video 40 (Hacking Mode)
    │     │                 ├── Video 45 (Session Management)
    │     │                 │     ├── Video 46 (Credential Harvesting)
    │     │                 │     │     ├── Video 47 (Persistence)
    │     │                 │     │     │     └── Video 48 (Lateral Movement)
    │     │                 │     │     ├── Video 49 (AD Enumeration)
    │     │                 │     │     └── Video 57 (Hash Cracking)
    │     │                 │     └── Video 47 (Persistence)
    │     │                 └── Video 56 (Runecraft Payload Builder)
    │     ├── Video 36 (SSH Brute-force)
    │     └── Video 41 (Stealth Mode)
    │           ├── Video 42 (ProxyChains)
    │           │     ├── Video 43 (Tor Integration)
    │           │     └── Video 44 (AWS Deployment)
    │           └── Video 44 (AWS Deployment)
    ├── Video 24 (Scanner Overview)
    │     └── Video 55 (Guided Mode)
    └── Video 59 (Automation and Scheduling)
          └── Video 60 (Multi-Target Campaigns)
                └── Video 61 (Plugin System)
```

---

## Configuration Prerequisites Summary

The following table lists all configuration prerequisites required across the series, grouped by category.

### API Keys and External Service Access

| Prerequisite | Required For Videos | Setup Location |
|---|---|---|
| Shodan API Key | Video 22 (Threat Intelligence), Video 23 (Infrastructure OSINT) | Settings → API Integrations |
| VirusTotal API Key | Video 22 (Threat Intelligence) | Settings → API Integrations |
| Breach Database API Access | Video 19 (Breach Intelligence) | Settings → API Integrations |
| AWS IAM Credentials | Video 44 (AWS Deployment) | AWS CLI configuration |
| AWS CLI | Video 44 (AWS Deployment) | System installation |

### External Tool Dependencies

| Tool | Required For Videos | Installation |
|---|---|---|
| nmap | Video 6, Video 16 | System package manager |
| proxychains / proxychains-ng | Video 42, Video 43 | System package manager |
| tor / torsocks | Video 43 | System package manager |
| hashcat | Video 57 | System package manager or binary |
| john (John the Ripper) | Video 57 | System package manager |
| metasploit | Video 40, Video 45 (reference) | Kali Linux or standalone install |
| empire | Video 40 (reference) | PowerShell Empire repository |
| impacket suite | Video 37, Video 38, Video 46, Video 48 (reference) | pip install impacket |
| bloodhound / sharphound | Video 49 (reference) | BloodHound repository |
| responder | Video 38 (reference) | Kali Linux or standalone install |
| hydra | Video 36 (reference) | System package manager |

### Lab Environment Access

| Prerequisite | Required For Videos | Notes |
|---|---|---|
| Hack The Box (HTB) subscription | Videos 7, 8, 9, 12, 13, 15, 36, 37, 38, 45–49 | Active subscription for machine access |
| TryHackMe (THM) subscription | Videos 30, 33, 34, 36, 37 | Free/paid rooms |
| DVWA instance | Videos 28, 29, 31, 32 | Self-hosted Docker container |
| scanme.nmap.org | Video 6 | Public (no subscription needed) |
| Own cloud infrastructure | Videos 23, 43, 44 | AWS/Azure account |
| AD lab environment | Videos 38, 48, 49 | HTB Pro Labs or self-hosted |

### License Tier Requirements

| Tier | Videos Requiring This Tier |
|---|---|
| Free | Videos 5–16 (Section 2), Videos 17–18, 20–21, 23 (Section 3 partial), Video 24–26 (Section 4 partial), Videos 28–35 (Section 5), Video 50–51, 54 (Section 9 partial) |
| Professional | Videos 38 (partial), 40 (Basic), 41–44 (Section 7), 56 (Runecraft), 57 (Hash Cracking), 58 (Local DNS), 59 (Automation) |
| Enterprise | Videos 19, 22 (Section 3), 27 (AI Scanning), 39 (Full Exploit DB), 40 (Advanced), 45–49 (Section 8), 52–53 (Section 9), 60 (Multi-Target), 61 (Plugins) |

### VPN and Network Configuration

| Prerequisite | Required For Videos | Notes |
|---|---|---|
| HTB VPN connection (.ovpn) | All HTB lab videos | Connect before starting demos |
| THM VPN connection | All THM lab videos | Connect before starting demos |
| Proxy server list | Video 42 (ProxyChains) | HTTP/SOCKS4/SOCKS5 proxies |
| Tor network access | Video 43 (Tor Integration) | Tor daemon running |
| Isolated network segment | Videos 38, 47, 48 | For relay/persistence demos |

---

## Notes

- Source file paths are relative to the project root (`huginn/`)
- External tools marked as "(reference)" are shown for comparison/context in the video but are not strictly required — Huginn provides its own implementation
- The `app/tools/` directory contains scanner worker implementations that wrap core modules for specific protocols
- The `tools/` top-level directory contains standalone tool scripts for direct CLI usage
- Components in subdirectories (e.g., `app/components/cracking/`, `app/components/db_attacks/`) contain multiple sub-components for complex features
- The `app/core/transport_plugins/` directory (`http_beacon_plugin.py`, `reverse_tcp_plugin.py`) supports Video 40 (Hacking Mode) and Video 56 (Runecraft)
