# VIDEO 16: AV/Firewall Detection
### Security Product Identification, Evasion Profiling & Rule Mapping
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn dashboard with Recon & Enumeration page open, AV/Firewall Detection section highlighted in the service scanner panel]**

> "Welcome back to the Huginn tutorial series. This is the final video in Section 2 — Recon and Enumeration Tools. We are covering AV and Firewall detection — the process of identifying what security products are protecting your target before you attempt exploitation. Knowing whether a target has a WAF, host-based firewall, IDS/IPS, or antivirus changes your entire approach. Attempting exploitation without this intelligence often results in blocked payloads, triggered alerts, and a burned engagement."

**[Screen: Slide showing the security product landscape — Network Firewalls, WAFs, Host-based AV, IDS/IPS, EDR]**

> "Today we will use Huginn's AV/Firewall scanner and WAF detector against the THM Firewalls room to identify firewall rules, fingerprint WAF products, and detect IDS/IPS indicators. This completes our reconnaissance toolkit and sets us up for the OSINT and exploitation sections ahead."

---

## SECTION 1: Understanding Security Product Types (1:30 – 4:00)

**[Screen: Diagram showing network topology with security products at different layers — perimeter firewall, WAF in front of web apps, host-based AV/EDR on endpoints, network IDS inline]**

> "Security products operate at different layers and serve different purposes. Network firewalls filter traffic by IP, port, and protocol — they determine what ports are even reachable. Web Application Firewalls, or WAFs, sit in front of web applications and inspect HTTP traffic for attack signatures like SQL injection or XSS payloads. Host-based antivirus and EDR solutions run on the endpoint itself and detect malicious files or behavior. Network IDS and IPS systems monitor traffic patterns for known attack signatures."

**[Screen: Table showing detection methods for each security product type]**

> "Each type leaves different fingerprints. Firewalls create filtered port states in our scan results. WAFs modify HTTP headers and return distinctive error pages. AV products expose themselves through running services, registry keys, or process names. IDS/IPS systems may reset connections or inject TCP RST packets when they detect something suspicious."

| Security Product | Detection Method |
|-----------------|-----------------|
| Network Firewall | Filtered ports, TTL analysis, TCP window inconsistencies |
| WAF | Custom headers, block pages, response timing changes |
| Host AV | Service enumeration, process listing, registry keys |
| IDS/IPS | Connection resets, packet drops after specific payloads |

**[Screen: OSCP/CEH callout noting that understanding defensive controls is part of the Information Gathering phase]**

> "For certification purposes, identifying security controls is explicitly part of the OSCP Information Gathering domain and the CEH Enumeration domain. On the exam, knowing that a firewall is filtering certain ports saves you from wasting time on blocked attack vectors."

---

## SECTION 2: Huginn AV/Firewall Scanner Interface (4:00 – 6:30)

**[Screen: Huginn UI — Recon & Enumeration page, navigating to the AV/Firewall Detection module]**

> "Huginn's AV/Firewall detection combines three capabilities into one module. The firewall detection scanner uses nmap to identify filtered ports and analyze packet responses. The WAF detector sends crafted HTTP requests and analyzes responses for WAF signatures. And the evasion profiler tests various techniques to map what gets through and what gets blocked."

**[Screen: AV/Firewall scanner panel showing three tabs — Firewall Detection, WAF Detection, Evasion Profile]**

> "The Firewall Detection tab takes a target IP and runs specialized nmap scans looking for filtered ports, TTL inconsistencies, and TCP window size anomalies that indicate a stateful firewall. The WAF Detection tab takes a URL and tests for known WAF products by checking response headers and triggering block pages. The Evasion Profile tab maps which payloads and techniques are blocked versus allowed."

```bash
# Huginn's firewall detection uses these nmap techniques:
# ACK scan to detect filtered vs unfiltered:
nmap -sA <target>

# Window scan for additional state detection:
nmap -sW <target>

# Fragmentation to test firewall inspection depth:
nmap -f <target>

# Decoy scan to test source IP filtering:
nmap -D RND:5 <target>
```

**[Screen: WAF detector configuration showing — target URL, test payload selection, custom header options]**

> "The WAF detector works differently. It sends a normal request first to establish a baseline response, then sends requests containing common attack signatures — SQL injection patterns, XSS payloads, path traversal sequences. If the response changes — different status code, different headers, a block page — that indicates a WAF is intercepting."

---

## SECTION 3: Live Demo — Firewall Rule Detection (6:30 – 10:00)

**[Screen: Terminal showing THM VPN connection established, THM Firewalls room target IP displayed]**

> "Our target today is the THM Firewalls room. This is a Medium difficulty room specifically designed to teach firewall detection and evasion. Let's start with firewall rule detection."

```bash
# First, a standard TCP SYN scan to see what's open:
nmap -sS -p 1-1000 <THM_TARGET_IP>
```

**[Screen: Nmap results showing mix of open, closed, and filtered ports]**

> "Notice the mix of states. Open ports respond with SYN-ACK. Closed ports respond with RST. But filtered ports give us no response at all — that is the firewall dropping our packets silently. The ratio and pattern of filtered ports tells us about the firewall configuration."

**[Screen: Huginn UI — entering THM target IP, clicking Run Firewall Detection]**

> "Let's run Huginn's firewall detection. It executes multiple scan types and correlates the results to determine the firewall's behavior."

```bash
# ACK scan — all ports should return RST if no firewall:
nmap -sA -p 80,443,22,8080 <THM_TARGET_IP>

# If ACK scan shows "filtered" — stateful firewall present
# If ACK scan shows "unfiltered" — no stateful inspection on that port
```

**[Screen: Results panel showing — Stateful Firewall Detected, filtered ports listed, analysis of allowed vs blocked services]**

> "The results confirm a stateful firewall. The ACK scan reveals which ports have stateful inspection — packets that are not part of an established connection are dropped. Huginn presents this as a clear table: port, SYN scan result, ACK scan result, and the inferred firewall rule."

**[Screen: Huginn results table showing port-by-port analysis with columns: Port, SYN State, ACK State, Inferred Rule]**

> "This is actionable intelligence. Ports showing open in SYN scan but filtered in ACK scan have standard stateful firewall rules — allow inbound connections to these services. Ports filtered in both scans are fully blocked. Ports unfiltered in ACK scan may have weak or absent filtering — potential bypass opportunities."

```bash
# Additional firewall fingerprinting:
# TTL analysis — different TTL values suggest a device in the path:
nmap --ttl 64 -sS <THM_TARGET_IP>

# IP ID header analysis:
nmap -sI <zombie_ip> <THM_TARGET_IP>
```

**[Screen: Huginn extracting filtered port list and generating a firewall rule map diagram]**

> "Huginn also extracts the filtered port list and generates a visual firewall rule map. This makes it easy to see at a glance which services are accessible and which are blocked — essential for planning your exploitation approach."

---

## SECTION 4: WAF Fingerprinting (10:00 – 13:30)

**[Screen: Huginn UI — switching to WAF Detection tab, entering a web application URL from the THM target]**

> "Now let's switch to WAF fingerprinting. If the target has a web application, there may be a WAF in front of it. Huginn's WAF detector checks for eight major WAF products: Cloudflare, AWS WAF, Akamai, Incapsula, ModSecurity, F5 BIG-IP, Barracuda, and Sucuri."

**[Screen: WAF detection configuration showing baseline request and test payloads]**

> "The detection process works in two phases. Phase one sends a clean, normal HTTP request to establish the baseline — normal status code, normal headers, normal response body. Phase two sends requests with attack signatures embedded and compares the responses."

```bash
# WAF detection logic:
# 1. Send normal request → baseline response (200 OK)
# 2. Send request with SQLi payload → compare response
#    Normal URL: http://target/page?id=1
#    Test URL:   http://target/page?id=1' OR '1'='1
# 3. If response changes (403, different headers, block page) → WAF detected
# 4. Analyze block page and headers for WAF product signatures
```

**[Screen: Running WAF detection — progress indicator showing test payloads being sent]**

> "Let's run the detection. Huginn sends the baseline request, then cycles through test payloads — SQL injection patterns, XSS script tags, path traversal sequences, command injection characters."

**[Screen: WAF detection results showing — WAF Detected: Yes, Product: ModSecurity, Confidence: 75%, Evidence: 403 response with mod_security header]**

> "We got a hit. ModSecurity is detected with 75 percent confidence. The evidence is a 403 Forbidden response when we include SQL injection patterns, combined with the mod_security signature in the response. Huginn calculates confidence based on a scoring system — header matches score two points, content matches score two points, and status code changes score one point. A score of two or above triggers detection."

```bash
# WAF signature matching example:
# Cloudflare: Look for cf-ray, cf-cache-status headers
# AWS WAF: Look for x-amzn-requestid, x-amzn-trace-id headers
# ModSecurity: Look for mod_security in headers/body, 406 status codes
# F5 BIG-IP: Look for bigipserver header, x-wa-info header
```

**[Screen: Detailed WAF results showing which payloads were blocked vs allowed]**

> "The detailed results show exactly which payloads triggered blocks and which passed through. This is your evasion roadmap. If standard SQL injection gets blocked but time-based blind injection passes, you know the WAF has signature-based rules that you can potentially bypass with encoding or obfuscation."

**[Screen: Huginn WAF evasion suggestions based on detected product]**

> "Huginn also provides evasion suggestions based on the detected WAF product. For ModSecurity, common bypasses include case variation, comment injection, and encoding tricks. For Cloudflare, chunked transfer encoding and header manipulation may work. These suggestions become relevant in the exploitation sections — specifically the Stealth and Evasion module in Section 7."

---

## SECTION 5: IDS/IPS Detection and Evasion Indicators (13:30 – 15:30)

**[Screen: Huginn UI — Evasion Profile tab showing fragmentation tests, timing tests, and encoding tests]**

> "The final piece is IDS/IPS detection. Unlike firewalls which block at the port level, IDS/IPS systems inspect packet content for attack signatures. Huginn detects their presence through behavioral analysis."

```bash
# IDS/IPS detection techniques:
# 1. Fragmentation test — does splitting packets avoid detection?
nmap -f <target>        # Fragment packets into 8 bytes
nmap --mtu 16 <target>  # Custom MTU fragmentation

# 2. Timing test — does slowing down avoid detection?
nmap -T0 <target>       # Paranoid timing (5 min between probes)
nmap -T4 <target>       # Aggressive timing

# 3. Decoy scan — does mixed source IPs avoid detection?
nmap -D RND:10 <target>
```

**[Screen: Evasion profile results showing — Fragmentation: passes, Slow timing: passes, Fast timing: blocked, Standard payloads: blocked]**

> "The evasion profile maps what gets through. If normal-speed scans get blocked but paranoid-timing scans succeed, the IDS has rate-based detection. If fragmented packets pass but complete packets are dropped, the IDS does not reassemble fragments before inspection. This intelligence directly informs your exploitation strategy."

**[Screen: Huginn generating an evasion profile summary document with recommendations]**

> "Huginn generates an evasion profile summary that tells you: the detected security products, their detection capabilities, tested bypass techniques, and recommended stealth settings for this specific target. This feeds directly into Stealth Mode configuration covered later in Section 7."

---

## SECTION 6: Section 2 Summary (15:30 – 16:30)

**[Screen: Section 2 overview graphic showing all 12 videos covered — DNS through AV/Firewall Detection]**

> "With AV/Firewall Detection complete, we have now covered all twelve reconnaissance and enumeration tools in Section 2. From DNS zone transfers through port scanning, service enumeration, and security product detection, you now have a complete toolkit for the Information Gathering phase of any penetration test. Every tool we covered maps directly to OSCP and CEH certification objectives."

**[Screen: Section 2 Tier Reference Table]**

> "All twelve tools in this section are available in the Free tier — no license upgrade required. Here is the complete tier reference for Section 2."

---

## OUTRO (16:30 – end)

> "That completes Section 2 of the Huginn tutorial series — Recon and Enumeration Tools. We covered DNS, port scanning, SMB, SMTP, SNMP, HTTP fingerprinting, API enumeration, RPC, LDAP, IKE/VPN assessment, database enumeration, and now AV/firewall detection. You have a full reconnaissance methodology from start to finish. In Section 3, we move into OSINT and Intelligence Gathering, starting with Subdomain Discovery (see Video 17: Subdomain Discovery), where we use passive techniques to map an organization's external footprint without touching their infrastructure. Thanks for watching, and I will see you in the next section."

---

## Section 2: Tier Reference Table

| Video | Title | License Tier |
|-------|-------|-------------|
| 5 | DNS Enumeration | Free |
| 6 | Port Scanning | Free |
| 7 | SMB Enumeration | Free |
| 8 | SMTP Enumeration | Free |
| 9 | SNMP Enumeration | Free |
| 10 | HTTP/S Fingerprinting | Free |
| 11 | API Enumeration | Free |
| 12 | RPC Enumeration | Free |
| 13 | LDAP Enumeration | Free |
| 14 | IKE/VPN Assessment | Free |
| 15 | Database Enumeration | Free |
| 16 | AV/Firewall Detection | Free |
