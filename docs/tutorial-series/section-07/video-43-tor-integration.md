# VIDEO 43: Tor Integration
### Onion Routing, Circuit Management & Exit Node Selection
**Suggested length:** 14–16 minutes
**License Tier:** Professional
**Certification Relevance:** CEH: Evading IDS/Firewalls

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 7 title card "Stealth and Evasion"]**

> "Welcome back to Section 7 — Stealth and Evasion. In the previous video, we configured multi-proxy routing with ProxyChains — setting up HTTP, SOCKS4, and SOCKS5 proxies in strict, dynamic, and random chain modes (see Video 42: ProxyChains). Today we're taking anonymization to the next level with Tor integration. Tor routes your traffic through multiple encrypted relays operated by volunteers worldwide, making it extremely difficult to trace connections back to your origin. We'll integrate Tor with Huginn's stealth scanning features, verify our anonymization, and understand the operational considerations for using Tor in authorized penetration testing."

**[Screen: License tier badge — "Professional Tier Required" prominently displayed]**

> "Tor integration is a Professional tier feature. You'll need an active Professional or Enterprise license to access this functionality in Huginn. You'll also need Tor installed on your system — I'll walk through verifying that setup."

**[Screen: Prerequisites checklist — Tor service installed, Professional license active, own EC2 instance for verification, Video 42 completed]**

> "Prerequisites for this video. You should have completed Video 42 on ProxyChains since Tor integration builds on that foundation. You need Tor installed and running on your system — we'll verify that shortly. And we're using our own EC2 instance as the destination target for verification. This instance runs a simple HTTP endpoint that shows the connecting IP address, so we can confirm our traffic is actually routing through Tor."

---

## SECTION 1: Understanding Tor Architecture (1:30 – 3:15)

**[Screen: Animated diagram showing Tor circuit — Your Machine → Guard Node → Middle Relay → Exit Node → Destination]**

> "Before we configure anything, let's understand how Tor works at a high level. When you send traffic through Tor, it passes through three relays — the guard node, the middle relay, and the exit node. Each relay only knows the identity of the relay immediately before and after it. The guard node knows your real IP but doesn't know your destination. The exit node knows your destination but doesn't know your real IP. The middle relay knows neither. This three-hop architecture provides strong anonymity."

**[Screen: Diagram showing encryption layers — three layers of encryption peeled at each hop]**

> "The name 'onion routing' comes from the encryption structure. Your traffic is wrapped in three layers of encryption — one for each relay. The guard node peels the first layer, revealing the middle relay's address. The middle relay peels the second layer, revealing the exit node. The exit node peels the final layer and forwards your unencrypted request to the destination. Nobody along the path can see the full picture."

**[Screen: Important callout box — "Exit Node Awareness: Traffic between exit node and destination is UNENCRYPTED unless you're using HTTPS"]**

> "Critical operational awareness — traffic between the exit node and your destination is unencrypted unless you're using HTTPS. Exit node operators can potentially observe your traffic. For penetration testing, this means you should never send credentials or sensitive data through Tor without TLS. For scanning purposes, the destination server sees the exit node's IP address, not yours — which is the anonymity we want."

---

## SECTION 2: Tor Installation and Service Verification (3:15 – 5:00)

**[Screen: Terminal showing Tor installation verification commands]**

> "Let's verify Tor is installed and running. On Kali Linux and most penetration testing distributions, Tor is available in the package manager. Let me check the service status."

```bash
# Verify Tor installation
which tor
# /usr/bin/tor

# Check Tor service status
sudo systemctl status tor
# ● tor.service - Anonymizing overlay network for TCP
#    Loaded: loaded (/lib/systemd/system/tor.service; disabled)
#    Active: inactive (dead)

# Start the Tor service
sudo systemctl start tor

# Verify it's running
sudo systemctl status tor
# ● tor.service - Anonymizing overlay network for TCP
#    Loaded: loaded (/lib/systemd/system/tor.service; disabled)
#    Active: active (running) since Mon 2024-01-15 09:32:41 EST
#    Process: 4521 ExecStartPre=/usr/bin/tor --verify-config (code=exited, status=0/SUCCESS)
#   Main PID: 4523 (tor)
#     Memory: 31.2M
#        CPU: 892ms
#     CGroup: /system.slice/tor.service
#             └─4523 /usr/bin/tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc

# Check Tor SOCKS port is listening
ss -tlnp | grep 9050
# LISTEN  0  4096  127.0.0.1:9050  0.0.0.0:*  users:(("tor",pid=4523,fd=6))
```

**[Screen: Terminal output showing Tor service active and SOCKS port 9050 listening]**

> "Tor is running and listening on port 9050. This is the local SOCKS5 proxy that Tor exposes — any traffic sent to 127.0.0.1:9050 will be routed through the Tor network. The control port on 9051 allows us to request new circuits, but for our purposes the SOCKS port is what matters."

**[Screen: Terminal showing quick connectivity test through Tor]**

> "Let's do a quick sanity check — verify we can reach the internet through Tor and confirm our IP changes."

```bash
# Quick Tor connectivity test
# Check your real IP first
curl -s http://httpbin.org/ip
# {"origin": "203.0.113.45"}

# Now check through Tor using torsocks
torsocks curl -s http://httpbin.org/ip
# {"origin": "185.220.101.42"}

# The IPs are different — Tor is working
# 185.220.101.42 is a Tor exit node, not our real IP
```

**[Screen: Side-by-side comparison — real IP vs Tor IP highlighted in green/blue]**

> "Two different IPs. 203.0.113.45 is our real IP address. 185.220.101.42 is a Tor exit node somewhere in the world. The destination server — httpbin.org in this case — only sees the exit node address. Our real IP is hidden behind three layers of relays. Now let's integrate this into Huginn."

---

## SECTION 3: Huginn Tor Configuration (5:00 – 7:30)

**[Screen: Huginn Global Settings → Stealth & Proxy Configuration panel]**

> "In Huginn, Tor integration lives under Global Settings in the Stealth and Proxy Configuration panel. Navigate there from the sidebar — Settings, then Stealth & Proxy. You'll see the ProxyChains configuration we set up in the previous video, and below it, the dedicated Tor Integration section."

**[Screen: Huginn Tor Integration panel — Enable Tor toggle, SOCKS port field (9050), circuit refresh options]**

> "The Tor Integration panel has three main controls. The Enable Tor toggle activates Tor routing for all stealth operations. The SOCKS Port field — defaulting to 9050 — tells Huginn where to find the local Tor SOCKS proxy. And the Circuit Refresh section controls how often Huginn requests a new Tor circuit, which changes your exit node and apparent IP address."

```bash
# Huginn Tor Configuration
# ═══════════════════════════════════════
#
# Tor Integration Settings:
# ┌────────────────────────┬───────────────────────────────┐
# │ Setting                │ Value                         │
# ├────────────────────────┼───────────────────────────────┤
# │ Tor Enabled            │ True                          │
# │ SOCKS Port             │ 9050                          │
# │ SOCKS Host             │ 127.0.0.1                     │
# │ Proxy Type             │ socks5                        │
# │ Circuit Refresh        │ Every 10 requests             │
# │ DNS Through Tor        │ True (proxy_dns enabled)      │
# └────────────────────────┴───────────────────────────────┘
#
# ProxyChainsManager.enable_tor(tor_port=9050)
# [*] Tor enabled on port 9050
# [*] Added socks5 proxy 127.0.0.1:9050 to chain
# [+] Tor integration active
```

**[Screen: Huginn showing the enable_tor() function being called — ProxyChainsManager code visible in background]**

> "Under the hood, when you enable Tor, Huginn's ProxyChainsManager calls enable_tor(), which adds a SOCKS5 proxy entry pointing at 127.0.0.1:9050 to your proxy chain. The proxy_dns option ensures DNS queries also route through Tor — this is critical. Without it, your DNS queries go directly to your ISP's resolver, leaking which domains you're looking up even though the actual connections route through Tor. Always enable proxy_dns when using Tor for anonymity."

**[Screen: Huginn showing chain type selection with Tor — Dynamic Chain recommended]**

> "For chain type with Tor, Dynamic is recommended. Dynamic mode skips unavailable proxies and continues through the chain. If you have additional proxies configured alongside Tor — say a SOCKS5 proxy before the Tor entry — dynamic mode ensures your traffic still reaches the network even if one proxy goes down. Strict mode would fail entirely if any proxy in the chain is unreachable."

```bash
# Recommended Tor chain configuration
# ═══════════════════════════════════════
#
# Chain Type: dynamic_chain
# Proxy DNS:  enabled
#
# [ProxyList]
# socks5 127.0.0.1 9050
#
# Generated by ProxyChainsManager.generate_proxychains_config()
#
# For additional anonymity, add a VPN or proxy BEFORE Tor:
# socks5 your-vpn-proxy 1080
# socks5 127.0.0.1 9050
#
# This creates: You → VPN → Tor Guard → Middle → Exit → Target
# Even your ISP can't see you're using Tor
```

---

## SECTION 4: IP Verification Against Own Infrastructure (7:30 – 9:30)

**[Screen: Huginn Tor Integration — "Verify IP" button and IP verification panel]**

> "Now the critical step — verifying our anonymization actually works. We'll use our own EC2 instance as the verification endpoint. This instance runs a minimal HTTP server that returns the connecting client's IP address. By checking what IP our EC2 sees, we confirm whether Tor is properly masking our identity."

**[Screen: Terminal showing EC2 instance details — public IP, security group allowing HTTP inbound]**

```bash
# Our verification EC2 instance
# ═══════════════════════════════
#
# Instance: i-0a1b2c3d4e5f67890
# Region: us-east-1
# Public IP: 54.210.167.89
# Security Group: sg-proxy-verify (allows HTTP inbound from 0.0.0.0/0)
#
# Running: simple IP echo server on port 80
# Endpoint: http://54.210.167.89/ip
# Returns: JSON with connecting client IP
```

**[Screen: Huginn executing IP verification through Tor — showing the proxy chain test]**

> "Let's run Huginn's proxy chain test against our verification endpoint."

```bash
# Huginn proxy chain verification
# ═══════════════════════════════════════
#
# ProxyChainsManager.test_proxy_chain()
#
# [*] Testing proxy chain connectivity...
# [*] Chain: dynamic_chain
# [*] Proxies: socks5://127.0.0.1:9050 (Tor)
# [*] Target: http://54.210.167.89/ip
# [*] Executing: curl -s http://54.210.167.89/ip
#
# [+] Response received:
# {
#   "client_ip": "104.244.76.13",
#   "timestamp": "2024-01-15T14:32:41Z",
#   "server": "ip-echo-1.0"
# }
#
# [+] Chain test PASSED
# [+] Exit node IP: 104.244.76.13
# [+] Your real IP is NOT visible to the destination
#
# Verification:
# ┌───────────────┬──────────────────┐
# │ Your real IP  │ 203.0.113.45     │
# │ Destination   │ 54.210.167.89    │  (our EC2)
# │ Seen by dest  │ 104.244.76.13    │  (Tor exit node)
# └───────────────┴──────────────────┘
```

**[Screen: Huginn showing green verification checkmark — "Tor Anonymization Verified" with IP comparison table]**

> "Perfect. Our EC2 instance sees 104.244.76.13 — a Tor exit node — not our real IP address 203.0.113.45. The anonymization is confirmed. Huginn shows this in a clear comparison table so you can verify at a glance that your identity is protected before starting any scanning operations."

**[Screen: Huginn showing circuit refresh — requesting new identity]**

> "Let's request a new circuit and verify the IP changes."

```bash
# Request new Tor circuit (new exit node)
# ═══════════════════════════════════════
#
# [*] Requesting new Tor circuit...
# [*] Signal sent to Tor control port (9051)
# [*] Waiting for new circuit establishment...
# [+] New circuit established
#
# [*] Re-testing proxy chain...
# {
#   "client_ip": "199.249.230.87",
#   "timestamp": "2024-01-15T14:33:12Z"
# }
#
# [+] Exit node changed: 104.244.76.13 → 199.249.230.87
# [+] IP rotation confirmed
```

**[Screen: Huginn showing IP changed from previous exit node to a new one]**

> "The exit node changed from 104.244.76.13 to 199.249.230.87. Each circuit refresh gives us a completely different IP from a different geographic location. This is powerful for avoiding IP-based rate limiting and detection during assessments."

---

## SECTION 5: Integrating Tor with Scanning Operations (9:30 – 12:00)

**[Screen: Huginn Stealth Mode settings with Tor enabled — showing scan configuration panel]**

> "Now let's use Tor with Huginn's scanning features. When Tor is enabled and you launch a scan with stealth mode active, all scan traffic routes through the Tor network. Let's run a port scan against our EC2 instance through Tor and see the difference."

**[Screen: Huginn scan configuration — target set to EC2 instance, Stealth Mode: Sneaky, Tor enabled]**

```bash
# Scanning through Tor
# ═══════════════════════════════════════
#
# Scan Configuration:
# ┌────────────────────────┬─────────────────────────────┐
# │ Target                 │ 54.210.167.89 (own EC2)     │
# │ Scan Type              │ TCP Connect (SYN not avail) │
# │ Ports                  │ 22, 80, 443, 8080          │
# │ Stealth Mode           │ Sneaky                      │
# │ Proxy                  │ Tor (socks5://127.0.0.1:9050)│
# │ Timing                 │ Reduced (stealth throttle)  │
# └────────────────────────┴─────────────────────────────┘
#
# Command generated by ProxyChainsManager:
# proxychains -f /tmp/huginn_proxy_abc123.conf nmap -sT -p 22,80,443,8080 54.210.167.89
#
# [*] Starting Tor-routed scan...
# [*] Scan traffic routing through Tor circuit
# [*] Exit node: 199.249.230.87 (current circuit)
```

**[Screen: Important callout — "Tor Scanning Limitations" in yellow warning box]**

> "Important limitation — when scanning through Tor, you cannot use SYN scans. Tor only supports TCP connections, not raw packets. That means nmap's -sS flag won't work through Tor. You must use TCP connect scans with -sT. This is slightly noisier from a log perspective on the target, but your source IP remains anonymous. Also, UDP scanning is not possible through Tor — TCP only."

```bash
# Scan output (through Tor)
# ═══════════════════════════════════════
#
# Starting Nmap scan via ProxyChains (Tor)
# Nmap scan report for 54.210.167.89
# Host is up (latency 0.834s via Tor).
#
# PORT     STATE  SERVICE
# 22/tcp   open   ssh
# 80/tcp   open   http
# 443/tcp  closed https
# 8080/tcp closed http-proxy
#
# Scan completed — 4 ports scanned in 12.3 seconds
#
# Note: Latency is higher through Tor (0.834s vs ~0.050s direct)
# This is expected — traffic traverses 3 relays + exit node
#
# EC2 access logs show source IP: 199.249.230.87 (Tor exit)
# Our real IP (203.0.113.45) does NOT appear in target logs
```

**[Screen: Huginn scan results showing completed scan with Tor indicator — shield icon next to results]**

> "Scan complete. Notice the increased latency — 834 milliseconds versus the 50 milliseconds we'd see with a direct connection. That's the cost of three relay hops. The scan took 12 seconds for four ports. For larger scans, Tor adds significant time. This is why you combine Tor with targeted scanning — use your normal reconnaissance to identify interesting ports first, then scan specific targets through Tor when you need anonymity."

**[Screen: EC2 CloudWatch logs showing access from Tor exit node IP — no trace of real IP]**

> "Checking our EC2 instance's access logs confirms it. The only source IP logged is the Tor exit node. Our real IP address appears nowhere in the target's logs, VPC flow logs, or security group hit counters. From the target's perspective, the scan came from a Tor exit node in a completely different country."

---

## SECTION 6: Operational Considerations and Exit Node Awareness (12:00 – 14:00)

**[Screen: Slide titled "Tor Operational Security Considerations for Pentesters"]**

> "Using Tor in penetration testing comes with specific considerations you need to understand. First — exit node trust. You're sending traffic through volunteer-operated exit nodes. Malicious exit nodes can observe unencrypted traffic. Always use TLS for sensitive communications. For scanning, this is less of a concern since we're sending probe packets, not credentials."

**[Screen: Diagram showing exit node monitoring scenario — and mitigation with HTTPS]**

> "Second — Tor exit node IP addresses are publicly listed. Many security products maintain Tor exit node blocklists. If the target runs a WAF or IDS that blocks known Tor exits, your scans will fail. This is where combining Tor with a VPN or using the AWS proxy deployment from the next video becomes valuable — the target sees a cloud IP, not a flagged Tor exit."

```bash
# Common Tor limitations for penetration testing:
#
# 1. TCP ONLY — No UDP, no raw packets (no SYN scans)
# 2. LATENCY — 500ms-2000ms added per request (3 relay hops)
# 3. BANDWIDTH — Tor relays have limited throughput
# 4. EXIT BLOCKLISTS — Many targets block known Tor exit IPs
# 5. EXIT MONITORING — Unencrypted traffic visible to exit operators
#
# Mitigations:
# 1. Use TCP connect scans (-sT) instead of SYN scans
# 2. Target specific ports rather than full range scans
# 3. Use circuit refresh to distribute load across exits
# 4. Combine with VPN/cloud proxies for targets blocking Tor
# 5. Always use TLS (HTTPS) for any data-bearing connections
```

**[Screen: Huginn showing ProxyChains configuration with VPN + Tor layered setup]**

> "For maximum anonymity in professional engagements, layer your proxies. A VPN before Tor hides Tor usage from your ISP. Tor before a proxy hides your IP from the final proxy. Each layer adds protection against different adversaries. In Huginn's ProxyChainsManager, you can build these layered configurations by adding proxies in order."

```bash
# Layered anonymity configuration
# ═══════════════════════════════════════
#
# Option A: VPN → Tor (hide Tor usage from ISP)
# [ProxyList]
# socks5 vpn-proxy.example 1080    # VPN SOCKS proxy
# socks5 127.0.0.1 9050            # Tor
#
# Option B: Tor → External Proxy (avoid Tor exit blocklists)
# [ProxyList]
# socks5 127.0.0.1 9050            # Tor
# socks5 clean-proxy.example 1080  # Non-Tor exit IP
#
# The target sees the last proxy in the chain
# Option B is useful when targets block Tor exits
```

**[Screen: Huginn status panel showing active Tor session — circuit age, bandwidth usage, exit node country]**

> "Huginn tracks your Tor session metadata — circuit age, bandwidth consumed, and the approximate location of your current exit node. Monitor circuit age to decide when to refresh. Long-lived circuits are more susceptible to traffic correlation attacks, though this is primarily a concern against nation-state adversaries rather than standard penetration test targets."

---

## SECTION 7: Certification Mapping and Practice (14:00 – 15:00)

**[Screen: Slide showing CEH domain mapping — Module 12: Evading IDS, Firewalls, and Honeypots]**

> "Tor integration maps to CEH Module 12 — Evading IDS, Firewalls, and Honeypots. The CEH exam covers anonymization techniques, proxy-based evasion, and traffic tunneling. Understanding how Tor works, its limitations with different scan types, and when exit node blocklists apply are all testable concepts. For OSCP, while Tor isn't directly tested, understanding network anonymization helps with the post-exploitation pivoting concepts in the exam."

**[Screen: Practice recommendations with relevant resources]**

> "For practice, set up your own Tor-based scanning environment. Deploy an EC2 instance with logging enabled, configure Tor on your attack machine, and scan through it. Verify your IP never appears in the target logs. Try different scan types through Tor and observe which work and which fail. This hands-on verification builds real understanding of the capabilities and limitations."

---

## OUTRO (15:00 – end)

**[Screen: Summary slide — Tor Integration: Onion Routing Architecture | Service Setup | Huginn Configuration | IP Verification | Scan Integration | Operational Considerations | Next: Video 44 — AWS Infrastructure Deployment]**

> "That's Tor integration with Huginn. We covered how onion routing provides anonymity through three relay hops, verified Tor is running and our real IP is hidden, configured Huginn's ProxyChainsManager for Tor routing, verified anonymization against our own EC2 endpoint, ran a scan through Tor to confirm it works end-to-end, and discussed the operational considerations around exit node trust and blocklists. In the next video, we'll deploy our own proxy and VPN infrastructure on AWS — giving us clean, non-Tor IP addresses that won't trigger exit node blocklists while still hiding our real origin. See you there."

