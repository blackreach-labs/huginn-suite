# VIDEO 41: Stealth Mode
### Evasion Levels, Traffic Patterns & Detection Avoidance
**Suggested length:** 16–18 minutes
**License Tier:** Professional
**Certification Relevance:** CEH: Evading IDS/Firewalls | OSCP: Operational Awareness

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 7 title card "Stealth and Evasion"]**

> "Welcome to Section 7 — Stealth and Evasion. This is a different phase of the attack chain. In Sections 5 and 6 we focused on exploitation — firing payloads, gaining shells, running modules. Now we step back and ask a critical operational question: how detectable were those activities? In a real engagement, getting caught by an IDS or tripping a firewall rule means your client's blue team shuts you down — and in some cases, that's a failed engagement. Stealth Mode gives you control over how loud or quiet your traffic footprint is."

**[Screen: Section 7 overview — Video 41: Stealth Mode, Video 42: ProxyChains, Video 43: Tor Integration, Video 44: AWS Deployment]**

> "Section 7 has four videos. Today in Video 41, we configure Huginn's stealth levels and measure the actual traffic difference between them using our own EC2 instance running Suricata IDS. In Video 42, we'll route traffic through proxy chains. Video 43 covers Tor integration. And Video 44 shows automated AWS infrastructure deployment for distributed operations. All four videos require the Professional tier license."

**[Screen: License tier badge — "PROFESSIONAL TIER REQUIRED" with gold badge icon]**

> "Important — everything in this section is a Professional tier feature. If you're on the Free tier, you'll see Stealth Mode options greyed out in Global Settings. Upgrade to Professional to unlock evasion levels, rate control, header randomization, jitter configuration, and proxy rotation. Let's dive in."

---

## SECTION 1: Stealth Mode Architecture (1:30 – 3:30)

**[Screen: Architecture diagram — StealthEngine, StealthConfig, StealthHTTPClient, RateLimiter, and EvasionEngine components with data flow arrows]**

> "Stealth Mode is built on five interconnected components. The StealthEngine is the brain — it manages evasion levels, timing profiles, dynamic rate adjustment, header randomization, jitter, and proxy rotation. StealthConfig handles persistent configuration storage — your stealth settings survive application restarts. The StealthHTTPClient wraps every outbound HTTP request with stealth features applied automatically. The RateLimiter enforces request frequency limits globally across all scanning tools. And the EvasionEngine handles payload-level obfuscation — WAF bypass techniques, encoding, and fragmentation."

**[Screen: Code diagram showing StealthEngine.__init__ — timing_profiles dictionary with paranoid, sneaky, polite, normal entries]**

> "The core concept is the timing profile. Huginn defines four evasion levels — Normal, Polite, Sneaky, and Paranoid — each with progressively more aggressive traffic shaping. Normal sends requests with 0.1 to 1 second delays at 50 requests per second with minimal jitter. Paranoid spaces requests 5 to 15 seconds apart at just 1 request per second with heavy jitter. The difference isn't just speed — it's the traffic pattern that an IDS sees."

```python
# StealthEngine timing profiles (from stealth_engine.py)
# ═══════════════════════════════════════════════════════
timing_profiles = {
    "paranoid": {"delay": (5, 15), "jitter": 0.8, "rate": 1},
    "sneaky":   {"delay": (2, 8),  "jitter": 0.6, "rate": 5},
    "polite":   {"delay": (1, 3),  "jitter": 0.4, "rate": 10},
    "normal":   {"delay": (0.1, 1),"jitter": 0.2, "rate": 50}
}
# delay: seconds between requests (min, max)
# jitter: randomization factor (0.0 = none, 1.0 = maximum)
# rate: max requests per second
```

**[Screen: Huginn Global Settings → Stealth Mode panel showing the evasion level dropdown and feature toggles]**

> "In the UI, Stealth Mode lives under Global Settings. The main controls are the Evasion Level dropdown — Normal, Polite, Sneaky, Paranoid — and individual feature toggles for dynamic rate limiting, header randomization, jitter, and proxy rotation. When you select an evasion level, Huginn adjusts all parameters automatically, but you can override individual settings for fine-grained control."

---

## SECTION 2: Lab Environment Setup (3:30 – 5:30)

**[Screen: AWS Console showing EC2 instance — Ubuntu 22.04, t2.medium, Security Group allowing inbound traffic from tester IP]**

> "For this demonstration, I've set up an EC2 instance running Suricata IDS. This is our own infrastructure — no third-party targets. The instance runs Ubuntu 22.04 with Suricata configured to monitor all inbound traffic, Apache web server on port 80 as our target service, and tcpdump capturing full packet data for analysis. I'll scan this instance from my local machine at each stealth level and compare the traffic patterns."

```bash
# Lab setup on EC2 instance (pre-configured)
# ═══════════════════════════════════════════
#
# Instance: t2.medium, Ubuntu 22.04 LTS
# Public IP: 54.210.xx.xx (our own EC2)
# Services: Apache (80), SSH (22), Suricata IDS
#
# Suricata configuration highlights:
# - ET Open ruleset loaded (Emerging Threats)
# - Custom scan detection rules enabled
# - Alert on port scan patterns
# - Alert on rapid sequential connections
# - pcap logging for traffic analysis
#
# tcpdump capture running:
sudo tcpdump -i eth0 -w /tmp/capture_normal.pcap host <tester_ip>
```

**[Screen: Suricata rule examples — showing scan detection rules that will trigger on aggressive scanning]**

> "Suricata is running the Emerging Threats Open ruleset — the same signatures used by production IDS deployments worldwide. It has rules for detecting port scan patterns, rapid sequential connections, unusual timing patterns, and known scanner fingerprints. This is what a real blue team would see. Let me show you the specific rules we'll be triggering."

```bash
# Relevant Suricata rules that detect scanning:
# ═══════════════════════════════════════════════
#
# alert tcp any any -> $HOME_NET any (msg:"ET SCAN Potential Port Scan";
#   flags:S; threshold: type both, track by_src, count 20, seconds 3;
#   sid:2001219; rev:5;)
#
# alert tcp any any -> $HOME_NET any (msg:"ET SCAN Rapid Multi-Port Connection";
#   flags:S; threshold: type both, track by_src, count 100, seconds 10;
#   sid:2001220; rev:3;)
#
# alert http any any -> $HOME_NET any (msg:"ET SCAN Web Application Scanner";
#   content:"Mozilla"; http_user_agent; threshold: type both,
#   track by_src, count 50, seconds 5; sid:2001221; rev:2;)
```

**[Screen: Terminal showing Suricata running with stats — packets processed, alerts: 0]**

> "Right now Suricata shows zero alerts — clean baseline. We're going to scan the same target four times, once at each evasion level, and watch those alert counts change. Let me reset the pcap capture between each test for clean comparison data."

---

## SECTION 3: Normal Mode — Baseline Traffic (5:30 – 7:30)

**[Screen: Huginn Global Settings → Stealth Mode → Evasion Level: "Normal" selected]**

> "First, Normal mode. This is Huginn's default behavior — no stealth applied. Requests fire as fast as possible with minimal delay, consistent User-Agent headers, no jitter, and no proxy rotation. This is how most scanning tools operate out of the box — fast but extremely visible."

**[Screen: Huginn launching a port scan and HTTP fingerprint scan against the EC2 target at Normal evasion level]**

```bash
# Normal mode configuration:
# ═════════════════════════
# Evasion Level: Normal
# Delay: 0.1–1.0 seconds
# Jitter: 0.2 (minimal randomization)
# Rate: 50 requests/second
# Header Randomization: OFF
# Proxy Rotation: OFF
# Dynamic Rate Limiting: OFF
#
# Launching scan against own EC2 instance...
# Target: 54.210.xx.xx
# Scan type: Port scan (top 100 ports) + HTTP fingerprint
```

**[Screen: Suricata alert log showing multiple alerts firing rapidly — ET SCAN alerts with timestamps]**

> "Watch the Suricata console. Within three seconds — multiple alerts. 'ET SCAN Potential Port Scan' triggers immediately because we sent more than 20 SYN packets in 3 seconds. 'Rapid Multi-Port Connection' fires next — 100 connections in 10 seconds. The HTTP scanner detection rule catches our consistent User-Agent making 50 requests in 5 seconds. Normal mode is a neon sign to any IDS."

```bash
# Suricata alerts — Normal mode (within first 10 seconds):
# ═══════════════════════════════════════════════════════════
#
# [**] [1:2001219:5] ET SCAN Potential Port Scan [**]
# 03/15/2024-14:22:03.441 | src: 203.0.113.xx → dst: 54.210.xx.xx
#
# [**] [1:2001220:3] ET SCAN Rapid Multi-Port Connection [**]
# 03/15/2024-14:22:06.892 | src: 203.0.113.xx → dst: 54.210.xx.xx
#
# [**] [1:2001221:2] ET SCAN Web Application Scanner [**]
# 03/15/2024-14:22:08.127 | src: 203.0.113.xx → dst: 54.210.xx.xx
#
# Total alerts in 30 seconds: 14
# Alert types triggered: 3 distinct rules
```

**[Screen: Wireshark showing the pcap capture — dense cluster of SYN packets with uniform timing intervals]**

> "In the packet capture, the pattern is obvious. Look at the timing column — packets arrive at almost perfectly regular intervals, 0.02 seconds apart. The source port increments predictably. Every packet has the same TTL, same window size, same TCP options. Any analyst looking at this traffic for five seconds knows it's automated scanning. Let's see how Polite mode changes this."

---

## SECTION 4: Polite Mode — Reduced Footprint (7:30 – 9:30)

**[Screen: Huginn Global Settings → Stealth Mode → Evasion Level changed to "Polite"]**

> "Polite mode. This is the first step into stealth — it slows things down and adds basic randomization. Delay increases to 1 to 3 seconds between requests, jitter factor goes to 0.4, and rate drops to 10 requests per second. Header randomization turns on by default at this level, cycling through common User-Agent strings."

```bash
# Polite mode configuration:
# ══════════════════════════
# Evasion Level: Polite
# Delay: 1.0–3.0 seconds
# Jitter: 0.4 (moderate randomization)
# Rate: 10 requests/second
# Header Randomization: ON (4 User-Agent rotation)
# Proxy Rotation: OFF
# Dynamic Rate Limiting: ON (adapts to errors)
#
# Scanning same target: 54.210.xx.xx
# Same scan type: Port scan (top 100 ports) + HTTP fingerprint
```

**[Screen: Suricata alerts — fewer than Normal mode, delayed in triggering]**

> "Different story. The port scan detection rule still triggers — 20 SYN packets in 3 seconds is now borderline. At 10 requests per second, it takes 2 seconds to hit 20 packets, so the rule fires but just barely. The Rapid Multi-Port rule? It needs 100 connections in 10 seconds — at our rate of 10 per second, we hit exactly 100 in 10 seconds. Right on the threshold. The HTTP scanner rule doesn't trigger at all because header randomization breaks the pattern matching."

```bash
# Suricata alerts — Polite mode:
# ═══════════════════════════════
#
# [**] [1:2001219:5] ET SCAN Potential Port Scan [**]
# 03/15/2024-14:25:12.667 | src: 203.0.113.xx → dst: 54.210.xx.xx
# (triggered at 2.1 seconds — borderline)
#
# [**] [1:2001220:3] ET SCAN Rapid Multi-Port Connection [**]
# 03/15/2024-14:25:22.443 | src: 203.0.113.xx → dst: 54.210.xx.xx
# (triggered at 10.2 seconds — threshold boundary)
#
# Total alerts in 60 seconds: 4
# Alert types triggered: 2 distinct rules (down from 3)
# Scan time: ~45 seconds (vs ~5 seconds in Normal)
```

**[Screen: Wireshark pcap comparison — Polite mode showing irregular spacing between packets and varying User-Agent strings]**

> "In the packet capture, the timing is already less uniform. Jitter adds randomness — instead of perfectly spaced packets, you see irregular gaps. 1.2 seconds, then 2.7 seconds, then 1.8 seconds. The User-Agent cycles between Chrome on Windows, Safari on Mac, Firefox on Linux, and Firefox on Windows. It's not invisible — the port scan pattern is still there — but it's substantially less obvious than Normal mode."

---

## SECTION 5: Sneaky Mode — Evading Common Rules (9:30 – 12:00)

**[Screen: Huginn Global Settings → Stealth Mode → Evasion Level changed to "Sneaky"]**

> "Sneaky mode is where stealth gets serious. Delay jumps to 2 to 8 seconds between requests, jitter factor is 0.6, and rate drops to 5 requests per second. At this level, Huginn also enables dynamic rate limiting — if the target starts responding slowly or returning errors, Huginn automatically backs off further. This mimics natural browsing patterns rather than automated scanning."

```bash
# Sneaky mode configuration:
# ══════════════════════════
# Evasion Level: Sneaky
# Delay: 2.0–8.0 seconds
# Jitter: 0.6 (high randomization)
# Rate: 5 requests/second
# Header Randomization: ON (full rotation)
# Proxy Rotation: ON (if proxies configured)
# Dynamic Rate Limiting: ON (aggressive backoff)
#
# Additional features at this level:
# - TLS fingerprint randomization
# - DNS resolution caching (reduces DNS queries)
# - TCP window size variation
#
# Scanning same target: 54.210.xx.xx
# Same scan type: Port scan (top 100 ports) + HTTP fingerprint
```

**[Screen: Suricata running — timer showing scan progress much slower, alert count staying at zero for extended period]**

> "Watch the alert count. Ten seconds... twenty seconds... thirty seconds... still zero. At 5 requests per second, it takes 4 seconds to reach 20 packets — the port scan rule needs 20 in 3 seconds. We never hit that threshold. The Rapid Multi-Port rule needs 100 in 10 seconds — at 5 per second, we only send 50 in 10 seconds. We're under every default threshold."

```bash
# Suricata alerts — Sneaky mode:
# ═══════════════════════════════
#
# Monitoring period: 120 seconds (full scan duration)
#
# Total alerts: 0
# Alert types triggered: 0
#
# Scan time: ~3 minutes 20 seconds (vs ~5 seconds Normal, ~45 seconds Polite)
# Packets sent: Same 100 ports scanned
# Detection: ZERO alerts from standard ET Open ruleset
```

**[Screen: Wireshark pcap of Sneaky mode — packets widely spaced with highly variable timing, different source port ranges]**

> "The pcap tells the story. Packets are spaced 2 to 8 seconds apart with heavy randomization — an analyst looking at this traffic would see what looks like a user browsing different pages slowly. The interval between packet 1 and packet 2 might be 3.4 seconds. Between 2 and 3, it's 6.1 seconds. Between 3 and 4, it's 2.8 seconds. No pattern. No rhythm. The jitter factor of 0.6 means the actual delay varies by up to 60 percent from the base value."

**[Screen: Side-by-side comparison — Normal mode pcap (dense cluster) vs Sneaky mode pcap (scattered dots on timeline)]**

> "Here's the visual comparison. Normal mode on top — a wall of packets crammed into 5 seconds. Sneaky mode below — the same 100 probes spread across over three minutes with no discernible pattern. Same data collected, same results obtained, completely different detection profile. The tradeoff is time — Sneaky takes 40 times longer than Normal. Choose based on your engagement constraints."

---

## SECTION 6: Paranoid Mode — Maximum Evasion (12:00 – 14:30)

**[Screen: Huginn Global Settings → Stealth Mode → Evasion Level changed to "Paranoid"]**

> "Paranoid mode. This is for engagements where detection means mission failure. 5 to 15 second delays between every single request. Jitter at 0.8 — nearly maximum randomization. Rate capped at 1 request per second. Every feature enabled: header randomization, dynamic rate limiting, proxy rotation, TLS fingerprint variation, and source port randomization."

```bash
# Paranoid mode configuration:
# ═════════════════════════════
# Evasion Level: Paranoid
# Delay: 5.0–15.0 seconds
# Jitter: 0.8 (near-maximum randomization)
# Rate: 1 request/second
# Header Randomization: ON (full rotation + custom agents)
# Proxy Rotation: ON (mandatory if proxies configured)
# Dynamic Rate Limiting: ON (ultra-conservative backoff)
#
# Advanced features at Paranoid level:
# - Request fragmentation where supported
# - Source port randomization
# - Connection reuse minimized (new TCP handshake per request)
# - DNS queries randomized and spread across resolvers
# - Timing correlated to target timezone business hours
#
# Scanning same target: 54.210.xx.xx
# Same scan type: Port scan (top 100 ports) + HTTP fingerprint
```

**[Screen: Huginn scan progress bar moving very slowly — estimated time: 25+ minutes for 100 ports]**

> "At Paranoid level, scanning 100 ports takes over 25 minutes. Each probe waits 5 to 15 seconds before the next one fires, with the actual interval randomized by up to 80 percent. Between each packet, Huginn might wait 6 seconds, then 12, then 8, then 14, then 5. The pattern is indistinguishable from random noise."

```bash
# Suricata alerts — Paranoid mode:
# ═════════════════════════════════
#
# Monitoring period: 25+ minutes (full scan duration)
#
# Total alerts: 0
# Alert types triggered: 0
#
# Even with CUSTOM aggressive detection rules:
# - Rule: "more than 5 SYN packets in 30 seconds" → NOT triggered
#   (Paranoid sends ~2 packets per 30 seconds)
# - Rule: "more than 10 unique ports in 60 seconds" → NOT triggered
#   (Paranoid hits ~4-6 ports per minute)
#
# Scan time: ~25 minutes
# Detection: ZERO — indistinguishable from normal internet noise
```

**[Screen: Wireshark Paranoid mode pcap — almost empty timeline with occasional single packets scattered across 25 minutes]**

> "The pcap for Paranoid mode looks like... nothing. Background internet noise. A packet here, another one 12 seconds later, another one 7 seconds after that. If you were monitoring this network, you'd need to watch for 25 minutes to even notice that 100 different ports were probed — and by then, it's lost in the sea of normal traffic. This is the tradeoff. Speed versus stealth. A 5-second scan becomes a 25-minute scan. Choose based on the engagement."

**[Screen: Summary comparison table — all four levels side by side with metrics]**

> "Let me summarize the four levels with real measured data from our Suricata lab."

| Metric | Normal | Polite | Sneaky | Paranoid |
|--------|--------|--------|--------|----------|
| Delay Range | 0.1–1.0s | 1.0–3.0s | 2.0–8.0s | 5.0–15.0s |
| Jitter Factor | 0.2 | 0.4 | 0.6 | 0.8 |
| Max Rate (req/s) | 50 | 10 | 5 | 1 |
| Scan Time (100 ports) | ~5 sec | ~45 sec | ~3.3 min | ~25 min |
| Suricata Alerts | 14 | 4 | 0 | 0 |
| Rules Triggered | 3 | 2 | 0 | 0 |
| Header Randomization | No | Yes | Yes | Yes |
| Dynamic Rate Limiting | No | Yes | Yes | Yes |

---

## SECTION 7: Dynamic Rate Limiting and Threat Profiles (14:30 – 16:30)

**[Screen: Huginn Stealth Mode advanced settings — Dynamic Rate Limiting panel with graphs showing rate adjustment over time]**

> "Beyond the static evasion levels, Huginn has two advanced stealth features worth understanding. First is dynamic rate limiting. When enabled, Huginn monitors response times and error rates from the target. If the target slows down — maybe a WAF is throttling you — Huginn automatically reduces its request rate. If you start getting 429 Too Many Requests responses, it backs off exponentially. This adaptive behavior mimics how a human would react to a slow website."

```bash
# Dynamic Rate Limiting behavior:
# ═══════════════════════════════
#
# Configuration:
# - Base rate: matches evasion level (e.g., 10 req/s for Polite)
# - Error threshold: 10% — if >10% of requests error, reduce rate
# - Response time threshold: 2.0s — if avg response > 2s, reduce rate
# - Backoff factor: 0.7 — reduce to 70% of current rate on trigger
# - Recovery: gradually increase rate when errors clear
#
# Example dynamic adjustment:
# t=0:   Rate: 10 req/s (base)
# t=5:   Target responds in 2.3s avg → rate drops to 7 req/s
# t=10:  Target still slow → rate drops to 5 req/s
# t=20:  Target recovers to 0.8s → rate climbs to 6 req/s
# t=30:  Stable responses → rate returns to 8 req/s
```

**[Screen: Huginn Threat Profile selector showing presets — Generic, CloudFlare WAF, AWS CloudFront, Akamai CDN, IDS/IPS]**

> "Second advanced feature — Threat Profiles. These are presets that combine rate limiting, jitter, header rotation, TLS fingerprinting, and DNS configuration optimized for specific defensive technologies. If you know your target is behind CloudFlare, select the CloudFlare WAF profile — Huginn drops to 3 requests per second, enables JA3 fingerprint evasion, and routes DNS through DNS-over-HTTPS to avoid DNS-based blocking. The IDS/IPS profile drops to 1 request per second and enables packet fragmentation where supported."

```python
# Threat profile presets (from stealth_engine.py)
# ════════════════════════════════════════════════
threat_profiles = {
    "generic":        {"rate": 10, "jitter": True, "headers": True, "tls": "standard"},
    "cloudflare_waf": {"rate": 3,  "jitter": True, "headers": True, "tls": "ja3_evasion", "dns": "doh"},
    "aws_cloudfront": {"rate": 5,  "jitter": True, "headers": True, "tls": "aws_optimized"},
    "akamai_cdn":     {"rate": 2,  "jitter": True, "headers": True, "tls": "akamai_evasion"},
    "ids_ips":        {"rate": 1,  "jitter": True, "headers": True, "fragmentation": True}
}
```

**[Screen: Huginn detection risk score indicator — showing a gauge from 0 (invisible) to 100 (maximum exposure) adjusting as settings change]**

> "One more thing — the detection risk score. Huginn calculates a real-time risk score from 0 to 100 based on your current stealth configuration. Normal mode with no proxy scores around 80 — highly detectable. Paranoid with proxies and full evasion features drops to around 10. This gives you quick visual feedback on how exposed your traffic pattern is before you launch a scan. Adjust settings, watch the score update, then decide if you're comfortable with the risk level for your engagement."

---

## SECTION 8: Certification Context and Practice (16:30 – 17:30)

**[Screen: Slide showing CEH Module 12 — Evading IDS, Firewalls, and Honeypots]**

> "Stealth mode maps directly to CEH Module 12 — Evading IDS, Firewalls, and Honeypots. The exam tests your knowledge of IDS evasion techniques including traffic fragmentation, timing manipulation, obfuscation, and tunneling. Understanding how threshold-based IDS rules work — and how to stay below those thresholds — is exactly what we demonstrated today with Suricata. For OSCP, stealth isn't directly tested in the exam, but operational awareness of detection risk is part of professional methodology."

**[Screen: Practice suggestions — setting up your own Suricata lab for testing]**

> "For practice, I recommend setting up your own Suricata instance. You can do this with a free-tier EC2 instance or a local VM. Install Suricata, load the ET Open ruleset, and run Huginn scans at different levels against it. Watching the alerts appear — or not appear — teaches you more about IDS behavior than any textbook. You can also try THM's 'IDS, IPS, and Firewall' room for structured practice with detection systems."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — Stealth Mode: Four Evasion Levels | Traffic Pattern Control | Dynamic Rate Limiting | Threat Profiles | IDS Evasion Verified | Next: ProxyChains]**

> "That wraps up Stealth Mode. We configured all four evasion levels — Normal, Polite, Sneaky, and Paranoid — and measured their real traffic impact against a Suricata IDS. Normal mode triggers 14 alerts across 3 rules. Polite reduces that to 4 alerts. Sneaky and Paranoid produce zero detections from standard rulesets. We also explored dynamic rate limiting and threat profiles for adaptive evasion. The tradeoff is always speed versus stealth — a 5-second scan at Normal takes 25 minutes at Paranoid. Next up in Video 42, we add another layer of anonymity — routing all traffic through proxy chains with HTTP, SOCKS4, SOCKS5, and Tor proxies. See you there."
