# VIDEO 58: Local DNS Server
### Custom DNS Records, Port 5353 Configuration & Lab Environments
**Suggested length:** 14–17 minutes
**License Tier:** Professional
**Certification Relevance:** OSCP: Information Gathering (DNS resolution control) | CEH: Footprinting & Reconnaissance

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 10 title card "Advanced Features and Workflows"]**

> "Welcome to Section 10 — Advanced Features and Workflows. We're now past the core attack chain and into the features that separate casual scanning from professional-grade operations. Back in Video 5 (see Video 5: DNS Enumeration), we used Huginn's DNS tools to query external targets and enumerate records. Today we flip that around — instead of querying someone else's DNS server, we're running our own. Huginn's Local DNS Server lets you define custom DNS records, point them at lab targets, and control name resolution for your entire testing environment. This is a Professional tier feature, and it solves a real operational problem: how do you test against hostnames when you don't control the DNS infrastructure? You run your own. Let's build one."

**[Screen: Diagram showing the problem — a tester needs to scan "app.target.local" but has no DNS entry for it, resulting in resolution failures across Huginn's tools]**

> "Here's the scenario. You have a lab environment — maybe DVWA on localhost, maybe a cluster of VMs — and the applications expect to be addressed by hostname. Without proper DNS, you're stuck editing hosts files, which doesn't scale and doesn't persist across Huginn's various scanning modules. The Local DNS Server provides a centralized solution: define your records once, point Huginn at port 5353, and every module resolves hostnames through your custom entries. No more hosts file editing. No more resolution failures mid-scan."

---

## SECTION 1: Architecture Overview (1:30 – 3:30)

**[Screen: Architecture diagram showing Huginn's Local DNS Server — `local_dns_server.py` running on port 53530 by default, with `dns_settings.py` managing the global configuration and `dns_controls_component.py` providing the UI]**

> "The Local DNS Server is built from three components. First, `local_dns_server.py` — that's the actual UDP DNS server that listens for queries and responds with your custom records. It handles A records, AAAA records, CNAME records, and MX records. Second, `dns_settings.py` — the global settings manager that stores your DNS configuration choice and the port number, persisting it across sessions. Third, the DNS controls component in the UI that lets you manage everything visually. The server runs on port 53530 by default — not port 53, because that would require root privileges and conflict with system DNS. You can change the port in settings."

**[Screen: Code snippet from `local_dns_server.py` showing the class initialization — `def __init__(self, port: int = 53530)` with the license check via `is_licensed()`]**

> "Notice the license gate right at initialization. The `is_licensed()` method checks for a valid Professional tier license before the server will start. This is a Professional feature — Free tier users see the interface but cannot activate the server. The default port of 53530 avoids privilege issues on Linux and macOS where binding to ports below 1024 requires root. On Windows, this isn't strictly necessary, but the high port keeps things consistent across platforms."

```python
# Local DNS Server initialization (app/core/local_dns_server.py)
class LocalDNSServer:
    def __init__(self, port: int = 53530):
        self.port = port
        self.records = {}  # domain -> {record_type -> [values]}
        self.running = False
        self.server_socket = None
        self.server_thread = None
        self.records_file = os.path.join("resources", "config", "dns_records.json")
        self.load_records()

    def is_licensed(self) -> bool:
        """Check Professional tier license"""
        from app.core.license_manager import license_manager
        return license_manager.is_feature_available("local_dns_server")
```

---

## SECTION 2: Enabling and Configuring the Server (3:30 – 5:30)

**[Screen: Huginn UI → Global Settings → DNS Configuration panel — showing "DNS Server" dropdown with "Default DNS" selected, and a "LocalDNS" option available]**

> "Navigate to Global Settings — you'll find the DNS Configuration panel. The dropdown shows two options: Default DNS, which uses your system's configured resolver, and LocalDNS, which routes all Huginn DNS queries through the built-in server. Before switching to LocalDNS, we need to start the server and add some records. Let's configure the port first."

**[Screen: DNS Configuration panel expanded — showing port input field set to 53530, a "Start Server" button, and server status indicator showing "Stopped"]**

> "The port defaults to 53530. If you need a different port — maybe you're running another service there — change it now. Click 'Start Server' to bring up the DNS listener. The status indicator should flip from red 'Stopped' to green 'Running'. Behind the scenes, `dns_settings.py` persists your port choice to `resources/config/dns_settings.json` so it survives application restarts."

```bash
# DNS Settings configuration file (resources/config/dns_settings.json)
{
  "current_dns": "LocalDNS",
  "local_dns_port": 53530
}
```

**[Screen: Clicking "Start Server" — status changes to green "Running" with a log entry: "LocalDNS server started on port 53530"]**

> "Server's running. The UDP socket is bound and listening for DNS queries. Now let's add records so the server has something to resolve."

---

## SECTION 3: Adding Custom DNS Records (5:30 – 8:00)

**[Screen: DNS Records Management panel — showing an empty records table with columns: Domain, Type, Value, and action buttons (Add, Remove)]**

> "The records panel is where you define your custom DNS entries. Each record needs three fields: the domain name — what you want to resolve — the record type — A, AAAA, CNAME, or MX — and the value — the IP address or hostname it should resolve to. Let's build out a realistic lab environment."

**[Screen: Adding first record — Domain: "dvwa.lab", Type: "A", Value: "127.0.0.1" — clicking Add]**

> "First record: `dvwa.lab` pointing to `127.0.0.1`. This lets every Huginn module address our local DVWA instance by hostname instead of raw IP. Particularly useful when testing applications that use virtual hosting or host-header routing."

**[Screen: Adding multiple records in sequence — "api.lab" → "127.0.0.1", "db.lab" → "192.168.1.50", "mail.lab" → "192.168.1.51", "cdn.lab" as CNAME → "dvwa.lab"]**

> "Let's add a full lab topology. API server on localhost, database on a separate VM at 192.168.1.50, mail server at .51, and a CNAME record pointing `cdn.lab` to `dvwa.lab`. Notice the CNAME — the server will recursively resolve that, returning the A record for `dvwa.lab` when queried for `cdn.lab`. You're building a complete DNS zone for your test environment."

```bash
# Adding DNS records via the interface:
Record 1: dvwa.lab       A      127.0.0.1
Record 2: api.lab        A      127.0.0.1
Record 3: db.lab         A      192.168.1.50
Record 4: mail.lab       MX     192.168.1.51
Record 5: cdn.lab        CNAME  dvwa.lab

# Records are persisted to: resources/config/dns_records.json
{
  "dvwa.lab": {"A": ["127.0.0.1"]},
  "api.lab": {"A": ["127.0.0.1"]},
  "db.lab": {"A": ["192.168.1.50"]},
  "mail.lab": {"MX": ["192.168.1.51"]},
  "cdn.lab": {"CNAME": ["dvwa.lab"]}
}
```

**[Screen: Records table now populated with all five entries, each showing a green checkmark indicating active resolution]**

> "Five records defined. The server immediately begins resolving queries for these domains. Records persist to `dns_records.json` so you don't lose your lab configuration between sessions. Now let's verify it actually works."

---

## SECTION 4: Testing DNS Resolution (8:00 – 10:00)

**[Screen: Terminal/command prompt opened alongside Huginn — running `nslookup dvwa.lab 127.0.0.1 -port=53530`]**

> "Let's verify from the command line. Using nslookup, we query our local server directly — specify the server as 127.0.0.1 and the port as 53530. We ask for `dvwa.lab`."

```bash
# Testing resolution with nslookup
$ nslookup dvwa.lab 127.0.0.1 -port=53530
Server:   127.0.0.1
Address:  127.0.0.1#53530

Name:     dvwa.lab
Address:  127.0.0.1

# Testing CNAME resolution
$ nslookup cdn.lab 127.0.0.1 -port=53530
Server:   127.0.0.1
Address:  127.0.0.1#53530

cdn.lab   canonical name = dvwa.lab
Name:     dvwa.lab
Address:  127.0.0.1

# Testing a domain that doesn't exist in our records
$ nslookup google.com 127.0.0.1 -port=53530
Server:   127.0.0.1
Address:  127.0.0.1#53530

** server can't find google.com: NXDOMAIN
```

**[Screen: nslookup returns "Name: dvwa.lab, Address: 127.0.0.1" — successful resolution]**

> "Perfect. `dvwa.lab` resolves to 127.0.0.1. The CNAME for `cdn.lab` chains correctly to `dvwa.lab` and returns the same IP. And notice — querying for `google.com` returns NXDOMAIN because it's not in our records. The Local DNS Server only resolves what you've explicitly defined. It's not a recursive resolver and doesn't forward to upstream DNS. This is intentional — it keeps your lab isolated and prevents DNS leakage during stealth engagements."

**[Screen: Switching back to Huginn UI → DNS dropdown → selecting "LocalDNS" — all modules now route DNS through the local server]**

> "Now switch the global DNS setting to LocalDNS. From this point forward, every Huginn module — scanner, enumeration tools, web exploits — resolves hostnames through your local server. Let's prove it with a scan."

---

## SECTION 5: Integration with Scanning Modules (10:00 – 12:30)

**[Screen: Huginn Scanner page → entering "dvwa.lab" as the target instead of 127.0.0.1 — configuring a Normal profile scan]**

> "Here's where the value becomes clear. Open the Scanner page — instead of typing 127.0.0.1, enter `dvwa.lab`. With LocalDNS active, Huginn resolves that hostname through our server, gets 127.0.0.1 back, and scans it. The scan target field now accepts any hostname you've defined in your DNS records."

**[Screen: Scan starting — showing the resolution log: "Resolving dvwa.lab → 127.0.0.1 (via LocalDNS:53530)" — then scan proceeds normally]**

> "Watch the resolution log in the scan output. You can see Huginn querying the local server, receiving the A record, and proceeding with the scan. This works across all modules — DNS enumeration, port scanning, web exploitation, everything. The resolution is transparent to each module."

```bash
# Huginn scan log showing LocalDNS resolution:
[14:23:01] Target: dvwa.lab
[14:23:01] DNS Resolution: dvwa.lab → 127.0.0.1 (via LocalDNS:53530)
[14:23:01] Starting Normal profile scan against 127.0.0.1
[14:23:02] Port scan: 80/tcp open (HTTP)
[14:23:02] Port scan: 3306/tcp open (MySQL)
[14:23:03] HTTP fingerprint: Apache/2.4.54 (Debian)
[14:23:03] Technology detected: PHP 8.1.12, MySQL 5.7
[14:23:04] Vulnerability scan in progress...
```

**[Screen: Web Exploits page → entering "http://dvwa.lab/vulnerabilities/sqli/" as the target URL — tool resolves and connects]**

> "Same for web exploitation. Enter `http://dvwa.lab/vulnerabilities/sqli/` in the SQL Injection tool. The hostname resolves through LocalDNS, and the tool connects to your DVWA instance. This is especially important for applications that use host-header-based routing — sending traffic to the IP directly might hit the wrong virtual host. Using the hostname ensures correct routing."

---

## SECTION 6: Multi-Target Lab Environments (12:30 – 14:30)

**[Screen: Records table showing a more complex lab setup — 8 records representing a full corporate lab: web.corp.lab, mail.corp.lab, dc.corp.lab, sql.corp.lab, ftp.corp.lab, vpn.corp.lab, app1.corp.lab, app2.corp.lab]**

> "The real power emerges in multi-target lab environments. Imagine you're simulating a corporate network — you have a domain controller, mail server, web servers, databases, all on different VMs. Define all of them in LocalDNS and you have a fully addressable lab infrastructure by name. No hosts file management, no memorizing IP addresses across VMs."

```bash
# Full corporate lab DNS configuration:
web.corp.lab      A    192.168.56.10    # Apache web server VM
mail.corp.lab     A    192.168.56.11    # Postfix mail VM
dc.corp.lab       A    192.168.56.12    # Active Directory DC
sql.corp.lab      A    192.168.56.13    # MSSQL database VM
ftp.corp.lab      A    192.168.56.14    # FTP server VM
vpn.corp.lab      A    192.168.56.15    # OpenVPN server
app1.corp.lab     A    192.168.56.20    # First web application
app2.corp.lab     A    192.168.56.21    # Second web application
```

**[Screen: Scanner page — entering target list: "web.corp.lab, mail.corp.lab, sql.corp.lab" — all three resolve through LocalDNS]**

> "Now you can scan multiple targets by hostname. Enter `web.corp.lab, mail.corp.lab, sql.corp.lab` and Huginn resolves each through LocalDNS. This integrates seamlessly with the Multi-Target Campaign feature we'll cover in Video 60 (see Video 60: Multi-Target Campaigns) — define your DNS records here, then reference hostnames in campaign target lists."

**[Screen: Showing records export/import buttons — exporting the full lab DNS configuration as a JSON file for team sharing]**

> "You can export your DNS records as JSON and share them with your team. When everyone runs the same LocalDNS configuration, the entire team can reference lab targets by consistent hostnames. Import a colleague's records file and your Huginn instance immediately resolves the same names to the same addresses. Lab infrastructure becomes portable."

---

## SECTION 7: Stealth Implications and Best Practices (14:30 – 16:00)

**[Screen: Diagram comparing DNS resolution paths — "Default DNS" path showing queries going to external resolvers (potential DNS leak) vs. "LocalDNS" path showing all resolution staying local]**

> "There's a stealth dimension to LocalDNS that's worth understanding. When you use Default DNS, Huginn's hostname queries go to your system resolver — which might forward to your ISP or a public resolver like 8.8.8.8. That's a DNS leak. If you're running a stealth engagement through Tor or proxychains (see Video 42: ProxyChains) (see Video 43: Tor Integration), DNS queries that bypass the tunnel reveal your investigation targets. LocalDNS solves this: all resolution stays on localhost. No external DNS queries, no leakage."

**[Screen: Best practices list displayed as a configuration checklist]**

> "Best practices for the Local DNS Server: First, use meaningful domain suffixes like `.lab` or `.test` — never use real TLDs that could conflict with legitimate resolution. Second, keep your records file version-controlled if you're working across multiple engagements. Third, remember that LocalDNS only resolves records you define — for anything else, you'll get NXDOMAIN. If you need both custom records and external resolution, you'll need to switch DNS modes between tasks or add explicit records for external targets. Fourth, always verify resolution with nslookup before running a full scan — catching a typo in your records before a 30-minute scan saves time."

```bash
# Best Practices Summary:
# 1. Use .lab, .test, .local suffixes (RFC 2606 reserved)
# 2. Version-control dns_records.json across engagements
# 3. Verify resolution BEFORE running scans:
$  nslookup target.lab 127.0.0.1 -port=53530
# 4. Pair with ProxyChains/Tor for zero DNS leakage
# 5. Export/import records for team-wide consistency
```

---

## OUTRO (16:00 – end)

**[Screen: Huginn Global Settings page showing LocalDNS active with green status indicator, 5 custom records defined]**

> "That's the Local DNS Server — Professional tier. You now have full control over name resolution in your testing environment. Custom A, AAAA, CNAME, and MX records. Persistent configuration across sessions. Integration with every Huginn module. And zero DNS leakage when paired with stealth features. Next up in Video 59, we're looking at Automation and Scheduling — running scans on timers so you can set recurring assessments without manual intervention (see Video 59: Automation & Scheduling). See you there."

---

*Source files referenced: `app/core/local_dns_server.py`, `app/core/dns_settings.py`, `app/components/dns_controls_component.py`*
*Demo target: Own cloud infrastructure — local DNS server configuration*
*Prerequisites: Video 5 (DNS Enumeration), Professional tier license*
