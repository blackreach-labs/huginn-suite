"""
Real OSINT reconnaissance engines for Infrastructure analysis.

Implements: DNS Analysis, Tech Stack Detection, ASN Lookup, WHOIS,
Certificate Transparency Search, and Port Discovery.
"""

import socket
import ssl
import struct
import time
import json
import re
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import dns.resolver as dns_resolver
import dns.reversename as dns_reversename
import dns.rdatatype as dns_rdatatype

from app.core.logger import logger

# Common ports for discovery
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465,
    587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
    6379, 8000, 8080, 8443, 8888, 9090, 9200, 27017
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    9090: "Web-Admin", 9200: "Elasticsearch", 27017: "MongoDB"
}


# ---------------------------------------------------------------------------
# DNS Analysis
# ---------------------------------------------------------------------------

def dns_analysis(domain: str, progress_callback=None) -> Dict:
    """
    Perform comprehensive DNS analysis on a domain.

    Returns dict with record types and their values.
    """
    results = {
        "domain": domain,
        "records": {},
        "total_records": 0,
        "nameservers": [],
        "mail_servers": [],
        "errors": [],
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA", "PTR"]

    resolver = dns_resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in record_types:
        if progress_callback:
            progress_callback(f"Querying {rtype} records for {domain}...")

        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                record_str = rdata.to_text()
                records.append(record_str)

                if rtype == "NS":
                    results["nameservers"].append(record_str)
                elif rtype == "MX":
                    results["mail_servers"].append(record_str)

            if records:
                results["records"][rtype] = records
                results["total_records"] += len(records)

        except dns_resolver.NoAnswer:
            pass
        except dns_resolver.NXDOMAIN:
            results["errors"].append(f"Domain {domain} does not exist (NXDOMAIN)")
            break
        except dns_resolver.NoNameservers:
            results["errors"].append(f"No nameservers available for {rtype}")
        except Exception as e:
            if "Timeout" in type(e).__name__:
                results["errors"].append(f"Timeout querying {rtype}")
            else:
                results["errors"].append(f"{rtype}: {str(e)}")

    # Try zone transfer (usually fails but worth trying)
    if results["nameservers"]:
        if progress_callback:
            progress_callback("Attempting zone transfer (AXFR)...")
        try:
            import dns.zone
            import dns.query
            ns = results["nameservers"][0].rstrip(".")
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            results["zone_transfer"] = True
            results["zone_records"] = len(zone.nodes)
        except Exception:
            results["zone_transfer"] = False

    return results


# ---------------------------------------------------------------------------
# Technology Stack Detection
# ---------------------------------------------------------------------------

def tech_stack_detection(domain: str, progress_callback=None) -> Dict:
    """
    Detect web technologies by analyzing HTTP headers, response body, and known paths.
    """
    results = {
        "domain": domain,
        "technologies": [],
        "headers": {},
        "server": None,
        "powered_by": None,
        "framework": None,
        "cms": None,
        "cdn": None,
        "errors": [],
    }

    urls = [f"https://{domain}", f"http://{domain}"]

    for url in urls:
        if progress_callback:
            progress_callback(f"Probing {url}...")

        try:
            resp = requests.get(url, timeout=10, allow_redirects=True, verify=False,
                              headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

            results["headers"] = dict(resp.headers)
            results["status_code"] = resp.status_code
            results["final_url"] = resp.url

            # Server header
            server = resp.headers.get("Server", "")
            if server:
                results["server"] = server
                results["technologies"].append({"name": server, "category": "Web Server"})

            # X-Powered-By
            powered_by = resp.headers.get("X-Powered-By", "")
            if powered_by:
                results["powered_by"] = powered_by
                results["technologies"].append({"name": powered_by, "category": "Runtime"})

            # Detect from headers
            _detect_from_headers(resp.headers, results)

            # Detect from body
            if resp.text:
                _detect_from_body(resp.text, results)

            break  # Success, don't try HTTP if HTTPS worked

        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            results["errors"].append(f"Timeout connecting to {url}")
        except Exception as e:
            results["errors"].append(str(e))

    # Check known paths
    if progress_callback:
        progress_callback("Checking known technology paths...")
    _check_known_paths(domain, results)

    return results


def _detect_from_headers(headers, results):
    """Detect technologies from HTTP headers."""
    header_signatures = {
        "X-Drupal-Cache": ("Drupal", "CMS"),
        "X-Generator": (None, "Generator"),  # value is the tech
        "X-AspNet-Version": ("ASP.NET", "Framework"),
        "X-AspNetMvc-Version": ("ASP.NET MVC", "Framework"),
        "X-Shopify-Stage": ("Shopify", "E-commerce"),
        "CF-RAY": ("Cloudflare", "CDN"),
        "X-Cache": (None, "CDN/Cache"),
        "X-Varnish": ("Varnish", "Cache"),
        "X-Fastly-Request-ID": ("Fastly", "CDN"),
        "X-Amz-Cf-Id": ("Amazon CloudFront", "CDN"),
        "X-Azure-Ref": ("Azure CDN", "CDN"),
    }

    for header, (tech_name, category) in header_signatures.items():
        value = headers.get(header, "")
        if value:
            name = tech_name or value
            results["technologies"].append({"name": name, "category": category})
            if category == "CDN":
                results["cdn"] = name
            elif category == "CMS":
                results["cms"] = name


def _detect_from_body(body: str, results):
    """Detect technologies from HTML body content."""
    body_lower = body.lower()

    signatures = [
        (r'<meta name="generator" content="WordPress ([^"]+)"', "WordPress", "CMS"),
        (r'wp-content/', "WordPress", "CMS"),
        (r'wp-includes/', "WordPress", "CMS"),
        (r'/sites/default/files/', "Drupal", "CMS"),
        (r'Joomla!', "Joomla", "CMS"),
        (r'content="Wix\.com', "Wix", "Website Builder"),
        (r'squarespace', "Squarespace", "Website Builder"),
        (r'react', "React", "JS Framework"),
        (r'__next', "Next.js", "JS Framework"),
        (r'ng-version', "Angular", "JS Framework"),
        (r'vue\.js|vuejs', "Vue.js", "JS Framework"),
        (r'jquery', "jQuery", "JS Library"),
        (r'bootstrap', "Bootstrap", "CSS Framework"),
        (r'tailwindcss|tailwind', "Tailwind CSS", "CSS Framework"),
        (r'google-analytics|gtag', "Google Analytics", "Analytics"),
        (r'googletagmanager', "Google Tag Manager", "Analytics"),
        (r'cloudflare', "Cloudflare", "CDN"),
    ]

    seen = set()
    for pattern, name, category in signatures:
        if name not in seen and re.search(pattern, body, re.IGNORECASE):
            results["technologies"].append({"name": name, "category": category})
            seen.add(name)
            if category == "CMS" and not results["cms"]:
                results["cms"] = name


def _check_known_paths(domain: str, results):
    """Check for known technology indicator paths."""
    paths = {
        "/robots.txt": "robots.txt",
        "/wp-login.php": "WordPress",
        "/administrator/": "Joomla",
        "/user/login": "Drupal",
        "/.env": "Environment File Exposed",
        "/.git/HEAD": "Git Repository Exposed",
        "/api/": "API Endpoint",
        "/graphql": "GraphQL",
        "/swagger/": "Swagger/OpenAPI",
    }

    for path, tech in paths.items():
        try:
            resp = requests.head(f"https://{domain}{path}", timeout=5, verify=False,
                               allow_redirects=False,
                               headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code in (200, 301, 302, 403):
                results["technologies"].append({
                    "name": tech,
                    "category": "Detected Path",
                    "path": path,
                    "status": resp.status_code,
                })
        except Exception:
            pass


# ---------------------------------------------------------------------------
# ASN Lookup
# ---------------------------------------------------------------------------

def asn_lookup(domain: str, progress_callback=None) -> Dict:
    """
    Perform ASN (Autonomous System Number) lookup using Team Cymru DNS method.
    """
    results = {
        "domain": domain,
        "ip": None,
        "asn": None,
        "asn_name": None,
        "prefix": None,
        "country": None,
        "registry": None,
        "allocated": None,
        "errors": [],
    }

    # Resolve domain to IP first
    if progress_callback:
        progress_callback(f"Resolving {domain} to IP...")

    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip
    except socket.gaierror as e:
        results["errors"].append(f"Cannot resolve {domain}: {e}")
        return results

    # Team Cymru DNS-based ASN lookup
    if progress_callback:
        progress_callback(f"Looking up ASN for {ip}...")

    try:
        # Reverse the IP for DNS query
        octets = ip.split(".")
        reversed_ip = ".".join(reversed(octets))
        query = f"{reversed_ip}.origin.asn.cymru.com"

        resolver = dns_resolver.Resolver()
        resolver.timeout = 5
        answers = resolver.resolve(query, "TXT")

        for rdata in answers:
            txt = rdata.to_text().strip('"')
            # Format: ASN | Prefix | Country | Registry | Allocated
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 5:
                results["asn"] = parts[0]
                results["prefix"] = parts[1]
                results["country"] = parts[2]
                results["registry"] = parts[3]
                results["allocated"] = parts[4]
            break

        # Get ASN name
        if results["asn"]:
            if progress_callback:
                progress_callback(f"Looking up ASN name for AS{results['asn']}...")
            try:
                name_query = f"AS{results['asn']}.asn.cymru.com"
                name_answers = resolver.resolve(name_query, "TXT")
                for rdata in name_answers:
                    txt = rdata.to_text().strip('"')
                    parts = [p.strip() for p in txt.split("|")]
                    if len(parts) >= 5:
                        results["asn_name"] = parts[4]
                    break
            except Exception:
                pass

    except Exception as e:
        results["errors"].append(f"ASN lookup failed: {e}")

    return results


# ---------------------------------------------------------------------------
# WHOIS Lookup
# ---------------------------------------------------------------------------

def whois_lookup(domain: str, progress_callback=None) -> Dict:
    """
    Perform WHOIS lookup using raw socket connection to WHOIS servers.
    """
    results = {
        "domain": domain,
        "raw": "",
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "nameservers": [],
        "status": [],
        "registrant": None,
        "errors": [],
    }

    if progress_callback:
        progress_callback(f"Querying WHOIS for {domain}...")

    # Determine WHOIS server based on TLD
    tld = domain.rsplit(".", 1)[-1].lower()
    whois_servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "info": "whois.afilias.net",
        "biz": "whois.biz",
        "us": "whois.nic.us",
        "uk": "whois.nic.uk",
        "de": "whois.denic.de",
        "fr": "whois.nic.fr",
        "au": "whois.auda.org.au",
        "ca": "whois.cira.ca",
    }

    whois_server = whois_servers.get(tld, f"whois.nic.{tld}")

    try:
        # Connect to WHOIS server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((whois_server, 43))
        sock.send(f"{domain}\r\n".encode())

        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        sock.close()

        raw_text = response.decode("utf-8", errors="replace")
        results["raw"] = raw_text

        # Check if we need to follow a referral
        referral_match = re.search(r"Registrar WHOIS Server:\s*(.+)", raw_text, re.IGNORECASE)
        if referral_match:
            referral_server = referral_match.group(1).strip()
            if referral_server and referral_server != whois_server:
                if progress_callback:
                    progress_callback(f"Following referral to {referral_server}...")
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(10)
                    sock2.connect((referral_server, 43))
                    sock2.send(f"{domain}\r\n".encode())
                    response2 = b""
                    while True:
                        try:
                            data = sock2.recv(4096)
                            if not data:
                                break
                            response2 += data
                        except socket.timeout:
                            break
                    sock2.close()
                    raw_text = response2.decode("utf-8", errors="replace")
                    results["raw"] = raw_text
                except Exception:
                    pass

        # Parse common fields
        _parse_whois_fields(raw_text, results)

    except socket.gaierror:
        results["errors"].append(f"Cannot resolve WHOIS server: {whois_server}")
    except socket.timeout:
        results["errors"].append(f"Timeout connecting to {whois_server}")
    except ConnectionRefusedError:
        results["errors"].append(f"Connection refused by {whois_server}")
    except Exception as e:
        results["errors"].append(f"WHOIS error: {e}")

    return results


def _parse_whois_fields(raw: str, results: Dict):
    """Parse common WHOIS fields from raw text."""
    patterns = {
        "registrar": r"Registrar(?:\s*Name)?:\s*(.+)",
        "creation_date": r"(?:Creat(?:ion|ed)\s*Date|Registration\s*Date):\s*(.+)",
        "expiration_date": r"(?:Expir(?:ation|y)\s*Date|Registry\s*Expiry\s*Date):\s*(.+)",
        "updated_date": r"(?:Updated?\s*Date|Last\s*Modified):\s*(.+)",
        "registrant": r"Registrant(?:\s*(?:Organization|Name|Contact\s*Name))?:\s*(.+)",
    }

    for field_name, pattern in patterns.items():
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            # Skip if it's a URL or empty
            if value and not value.startswith("http") and value != "":
                results[field_name] = value

    # Nameservers
    ns_matches = re.findall(r"Name\s*Server:\s*(.+)", raw, re.IGNORECASE)
    results["nameservers"] = [ns.strip().lower() for ns in ns_matches if ns.strip()]

    # Status
    status_matches = re.findall(r"(?:Domain\s*)?Status:\s*(.+)", raw, re.IGNORECASE)
    results["status"] = [s.strip() for s in status_matches[:5] if s.strip()]

    # Domain ID
    domain_id = re.search(r"Registry\s*Domain\s*ID:\s*(.+)", raw, re.IGNORECASE)
    if domain_id:
        results["domain_id"] = domain_id.group(1).strip()

    # DNSSEC
    dnssec = re.search(r"DNSSEC:\s*(.+)", raw, re.IGNORECASE)
    if dnssec:
        results["dnssec"] = dnssec.group(1).strip()


# ---------------------------------------------------------------------------
# Certificate Transparency Search
# ---------------------------------------------------------------------------

def cert_search(domain: str, progress_callback=None) -> Dict:
    """
    Search Certificate Transparency logs via crt.sh (free, no API key).
    """
    results = {
        "domain": domain,
        "certificates": [],
        "unique_domains": set(),
        "total_certs": 0,
        "errors": [],
    }

    if progress_callback:
        progress_callback(f"Searching crt.sh for certificates matching {domain}...")

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})

        if resp.status_code == 200:
            certs = resp.json()
            results["total_certs"] = len(certs)

            # Deduplicate and extract useful info
            seen_ids = set()
            for cert in certs[:200]:  # Limit to 200 most recent
                cert_id = cert.get("id")
                if cert_id in seen_ids:
                    continue
                seen_ids.add(cert_id)

                common_name = cert.get("common_name", "")
                name_value = cert.get("name_value", "")
                issuer = cert.get("issuer_name", "")
                not_before = cert.get("not_before", "")
                not_after = cert.get("not_after", "")

                results["certificates"].append({
                    "id": cert_id,
                    "common_name": common_name,
                    "name_value": name_value,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                })

                # Extract unique domains from name_value
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name:
                        results["unique_domains"].add(name)

            results["unique_domains"] = sorted(results["unique_domains"])

            if progress_callback:
                progress_callback(f"Found {results['total_certs']} certificates, {len(results['unique_domains'])} unique domains")

        else:
            results["errors"].append(f"crt.sh returned status {resp.status_code}")

    except requests.exceptions.Timeout:
        results["errors"].append("Timeout connecting to crt.sh")
    except Exception as e:
        results["errors"].append(f"Certificate search error: {e}")

    return results


# ---------------------------------------------------------------------------
# Port Discovery
# ---------------------------------------------------------------------------

def port_discovery(domain: str, ports: List[int] = None, timeout: float = 2.0,
                   max_threads: int = 50, progress_callback=None) -> Dict:
    """
    TCP connect scan on common ports using thread pool.
    """
    if ports is None:
        ports = COMMON_PORTS

    results = {
        "domain": domain,
        "ip": None,
        "open_ports": [],
        "closed_ports": [],
        "filtered_ports": [],
        "total_scanned": len(ports),
        "errors": [],
    }

    # Resolve domain
    if progress_callback:
        progress_callback(f"Resolving {domain}...")

    try:
        ip = socket.gethostbyname(domain)
        results["ip"] = ip
    except socket.gaierror as e:
        results["errors"].append(f"Cannot resolve {domain}: {e}")
        return results

    if progress_callback:
        progress_callback(f"Scanning {len(ports)} ports on {ip}...")

    # Scan ports in parallel
    scanned = 0

    def scan_port(port: int) -> Tuple[int, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port, "open"
            else:
                return port, "closed"
        except socket.timeout:
            return port, "filtered"
        except Exception:
            return port, "filtered"

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, port): port for port in ports}

        for future in as_completed(futures):
            port, status = future.result()
            scanned += 1

            service = PORT_SERVICES.get(port, "unknown")

            if status == "open":
                results["open_ports"].append({
                    "port": port,
                    "service": service,
                    "state": "open",
                })
                if progress_callback:
                    progress_callback(f"[OPEN] {port}/{service}")
            elif status == "filtered":
                results["filtered_ports"].append(port)

    # Sort open ports
    results["open_ports"].sort(key=lambda x: x["port"])

    # Try banner grabbing on open ports
    if progress_callback:
        progress_callback("Grabbing service banners...")

    for port_info in results["open_ports"][:10]:  # Limit banner grabs
        banner = _grab_banner(ip, port_info["port"])
        if banner:
            port_info["banner"] = banner

    return results


def _grab_banner(ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Attempt to grab a service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # For HTTP ports, send a request
        if port in (80, 8080, 8000, 8888):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        elif port == 443:
            # Skip SSL banner grab (would need SSL wrapping)
            sock.close()
            return None
        else:
            # Wait for banner
            pass

        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()

        # Truncate long banners
        if len(banner) > 200:
            banner = banner[:200] + "..."

        return banner if banner else None

    except Exception:
        return None
