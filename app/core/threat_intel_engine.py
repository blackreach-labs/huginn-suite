"""
Threat Intelligence OSINT Engine.

Performs real lookups against free threat intelligence APIs:
- VirusTotal (requires API key)
- Shodan (requires API key)
- URLVoid / URLScan.io (free)
- AlienVault OTX (free, optional key)
- ThreatCrowd (free, no key)
- Malware Bazaar (free, no key)
- AbuseIPDB (requires API key)
"""

import socket
import json
import re
from typing import Dict, Optional

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from app.core.logger import logger

HEADERS = {"User-Agent": "Huginn-ThreatIntel/1.0"}
TIMEOUT = 15


def _get_api_key(key_name: str) -> Optional[str]:
    """Get API key from global settings."""
    try:
        from shared.configuration.global_settings import global_settings
        return global_settings.get(f"api_keys.{key_name}")
    except Exception:
        return None


def _is_ip(target: str) -> bool:
    """Check if target is an IP address."""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


def _resolve_to_ip(target: str) -> Optional[str]:
    """Resolve domain to IP."""
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def virustotal_scan(target: str, progress_callback=None) -> Dict:
    """Query VirusTotal for domain/IP/URL reputation."""
    results = {"target": target, "detections": 0, "total_engines": 0,
               "categories": [], "details": [], "errors": []}

    api_key = _get_api_key("virustotal")
    if not api_key:
        results["errors"].append(
            "VirusTotal API key not configured.\n"
            "Get a free key at https://www.virustotal.com/gui/join-us\n"
            "Set 'virustotal' in Tools → Global Settings → API Keys"
        )
        return results

    if progress_callback:
        progress_callback(f"Querying VirusTotal for {target}...")

    headers = {"x-apikey": api_key, **HEADERS}

    try:
        if _is_ip(target):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{target}"

        resp = requests.get(url, headers=headers, timeout=TIMEOUT)

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            results["detections"] = stats.get("malicious", 0) + stats.get("suspicious", 0)
            results["total_engines"] = sum(stats.values())
            results["stats"] = stats
            results["reputation"] = data.get("reputation", 0)
            results["categories"] = list(data.get("categories", {}).values())

            # Last analysis results
            analysis = data.get("last_analysis_results", {})
            for engine, result in list(analysis.items())[:20]:
                if result.get("category") in ("malicious", "suspicious"):
                    results["details"].append({
                        "engine": engine,
                        "category": result["category"],
                        "result": result.get("result", ""),
                    })

            if progress_callback:
                progress_callback(f"VirusTotal: {results['detections']}/{results['total_engines']} detections")

        elif resp.status_code == 404:
            results["errors"].append("Target not found in VirusTotal database")
        elif resp.status_code == 401:
            results["errors"].append("Invalid VirusTotal API key")
        else:
            results["errors"].append(f"VirusTotal returned status {resp.status_code}")

    except Exception as e:
        results["errors"].append(f"VirusTotal error: {e}")

    return results


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def shodan_lookup(target: str, progress_callback=None) -> Dict:
    """Query Shodan for host information."""
    results = {"target": target, "ip": None, "ports": [], "services": [],
               "vulns": [], "os": None, "org": None, "errors": []}

    api_key = _get_api_key("shodan")
    if not api_key:
        results["errors"].append(
            "Shodan API key not configured.\n"
            "Get a free key at https://account.shodan.io/register\n"
            "Set 'shodan' in Tools → Global Settings → API Keys"
        )
        return results

    # Resolve to IP if domain
    ip = target if _is_ip(target) else _resolve_to_ip(target)
    if not ip:
        results["errors"].append(f"Cannot resolve {target} to IP")
        return results

    results["ip"] = ip

    if progress_callback:
        progress_callback(f"Querying Shodan for {ip}...")

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()
            results["ports"] = data.get("ports", [])
            results["os"] = data.get("os")
            results["org"] = data.get("org")
            results["isp"] = data.get("isp")
            results["country"] = data.get("country_name")
            results["city"] = data.get("city")
            results["vulns"] = data.get("vulns", [])
            results["hostnames"] = data.get("hostnames", [])

            for service in data.get("data", [])[:15]:
                results["services"].append({
                    "port": service.get("port"),
                    "transport": service.get("transport", "tcp"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "banner": service.get("data", "")[:100],
                })

            if progress_callback:
                progress_callback(f"Shodan: {len(results['ports'])} ports, {len(results['vulns'])} vulns")

        elif resp.status_code == 404:
            results["errors"].append("Host not found in Shodan database (not yet scanned)")
        elif resp.status_code == 401:
            results["errors"].append("Invalid Shodan API key")
        elif resp.status_code == 403:
            # Free plan doesn't have host lookup — try DNS resolve endpoint
            if progress_callback:
                progress_callback("Host lookup requires paid plan, trying DNS resolve...")
            _shodan_dns_fallback(target, ip, api_key, results, progress_callback)
        else:
            results["errors"].append(f"Shodan returned status {resp.status_code}")

    except Exception as e:
        results["errors"].append(f"Shodan error: {e}")

    return results


def _shodan_dns_fallback(target: str, ip: str, api_key: str, results: Dict, progress_callback=None):
    """Fallback for free Shodan plan — use DNS resolve and search endpoints."""
    try:
        # Try the free /dns/resolve endpoint
        domain = target if not _is_ip(target) else None
        if domain:
            url = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={api_key}"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                resolved_ip = data.get(domain)
                if resolved_ip:
                    results["ip"] = resolved_ip
                    if progress_callback:
                        progress_callback(f"DNS resolved: {domain} → {resolved_ip}")

        # Try the free /shodan/host/count endpoint
        url = f"https://api.shodan.io/shodan/host/count?key={api_key}&query=ip:{ip}"
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            results["total_results"] = data.get("total", 0)
            if progress_callback:
                progress_callback(f"Shodan has {data.get('total', 0)} results for this IP")

        # Try the free API info to show what's available
        url = f"https://api.shodan.io/api-info?key={api_key}"
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code == 200:
            info = resp.json()
            plan = info.get("plan", "free")
            results["errors"].append(
                f"Your Shodan plan ({plan}) doesn't include host lookup.\n"
                "Upgrade at https://account.shodan.io/billing for full results.\n"
                f"Query credits remaining: {info.get('query_credits', 0)}"
            )
        else:
            results["errors"].append(
                "Shodan host lookup requires a paid API plan.\n"
                "Free plan only supports search queries, not direct host lookups."
            )

    except Exception as e:
        results["errors"].append(f"Shodan fallback error: {e}")

    except Exception as e:
        results["errors"].append(f"Shodan error: {e}")

    return results


# ---------------------------------------------------------------------------
# URLScan.io (free alternative to URLVoid)
# ---------------------------------------------------------------------------

def urlvoid_check(target: str, progress_callback=None) -> Dict:
    """Check domain reputation using URLScan.io (free, no key needed)."""
    results = {"target": target, "verdicts": [], "score": 0,
               "categories": [], "ips": [], "errors": []}

    if progress_callback:
        progress_callback(f"Checking reputation for {target}...")

    try:
        # Search URLScan.io for existing scans of this domain
        url = f"https://urlscan.io/api/v1/search/?q=domain:{target}&size=5"
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()
            scan_results = data.get("results", [])
            results["total_scans"] = data.get("total", 0)

            for scan in scan_results:
                task = scan.get("task", {})
                page = scan.get("page", {})
                verdicts = scan.get("verdicts", {})

                overall = verdicts.get("overall", {})
                if overall.get("malicious"):
                    results["verdicts"].append("malicious")
                    results["score"] += 1

                results["ips"].append(page.get("ip", ""))
                results["categories"].append(page.get("server", ""))

            # Deduplicate
            results["ips"] = list(set(filter(None, results["ips"])))
            results["categories"] = list(set(filter(None, results["categories"])))

            if progress_callback:
                progress_callback(f"URLScan: {results['total_scans']} scans found, score={results['score']}")

        else:
            results["errors"].append(f"URLScan.io returned status {resp.status_code}")

    except Exception as e:
        results["errors"].append(f"URLScan error: {e}")

    return results


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

def alienvault_otx(target: str, progress_callback=None) -> Dict:
    """Query AlienVault OTX for threat indicators (free, no key required for basic)."""
    results = {"target": target, "pulses": [], "indicators": [],
               "geo": None, "errors": []}

    if progress_callback:
        progress_callback(f"Querying AlienVault OTX for {target}...")

    try:
        if _is_ip(target):
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/general"
        else:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"

        headers = {**HEADERS}
        api_key = _get_api_key("alienvault_otx")
        if api_key:
            headers["X-OTX-API-KEY"] = api_key

        resp = requests.get(url, headers=headers, timeout=TIMEOUT)

        if resp.status_code == 200:
            data = resp.json()

            # Pulse count (threat reports mentioning this IOC)
            pulse_info = data.get("pulse_info", {})
            results["pulse_count"] = pulse_info.get("count", 0)

            for pulse in pulse_info.get("pulses", [])[:10]:
                results["pulses"].append({
                    "name": pulse.get("name", ""),
                    "description": pulse.get("description", "")[:100],
                    "created": pulse.get("created", ""),
                    "tags": pulse.get("tags", [])[:5],
                })

            # General info
            results["reputation"] = data.get("reputation", 0)
            results["type"] = data.get("type", "")
            results["asn"] = data.get("asn", "")

            if progress_callback:
                progress_callback(f"OTX: {results['pulse_count']} threat pulses found")

        elif resp.status_code == 404:
            results["errors"].append("Target not found in OTX database")
        else:
            results["errors"].append(f"OTX returned status {resp.status_code}")

    except Exception as e:
        results["errors"].append(f"OTX error: {e}")

    return results


# ---------------------------------------------------------------------------
# ThreatFox (abuse.ch — free, no key, replaces defunct ThreatCrowd)
# ---------------------------------------------------------------------------

def threatfox_lookup(target: str, progress_callback=None) -> Dict:
    """Query ThreatFox for IOC threat data (requires free API key from abuse.ch)."""
    results = {"target": target, "iocs": [], "malware": [],
               "tags": [], "errors": []}

    if progress_callback:
        progress_callback(f"Querying ThreatFox for {target}...")

    api_key = _get_api_key("threatfox")

    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        
        headers = {"Content-Type": "application/json", **HEADERS}
        if api_key:
            headers["Auth-Key"] = api_key

        # Try searching as IOC first
        data = {"query": "search_ioc", "search_term": target}
        resp = requests.post(url, json=data, timeout=TIMEOUT, headers=headers)

        if resp.status_code == 200:
            result = resp.json()

            if result.get("query_status") == "ok" and result.get("data"):
                iocs = result["data"]
                results["total"] = len(iocs)

                for ioc in iocs[:15]:
                    results["iocs"].append({
                        "ioc": ioc.get("ioc", ""),
                        "threat_type": ioc.get("threat_type", ""),
                        "malware": ioc.get("malware_printable", ""),
                        "confidence": ioc.get("confidence_level", 0),
                        "first_seen": ioc.get("first_seen", ""),
                        "tags": ioc.get("tags", []),
                    })
                    if ioc.get("malware_printable"):
                        results["malware"].append(ioc["malware_printable"])
                    results["tags"].extend(ioc.get("tags", []) or [])

                results["malware"] = list(set(results["malware"]))
                results["tags"] = list(set(results["tags"]))[:20]

                if progress_callback:
                    progress_callback(f"ThreatFox: {len(iocs)} IOCs found")
            else:
                # No results — not necessarily an error, target may be clean
                results["total"] = 0
                if progress_callback:
                    progress_callback("ThreatFox: No IOCs found (target appears clean)")
        elif resp.status_code == 401:
            results["errors"].append(
                "ThreatFox API key required.\n"
                "Get a free key at https://threatfox.abuse.ch/api/\n"
                "Set 'threatfox' in Tools → Global Settings → API Keys"
            )
        else:
            results["errors"].append(f"ThreatFox returned status {resp.status_code}")

    except Exception as e:
        results["errors"].append(f"ThreatFox error: {e}")

    return results


# ---------------------------------------------------------------------------
# Malware Bazaar (free, no key)
# ---------------------------------------------------------------------------

def malware_bazaar(target: str, progress_callback=None) -> Dict:
    """Query Malware Bazaar for malware samples associated with a tag/domain."""
    results = {"target": target, "samples": [], "total": 0, "errors": []}

    if progress_callback:
        progress_callback(f"Querying Malware Bazaar for {target}...")

    try:
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_taginfo", "tag": target, "limit": 20}
        resp = requests.post(url, data=data, headers=HEADERS, timeout=TIMEOUT)

        if resp.status_code == 200:
            result = resp.json()
            if result.get("query_status") == "ok":
                samples = result.get("data", [])
                results["total"] = len(samples)

                for sample in samples[:15]:
                    results["samples"].append({
                        "sha256": sample.get("sha256_hash", ""),
                        "filename": sample.get("file_name", ""),
                        "file_type": sample.get("file_type", ""),
                        "signature": sample.get("signature", ""),
                        "first_seen": sample.get("first_seen", ""),
                        "tags": sample.get("tags", []),
                    })

                if progress_callback:
                    progress_callback(f"Malware Bazaar: {results['total']} samples found")
            else:
                # Try as hash
                data2 = {"query": "get_info", "hash": target}
                resp2 = requests.post(url, data=data2, headers=HEADERS, timeout=TIMEOUT)
                if resp2.status_code == 200:
                    result2 = resp2.json()
                    if result2.get("query_status") == "ok" and result2.get("data"):
                        sample = result2["data"][0]
                        results["samples"].append({
                            "sha256": sample.get("sha256_hash", ""),
                            "filename": sample.get("file_name", ""),
                            "file_type": sample.get("file_type", ""),
                            "signature": sample.get("signature", ""),
                            "first_seen": sample.get("first_seen", ""),
                            "tags": sample.get("tags", []),
                        })
                        results["total"] = 1
                else:
                    results["errors"].append("No results found in Malware Bazaar")

    except Exception as e:
        results["errors"].append(f"Malware Bazaar error: {e}")

    return results


# ---------------------------------------------------------------------------
# Full Threat Intel (runs all modules)
# ---------------------------------------------------------------------------

def full_threat_intel(target: str, progress_callback=None) -> Dict:
    """Run all threat intelligence modules."""
    results = {"target": target}

    modules = [
        ("virustotal", "VirusTotal Scan", virustotal_scan),
        ("shodan", "Shodan Lookup", shodan_lookup),
        ("urlscan", "URLScan Reputation", urlvoid_check),
        ("otx", "AlienVault OTX", alienvault_otx),
        ("threatfox", "ThreatFox", threatfox_lookup),
        ("malware_bazaar", "Malware Bazaar", malware_bazaar),
    ]

    for i, (key, name, func) in enumerate(modules, 1):
        if progress_callback:
            progress_callback(f"[PHASE {i}/{len(modules)}] {name}...")
        try:
            results[key] = func(target, progress_callback)
        except Exception as e:
            results[key] = {"errors": [str(e)]}

    return results
