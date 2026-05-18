# app/core/breach_intel_engine.py
"""
Comprehensive Breach Intelligence Engine
Multi-source breach analysis with phased execution:
  Phase 1: Have I Been Pwned check (real API)
  Phase 2: DeHashed database search (real API)
  Phase 3: Local breach database query
  Phase 4: Dark web monitoring (simulated — requires Tor/specialized access)
  Phase 5: Document exposure analysis (Google dorking patterns)
"""
import time
import hashlib
import re
import requests
from typing import Dict, List, Optional
from PyQt6.QtCore import QThreadPool
from app.core.base_worker import BaseWorker
from app.core.html_utils import h
from app.core.breach_database import breach_db
from app.core.logger import logger

# Rate limit tracking for HIBP
_last_hibp_request = 0.0


def _get_api_key(key_name: str) -> str:
    """Retrieve an API key from global settings"""
    try:
        from shared.configuration.global_settings import global_settings
        return global_settings.get(f"api_keys.{key_name}", "") or ""
    except ImportError:
        return ""


class BreachIntelWorker(BaseWorker):
    """Worker for comprehensive breach intelligence gathering"""

    HIBP_BASE = "https://haveibeenpwned.com/api/v3"
    HIBP_USER_AGENT = "Huginn-BreachIntel/1.0"
    HIBP_RATE_LIMIT = 1.6  # seconds between requests (API requires 1500ms+)

    DEHASHED_BASE = "https://api.dehashed.com/search"

    def __init__(self, target: str, phases: Optional[List[str]] = None):
        super().__init__()
        self.target = target.strip()
        self.phases = phases or ["hibp", "dehashed", "local_db", "dark_web", "doc_exposure"]
        self.results: Dict = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.HIBP_USER_AGENT})

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------
    def run(self):
        try:
            self._emit_header()

            phase_map = {
                "hibp": (1, "Have I Been Pwned check", self._phase_hibp),
                "dehashed": (2, "DeHashed database search", self._phase_dehashed),
                "local_db": (3, "Local breach database query", self._phase_local_db),
                "dark_web": (4, "Dark web monitoring", self._phase_dark_web),
                "doc_exposure": (5, "Document exposure analysis", self._phase_doc_exposure),
            }

            total = len(self.phases)
            for idx, phase_key in enumerate(self.phases):
                if not self.is_running:
                    self._emit_warning("Analysis cancelled by user")
                    break

                if phase_key not in phase_map:
                    continue

                num, label, method = phase_map[phase_key]
                self._emit_phase_start(num, label)
                phase_results = method()
                self.results[phase_key] = phase_results
                self._emit_phase_results(phase_key, phase_results)

                progress = int(((idx + 1) / total) * 100)
                self.signals.progress.emit(progress)

            self._emit_summary()
            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Breach intel error: {e}")
            self.signals.error.emit(
                f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>"
            )
            self.signals.finished.emit()

    # ------------------------------------------------------------------
    # Phase 1: Have I Been Pwned (real API)
    # ------------------------------------------------------------------
    def _phase_hibp(self) -> Dict:
        """Check Have I Been Pwned API v3"""
        results = {"breaches": [], "pastes": [], "error": None}

        api_key = _get_api_key("hibp")
        if not api_key:
            results["error"] = "No HIBP API key configured (Settings → API Keys → hibp)"
            return results

        if not self._is_email(self.target):
            results["error"] = "HIBP requires a valid email address"
            return results

        headers = {
            "hibp-api-key": api_key,
            "User-Agent": self.HIBP_USER_AGENT,
        }

        # --- Breached accounts ---
        self._hibp_rate_limit()
        try:
            url = f"{self.HIBP_BASE}/breachedaccount/{requests.utils.quote(self.target)}"
            params = {"truncateResponse": "false"}
            resp = self.session.get(url, headers=headers, params=params, timeout=15)

            if resp.status_code == 200:
                for breach in resp.json():
                    results["breaches"].append({
                        "name": breach.get("Name", "Unknown"),
                        "domain": breach.get("Domain", ""),
                        "breach_date": breach.get("BreachDate", ""),
                        "added_date": breach.get("AddedDate", ""),
                        "pwn_count": breach.get("PwnCount", 0),
                        "data_classes": breach.get("DataClasses", []),
                        "is_verified": breach.get("IsVerified", False),
                        "is_sensitive": breach.get("IsSensitive", False),
                        "description": breach.get("Description", ""),
                    })
            elif resp.status_code == 404:
                pass  # Not found — no breaches (good news)
            elif resp.status_code == 401:
                results["error"] = "HIBP API key is invalid or expired"
            elif resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After", "2")
                results["error"] = f"HIBP rate limited — retry after {retry_after}s"
            else:
                results["error"] = f"HIBP returned HTTP {resp.status_code}"

        except requests.exceptions.Timeout:
            results["error"] = "HIBP request timed out"
        except requests.exceptions.ConnectionError:
            results["error"] = "Cannot reach HIBP API — check network connection"
        except Exception as e:
            results["error"] = f"HIBP error: {str(e)}"

        if results["error"]:
            return results

        # --- Paste accounts ---
        self._hibp_rate_limit()
        try:
            url = f"{self.HIBP_BASE}/pasteaccount/{requests.utils.quote(self.target)}"
            resp = self.session.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                for paste in resp.json():
                    results["pastes"].append({
                        "source": paste.get("Source", "Unknown"),
                        "id": paste.get("Id", ""),
                        "title": paste.get("Title", ""),
                        "date": paste.get("Date", ""),
                        "email_count": paste.get("EmailCount", 0),
                    })
            elif resp.status_code == 404:
                pass  # Not found in any pastes
            # Non-critical — don't overwrite breach results with paste errors

        except Exception as e:
            logger.warning(f"HIBP paste lookup failed: {e}")

        return results

    def _hibp_rate_limit(self):
        """Enforce HIBP rate limiting (1500ms between requests)"""
        global _last_hibp_request
        elapsed = time.time() - _last_hibp_request
        if elapsed < self.HIBP_RATE_LIMIT:
            time.sleep(self.HIBP_RATE_LIMIT - elapsed)
        _last_hibp_request = time.time()

    # ------------------------------------------------------------------
    # Phase 2: DeHashed (real API)
    # ------------------------------------------------------------------
    def _phase_dehashed(self) -> Dict:
        """Search DeHashed commercial breach database via API"""
        results = {"entries": [], "total_results": 0, "error": None}

        api_key = _get_api_key("dehashed")
        dehashed_email = _get_api_key("dehashed_email")

        if not api_key or not dehashed_email:
            results["error"] = (
                "No DeHashed API credentials configured "
                "(Settings → API Keys → dehashed + dehashed_email)"
            )
            return results

        try:
            # DeHashed uses HTTP Basic Auth: email:api_key
            if self._is_email(self.target):
                query = f"email:{self.target}"
            else:
                query = f"domain:{self.target}"

            resp = self.session.get(
                self.DEHASHED_BASE,
                params={"query": query, "size": 50},
                auth=(dehashed_email, api_key),
                headers={"Accept": "application/json"},
                timeout=20,
            )

            if resp.status_code == 200:
                data = resp.json()
                results["total_results"] = data.get("total", 0)

                for entry in data.get("entries", []) or []:
                    results["entries"].append({
                        "id": entry.get("id", ""),
                        "email": entry.get("email", ""),
                        "username": entry.get("username", ""),
                        "password": entry.get("password", ""),
                        "hashed_password": entry.get("hashed_password", ""),
                        "name": entry.get("name", ""),
                        "database_name": entry.get("database_name", ""),
                        "ip_address": entry.get("ip_address", ""),
                        "phone": entry.get("phone", ""),
                    })
            elif resp.status_code == 401:
                results["error"] = "DeHashed credentials are invalid"
            elif resp.status_code == 402:
                results["error"] = "DeHashed subscription expired or credits exhausted"
            elif resp.status_code == 429:
                results["error"] = "DeHashed rate limited — try again later"
            else:
                results["error"] = f"DeHashed returned HTTP {resp.status_code}"

        except requests.exceptions.Timeout:
            results["error"] = "DeHashed request timed out"
        except requests.exceptions.ConnectionError:
            results["error"] = "Cannot reach DeHashed API — check network connection"
        except Exception as e:
            results["error"] = f"DeHashed error: {str(e)}"

        return results

    # ------------------------------------------------------------------
    # Phase 3: Local Breach Database
    # ------------------------------------------------------------------
    def _phase_local_db(self) -> Dict:
        """Query local SQLite breach database"""
        results = {"entries": [], "error": None}

        try:
            if self._is_email(self.target):
                entries = breach_db.search_email(self.target)
            else:
                entries = breach_db.search_domain(self.target)

            results["entries"] = entries

        except Exception as e:
            results["error"] = str(e)

        return results

    # ------------------------------------------------------------------
    # Phase 4: Dark Web Monitoring
    # ------------------------------------------------------------------
    def _phase_dark_web(self) -> Dict:
        """Dark web monitoring — requires specialized access (Tor, paid feeds).
        
        This phase checks for dark web intelligence feeds. Without a configured
        dark web monitoring API (e.g., Flare, SpyCloud, DarkOwl), it reports
        that no feed is available.
        """
        results = {"mentions": [], "marketplace_listings": [], "error": None}

        dark_web_key = _get_api_key("dark_web_monitor")

        if not dark_web_key:
            results["error"] = (
                "No dark web monitoring API configured "
                "(Settings → API Keys → dark_web_monitor). "
                "Supported: SpyCloud, DarkOwl, Flare.io"
            )
            return results

        # If a key is configured, attempt the API call
        # This is a placeholder for whichever dark web intel provider is used
        try:
            # SpyCloud-style endpoint (most common for breach intel)
            resp = self.session.get(
                "https://api.spycloud.io/enterprise-v2/breach/data/emails",
                params={"query": self.target, "severity": "2,5,20,25"},
                headers={
                    "Authorization": f"Bearer {dark_web_key}",
                    "Accept": "application/json",
                },
                timeout=20,
            )

            if resp.status_code == 200:
                data = resp.json()
                for hit in data.get("results", []):
                    results["mentions"].append({
                        "source": hit.get("source_id", "Dark Web Feed"),
                        "date": hit.get("spycloud_publish_date", ""),
                        "context": hit.get("target_domain", ""),
                        "confidence": "HIGH" if hit.get("severity", 0) >= 20 else "MEDIUM",
                        "threat_level": self._severity_to_threat(hit.get("severity", 0)),
                    })
            elif resp.status_code == 401:
                results["error"] = "Dark web monitor API key is invalid"
            elif resp.status_code == 403:
                results["error"] = "Dark web monitor access denied — check subscription"
            else:
                results["error"] = f"Dark web monitor returned HTTP {resp.status_code}"

        except requests.exceptions.ConnectionError:
            results["error"] = "Cannot reach dark web monitoring API"
        except Exception as e:
            results["error"] = f"Dark web monitor error: {str(e)}"

        return results

    def _severity_to_threat(self, severity: int) -> str:
        if severity >= 25:
            return "CRITICAL"
        elif severity >= 20:
            return "HIGH"
        elif severity >= 5:
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Phase 5: Document Exposure Analysis
    # ------------------------------------------------------------------
    def _phase_doc_exposure(self) -> Dict:
        """Analyze document exposure via search engine queries.
        
        Uses Google Custom Search API if configured, otherwise generates
        the dork queries for manual use and reports no API available.
        """
        results = {"exposed_documents": [], "google_dorks_used": [], "error": None}

        domain = self._extract_domain(self.target)

        # Build dork queries
        dorks = [
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:xlsx',
            f'site:{domain} filetype:docx confidential',
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:env',
            f'site:{domain} filetype:log password',
            f'"{self.target}" filetype:csv',
            f'inurl:"{domain}" ext:bak',
            f'site:{domain} filetype:key',
            f'site:{domain} intitle:"index of" password',
        ]
        results["google_dorks_used"] = dorks

        # Check for Google Custom Search API
        google_cse_key = _get_api_key("google_cse")
        google_cse_cx = _get_api_key("google_cse_cx")

        if not google_cse_key or not google_cse_cx:
            results["error"] = (
                "No Google Custom Search API configured "
                "(Settings → API Keys → google_cse + google_cse_cx). "
                "Dork queries generated for manual use."
            )
            return results

        # Execute searches via Google Custom Search JSON API
        try:
            for dork in dorks[:5]:  # Limit to 5 queries to conserve API quota
                if not self.is_running:
                    break

                resp = self.session.get(
                    "https://www.googleapis.com/customsearch/v1",
                    params={
                        "key": google_cse_key,
                        "cx": google_cse_cx,
                        "q": dork,
                        "num": 5,
                    },
                    timeout=10,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("items", []):
                        link = item.get("link", "")
                        title = item.get("title", "")
                        # Determine file type from URL
                        file_ext = self._extract_extension(link)
                        risk = self._assess_doc_risk(link, title)

                        results["exposed_documents"].append({
                            "url": link,
                            "type": file_ext.upper() if file_ext else "UNKNOWN",
                            "title": title,
                            "risk": risk,
                            "dork_used": dork,
                        })
                elif resp.status_code == 429:
                    results["error"] = "Google CSE quota exceeded"
                    break
                elif resp.status_code == 403:
                    results["error"] = "Google CSE API key invalid or restricted"
                    break

                time.sleep(0.3)  # Be polite to the API

        except requests.exceptions.ConnectionError:
            results["error"] = "Cannot reach Google Custom Search API"
        except Exception as e:
            results["error"] = f"Document exposure error: {str(e)}"

        return results

    def _extract_extension(self, url: str) -> str:
        """Extract file extension from URL"""
        match = re.search(r'\.([a-zA-Z0-9]{2,5})(?:\?|#|$)', url)
        return match.group(1) if match else ""

    def _assess_doc_risk(self, url: str, title: str) -> str:
        """Assess risk level of an exposed document"""
        critical_indicators = [".env", ".key", ".pem", "password", "credential", "secret", ".sql"]
        high_indicators = ["confidential", "internal", "private", "backup", ".bak"]

        combined = (url + " " + title).lower()

        if any(ind in combined for ind in critical_indicators):
            return "CRITICAL"
        elif any(ind in combined for ind in high_indicators):
            return "HIGH"
        elif any(ext in combined for ext in [".pdf", ".docx", ".xlsx"]):
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Output formatting
    # ------------------------------------------------------------------
    def _emit_header(self):
        self.signals.output.emit(
            "<p style='color: #64C8FF; font-size: 14px; font-weight: bold;'>"
            f"[COMPREHENSIVE BREACH INTEL] Multi-source analysis for: {h(self.target)}"
            "</p><br>"
        )
        self.signals.output.emit(
            "<p style='color: #DCDCDC;'>"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "</p>"
        )

    def _emit_phase_start(self, num: int, label: str):
        self.signals.output.emit(
            f"<p style='color: #FFD93D; font-weight: bold;'>"
            f"\u25b6 Phase {num}: {h(label)}...</p>"
        )

    def _emit_phase_results(self, phase_key: str, results: Dict):
        """Format and emit results for each phase"""
        if results.get("error"):
            self.signals.output.emit(
                f"<p style='color: #FFA500;'>  \u26a0 {h(results['error'])}</p><br>"
            )
            return

        if phase_key == "hibp":
            self._format_hibp(results)
        elif phase_key == "dehashed":
            self._format_dehashed(results)
        elif phase_key == "local_db":
            self._format_local_db(results)
        elif phase_key == "dark_web":
            self._format_dark_web(results)
        elif phase_key == "doc_exposure":
            self._format_doc_exposure(results)

        self.signals.output.emit(
            "<p style='color: #DCDCDC;'>"
            "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
            "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
            "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
            "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
            "\u2500</p>"
        )

    def _format_hibp(self, results: Dict):
        breaches = results.get("breaches", [])
        pastes = results.get("pastes", [])

        if breaches:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B; font-weight: bold;'>"
                f"  \u2717 FOUND IN {len(breaches)} BREACHES:</p>"
            )
            for b in breaches:
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>"
                    f"    \u2022 <span style='color: #FF6B6B;'>{h(b['name'])}</span> "
                    f"({h(b['domain'])}) \u2014 {h(b['breach_date'])}</p>"
                )
                data_classes = b.get("data_classes", [])
                if data_classes:
                    self.signals.output.emit(
                        f"<p style='color: #888;'>"
                        f"      Data: {h(', '.join(data_classes))} | "
                        f"Records: {b['pwn_count']:,}</p>"
                    )
        else:
            self.signals.output.emit(
                "<p style='color: #00FF41;'>  \u2713 Not found in any known breaches</p>"
            )

        if pastes:
            self.signals.output.emit(
                f"<p style='color: #FFA500;'>  \u26a0 Found in {len(pastes)} paste(s):</p>"
            )
            for p in pastes:
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>"
                    f"    \u2022 {h(p['source'])} ({h(p['id'])}) \u2014 {h(p['date'])} "
                    f"({p['email_count']:,} emails)</p>"
                )

    def _format_dehashed(self, results: Dict):
        entries = results.get("entries", [])
        total = results.get("total_results", 0)

        if entries:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B; font-weight: bold;'>"
                f"  \u2717 {total} RECORDS FOUND in commercial breach databases:</p>"
            )
            for entry in entries[:10]:  # Cap display at 10
                db_name = entry.get("database_name", "Unknown")
                hashed_pw = entry.get("hashed_password", "")
                plaintext_pw = entry.get("password", "")

                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>"
                    f"    \u2022 <span style='color: #FFA500;'>{h(db_name)}</span></p>"
                )
                if entry.get("email"):
                    self.signals.output.emit(
                        f"<p style='color: #888;'>"
                        f"      Email: {h(entry['email'])}</p>"
                    )
                if entry.get("username"):
                    self.signals.output.emit(
                        f"<p style='color: #888;'>"
                        f"      Username: {h(entry['username'])}</p>"
                    )
                if hashed_pw:
                    hash_display = hashed_pw[:24] + "..." if len(hashed_pw) > 24 else hashed_pw
                    self.signals.output.emit(
                        f"<p style='color: #888;'>"
                        f"      Hash: {h(hash_display)}</p>"
                    )
                if plaintext_pw:
                    # Partially redact plaintext passwords in output
                    redacted = plaintext_pw[0] + "*" * (len(plaintext_pw) - 2) + plaintext_pw[-1] if len(plaintext_pw) > 2 else "**"
                    self.signals.output.emit(
                        f"<p style='color: #FF4500;'>"
                        f"      Password: {h(redacted)} (PLAINTEXT EXPOSED)</p>"
                    )

            if total > 10:
                self.signals.output.emit(
                    f"<p style='color: #888;'>    ... and {total - 10} more results</p>"
                )
        else:
            self.signals.output.emit(
                "<p style='color: #00FF41;'>  \u2713 No results in DeHashed</p>"
            )

    def _format_local_db(self, results: Dict):
        entries = results.get("entries", [])

        if entries:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B; font-weight: bold;'>"
                f"  \u2717 {len(entries)} RECORDS in local breach database:</p>"
            )
            for entry in entries:
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>"
                    f"    \u2022 <span style='color: #FFA500;'>"
                    f"{h(entry.get('breach_name', 'Unknown'))}</span> "
                    f"\u2014 {h(entry.get('breach_date', 'N/A'))}</p>"
                )
                pw_hash = entry.get("password_hash", "")
                if pw_hash:
                    self.signals.output.emit(
                        f"<p style='color: #888;'>      Hash: {h(pw_hash)}</p>"
                    )
        else:
            self.signals.output.emit(
                "<p style='color: #00FF41;'>  \u2713 No matches in local breach database</p>"
            )

    def _format_dark_web(self, results: Dict):
        mentions = results.get("mentions", [])
        listings = results.get("marketplace_listings", [])

        if mentions:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B; font-weight: bold;'>"
                f"  \u2717 {len(mentions)} DARK WEB MENTIONS detected:</p>"
            )
            for m in mentions:
                threat_color = {
                    "CRITICAL": "#FF4500",
                    "HIGH": "#FF6B6B",
                    "MEDIUM": "#FFA500",
                    "LOW": "#FFD93D",
                }.get(m.get("threat_level", ""), "#DCDCDC")

                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>"
                    f"    \u2022 <span style='color: {threat_color};'>"
                    f"[{h(m.get('threat_level', 'N/A'))}]</span> "
                    f"{h(m.get('source', ''))} \u2014 {h(m.get('date', ''))}</p>"
                )
                self.signals.output.emit(
                    f"<p style='color: #888;'>"
                    f"      Context: {h(m.get('context', ''))} "
                    f"(Confidence: {h(m.get('confidence', 'N/A'))})</p>"
                )
        else:
            self.signals.output.emit(
                "<p style='color: #00FF41;'>  \u2713 No dark web mentions found</p>"
            )

        if listings:
            self.signals.output.emit(
                f"<p style='color: #FF4500; font-weight: bold;'>"
                f"  \u26a0 {len(listings)} MARKETPLACE LISTING(S):</p>"
            )
            for listing in listings:
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>"
                    f"    \u2022 {h(listing.get('marketplace', ''))} \u2014 "
                    f"${listing.get('price_usd', 0):.2f} "
                    f"({h(listing.get('listing_type', ''))})</p>"
                )
                includes = listing.get("includes", [])
                if includes:
                    self.signals.output.emit(
                        f"<p style='color: #888;'>"
                        f"      Includes: {h(', '.join(includes))}</p>"
                    )

    def _format_doc_exposure(self, results: Dict):
        docs = results.get("exposed_documents", [])
        dorks = results.get("google_dorks_used", [])

        if docs:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B; font-weight: bold;'>"
                f"  \u2717 {len(docs)} EXPOSED DOCUMENTS found:</p>"
            )
            for doc in docs:
                risk_color = "#FF4500" if doc["risk"] == "CRITICAL" else "#FF6B6B" if doc["risk"] == "HIGH" else "#FFA500"
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>"
                    f"    \u2022 <span style='color: {risk_color};'>[{h(doc['risk'])}]</span> "
                    f"{h(doc['title'])} ({h(doc['type'])})</p>"
                )
                self.signals.output.emit(
                    f"<p style='color: #888;'>"
                    f"      URL: {h(doc['url'])}</p>"
                )
        else:
            self.signals.output.emit(
                "<p style='color: #00FF41;'>  \u2713 No exposed documents detected</p>"
            )

        if dorks:
            self.signals.output.emit(
                f"<p style='color: #64C8FF;'>  Dorks generated ({len(dorks)}):</p>"
            )
            for dork in dorks[:4]:
                self.signals.output.emit(
                    f"<p style='color: #555;'>    \u25e6 {h(dork)}</p>"
                )
            if len(dorks) > 4:
                self.signals.output.emit(
                    f"<p style='color: #555;'>    ... and {len(dorks) - 4} more</p>"
                )

    def _emit_summary(self):
        """Emit final summary with risk assessment"""
        self.signals.output.emit(
            "<p style='color: #DCDCDC;'>"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
            "</p>"
        )

        # Calculate risk score
        risk_score = self._calculate_risk_score()
        risk_label, risk_color = self._risk_level(risk_score)

        self.signals.output.emit(
            f"<p style='color: {risk_color}; font-size: 14px; font-weight: bold;'>"
            f"[RISK ASSESSMENT] Score: {risk_score}/100 \u2014 {h(risk_label)}</p>"
        )

        # Recommendations
        recommendations = self._generate_recommendations()
        if recommendations:
            self.signals.output.emit(
                "<p style='color: #64C8FF; font-weight: bold;'>Recommendations:</p>"
            )
            for rec in recommendations:
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>  \u2192 {h(rec)}</p>"
                )

        self.signals.output.emit(
            "<p style='color: #00FF41; font-weight: bold;'><br>"
            "\u2713 Comprehensive breach intelligence complete</p>"
        )

    def _emit_warning(self, msg: str):
        self.signals.output.emit(
            f"<p style='color: #FFA500;'>\u26a0 {h(msg)}</p>"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _is_email(self, target: str) -> bool:
        return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target))

    def _extract_domain(self, target: str) -> str:
        if self._is_email(target):
            return target.split("@")[1]
        return target

    def _calculate_risk_score(self) -> int:
        """Calculate overall risk score 0-100 based on actual findings"""
        score = 0

        hibp = self.results.get("hibp", {})
        if not hibp.get("error"):
            breaches = hibp.get("breaches", [])
            if breaches:
                score += min(len(breaches) * 10, 30)
                # Extra weight for recent breaches
                for b in breaches:
                    if b.get("breach_date", "") >= "2022":
                        score += 3
            if hibp.get("pastes"):
                score += min(len(hibp["pastes"]) * 5, 10)

        dehashed = self.results.get("dehashed", {})
        if not dehashed.get("error"):
            entries = dehashed.get("entries", [])
            if entries:
                score += min(len(entries) * 5, 20)
                # Extra weight for plaintext passwords
                plaintext_count = sum(1 for e in entries if e.get("password"))
                score += min(plaintext_count * 8, 15)

        local_db = self.results.get("local_db", {})
        if not local_db.get("error"):
            if local_db.get("entries"):
                score += min(len(local_db["entries"]) * 8, 15)

        dark_web = self.results.get("dark_web", {})
        if not dark_web.get("error"):
            mentions = dark_web.get("mentions", [])
            if mentions:
                score += min(len(mentions) * 7, 15)
            if dark_web.get("marketplace_listings"):
                score += 10

        doc_exposure = self.results.get("doc_exposure", {})
        if not doc_exposure.get("error"):
            docs = doc_exposure.get("exposed_documents", [])
            if docs:
                critical_docs = sum(1 for d in docs if d.get("risk") == "CRITICAL")
                score += min(critical_docs * 8 + len(docs) * 2, 15)

        return min(score, 100)

    def _risk_level(self, score: int) -> tuple:
        if score >= 80:
            return "CRITICAL", "#FF4500"
        elif score >= 60:
            return "HIGH", "#FF6B6B"
        elif score >= 40:
            return "MEDIUM", "#FFA500"
        elif score >= 20:
            return "LOW", "#FFD93D"
        else:
            return "MINIMAL", "#00FF41"

    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations based on findings"""
        recs = []

        hibp = self.results.get("hibp", {})
        if not hibp.get("error") and hibp.get("breaches"):
            recs.append("Immediate password reset on all breached services")
            recs.append("Enable MFA on all accounts associated with this email")

        dehashed = self.results.get("dehashed", {})
        if not dehashed.get("error") and dehashed.get("entries"):
            has_plaintext = any(e.get("password") for e in dehashed["entries"])
            if has_plaintext:
                recs.append("Plaintext passwords exposed — assume full credential compromise")
            else:
                recs.append("Hashed credentials found — assess hash strength and rotate")

        dark_web = self.results.get("dark_web", {})
        if not dark_web.get("error"):
            if dark_web.get("marketplace_listings"):
                recs.append("Active marketplace listings — consider identity monitoring service")
            if dark_web.get("mentions"):
                recs.append("Dark web exposure — rotate all credentials immediately")

        doc_exposure = self.results.get("doc_exposure", {})
        if not doc_exposure.get("error") and doc_exposure.get("exposed_documents"):
            recs.append("Request removal of indexed sensitive documents from search engines")
            recs.append("Audit web server directory listings and access controls")

        if not recs:
            recs.append("No immediate action required — continue periodic monitoring")

        return recs
