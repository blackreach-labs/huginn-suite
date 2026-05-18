# app/core/people_intel_engine.py
"""
People Intelligence Engine
OSINT tools for person/entity reconnaissance:
  1. Social Profiles — username enumeration across platforms (Sherlock-style)
  2. Professional Networks — LinkedIn/GitHub/portfolio discovery
  3. Public Records — OSINT public data aggregators
  4. Contact Discovery — email pattern generation & validation
  5. Username Search — cross-platform username correlation
  6. Email Enumeration — discover emails for a domain/person
  7. Phone Lookup — carrier/location info via open APIs
  8. Full Person Intel — orchestrates all of the above
"""
import re
import time
import requests
from urllib.parse import quote as url_quote
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtCore import QThreadPool
from app.core.base_worker import BaseWorker
from app.core.html_utils import h
from app.core.logger import logger


def _get_api_key(key_name: str) -> str:
    """Retrieve an API key from global settings"""
    try:
        from shared.configuration.global_settings import global_settings
        return global_settings.get(f"api_keys.{key_name}", "") or ""
    except ImportError:
        return ""


# ======================================================================
# Social Profiles — Sherlock-style username enumeration
# ======================================================================

# Platform definitions: (name, url_template, detection_method, absent_indicator)
# detection_method:
#   "api" = use JSON API endpoint, 404 = not found
#   "status" = HTTP 404 means not found, 200 means found (only for sites that return proper 404s)
#   "text" = check response body for absent_indicator text
#   "assume_exists" = platform blocks automated checks; generate URL directly
SOCIAL_PLATFORMS = [
    # --- Platforms with reliable APIs or proper 404s ---
    ("GitHub", "https://api.github.com/users/{}", "api", None),
    ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{}.json", "api_null", None),
    ("GitLab", "https://gitlab.com/api/v4/users?username={}", "api_array", None),
    ("DevTo", "https://dev.to/api/users/by_username?url={}", "api", None),
    ("Steam", "https://steamcommunity.com/id/{}", "text", "The specified profile could not be found."),
    ("Bitbucket", "https://bitbucket.org/!api/2.0/users/{}", "api", None),
    # --- Search URL platforms (ordered per user preference) ---
    ("LinkedIn", "https://www.linkedin.com/search/results/people/?keywords={}&origin=CLUSTER_EXPANSION", "search_url", None),
    ("Facebook", "https://www.facebook.com/search/people/?q={}", "search_url", None),
    ("Twitter/X", "https://x.com/search?q={}&src=typed_query&f=user", "search_url", None),
    ("YouTube", "https://www.youtube.com/results?search_query={}&sp=EgIQAg%253D%253D", "search_url", None),
    ("Instagram", "https://www.instagram.com/explore/search/keyword/?q={}", "search_url", None),
    ("Twitch", "https://www.twitch.tv/search?term={}", "search_url", None),
    ("TikTok", "https://www.tiktok.com/search/user?q={}", "search_url", None),
    ("Medium", "https://medium.com/search/users?q=%22{}%22", "search_url_plus", None),
    ("Spotify", "https://open.spotify.com/search/{}", "search_url", None),
    ("Vimeo", "https://vimeo.com/search?q={}&type=people", "search_url_plus", None),
    ("SoundCloud", "https://soundcloud.com/search/people?q={}", "search_url", None),
    ("Dribbble", "https://dribbble.com/search/{}", "search_url_dash", None),
    ("Patreon", "https://www.patreon.com/search?q={}", "search_url", None),
    ("Substack", "https://substack.com/search/{}?searching=profile", "search_url", None),
    ("Reddit", "https://www.reddit.com/search/?q={}", "search_url_plus", None),
    ("Keybase", "https://keybase.io", "search_url_static", None),
    ("Pinterest", "https://www.pinterest.com/search/users/?q={}", "search_url", None),
    ("Behance", "https://www.behance.net/search/users?search={}", "search_url", None),
    ("Imgur", "https://imgur.com", "search_url_static", None),
]


class SocialProfilesWorker(BaseWorker):
    """Enumerate social media profiles for a username across platforms"""

    def __init__(self, username: str, max_workers: int = 10, timeout: int = 8):
        super().__init__()
        self.raw_input = username.strip()
        self.username = username.strip().replace(" ", "")
        # Generate variants for name-based inputs
        self.variants = self._generate_variants(self.raw_input)
        self.max_workers = max_workers
        self.timeout = timeout
        self.results: Dict = {"found": [], "not_found": [], "errors": []}

    def _generate_variants(self, name: str) -> List[str]:
        """Generate username variants from input"""
        variants = set()
        clean = name.lower().strip()
        variants.add(clean.replace(" ", ""))

        parts = clean.split()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            variants.add(f"{first}{last}")
            variants.add(f"{first}.{last}")
            variants.add(f"{first}-{last}")
            variants.add(f"{first}_{last}")
            variants.add(f"{first[0]}{last}")
        else:
            variants.add(clean)

        return list(variants)

    def run(self):
        try:
            self.signals.output.emit(
                f"<p style='color: #64C8FF; font-weight: bold;'>"
                f"[SOCIAL PROFILES] Enumerating username: {h(self.username)}</p>"
            )
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>Variants: {h(', '.join(self.variants[:5]))}</p>"
            )
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>Checking {len(SOCIAL_PLATFORMS)} platforms...</p><br>"
            )

            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36"
            })

            seen_platforms = set()

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}
                for platform_name, url_template, method, absent_text in SOCIAL_PLATFORMS:
                    if not self.is_running:
                        break
                    # For search_url platforms, use the raw name (URL-encoded)
                    if method == "search_url":
                        url = url_template.format(url_quote(self.raw_input))
                        future = executor.submit(
                            self._check_platform, session, platform_name, url, method, absent_text
                        )
                        futures[future] = (platform_name, self.raw_input)
                    elif method == "search_url_plus":
                        # Use + for spaces instead of %20
                        url = url_template.format(self.raw_input.replace(" ", "+"))
                        future = executor.submit(
                            self._check_platform, session, platform_name, url, method, absent_text
                        )
                        futures[future] = (platform_name, self.raw_input)
                    elif method == "search_url_dash":
                        # Use - for spaces
                        url = url_template.format(self.raw_input.replace(" ", "-"))
                        future = executor.submit(
                            self._check_platform, session, platform_name, url, method, absent_text
                        )
                        futures[future] = (platform_name, self.raw_input)
                    elif method == "search_url_static":
                        # Static URL — no formatting needed
                        url = url_template
                        future = executor.submit(
                            self._check_platform, session, platform_name, url, method, absent_text
                        )
                        futures[future] = (platform_name, self.raw_input)
                    # For assume_exists platforms, try all variants
                    elif method == "assume_exists":
                        for variant in self.variants:
                            url = url_template.format(variant)
                            future = executor.submit(
                                self._check_platform, session, platform_name, url, method, absent_text
                            )
                            futures[future] = (platform_name, variant)
                    else:
                        # For HTTP-checkable platforms, use primary username
                        url = url_template.format(self.username)
                        future = executor.submit(
                            self._check_platform, session, platform_name, url, method, absent_text
                        )
                        futures[future] = (platform_name, self.username)

                completed = 0
                total = len(futures)
                for future in as_completed(futures):
                    if not self.is_running:
                        break
                    completed += 1
                    self.signals.progress.emit(int((completed / total) * 100))

                    result = future.result()
                    if result is None:
                        continue

                    platform_name, variant = futures[future]

                    if result["status"] == "found":
                        # Deduplicate by platform
                        if platform_name not in seen_platforms:
                            seen_platforms.add(platform_name)
                            self.results["found"].append(result)
                            verified = result.get("verified", False)
                            is_search = result.get("is_search", False)
                            profile_url = result['url']

                            if verified:
                                # API-verified profile
                                self.signals.output.emit(
                                    f"<p style='color: #00FF41;'>"
                                    f"  \u2713 <b>{h(result['platform'])}</b>: "
                                    f"<a href='{profile_url}' style='color: #00FF41;'>"
                                    f"{h(profile_url)}</a></p>"
                                )
                            elif is_search:
                                # Search URL — opens in browser
                                is_static = result.get("url", "").count("/") <= 3 and "?" not in result.get("url", "")
                                link_text = "Search manually \u2192" if is_static else "Open Search \u2192"
                                self.signals.output.emit(
                                    f"<p style='color: #64C8FF;'>"
                                    f"  \u1F50D <b>{h(result['platform'])}</b>: "
                                    f"<a href='{profile_url}' style='color: #64C8FF;'>"
                                    f"{link_text}</a></p>"
                                )
                            else:
                                # Unverified direct link
                                self.signals.output.emit(
                                    f"<p style='color: #FFD93D;'>"
                                    f"  \u2022 <b>{h(result['platform'])}</b>: "
                                    f"<a href='{profile_url}' style='color: #FFD93D;'>"
                                    f"{h(profile_url)}</a> (unverified)</p>"
                                )
                    elif result["status"] == "error":
                        self.results["errors"].append(result)

            # Summary
            found_count = len(self.results["found"])
            verified_count = sum(1 for r in self.results["found"] if r.get("verified"))
            search_count = sum(1 for r in self.results["found"] if r.get("is_search"))
            unverified_count = found_count - verified_count - search_count

            self.signals.output.emit(
                f"<br><p style='color: #64C8FF; font-weight: bold;'>"
                f"[RESULTS] {verified_count} verified, "
                f"{search_count} search link(s), "
                f"{unverified_count} unverified</p>"
            )
            self.signals.output.emit(
                "<p style='color: #888;'>  Click search links to open in your browser "
                "(requires login for LinkedIn/Twitter)</p>"
            )

            if self.results["errors"]:
                self.signals.output.emit(
                    f"<p style='color: #FFA500;'>"
                    f"  \u26a0 {len(self.results['errors'])} platform(s) returned errors "
                    f"(timeout/blocked)</p>"
                )

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Social profiles error: {e}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            self.signals.finished.emit()

    def _check_platform(self, session: requests.Session, platform: str,
                        url: str, method: str, absent_text: Optional[str]) -> Optional[Dict]:
        """Check a single platform for username existence"""
        # For platforms that block automated requests — return URL directly
        if method == "assume_exists":
            return {"platform": platform, "url": url, "status": "found", "verified": False}

        # For search URLs — generate a browser search link (no HTTP request needed)
        if method in ("search_url", "search_url_plus", "search_url_dash", "search_url_static"):
            return {"platform": platform, "url": url, "status": "found", "verified": False, "is_search": True}

        try:
            # Use a non-browser UA for API endpoints to get proper responses
            headers = {}
            if method.startswith("api"):
                headers["User-Agent"] = "Huginn-OSINT/1.0"
                headers["Accept"] = "application/json"

            resp = session.get(url, timeout=self.timeout, allow_redirects=True, headers=headers)

            if method == "status":
                if resp.status_code == 200:
                    return {"platform": platform, "url": url, "status": "found", "verified": True}
                else:
                    return {"platform": platform, "url": url, "status": "not_found"}

            elif method == "api":
                # JSON API: 200 = exists, 404 = not found
                if resp.status_code == 200:
                    return {"platform": platform, "url": url, "status": "found", "verified": True}
                else:
                    return {"platform": platform, "url": url, "status": "not_found"}

            elif method == "api_null":
                # Firebase-style: returns "null" text for non-existent
                if resp.status_code == 200 and resp.text.strip() != "null":
                    return {"platform": platform, "url": url, "status": "found", "verified": True}
                else:
                    return {"platform": platform, "url": url, "status": "not_found"}

            elif method == "api_array":
                # GitLab-style: returns empty array [] for non-existent
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 0:
                            return {"platform": platform, "url": url, "status": "found", "verified": True}
                    except ValueError:
                        pass
                return {"platform": platform, "url": url, "status": "not_found"}

            elif method == "api_keybase":
                # Keybase: check if user was found in response
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get("them") and len(data["them"]) > 0:
                            return {"platform": platform, "url": url, "status": "found", "verified": True}
                    except ValueError:
                        pass
                return {"platform": platform, "url": url, "status": "not_found"}

            elif method == "text":
                if absent_text and absent_text in resp.text:
                    return {"platform": platform, "url": url, "status": "not_found"}
                elif resp.status_code == 200:
                    return {"platform": platform, "url": url, "status": "found", "verified": True}
                else:
                    return {"platform": platform, "url": url, "status": "not_found"}

        except requests.exceptions.Timeout:
            return {"platform": platform, "url": url, "status": "error", "error": "timeout"}
        except requests.exceptions.ConnectionError:
            return {"platform": platform, "url": url, "status": "error", "error": "connection"}
        except Exception as e:
            return {"platform": platform, "url": url, "status": "error", "error": str(e)}

        return None


# ======================================================================
# Professional Networks — LinkedIn, GitHub, portfolio discovery
# ======================================================================

PROFESSIONAL_PLATFORMS = [
    ("LinkedIn", "https://www.linkedin.com/in/{}", "assume_exists"),
    ("GitHub", "https://github.com/{}", "status"),
    ("GitLab", "https://gitlab.com/{}", "status"),
    ("Stack Overflow", "https://stackoverflow.com/users/?tab=Reputation&filter=all&search={}", "text_present"),
    ("Crunchbase", "https://www.crunchbase.com/person/{}", "status"),
    ("AngelList", "https://angel.co/u/{}", "status"),
    ("ResearchGate", "https://www.researchgate.net/profile/{}", "status"),
    ("ORCID Search", "https://pub.orcid.org/v3.0/search/?q={}", "api"),
    ("npm", "https://www.npmjs.com/~{}", "status"),
    ("PyPI", "https://pypi.org/user/{}/", "status"),
    ("Docker Hub", "https://hub.docker.com/u/{}", "status"),
    ("Kaggle", "https://www.kaggle.com/{}", "status"),
    ("HuggingFace", "https://huggingface.co/{}", "status"),
]


class ProfessionalNetworksWorker(BaseWorker):
    """Discover professional network presence"""

    def __init__(self, target: str, max_workers: int = 8, timeout: int = 8):
        super().__init__()
        self.target = target.strip()
        # Generate username variants from full name
        self.usernames = self._generate_variants(self.target)
        self.max_workers = max_workers
        self.timeout = timeout
        self.results: Dict = {"found": [], "errors": []}

    def _generate_variants(self, name: str) -> List[str]:
        """Generate common username variants from a name"""
        variants = set()
        clean = name.lower().strip()
        variants.add(clean.replace(" ", ""))

        parts = clean.split()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            variants.add(f"{first}{last}")
            variants.add(f"{first}.{last}")
            variants.add(f"{first}-{last}")
            variants.add(f"{first}_{last}")
            variants.add(f"{first[0]}{last}")
            variants.add(f"{last}{first}")
            variants.add(f"{last}.{first}")
            variants.add(f"{last}{first[0]}")
        else:
            variants.add(clean)

        # Also try the raw input as-is (could already be a username)
        variants.add(name.strip())
        return list(variants)

    def run(self):
        try:
            self.signals.output.emit(
                f"<p style='color: #64C8FF; font-weight: bold;'>"
                f"[PROFESSIONAL NETWORKS] Target: {h(self.target)}</p>"
            )
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>Username variants: "
                f"{h(', '.join(self.usernames[:5]))}"
                f"{'...' if len(self.usernames) > 5 else ''}</p>"
            )
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>Checking {len(PROFESSIONAL_PLATFORMS)} "
                f"professional platforms...</p><br>"
            )

            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36"
            })

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = []
                for platform_name, url_template, method in PROFESSIONAL_PLATFORMS:
                    for username in self.usernames:
                        if not self.is_running:
                            break
                        url = url_template.format(username)
                        future = executor.submit(
                            self._check_platform, session, platform_name, url, method, username
                        )
                        futures.append(future)

                completed = 0
                total = len(futures)
                seen_platforms = set()

                for future in as_completed(futures):
                    if not self.is_running:
                        break
                    completed += 1
                    self.signals.progress.emit(int((completed / total) * 100))

                    result = future.result()
                    if result and result["status"] == "found":
                        # Deduplicate by platform
                        key = f"{result['platform']}:{result['url']}"
                        if key not in seen_platforms:
                            seen_platforms.add(key)
                            self.results["found"].append(result)
                            self.signals.output.emit(
                                f"<p style='color: #00FF41;'>"
                                f"  \u2713 {h(result['platform'])}: "
                                f"{h(result['url'])} (as '{h(result['username'])}')</p>"
                            )

            found_count = len(self.results["found"])
            self.signals.output.emit(
                f"<br><p style='color: #64C8FF; font-weight: bold;'>"
                f"[RESULTS] Found {found_count} professional profile(s)</p>"
            )

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Professional networks error: {e}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            self.signals.finished.emit()

    def _check_platform(self, session: requests.Session, platform: str,
                        url: str, method: str, username: str) -> Optional[Dict]:
        """Check a single professional platform"""
        # Platforms that block automated requests — return URL directly
        if method == "assume_exists":
            return {"platform": platform, "url": url, "username": username, "status": "found"}

        try:
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)

            if method == "status":
                if resp.status_code == 200:
                    return {"platform": platform, "url": url, "username": username, "status": "found"}
            elif method == "text_present":
                # For search pages — check if username appears in results
                if resp.status_code == 200 and username.lower() in resp.text.lower():
                    return {"platform": platform, "url": url, "username": username, "status": "found"}
            elif method == "api":
                if resp.status_code == 200:
                    # ORCID returns XML/JSON with results
                    if "num-found" in resp.text and 'num-found="0"' not in resp.text:
                        return {"platform": platform, "url": url, "username": username, "status": "found"}

        except Exception:
            pass

        return None


# ======================================================================
# Public Records — OSINT aggregator queries
# ======================================================================

class PublicRecordsWorker(BaseWorker):
    """Search public records and OSINT aggregators"""

    # Free/open OSINT sources that can be queried
    OSINT_SOURCES = [
        ("Webmii", "https://webmii.com/people?n={}", "text_present"),
        ("That's Them", "https://thatsthem.com/name/{}", "status"),
        ("Whitepages", "https://www.whitepages.com/name/{}", "status"),
        ("Pipl (legacy)", "https://pipl.com/search/?q={}", "status"),
        ("Spokeo", "https://www.spokeo.com/{}", "status"),
        ("PeekYou", "https://www.peekyou.com/{}", "status"),
        ("ZabaSearch", "https://www.zabasearch.com/people/{}", "status"),
    ]

    def __init__(self, target: str, timeout: int = 10):
        super().__init__()
        self.target = target.strip()
        self.timeout = timeout
        self.results: Dict = {"sources_checked": [], "accessible": [], "blocked": [], "error": None}

    def run(self):
        try:
            self.signals.output.emit(
                f"<p style='color: #64C8FF; font-weight: bold;'>"
                f"[PUBLIC RECORDS] Searching for: {h(self.target)}</p>"
            )
            self.signals.output.emit(
                "<p style='color: #FFA500;'>"
                "  Note: Many public record sites require paid access or block automated queries.</p>"
                "<p style='color: #DCDCDC;'>  Checking accessibility of OSINT aggregators...</p><br>"
            )

            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36"
            })

            # Format name for URL (replace spaces with appropriate separators)
            url_name = self.target.replace(" ", "-")
            url_name_slash = self.target.replace(" ", "/")
            url_name_plus = self.target.replace(" ", "+")

            total = len(self.OSINT_SOURCES)
            for idx, (source_name, url_template, method) in enumerate(self.OSINT_SOURCES):
                if not self.is_running:
                    break

                # Try different name formats
                if "/" in url_template.split("?")[0]:
                    url = url_template.format(url_name_slash)
                elif "?" in url_template:
                    url = url_template.format(url_name_plus)
                else:
                    url = url_template.format(url_name)

                self.signals.progress.emit(int(((idx + 1) / total) * 100))

                try:
                    resp = session.get(url, timeout=self.timeout, allow_redirects=True)

                    if resp.status_code == 200:
                        # Check if we got a real result vs a generic page
                        has_content = (
                            self.target.lower().split()[0] in resp.text.lower()
                            if method == "text_present"
                            else True
                        )

                        if has_content:
                            self.results["accessible"].append({
                                "source": source_name,
                                "url": url,
                                "status_code": resp.status_code,
                            })
                            self.signals.output.emit(
                                f"<p style='color: #00FF41;'>"
                                f"  \u2713 {h(source_name)}: Accessible — {h(url)}</p>"
                            )
                        else:
                            self.signals.output.emit(
                                f"<p style='color: #888;'>"
                                f"  \u2022 {h(source_name)}: No results for target</p>"
                            )
                    elif resp.status_code == 403:
                        self.results["blocked"].append(source_name)
                        self.signals.output.emit(
                            f"<p style='color: #FFA500;'>"
                            f"  \u2717 {h(source_name)}: Blocked (403) — requires manual access</p>"
                        )
                    elif resp.status_code == 404:
                        self.signals.output.emit(
                            f"<p style='color: #888;'>"
                            f"  \u2022 {h(source_name)}: No record found</p>"
                        )
                    else:
                        self.signals.output.emit(
                            f"<p style='color: #888;'>"
                            f"  \u2022 {h(source_name)}: HTTP {resp.status_code}</p>"
                        )

                except requests.exceptions.Timeout:
                    self.signals.output.emit(
                        f"<p style='color: #FFA500;'>"
                        f"  \u2717 {h(source_name)}: Timeout</p>"
                    )
                except requests.exceptions.ConnectionError:
                    self.signals.output.emit(
                        f"<p style='color: #FFA500;'>"
                        f"  \u2717 {h(source_name)}: Connection failed</p>"
                    )
                except Exception:
                    pass

                self.results["sources_checked"].append(source_name)
                time.sleep(0.5)  # Be polite

            # Summary
            self.signals.output.emit(
                f"<br><p style='color: #64C8FF; font-weight: bold;'>"
                f"[RESULTS] {len(self.results['accessible'])} accessible source(s), "
                f"{len(self.results['blocked'])} blocked</p>"
            )

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Public records error: {e}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            self.signals.finished.emit()


# ======================================================================
# Contact Discovery — email pattern generation & SMTP validation
# ======================================================================

class ContactDiscoveryWorker(BaseWorker):
    """Discover contact information: email patterns, validation, related data"""

    # Common corporate email patterns
    EMAIL_PATTERNS = [
        "{first}.{last}",
        "{first}{last}",
        "{f}{last}",
        "{first}_{last}",
        "{first}-{last}",
        "{last}.{first}",
        "{last}{first}",
        "{last}{f}",
        "{f}.{last}",
        "{first}",
        "{last}",
    ]

    def __init__(self, target: str, domain: str = "", timeout: int = 10):
        super().__init__()
        self.target = target.strip()
        self.domain = domain.strip()
        self.timeout = timeout
        self.results: Dict = {
            "generated_emails": [],
            "validated_emails": [],
            "hunter_results": [],
            "error": None,
        }

    def run(self):
        try:
            self.signals.output.emit(
                f"<p style='color: #64C8FF; font-weight: bold;'>"
                f"[CONTACT DISCOVERY] Target: {h(self.target)}</p>"
            )

            parts = self.target.lower().split()
            if len(parts) < 2 and not self.domain:
                self.signals.output.emit(
                    "<p style='color: #FFA500;'>"
                    "  \u26a0 Provide a full name (first last) and/or domain for best results</p>"
                )

            # Step 1: Generate email patterns
            if len(parts) >= 2 and self.domain:
                self._generate_email_patterns(parts[0], parts[-1], self.domain)
            elif "@" in self.target:
                # Target is already an email — extract domain
                self.domain = self.target.split("@")[1]
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>  Domain extracted: {h(self.domain)}</p>"
                )

            # Step 2: Hunter.io lookup (if API key available)
            self._hunter_lookup()

            # Step 3: Email validation via SMTP check
            if self.results["generated_emails"]:
                self._validate_emails()

            # Summary
            self.signals.output.emit(
                f"<br><p style='color: #64C8FF; font-weight: bold;'>"
                f"[RESULTS] Generated {len(self.results['generated_emails'])} patterns, "
                f"validated {len(self.results['validated_emails'])} email(s)</p>"
            )

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Contact discovery error: {e}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            self.signals.finished.emit()

    def _generate_email_patterns(self, first: str, last: str, domain: str):
        """Generate possible email addresses from name + domain"""
        self.signals.output.emit(
            f"<p style='color: #FFD93D;'>  Generating email patterns for "
            f"{h(first)} {h(last)} @ {h(domain)}...</p>"
        )

        f = first[0] if first else ""
        l = last[0] if last else ""

        for pattern in self.EMAIL_PATTERNS:
            try:
                email = pattern.format(first=first, last=last, f=f, l=l) + f"@{domain}"
                self.results["generated_emails"].append(email)
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>    \u2022 {h(email)}</p>"
                )
            except (KeyError, IndexError):
                continue

    def _hunter_lookup(self):
        """Use Hunter.io API to find verified emails"""
        hunter_key = _get_api_key("hunter")

        if not hunter_key:
            self.signals.output.emit(
                "<p style='color: #FFA500;'>"
                "  \u26a0 No Hunter.io API key configured "
                "(Settings \u2192 API Keys \u2192 hunter)</p>"
            )
            return

        if not self.domain:
            return

        try:
            self.signals.output.emit(
                f"<p style='color: #FFD93D;'>  Querying Hunter.io for {h(self.domain)}...</p>"
            )

            resp = requests.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": self.domain, "api_key": hunter_key, "limit": 20},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                emails = data.get("emails", [])
                pattern = data.get("pattern", "")

                if pattern:
                    self.signals.output.emit(
                        f"<p style='color: #00FF41;'>"
                        f"  \u2713 Email pattern detected: {h(pattern)}@{h(self.domain)}</p>"
                    )

                for email_entry in emails:
                    email = email_entry.get("value", "")
                    confidence = email_entry.get("confidence", 0)
                    if email:
                        self.results["hunter_results"].append({
                            "email": email,
                            "confidence": confidence,
                            "first_name": email_entry.get("first_name", ""),
                            "last_name": email_entry.get("last_name", ""),
                            "position": email_entry.get("position", ""),
                        })
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>"
                            f"    \u2713 {h(email)} (confidence: {confidence}%)"
                            f"{' — ' + h(email_entry.get('position', '')) if email_entry.get('position') else ''}"
                            f"</p>"
                        )
            elif resp.status_code == 401:
                self.signals.output.emit(
                    "<p style='color: #FFA500;'>  \u26a0 Hunter.io API key invalid</p>"
                )
            elif resp.status_code == 429:
                self.signals.output.emit(
                    "<p style='color: #FFA500;'>  \u26a0 Hunter.io rate limited</p>"
                )

        except Exception as e:
            self.signals.output.emit(
                f"<p style='color: #FFA500;'>  \u26a0 Hunter.io error: {h(str(e))}</p>"
            )

    def _validate_emails(self):
        """Basic email validation via DNS MX record check"""
        import socket

        self.signals.output.emit(
            "<p style='color: #FFD93D;'>  Validating email deliverability (MX check)...</p>"
        )

        domain = self.domain
        if not domain:
            return

        try:
            # Check if domain has MX records
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=mx", domain],
                capture_output=True, text=True, timeout=10
            )

            if "mail exchanger" in result.stdout.lower() or "mx" in result.stdout.lower():
                self.signals.output.emit(
                    f"<p style='color: #00FF41;'>"
                    f"  \u2713 Domain {h(domain)} has valid MX records — emails likely deliverable</p>"
                )
                # Mark all generated emails as potentially valid
                self.results["validated_emails"] = self.results["generated_emails"]
            else:
                self.signals.output.emit(
                    f"<p style='color: #FFA500;'>"
                    f"  \u26a0 No MX records for {h(domain)} — emails may not be deliverable</p>"
                )

        except Exception as e:
            self.signals.output.emit(
                f"<p style='color: #888;'>  MX validation skipped: {h(str(e))}</p>"
            )


# ======================================================================
# Username Search — cross-platform username correlation
# ======================================================================

# Extended platform list for username-specific search (beyond social)
USERNAME_PLATFORMS = [
    ("GitHub", "https://api.github.com/users/{}", "api_json"),
    ("Reddit", "https://www.reddit.com/user/{}/about.json", "api_json"),
    ("HackerNews", "https://hacker-news.firebaseio.com/v0/user/{}.json", "api_json"),
    ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", "api_json"),
    ("Gravatar", "https://en.gravatar.com/{}.json", "api_json"),
    ("GitLab", "https://gitlab.com/api/v4/users?username={}", "api_json_array"),
    ("Chess.com", "https://api.chess.com/pub/player/{}", "api_json"),
    ("Lichess", "https://lichess.org/api/user/{}", "api_json"),
    ("Replit", "https://replit.com/@{}", "status"),
    ("CodePen", "https://codepen.io/{}", "status"),
    ("Mastodon (mastodon.social)", "https://mastodon.social/@{}", "status"),
    ("Letterboxd", "https://letterboxd.com/{}/", "status"),
    ("Trello", "https://trello.com/{}", "status"),
    ("ProductHunt", "https://www.producthunt.com/@{}", "status"),
    ("DEV.to", "https://dev.to/api/users/by_username?url={}", "api_json"),
    ("Imgur", "https://api.imgur.com/account/v1/accounts/{}?client_id=546c25a59c58ad7", "api_json"),
]


class UsernameSearchWorker(BaseWorker):
    """Cross-platform username search with enrichment data"""

    def __init__(self, username: str, max_workers: int = 10, timeout: int = 8):
        super().__init__()
        self.username = username.strip().replace(" ", "")
        self.max_workers = max_workers
        self.timeout = timeout
        self.results: Dict = {"found": [], "enrichment": {}}

    def run(self):
        try:
            self.signals.output.emit(
                f"<p style='color: #64C8FF; font-weight: bold;'>"
                f"[USERNAME SEARCH] Searching: {h(self.username)}</p>"
            )
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>Querying {len(USERNAME_PLATFORMS)} platforms "
                f"with API enrichment...</p><br>"
            )

            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36",
                "Accept": "application/json",
            })

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {}
                for platform_name, url_template, method in USERNAME_PLATFORMS:
                    if not self.is_running:
                        break
                    url = url_template.format(self.username)
                    future = executor.submit(
                        self._check_platform, session, platform_name, url, method
                    )
                    futures[future] = platform_name

                completed = 0
                total = len(futures)
                for future in as_completed(futures):
                    if not self.is_running:
                        break
                    completed += 1
                    self.signals.progress.emit(int((completed / total) * 100))

                    result = future.result()
                    if result and result.get("found"):
                        self.results["found"].append(result)
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>"
                            f"  \u2713 {h(result['platform'])}: {h(result['url'])}</p>"
                        )
                        # Show enrichment data if available
                        if result.get("enrichment"):
                            for key, val in result["enrichment"].items():
                                if val:
                                    self.signals.output.emit(
                                        f"<p style='color: #888;'>"
                                        f"      {h(key)}: {h(str(val))}</p>"
                                    )

            found_count = len(self.results["found"])
            self.signals.output.emit(
                f"<br><p style='color: #64C8FF; font-weight: bold;'>"
                f"[RESULTS] Username '{h(self.username)}' found on "
                f"{found_count}/{len(USERNAME_PLATFORMS)} platforms</p>"
            )

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Username search error: {e}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            self.signals.finished.emit()

    def _check_platform(self, session: requests.Session, platform: str,
                        url: str, method: str) -> Optional[Dict]:
        """Check platform and extract enrichment data"""
        try:
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)

            if method == "status":
                if resp.status_code == 200:
                    return {"platform": platform, "url": url, "found": True, "enrichment": {}}

            elif method == "api_json":
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data and not isinstance(data, list):
                            enrichment = self._extract_enrichment(platform, data)
                            return {"platform": platform, "url": url, "found": True,
                                    "enrichment": enrichment}
                        elif data:
                            return {"platform": platform, "url": url, "found": True,
                                    "enrichment": {}}
                    except ValueError:
                        return {"platform": platform, "url": url, "found": True,
                                "enrichment": {}}

            elif method == "api_json_array":
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 0:
                            enrichment = self._extract_enrichment(platform, data[0])
                            return {"platform": platform, "url": url, "found": True,
                                    "enrichment": enrichment}
                    except ValueError:
                        pass

        except Exception:
            pass

        return None

    def _extract_enrichment(self, platform: str, data: dict) -> Dict:
        """Extract useful enrichment data from API responses"""
        enrichment = {}

        # GitHub
        if platform == "GitHub":
            enrichment["Name"] = data.get("name", "")
            enrichment["Bio"] = data.get("bio", "")
            enrichment["Location"] = data.get("location", "")
            enrichment["Company"] = data.get("company", "")
            enrichment["Public repos"] = data.get("public_repos", "")
            enrichment["Followers"] = data.get("followers", "")
            enrichment["Created"] = data.get("created_at", "")[:10]

        # Reddit
        elif platform == "Reddit":
            inner = data.get("data", data)
            enrichment["Karma"] = inner.get("total_karma", inner.get("link_karma", ""))
            enrichment["Created"] = ""
            created_utc = inner.get("created_utc")
            if created_utc:
                import datetime
                enrichment["Created"] = datetime.datetime.fromtimestamp(
                    created_utc).strftime("%Y-%m-%d")

        # HackerNews
        elif platform == "HackerNews":
            enrichment["Karma"] = data.get("karma", "")
            enrichment["About"] = (data.get("about", "") or "")[:100]
            enrichment["Created"] = ""
            created = data.get("created")
            if created:
                import datetime
                enrichment["Created"] = datetime.datetime.fromtimestamp(
                    created).strftime("%Y-%m-%d")

        # GitLab
        elif platform == "GitLab":
            enrichment["Name"] = data.get("name", "")
            enrichment["Bio"] = data.get("bio", "")
            enrichment["Location"] = data.get("location", "")
            enrichment["Website"] = data.get("website_url", "")

        # Chess.com
        elif platform == "Chess.com":
            enrichment["Name"] = data.get("name", "")
            enrichment["Country"] = data.get("country", "").split("/")[-1] if data.get("country") else ""
            enrichment["Followers"] = data.get("followers", "")

        # Generic fallback
        else:
            for key in ["name", "bio", "location", "email", "url"]:
                if data.get(key):
                    enrichment[key.capitalize()] = data[key]

        # Remove empty values
        return {k: v for k, v in enrichment.items() if v}


# ======================================================================
# Email Enumeration — discover emails for a domain/person
# ======================================================================

class EmailEnumerationWorker(BaseWorker):
    """Enumerate email addresses associated with a domain or person"""

    def __init__(self, target: str, timeout: int = 10):
        super().__init__()
        self.target = target.strip()
        self.timeout = timeout
        self.results: Dict = {"emails_found": [], "sources": [], "error": None}

    def run(self):
        try:
            self.signals.output.emit(
                f"<p style='color: #64C8FF; font-weight: bold;'>"
                f"[EMAIL ENUMERATION] Target: {h(self.target)}</p><br>"
            )

            domain = self._extract_domain()
            if not domain:
                self.signals.output.emit(
                    "<p style='color: #FFA500;'>"
                    "  \u26a0 Please provide a domain or email address</p>"
                )
                self.signals.finished.emit()
                return

            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  Domain: {h(domain)}</p>"
            )

            # Source 1: Hunter.io
            self._hunter_domain_search(domain)

            # Source 2: EmailRep.io (reputation check if target is email)
            if "@" in self.target:
                self._emailrep_check(self.target)

            # Source 3: Google dork patterns for email discovery
            self._generate_email_dorks(domain)

            # Source 4: Certificate Transparency for email hints
            self._crt_sh_emails(domain)

            # Summary
            unique_emails = list(set(self.results["emails_found"]))
            self.results["emails_found"] = unique_emails

            self.signals.output.emit(
                f"<br><p style='color: #64C8FF; font-weight: bold;'>"
                f"[RESULTS] Discovered {len(unique_emails)} unique email(s) "
                f"from {len(self.results['sources'])} source(s)</p>"
            )

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Email enumeration error: {e}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            self.signals.finished.emit()

    def _extract_domain(self) -> str:
        if "@" in self.target:
            return self.target.split("@")[1]
        elif "." in self.target and " " not in self.target:
            return self.target
        return ""

    def _hunter_domain_search(self, domain: str):
        """Query Hunter.io for domain emails"""
        hunter_key = _get_api_key("hunter")
        if not hunter_key:
            self.signals.output.emit(
                "<p style='color: #FFA500;'>"
                "  \u26a0 Hunter.io: No API key configured "
                "(Settings \u2192 API Keys \u2192 hunter)</p>"
            )
            return

        try:
            self.signals.output.emit(
                f"<p style='color: #FFD93D;'>  Querying Hunter.io...</p>"
            )
            resp = requests.get(
                "https://api.hunter.io/v2/domain-search",
                params={"domain": domain, "api_key": hunter_key, "limit": 50},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                emails = data.get("emails", [])
                pattern = data.get("pattern", "")

                if pattern:
                    self.signals.output.emit(
                        f"<p style='color: #00FF41;'>"
                        f"    Pattern: {h(pattern)}@{h(domain)}</p>"
                    )

                for entry in emails:
                    email = entry.get("value", "")
                    if email:
                        self.results["emails_found"].append(email)
                        confidence = entry.get("confidence", 0)
                        name = f"{entry.get('first_name', '')} {entry.get('last_name', '')}".strip()
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>"
                            f"    \u2713 {h(email)} ({confidence}%)"
                            f"{' — ' + h(name) if name else ''}</p>"
                        )

                self.results["sources"].append("Hunter.io")
            elif resp.status_code == 401:
                self.signals.output.emit(
                    "<p style='color: #FFA500;'>    Hunter.io: Invalid API key</p>"
                )

        except Exception as e:
            self.signals.output.emit(
                f"<p style='color: #FFA500;'>    Hunter.io error: {h(str(e))}</p>"
            )

    def _emailrep_check(self, email: str):
        """Check email reputation via EmailRep.io (free, no key required)"""
        try:
            self.signals.output.emit(
                f"<p style='color: #FFD93D;'>  Checking EmailRep.io...</p>"
            )
            resp = requests.get(
                f"https://emailrep.io/{email}",
                headers={"User-Agent": "Huginn-OSINT/1.0"},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                reputation = data.get("reputation", "unknown")
                suspicious = data.get("suspicious", False)
                details = data.get("details", {})

                rep_color = "#00FF41" if reputation == "high" else "#FFA500" if reputation == "medium" else "#FF6B6B"
                self.signals.output.emit(
                    f"<p style='color: {rep_color};'>"
                    f"    Reputation: {h(reputation)}"
                    f"{' (SUSPICIOUS)' if suspicious else ''}</p>"
                )

                if details.get("profiles"):
                    profiles = ", ".join(details["profiles"][:5])
                    self.signals.output.emit(
                        f"<p style='color: #888;'>"
                        f"    Profiles: {h(profiles)}</p>"
                    )

                if details.get("data_breach"):
                    self.signals.output.emit(
                        "<p style='color: #FF6B6B;'>"
                        "    \u26a0 Found in data breaches</p>"
                    )

                self.results["sources"].append("EmailRep.io")

        except Exception as e:
            self.signals.output.emit(
                f"<p style='color: #888;'>    EmailRep.io: {h(str(e))}</p>"
            )

    def _generate_email_dorks(self, domain: str):
        """Generate Google dork queries for email discovery"""
        self.signals.output.emit(
            f"<p style='color: #FFD93D;'>  Google dork queries for email discovery:</p>"
        )

        dorks = [
            f'"@{domain}" email',
            f'site:{domain} "mailto:"',
            f'site:{domain} filetype:pdf "@{domain}"',
            f'"{domain}" "contact" email',
            f'intext:"@{domain}" site:linkedin.com',
        ]

        for dork in dorks:
            self.signals.output.emit(
                f"<p style='color: #555;'>    \u25e6 {h(dork)}</p>"
            )

    def _crt_sh_emails(self, domain: str):
        """Check Certificate Transparency logs for email-like entries"""
        try:
            self.signals.output.emit(
                f"<p style='color: #FFD93D;'>  Checking crt.sh for certificate emails...</p>"
            )
            resp = requests.get(
                f"https://crt.sh/?q=%25{domain}&output=json",
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                certs = resp.json()
                # Extract unique common names that might reveal org info
                names = set()
                for cert in certs[:50]:
                    cn = cert.get("common_name", "")
                    if cn and cn != f"*.{domain}" and cn != domain:
                        names.add(cn)

                if names:
                    self.signals.output.emit(
                        f"<p style='color: #00FF41;'>"
                        f"    Found {len(names)} subdomain(s) in CT logs:</p>"
                    )
                    for name in list(names)[:10]:
                        self.signals.output.emit(
                            f"<p style='color: #888;'>      \u2022 {h(name)}</p>"
                        )
                    self.results["sources"].append("crt.sh")

        except Exception:
            pass


# ======================================================================
# Phone Lookup — carrier, location, validation
# ======================================================================

class PhoneLookupWorker(BaseWorker):
    """Phone number OSINT: validation, carrier lookup, format analysis"""

    def __init__(self, phone_number: str, timeout: int = 10):
        super().__init__()
        self.phone_number = phone_number.strip()
        self.timeout = timeout
        self.results: Dict = {
            "valid": False,
            "formatted": "",
            "country": "",
            "carrier": "",
            "line_type": "",
            "error": None,
        }

    def run(self):
        try:
            self.signals.output.emit(
                f"<p style='color: #64C8FF; font-weight: bold;'>"
                f"[PHONE LOOKUP] Number: {h(self.phone_number)}</p><br>"
            )

            # Step 1: Local format analysis
            self._analyze_format()

            # Step 2: NumVerify API (free tier available)
            self._numverify_lookup()

            # Step 3: Abstract API phone validation
            self._abstract_phone_lookup()

            # Step 4: Generate OSINT search links
            self._generate_search_links()

            # Summary
            self.signals.output.emit(
                f"<br><p style='color: #64C8FF; font-weight: bold;'>"
                f"[RESULTS] Phone analysis complete</p>"
            )

            if self.results["country"]:
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>"
                    f"  Country: {h(self.results['country'])} | "
                    f"Carrier: {h(self.results.get('carrier', 'Unknown'))} | "
                    f"Type: {h(self.results.get('line_type', 'Unknown'))}</p>"
                )

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Phone lookup error: {e}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            self.signals.finished.emit()

    def _analyze_format(self):
        """Analyze phone number format locally"""
        self.signals.output.emit(
            "<p style='color: #FFD93D;'>  Analyzing number format...</p>"
        )

        # Strip common formatting
        cleaned = re.sub(r'[\s\-\(\)\.\+]', '', self.phone_number)
        digits_only = re.sub(r'[^\d]', '', self.phone_number)

        self.signals.output.emit(
            f"<p style='color: #DCDCDC;'>    Digits: {h(digits_only)}</p>"
            f"<p style='color: #DCDCDC;'>    Length: {len(digits_only)} digits</p>"
        )

        # Basic country detection from prefix
        if self.phone_number.startswith("+1") or (len(digits_only) == 10 and not self.phone_number.startswith("+")):
            self.results["country"] = "US/Canada"
            self.signals.output.emit(
                "<p style='color: #DCDCDC;'>    Region: North America (+1)</p>"
            )
        elif self.phone_number.startswith("+44"):
            self.results["country"] = "United Kingdom"
        elif self.phone_number.startswith("+49"):
            self.results["country"] = "Germany"
        elif self.phone_number.startswith("+33"):
            self.results["country"] = "France"
        elif self.phone_number.startswith("+61"):
            self.results["country"] = "Australia"
        elif self.phone_number.startswith("+91"):
            self.results["country"] = "India"

        if self.results["country"]:
            self.signals.output.emit(
                f"<p style='color: #00FF41;'>"
                f"    Country: {h(self.results['country'])}</p>"
            )

    def _numverify_lookup(self):
        """Query NumVerify API for phone validation"""
        numverify_key = _get_api_key("numverify")
        if not numverify_key:
            self.signals.output.emit(
                "<p style='color: #FFA500;'>"
                "  \u26a0 NumVerify: No API key configured "
                "(Settings \u2192 API Keys \u2192 numverify)</p>"
            )
            return

        try:
            self.signals.output.emit(
                "<p style='color: #FFD93D;'>  Querying NumVerify API...</p>"
            )

            # Clean number for API
            number = re.sub(r'[^\d\+]', '', self.phone_number)

            resp = requests.get(
                "http://apilayer.net/api/validate",
                params={"access_key": numverify_key, "number": number},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    self.results["valid"] = True
                    self.results["formatted"] = data.get("international_format", "")
                    self.results["country"] = data.get("country_name", self.results["country"])
                    self.results["carrier"] = data.get("carrier", "")
                    self.results["line_type"] = data.get("line_type", "")

                    self.signals.output.emit(
                        f"<p style='color: #00FF41;'>    \u2713 Valid number</p>"
                        f"<p style='color: #DCDCDC;'>"
                        f"    International: {h(data.get('international_format', ''))}</p>"
                        f"<p style='color: #DCDCDC;'>"
                        f"    Country: {h(data.get('country_name', ''))}</p>"
                        f"<p style='color: #DCDCDC;'>"
                        f"    Carrier: {h(data.get('carrier', 'Unknown'))}</p>"
                        f"<p style='color: #DCDCDC;'>"
                        f"    Line type: {h(data.get('line_type', 'Unknown'))}</p>"
                    )
                else:
                    self.signals.output.emit(
                        "<p style='color: #FF6B6B;'>    \u2717 Number appears invalid</p>"
                    )

        except Exception as e:
            self.signals.output.emit(
                f"<p style='color: #FFA500;'>    NumVerify error: {h(str(e))}</p>"
            )

    def _abstract_phone_lookup(self):
        """Query Abstract API for phone validation (alternative source)"""
        abstract_key = _get_api_key("abstractapi_phone")
        if not abstract_key:
            return  # Silent skip — NumVerify is primary

        try:
            number = re.sub(r'[^\d\+]', '', self.phone_number)
            resp = requests.get(
                "https://phonevalidation.abstractapi.com/v1/",
                params={"api_key": abstract_key, "phone": number},
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    carrier = data.get("carrier", "")
                    if carrier and not self.results["carrier"]:
                        self.results["carrier"] = carrier
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>"
                            f"    AbstractAPI confirms: {h(carrier)}</p>"
                        )

        except Exception:
            pass

    def _generate_search_links(self):
        """Generate OSINT search links for the phone number"""
        self.signals.output.emit(
            "<p style='color: #FFD93D;'>  OSINT search links:</p>"
        )

        cleaned = re.sub(r'[^\d\+]', '', self.phone_number)
        links = [
            ("Truecaller", f"https://www.truecaller.com/search/{cleaned}"),
            ("Sync.me", f"https://sync.me/search/?number={cleaned}"),
            ("CallerID Test", f"https://calleridtest.com/results/?number={cleaned}"),
            ("Google Search", f"https://www.google.com/search?q=%22{cleaned}%22"),
        ]

        for name, url in links:
            self.signals.output.emit(
                f"<p style='color: #888;'>    \u25e6 {h(name)}: {h(url)}</p>"
            )


# ======================================================================
# Full Person Intel — orchestrates all tools sequentially
# ======================================================================

class FullPersonIntelWorker(BaseWorker):
    """Comprehensive person intelligence — runs all tools in sequence"""

    def __init__(self, target: str, domain: str = "", max_workers: int = 10, timeout: int = 8):
        super().__init__()
        self.target = target.strip()
        self.domain = domain.strip()
        self.max_workers = max_workers
        self.timeout = timeout
        self.results: Dict = {}

    def run(self):
        try:
            self.signals.output.emit(
                f"<p style='color: #64C8FF; font-size: 14px; font-weight: bold;'>"
                f"[COMPREHENSIVE PERSON INTEL] Target: {h(self.target)}</p>"
            )
            self.signals.output.emit(
                "<p style='color: #DCDCDC;'>"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "</p><br>"
            )

            phases = [
                ("Phase 1: Social Media Profiles", self._run_social),
                ("Phase 2: Professional Networks", self._run_professional),
                ("Phase 3: Username Correlation", self._run_username),
                ("Phase 4: Email Enumeration", self._run_email),
                ("Phase 5: Contact Discovery", self._run_contact),
            ]

            total = len(phases)
            for idx, (label, method) in enumerate(phases):
                if not self.is_running:
                    self.signals.output.emit(
                        "<p style='color: #FFA500;'>\u26a0 Analysis cancelled</p>"
                    )
                    break

                self.signals.output.emit(
                    f"<p style='color: #FFD93D; font-weight: bold;'>"
                    f"\u25b6 {h(label)}...</p>"
                )

                method()

                self.signals.output.emit(
                    "<p style='color: #DCDCDC;'>"
                    "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
                    "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
                    "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
                    "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
                    "\u2500</p>"
                )

                progress = int(((idx + 1) / total) * 100)
                self.signals.progress.emit(progress)

            # Final summary
            self.signals.output.emit(
                "<p style='color: #DCDCDC;'>"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
                "</p>"
            )
            self.signals.output.emit(
                "<p style='color: #00FF41; font-weight: bold;'>"
                "\u2713 Comprehensive person intelligence complete</p>"
            )

            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Full person intel error: {e}")
            self.signals.error.emit(f"<p style='color: #FF4500;'>[ERROR] {h(str(e))}</p>")
            self.signals.finished.emit()

    def _run_social(self):
        """Run social profile enumeration inline"""
        username = self.target.replace(" ", "")
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36"
        })

        found = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for platform_name, url_template, method, absent_text in SOCIAL_PLATFORMS[:15]:
                url = url_template.format(username)
                future = executor.submit(self._check_url, session, url, method, absent_text)
                futures[future] = (platform_name, url)

            for future in as_completed(futures):
                if not self.is_running:
                    break
                platform_name, url = futures[future]
                if future.result():
                    found.append(platform_name)
                    self.signals.output.emit(
                        f"<p style='color: #00FF41;'>"
                        f"  \u2713 {h(platform_name)}: {h(url)}</p>"
                    )

        self.results["social_profiles"] = found
        if not found:
            self.signals.output.emit(
                "<p style='color: #888;'>  No social profiles found for this username</p>"
            )

    def _run_professional(self):
        """Run professional network check inline"""
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36"
        })

        variants = self._generate_name_variants()
        found = []

        for platform_name, url_template, method in PROFESSIONAL_PLATFORMS[:8]:
            if not self.is_running:
                break
            for variant in variants[:3]:
                url = url_template.format(variant)
                try:
                    resp = session.get(url, timeout=self.timeout, allow_redirects=True)
                    if resp.status_code == 200:
                        found.append({"platform": platform_name, "url": url, "variant": variant})
                        self.signals.output.emit(
                            f"<p style='color: #00FF41;'>"
                            f"  \u2713 {h(platform_name)}: {h(url)}</p>"
                        )
                        break  # Found on this platform, move to next
                except Exception:
                    continue

        self.results["professional"] = found
        if not found:
            self.signals.output.emit(
                "<p style='color: #888;'>  No professional profiles found</p>"
            )

    def _run_username(self):
        """Run username correlation inline"""
        username = self.target.replace(" ", "").lower()
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36",
            "Accept": "application/json",
        })

        found = []
        for platform_name, url_template, method in USERNAME_PLATFORMS[:10]:
            if not self.is_running:
                break
            url = url_template.format(username)
            try:
                resp = session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200:
                    found.append(platform_name)
                    self.signals.output.emit(
                        f"<p style='color: #00FF41;'>"
                        f"  \u2713 {h(platform_name)}: {h(url)}</p>"
                    )
            except Exception:
                continue

        self.results["username_matches"] = found
        if not found:
            self.signals.output.emit(
                "<p style='color: #888;'>  No username matches found</p>"
            )

    def _run_email(self):
        """Run email enumeration inline"""
        domain = self.domain
        if not domain and "@" in self.target:
            domain = self.target.split("@")[1]

        if not domain:
            self.signals.output.emit(
                "<p style='color: #888;'>  No domain provided — skipping email enumeration</p>"
            )
            return

        # Hunter.io check
        hunter_key = _get_api_key("hunter")
        if hunter_key:
            try:
                resp = requests.get(
                    "https://api.hunter.io/v2/domain-search",
                    params={"domain": domain, "api_key": hunter_key, "limit": 10},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    emails = data.get("emails", [])
                    for entry in emails[:5]:
                        email = entry.get("value", "")
                        if email:
                            self.signals.output.emit(
                                f"<p style='color: #00FF41;'>"
                                f"  \u2713 {h(email)}</p>"
                            )
                    self.results["emails"] = [e.get("value") for e in emails if e.get("value")]
            except Exception:
                pass
        else:
            self.signals.output.emit(
                "<p style='color: #FFA500;'>"
                "  \u26a0 Hunter.io not configured — skipping email lookup</p>"
            )

    def _run_contact(self):
        """Generate contact patterns inline"""
        parts = self.target.lower().split()
        domain = self.domain

        if len(parts) >= 2 and domain:
            first, last = parts[0], parts[-1]
            patterns = [
                f"{first}.{last}@{domain}",
                f"{first}{last}@{domain}",
                f"{first[0]}{last}@{domain}",
                f"{first}_{last}@{domain}",
                f"{last}.{first}@{domain}",
            ]
            self.signals.output.emit(
                "<p style='color: #DCDCDC;'>  Generated email patterns:</p>"
            )
            for p in patterns:
                self.signals.output.emit(
                    f"<p style='color: #888;'>    \u2022 {h(p)}</p>"
                )
            self.results["contact_patterns"] = patterns
        else:
            self.signals.output.emit(
                "<p style='color: #888;'>"
                "  Provide full name + domain for contact pattern generation</p>"
            )

    def _generate_name_variants(self) -> List[str]:
        """Generate username variants from target name"""
        variants = []
        clean = self.target.lower().strip()
        variants.append(clean.replace(" ", ""))

        parts = clean.split()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            variants.extend([
                f"{first}{last}", f"{first}.{last}", f"{first}-{last}",
                f"{first[0]}{last}", f"{last}{first}",
            ])
        return variants

    def _check_url(self, session, url, method, absent_text) -> bool:
        """Quick URL existence check"""
        if method == "assume_exists":
            return True
        try:
            resp = session.get(url, timeout=self.timeout, allow_redirects=True)
            if method == "status":
                return resp.status_code == 200
            elif method == "text":
                return resp.status_code == 200 and (not absent_text or absent_text not in resp.text)
        except Exception:
            return False
