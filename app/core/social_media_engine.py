"""
Social Media OSINT Engine.

Performs real account discovery, content scraping, and analysis
using public APIs and web scraping techniques.
"""

import re
import time
import json
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from app.core.logger import logger

# Platforms to check for account discovery
PLATFORMS = {
    "twitter": {
        "url": "https://x.com/{username}",
        "check_url": "https://x.com/{username}",
    },
    "instagram": {
        "url": "https://www.instagram.com/{username}/",
        "check_url": "https://www.instagram.com/{username}/",
    },
    "github": {
        "url": "https://github.com/{username}",
        "check_url": "https://api.github.com/users/{username}",
    },
    "linkedin": {
        "url": "https://www.linkedin.com/in/{username}",
        "check_url": "https://www.linkedin.com/in/{username}",
    },
    "reddit": {
        "url": "https://www.reddit.com/user/{username}",
        "check_url": "https://www.reddit.com/user/{username}/about.json",
    },
    "tiktok": {
        "url": "https://www.tiktok.com/@{username}",
        "check_url": "https://www.tiktok.com/@{username}",
    },
    "youtube": {
        "url": "https://www.youtube.com/@{username}",
        "check_url": "https://www.youtube.com/@{username}",
    },
    "pinterest": {
        "url": "https://www.pinterest.com/{username}/",
        "check_url": "https://www.pinterest.com/{username}/",
    },
    "medium": {
        "url": "https://medium.com/@{username}",
        "check_url": "https://medium.com/@{username}",
    },
    "twitch": {
        "url": "https://www.twitch.tv/{username}",
        "check_url": "https://www.twitch.tv/{username}",
    },
    "snapchat": {
        "url": "https://www.snapchat.com/add/{username}",
        "check_url": "https://www.snapchat.com/add/{username}",
    },
    "facebook": {
        "url": "https://www.facebook.com/{username}",
        "check_url": "https://www.facebook.com/{username}",
    },
    "keybase": {
        "url": "https://keybase.io/{username}",
        "check_url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}",
    },
    "hackernews": {
        "url": "https://news.ycombinator.com/user?id={username}",
        "check_url": "https://hacker-news.firebaseio.com/v0/user/{username}.json",
    },
    "mastodon": {
        "url": "https://mastodon.social/@{username}",
        "check_url": "https://mastodon.social/@{username}",
    },
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/json",
    "Accept-Language": "en-US,en;q=0.9",
}


def _clean_username(target: str) -> str:
    """Extract username from URL or @mention."""
    target = target.strip()
    # Remove @ prefix
    if target.startswith("@"):
        target = target[1:]
    # Extract from URL
    for platform in ["twitter.com", "x.com", "instagram.com", "github.com",
                     "linkedin.com/in", "reddit.com/user", "tiktok.com/@"]:
        if platform in target:
            parts = target.rstrip("/").split("/")
            target = parts[-1].lstrip("@")
            break
    return target


# ---------------------------------------------------------------------------
# Account Discovery
# ---------------------------------------------------------------------------

def account_discovery(target: str, progress_callback=None) -> Dict:
    """
    Discover social media accounts for a username across multiple platforms.
    Uses HTTP HEAD/GET requests to check if profiles exist.
    """
    username = _clean_username(target)
    results = {
        "username": username,
        "found": [],
        "not_found": [],
        "errors": [],
        "total_checked": 0,
    }

    if progress_callback:
        progress_callback(f"Searching for '{username}' across {len(PLATFORMS)} platforms...")

    def check_platform(platform_name, platform_info):
        """Check if username exists on a platform."""
        url = platform_info["check_url"].format(username=username)
        try:
            resp = requests.get(url, headers=HEADERS, timeout=10,
                              allow_redirects=True, verify=False)

            # Platform-specific detection
            if platform_name == "github":
                if resp.status_code == 200:
                    data = resp.json()
                    return platform_name, True, {
                        "url": platform_info["url"].format(username=username),
                        "name": data.get("name", ""),
                        "bio": data.get("bio", ""),
                        "followers": data.get("followers", 0),
                        "repos": data.get("public_repos", 0),
                        "created": data.get("created_at", ""),
                    }
            elif platform_name == "reddit":
                if resp.status_code == 200:
                    try:
                        data = resp.json().get("data", {})
                        return platform_name, True, {
                            "url": platform_info["url"].format(username=username),
                            "karma": data.get("total_karma", 0),
                            "created": data.get("created_utc", 0),
                        }
                    except (json.JSONDecodeError, KeyError):
                        pass
            elif platform_name == "hackernews":
                if resp.status_code == 200 and resp.text != "null":
                    try:
                        data = resp.json()
                        return platform_name, True, {
                            "url": platform_info["url"].format(username=username),
                            "karma": data.get("karma", 0),
                            "about": data.get("about", "")[:100],
                        }
                    except (json.JSONDecodeError, KeyError):
                        pass
            elif platform_name == "keybase":
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get("them") and len(data["them"]) > 0 and data["them"][0]:
                            return platform_name, True, {
                                "url": platform_info["url"].format(username=username),
                            }
                    except (json.JSONDecodeError, KeyError, TypeError):
                        pass
                return platform_name, False, None
            else:
                # Generic check: 200 = found, 404 = not found
                if resp.status_code == 200:
                    # Additional check: some sites return 200 with "not found" page
                    body_lower = resp.text[:5000].lower()
                    not_found_indicators = [
                        "page not found", "user not found", "this page isn",
                        "sorry, this page", "nothing here", "doesn't exist",
                        "account suspended", "this account doesn",
                        "profile not found", "no user found", "404",
                        "we couldn't find", "not available", "does not exist",
                        "hmm...this page", "oops!", "something went wrong",
                    ]
                    # Platform-specific false positive checks
                    if platform_name == "medium":
                        # Medium shows a generic page for non-existent users
                        if "we couldn" in body_lower or "out of nothing" in body_lower or "page not found" in body_lower:
                            return platform_name, False, None
                        # Check if it's actually a profile page with content
                        if "@" + username.lower() not in body_lower and username.lower() not in body_lower:
                            return platform_name, False, None
                    elif platform_name == "snapchat":
                        # Snapchat always returns 200
                        if "add me on snapchat" not in body_lower and username.lower() not in body_lower:
                            return platform_name, False, None
                    elif platform_name == "pinterest":
                        if "profile not found" in body_lower or username.lower() not in body_lower:
                            return platform_name, False, None

                    if not any(ind in body_lower for ind in not_found_indicators):
                        return platform_name, True, {
                            "url": platform_info["url"].format(username=username),
                        }

            return platform_name, False, None

        except requests.exceptions.Timeout:
            return platform_name, None, "timeout"
        except requests.exceptions.ConnectionError:
            return platform_name, None, "connection_error"
        except Exception as e:
            return platform_name, None, str(e)

    # Check platforms in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(check_platform, name, info): name
            for name, info in PLATFORMS.items()
        }

        for future in as_completed(futures):
            platform_name, found, data = future.result()
            results["total_checked"] += 1

            if found is True:
                entry = {"platform": platform_name}
                if isinstance(data, dict):
                    entry.update(data)
                results["found"].append(entry)
                if progress_callback:
                    progress_callback(f"[FOUND] {platform_name}: {entry.get('url', '')}")
            elif found is False:
                results["not_found"].append(platform_name)
            else:
                results["errors"].append(f"{platform_name}: {data}")

            if progress_callback and results["total_checked"] % 5 == 0:
                progress_callback(f"Checked {results['total_checked']}/{len(PLATFORMS)} platforms...")

    return results


# ---------------------------------------------------------------------------
# Content Analysis (GitHub-based — the only platform with a free public API)
# ---------------------------------------------------------------------------

def content_analysis(target: str, progress_callback=None) -> Dict:
    """
    Analyze publicly available content for a user.
    Uses GitHub API (free, no key needed) for code/repo analysis.
    """
    username = _clean_username(target)
    results = {
        "username": username,
        "github": None,
        "errors": [],
    }

    if progress_callback:
        progress_callback(f"Analyzing public content for '{username}'...")

    # GitHub repos and activity
    try:
        if progress_callback:
            progress_callback("Fetching GitHub repositories...")

        resp = requests.get(f"https://api.github.com/users/{username}/repos?per_page=100&sort=updated",
                          headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            repos = resp.json()
            languages = {}
            topics = []
            total_stars = 0

            for repo in repos:
                lang = repo.get("language")
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1
                total_stars += repo.get("stargazers_count", 0)
                topics.extend(repo.get("topics", []))

            results["github"] = {
                "repos": len(repos),
                "languages": dict(sorted(languages.items(), key=lambda x: -x[1])),
                "total_stars": total_stars,
                "topics": list(set(topics))[:20],
                "recent_repos": [
                    {"name": r["name"], "description": r.get("description", ""), "stars": r["stargazers_count"]}
                    for r in repos[:10]
                ],
            }

            if progress_callback:
                progress_callback(f"GitHub: {len(repos)} repos, {len(languages)} languages, {total_stars} stars")
        elif resp.status_code == 404:
            results["github"] = {"error": "User not found on GitHub"}
        else:
            results["github"] = {"error": f"GitHub API returned {resp.status_code}"}

    except Exception as e:
        results["errors"].append(f"GitHub analysis: {e}")

    return results


# ---------------------------------------------------------------------------
# Network Mapping (GitHub followers/following)
# ---------------------------------------------------------------------------

def network_mapping(target: str, progress_callback=None) -> Dict:
    """Map social connections using GitHub's public API."""
    username = _clean_username(target)
    results = {
        "username": username,
        "followers": [],
        "following": [],
        "mutual": [],
        "errors": [],
    }

    if progress_callback:
        progress_callback(f"Mapping network connections for '{username}'...")

    try:
        # Followers
        if progress_callback:
            progress_callback("Fetching followers...")
        resp = requests.get(f"https://api.github.com/users/{username}/followers?per_page=100",
                          headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            results["followers"] = [u["login"] for u in resp.json()]

        # Following
        if progress_callback:
            progress_callback("Fetching following...")
        resp = requests.get(f"https://api.github.com/users/{username}/following?per_page=100",
                          headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            results["following"] = [u["login"] for u in resp.json()]

        # Mutual connections
        followers_set = set(results["followers"])
        following_set = set(results["following"])
        results["mutual"] = sorted(followers_set & following_set)

        if progress_callback:
            progress_callback(
                f"Network: {len(results['followers'])} followers, "
                f"{len(results['following'])} following, "
                f"{len(results['mutual'])} mutual"
            )

    except Exception as e:
        results["errors"].append(str(e))

    return results


# ---------------------------------------------------------------------------
# Timeline Reconstruction (GitHub events)
# ---------------------------------------------------------------------------

def timeline_recon(target: str, progress_callback=None) -> Dict:
    """Reconstruct activity timeline from GitHub public events."""
    username = _clean_username(target)
    results = {
        "username": username,
        "events": [],
        "activity_hours": {},
        "activity_days": {},
        "errors": [],
    }

    if progress_callback:
        progress_callback(f"Reconstructing timeline for '{username}'...")

    try:
        resp = requests.get(f"https://api.github.com/users/{username}/events/public?per_page=100",
                          headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            events = resp.json()

            for event in events:
                event_type = event.get("type", "")
                created_at = event.get("created_at", "")
                repo_name = event.get("repo", {}).get("name", "")

                results["events"].append({
                    "type": event_type,
                    "repo": repo_name,
                    "date": created_at,
                })

                # Activity pattern analysis
                if created_at:
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        hour = dt.hour
                        day = dt.strftime("%A")
                        results["activity_hours"][hour] = results["activity_hours"].get(hour, 0) + 1
                        results["activity_days"][day] = results["activity_days"].get(day, 0) + 1
                    except Exception:
                        pass

            if progress_callback:
                progress_callback(f"Timeline: {len(events)} recent events analyzed")

    except Exception as e:
        results["errors"].append(str(e))

    return results


# ---------------------------------------------------------------------------
# Metadata Extraction (from public profile data)
# ---------------------------------------------------------------------------

def metadata_extraction(target: str, progress_callback=None) -> Dict:
    """Extract metadata from public profiles."""
    username = _clean_username(target)
    results = {
        "username": username,
        "metadata": {},
        "errors": [],
    }

    if progress_callback:
        progress_callback(f"Extracting metadata for '{username}'...")

    # GitHub profile metadata
    try:
        resp = requests.get(f"https://api.github.com/users/{username}",
                          headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            results["metadata"]["github"] = {
                "name": data.get("name"),
                "company": data.get("company"),
                "location": data.get("location"),
                "email": data.get("email"),
                "bio": data.get("bio"),
                "blog": data.get("blog"),
                "twitter_username": data.get("twitter_username"),
                "created_at": data.get("created_at"),
                "updated_at": data.get("updated_at"),
                "hireable": data.get("hireable"),
                "public_repos": data.get("public_repos"),
                "public_gists": data.get("public_gists"),
                "followers": data.get("followers"),
                "following": data.get("following"),
            }
            # Filter out None values
            results["metadata"]["github"] = {
                k: v for k, v in results["metadata"]["github"].items() if v is not None
            }

            if progress_callback:
                progress_callback(f"GitHub metadata: {len(results['metadata']['github'])} fields extracted")

    except Exception as e:
        results["errors"].append(f"GitHub metadata: {e}")

    return results


# ---------------------------------------------------------------------------
# Full Social Intel (runs all modules)
# ---------------------------------------------------------------------------

def full_social_intel(target: str, progress_callback=None) -> Dict:
    """Run all social media intelligence modules."""
    username = _clean_username(target)
    results = {
        "username": username,
        "account_discovery": None,
        "content_analysis": None,
        "network_mapping": None,
        "timeline": None,
        "metadata": None,
    }

    if progress_callback:
        progress_callback(f"[PHASE 1/5] Account discovery for '{username}'...")
    results["account_discovery"] = account_discovery(target, progress_callback)

    if progress_callback:
        progress_callback(f"[PHASE 2/5] Content analysis...")
    results["content_analysis"] = content_analysis(target, progress_callback)

    if progress_callback:
        progress_callback(f"[PHASE 3/5] Network mapping...")
    results["network_mapping"] = network_mapping(target, progress_callback)

    if progress_callback:
        progress_callback(f"[PHASE 4/5] Timeline reconstruction...")
    results["timeline"] = timeline_recon(target, progress_callback)

    if progress_callback:
        progress_callback(f"[PHASE 5/5] Metadata extraction...")
    results["metadata"] = metadata_extraction(target, progress_callback)

    return results
