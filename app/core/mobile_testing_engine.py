# app/core/mobile_testing_engine.py
"""OWASP Mobile Top 10 2024 penetration testing engine.

Provides guided testing workflows, platform-specific checklists,
progress tracking, and finding creation with OWASP Mobile category mapping.
"""

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class MobilePlatform(Enum):
    """Supported mobile platforms."""

    ANDROID = "android"
    IOS = "ios"
    CROSS_PLATFORM = "cross_platform"


class OWASPMobileCategory(Enum):
    """OWASP Mobile Top 10 2024 categories."""

    M1 = "M1:2024 Improper Credential Usage"
    M2 = "M2:2024 Inadequate Supply Chain Security"
    M3 = "M3:2024 Insecure Authentication/Authorization"
    M4 = "M4:2024 Insufficient Input/Output Validation"
    M5 = "M5:2024 Insecure Communication"
    M6 = "M6:2024 Inadequate Privacy Controls"
    M7 = "M7:2024 Insufficient Binary Protections"
    M8 = "M8:2024 Security Misconfiguration"
    M9 = "M9:2024 Insecure Data Storage"
    M10 = "M10:2024 Insufficient Cryptography"


class CheckStatus(Enum):
    """Status of a checklist item."""

    NOT_STARTED = "not_started"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class MobileCheckItem:
    """A single check item in a mobile testing checklist."""

    id: str
    category: OWASPMobileCategory
    name: str
    description: str
    platform: MobilePlatform
    is_automated: bool = False
    status: CheckStatus = CheckStatus.NOT_STARTED
    notes: str = ""
    completed_at: Optional[str] = None


@dataclass
class MobileTestCategory:
    """A testing category containing multiple check items."""

    category: OWASPMobileCategory
    name: str
    description: str
    check_items: List[MobileCheckItem] = field(default_factory=list)

    @property
    def total_checks(self) -> int:
        """Total number of check items in this category."""
        return len(self.check_items)

    @property
    def completed_checks(self) -> int:
        """Number of completed (passed or failed) check items."""
        return sum(
            1 for item in self.check_items if item.status in (CheckStatus.PASSED, CheckStatus.FAILED)
        )

    @property
    def pending_checks(self) -> int:
        """Number of pending (not_started) check items."""
        return sum(
            1 for item in self.check_items if item.status == CheckStatus.NOT_STARTED
        )


@dataclass
class MobileFinding:
    """A finding discovered during mobile application testing."""

    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    owasp_category: OWASPMobileCategory
    platform: MobilePlatform
    description: str
    impact: str
    remediation: str
    evidence: str = ""
    cwe_id: str = ""
    discovered_at: str = ""
    tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# OWASP Mobile Top 10 2024 Check Items
# ---------------------------------------------------------------------------

def _build_owasp_mobile_checklists() -> Dict[OWASPMobileCategory, List[dict]]:
    """Build the full set of OWASP Mobile Top 10 2024 check items.

    Returns a dict mapping category to list of check item definitions.
    Each definition has: name, description, platform.
    """
    return {
        OWASPMobileCategory.M1: [
            {
                "name": "Hardcoded credentials check",
                "description": "Search application binary and resources for hardcoded API keys, passwords, or tokens",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Credential storage mechanism review",
                "description": "Verify credentials are stored using platform-secure storage (Keychain/Keystore)",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Android Keystore usage validation",
                "description": "Confirm Android app uses Android Keystore for sensitive credential storage",
                "platform": MobilePlatform.ANDROID,
                "is_automated": False,
            },
            {
                "name": "iOS Keychain usage validation",
                "description": "Confirm iOS app uses Keychain Services with appropriate protection class",
                "platform": MobilePlatform.IOS,
                "is_automated": False,
            },
            {
                "name": "Credential transmission security",
                "description": "Verify credentials are transmitted only over encrypted channels",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "OAuth/token refresh mechanism",
                "description": "Validate proper token lifecycle management and secure refresh flows",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
        ],
        OWASPMobileCategory.M2: [
            {
                "name": "Third-party library inventory",
                "description": "Enumerate all third-party dependencies and their versions",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Known vulnerability scan of dependencies",
                "description": "Check all dependencies against known CVE databases",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Gradle dependency verification (Android)",
                "description": "Verify dependency checksum validation is enabled in Gradle builds",
                "platform": MobilePlatform.ANDROID,
                "is_automated": False,
            },
            {
                "name": "CocoaPods/SPM integrity check (iOS)",
                "description": "Verify package manager integrity checks for iOS dependencies",
                "platform": MobilePlatform.IOS,
                "is_automated": False,
            },
            {
                "name": "SDK permissions audit",
                "description": "Review permissions requested by third-party SDKs for excessive access",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Supply chain signature verification",
                "description": "Verify code signing and provenance of integrated libraries",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
        ],
        OWASPMobileCategory.M3: [
            {
                "name": "Biometric authentication bypass",
                "description": "Attempt to bypass biometric authentication mechanisms",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Session token management review",
                "description": "Verify session tokens are properly generated, rotated, and invalidated",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Local authentication bypass (Android)",
                "description": "Test for client-side authentication bypass via Frida/Objection on Android",
                "platform": MobilePlatform.ANDROID,
                "is_automated": False,
            },
            {
                "name": "Local authentication bypass (iOS)",
                "description": "Test for client-side authentication bypass via Frida/Objection on iOS",
                "platform": MobilePlatform.IOS,
                "is_automated": False,
            },
            {
                "name": "Authorization enforcement testing",
                "description": "Verify server-side authorization checks cannot be bypassed",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Multi-factor authentication review",
                "description": "Test MFA implementation for bypass and downgrade attacks",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Account lockout mechanism",
                "description": "Verify brute-force protections are enforced server-side",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
        ],
        OWASPMobileCategory.M4: [
            {
                "name": "Input validation testing",
                "description": "Test all input fields for injection vulnerabilities (SQL, XSS, command)",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Deep link/URL scheme injection",
                "description": "Test custom URL schemes and deep links for injection attacks",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Intent injection (Android)",
                "description": "Test exported activities and broadcast receivers for intent injection",
                "platform": MobilePlatform.ANDROID,
                "is_automated": False,
            },
            {
                "name": "Pasteboard data leakage (iOS)",
                "description": "Check if sensitive data is exposed via iOS pasteboard",
                "platform": MobilePlatform.IOS,
                "is_automated": False,
            },
            {
                "name": "WebView JavaScript interface abuse",
                "description": "Test WebView configurations for JavaScript bridge exploitation",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Output encoding validation",
                "description": "Verify proper output encoding to prevent rendering injection",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
        ],
        OWASPMobileCategory.M5: [
            {
                "name": "Certificate pinning bypass",
                "description": "Attempt to bypass SSL/TLS certificate pinning using Frida or Objection",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Network Security Config review (Android)",
                "description": "Analyze Android Network Security Configuration for weaknesses",
                "platform": MobilePlatform.ANDROID,
                "is_automated": True,
            },
            {
                "name": "App Transport Security review (iOS)",
                "description": "Analyze iOS ATS configuration for exceptions allowing insecure connections",
                "platform": MobilePlatform.IOS,
                "is_automated": True,
            },
            {
                "name": "TLS version and cipher suite analysis",
                "description": "Verify minimum TLS 1.2 usage with strong cipher suites",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Man-in-the-middle interception test",
                "description": "Intercept traffic with proxy to identify insecure communications",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Custom protocol security review",
                "description": "Review non-HTTP protocols for encryption and authentication",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
        ],
        OWASPMobileCategory.M6: [
            {
                "name": "PII data collection audit",
                "description": "Identify all personally identifiable information collected by the app",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Privacy policy compliance check",
                "description": "Verify data collection matches stated privacy policy",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Advertising/tracking SDK review",
                "description": "Identify and assess tracking SDKs for privacy impact",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Data minimization assessment",
                "description": "Verify only necessary data is collected and retained",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Consent mechanism validation",
                "description": "Verify proper user consent flows before data collection",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
        ],
        OWASPMobileCategory.M7: [
            {
                "name": "Root/jailbreak detection bypass",
                "description": "Attempt to bypass root/jailbreak detection mechanisms",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Code obfuscation assessment",
                "description": "Evaluate effectiveness of code obfuscation (ProGuard/R8 or equivalent)",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Anti-tampering mechanism test",
                "description": "Test integrity checks and anti-tampering controls",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Debugger detection bypass",
                "description": "Attempt to attach debugger bypassing anti-debug protections",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Android APK reverse engineering",
                "description": "Decompile APK using jadx/apktool and analyze code",
                "platform": MobilePlatform.ANDROID,
                "is_automated": True,
            },
            {
                "name": "iOS binary analysis",
                "description": "Analyze iOS binary for symbols, class dumps, and protections (PIE, ARC, stack canaries)",
                "platform": MobilePlatform.IOS,
                "is_automated": True,
            },
            {
                "name": "Runtime instrumentation (Frida)",
                "description": "Use Frida to hook and modify runtime behavior",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
        ],
        OWASPMobileCategory.M8: [
            {
                "name": "Debug mode check",
                "description": "Verify application is not built in debug mode for release",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Backup allowance review (Android)",
                "description": "Check android:allowBackup flag and backup extraction",
                "platform": MobilePlatform.ANDROID,
                "is_automated": True,
            },
            {
                "name": "Exported component review (Android)",
                "description": "Review exported activities, services, receivers, and content providers",
                "platform": MobilePlatform.ANDROID,
                "is_automated": True,
            },
            {
                "name": "Entitlements review (iOS)",
                "description": "Review iOS entitlements for excessive capabilities",
                "platform": MobilePlatform.IOS,
                "is_automated": True,
            },
            {
                "name": "Permission over-provisioning check",
                "description": "Identify unnecessary permissions requested by the application",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Default configuration assessment",
                "description": "Check for insecure default settings in frameworks and SDKs",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
        ],
        OWASPMobileCategory.M9: [
            {
                "name": "SharedPreferences/UserDefaults analysis",
                "description": "Check for sensitive data in SharedPreferences (Android) or UserDefaults (iOS)",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "SQLite database inspection",
                "description": "Examine local SQLite databases for unencrypted sensitive data",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "File system storage review",
                "description": "Check internal/external storage for sensitive file contents",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Cache and temporary file review",
                "description": "Inspect HTTP cache, image cache, and temp files for data leaks",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Logging output review",
                "description": "Check logcat/console logs for sensitive information leakage",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Clipboard data exposure",
                "description": "Verify sensitive data is not exposed via clipboard mechanisms",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "IPC data leakage (Android)",
                "description": "Check content providers and intents for data exposure to other apps",
                "platform": MobilePlatform.ANDROID,
                "is_automated": True,
            },
            {
                "name": "Keychain accessibility review (iOS)",
                "description": "Verify Keychain items use appropriate protection classes",
                "platform": MobilePlatform.IOS,
                "is_automated": False,
            },
        ],
        OWASPMobileCategory.M10: [
            {
                "name": "Encryption algorithm assessment",
                "description": "Identify cryptographic algorithms used and verify strength (no DES, RC4, MD5)",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Key management review",
                "description": "Verify cryptographic keys are not hardcoded and are properly managed",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Random number generation audit",
                "description": "Verify use of cryptographically secure random number generators",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Custom cryptography detection",
                "description": "Identify and flag any custom/homebrew cryptographic implementations",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": True,
            },
            {
                "name": "Key derivation function review",
                "description": "Verify proper KDF usage (PBKDF2, Argon2) with appropriate iterations",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
            {
                "name": "Certificate validation implementation",
                "description": "Review certificate validation logic for bypass vulnerabilities",
                "platform": MobilePlatform.CROSS_PLATFORM,
                "is_automated": False,
            },
        ],
    }


# Pre-built checklist data accessible externally
OWASP_MOBILE_CHECKLISTS = _build_owasp_mobile_checklists()


# ---------------------------------------------------------------------------
# Mobile Testing Engine
# ---------------------------------------------------------------------------

class MobileTestingEngine(QObject):
    """Engine for OWASP Mobile Top 10 2024 penetration testing workflows.

    Provides platform-specific checklists, progress tracking, and finding
    creation with OWASP Mobile category and platform tags.
    """

    # Signals
    check_completed = pyqtSignal(str, str)  # category_id, check_item_id
    finding_created = pyqtSignal(dict)  # finding data dict

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._platform: MobilePlatform = MobilePlatform.CROSS_PLATFORM
        self._categories: Dict[OWASPMobileCategory, MobileTestCategory] = {}
        self._findings: List[MobileFinding] = []
        self._database = None
        self._initialize_categories()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def platform(self) -> MobilePlatform:
        """Currently selected target platform."""
        return self._platform

    @property
    def categories(self) -> Dict[OWASPMobileCategory, MobileTestCategory]:
        """All testing categories with their check items."""
        return self._categories

    @property
    def findings(self) -> List[MobileFinding]:
        """All findings created during this session."""
        return self._findings

    @property
    def database(self):
        """Optional engagement database for persistence."""
        return self._database

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_database(self, db) -> None:
        """Set the engagement database for finding persistence."""
        self._database = db

    def set_platform(self, platform: MobilePlatform) -> None:
        """Set the target platform and rebuild checklists.

        Filters check items to show only those relevant to the
        selected platform (platform-specific + cross-platform items).
        """
        self._platform = platform
        self._initialize_categories()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _initialize_categories(self) -> None:
        """Build testing categories with check items for the current platform."""
        self._categories = {}
        for category_enum, check_defs in OWASP_MOBILE_CHECKLISTS.items():
            filtered_checks = []
            for idx, check_def in enumerate(check_defs):
                item_platform = check_def["platform"]
                # Include cross-platform items always, plus platform-specific
                if (
                    self._platform == MobilePlatform.CROSS_PLATFORM
                    or item_platform == MobilePlatform.CROSS_PLATFORM
                    or item_platform == self._platform
                ):
                    check_item = MobileCheckItem(
                        id=f"{category_enum.name}-{idx + 1:02d}",
                        category=category_enum,
                        name=check_def["name"],
                        description=check_def["description"],
                        platform=item_platform,
                        is_automated=check_def.get("is_automated", False),
                        status=CheckStatus.NOT_STARTED,
                    )
                    filtered_checks.append(check_item)

            cat_name = category_enum.value.split(" ", 1)[1] if " " in category_enum.value else category_enum.value
            test_category = MobileTestCategory(
                category=category_enum,
                name=cat_name,
                description=f"OWASP Mobile Top 10 2024 - {cat_name}",
                check_items=filtered_checks,
            )
            self._categories[category_enum] = test_category

    # ------------------------------------------------------------------
    # Checklist Operations
    # ------------------------------------------------------------------

    def mark_complete(self, check_item_id: str, notes: str = "") -> bool:
        """Mark a check item as passed.

        Args:
            check_item_id: The unique ID of the check item (e.g. 'M1-01').
            notes: Optional notes about the check result.

        Returns:
            True if the item was found and marked, False otherwise.
        """
        item = self._find_check_item(check_item_id)
        if item is None:
            return False

        item.status = CheckStatus.PASSED
        item.notes = notes
        item.completed_at = datetime.now(timezone.utc).isoformat()

        # Emit signal with category name and check item id
        self.check_completed.emit(item.category.name, check_item_id)
        return True

    def mark_not_applicable(self, check_item_id: str, notes: str = "") -> bool:
        """Mark a check item as skipped.

        Args:
            check_item_id: The unique ID of the check item.
            notes: Reason why this check was skipped.

        Returns:
            True if the item was found and marked, False otherwise.
        """
        item = self._find_check_item(check_item_id)
        if item is None:
            return False

        item.status = CheckStatus.SKIPPED
        item.notes = notes
        return True

    def mark_failed(self, check_item_id: str, notes: str = "") -> bool:
        """Mark a check item as failed (vulnerability found).

        Args:
            check_item_id: The unique ID of the check item.
            notes: Details about the failure.

        Returns:
            True if the item was found and marked, False otherwise.
        """
        item = self._find_check_item(check_item_id)
        if item is None:
            return False

        item.status = CheckStatus.FAILED
        item.notes = notes
        item.completed_at = datetime.now(timezone.utc).isoformat()

        # Emit signal with category name and check item id
        self.check_completed.emit(item.category.name, check_item_id)
        return True

    def reset_check(self, check_item_id: str) -> bool:
        """Reset a check item back to not_started status.

        Args:
            check_item_id: The unique ID of the check item.

        Returns:
            True if the item was found and reset, False otherwise.
        """
        item = self._find_check_item(check_item_id)
        if item is None:
            return False

        item.status = CheckStatus.NOT_STARTED
        item.notes = ""
        item.completed_at = None
        return True

    # ------------------------------------------------------------------
    # Progress Tracking
    # ------------------------------------------------------------------

    def get_progress(
        self, category: Optional[OWASPMobileCategory] = None
    ) -> Dict[str, int]:
        """Get progress metrics for a category or overall.

        Args:
            category: Specific category to get progress for.
                     If None, returns overall progress across all categories.

        Returns:
            Dict with keys: 'total', 'completed', 'not_started', 'passed', 'failed', 'skipped'
        """
        if category is not None:
            test_cat = self._categories.get(category)
            if test_cat is None:
                return {"total": 0, "completed": 0, "not_started": 0, "passed": 0, "failed": 0, "skipped": 0}
            return self._compute_progress(test_cat.check_items)

        # Overall progress across all categories
        all_items: List[MobileCheckItem] = []
        for test_cat in self._categories.values():
            all_items.extend(test_cat.check_items)
        return self._compute_progress(all_items)

    def get_category_progress(self) -> Dict[OWASPMobileCategory, Dict[str, int]]:
        """Get progress for each category.

        Returns:
            Dict mapping each category to its progress metrics.
        """
        result = {}
        for cat_enum, test_cat in self._categories.items():
            result[cat_enum] = self._compute_progress(test_cat.check_items)
        return result

    # ------------------------------------------------------------------
    # Finding Creation
    # ------------------------------------------------------------------

    def create_finding(
        self,
        title: str,
        severity: str,
        owasp_category: OWASPMobileCategory,
        platform: MobilePlatform,
        description: str,
        impact: str,
        remediation: str,
        evidence: str = "",
        cwe_id: str = "",
        tags: Optional[List[str]] = None,
    ) -> MobileFinding:
        """Create a mobile testing finding.

        Creates a finding tagged with the OWASP Mobile category and platform.
        Optionally persists to the engagement database if one is set.

        Args:
            title: Finding title.
            severity: Severity level (critical, high, medium, low, info).
            owasp_category: OWASP Mobile Top 10 category.
            platform: Target platform for this finding.
            description: Detailed description.
            impact: Business/security impact.
            remediation: Recommended fix.
            evidence: Supporting evidence text.
            cwe_id: CWE identifier if applicable.
            tags: Additional tags for categorization.

        Returns:
            The created MobileFinding instance.
        """
        finding_id = str(uuid.uuid4())
        # Build tags including OWASP category and platform
        finding_tags = tags or []
        finding_tags.append(f"owasp-mobile:{owasp_category.name}")
        finding_tags.append(f"platform:{platform.value}")

        finding = MobileFinding(
            id=finding_id,
            title=title,
            severity=severity,
            owasp_category=owasp_category,
            platform=platform,
            description=description,
            impact=impact,
            remediation=remediation,
            evidence=evidence,
            cwe_id=cwe_id,
            discovered_at=datetime.now(timezone.utc).isoformat(),
            tags=finding_tags,
        )

        self._findings.append(finding)
        self._persist_finding(finding)
        self.finding_created.emit(asdict(finding))
        return finding

    # ------------------------------------------------------------------
    # Query Methods
    # ------------------------------------------------------------------

    def get_checks_for_category(
        self, category: OWASPMobileCategory
    ) -> List[MobileCheckItem]:
        """Get all check items for a specific category.

        Args:
            category: The OWASP Mobile category.

        Returns:
            List of check items for that category.
        """
        test_cat = self._categories.get(category)
        if test_cat is None:
            return []
        return test_cat.check_items

    def get_all_categories(self) -> List[Dict]:
        """Get summary of all categories with progress info.

        Returns:
            List of dicts with category info and progress.
        """
        result = []
        for cat_enum, test_cat in self._categories.items():
            progress = self._compute_progress(test_cat.check_items)
            result.append({
                "category": cat_enum,
                "name": test_cat.name,
                "description": test_cat.description,
                "total": progress["total"],
                "completed": progress["completed"],
                "not_started": progress["not_started"],
                "passed": progress["passed"],
                "failed": progress["failed"],
                "skipped": progress["skipped"],
            })
        return result

    def get_findings_by_category(
        self, category: OWASPMobileCategory
    ) -> List[MobileFinding]:
        """Get all findings for a specific OWASP Mobile category.

        Args:
            category: The OWASP Mobile category to filter by.

        Returns:
            Filtered list of findings.
        """
        return [f for f in self._findings if f.owasp_category == category]

    def get_findings_by_platform(
        self, platform: MobilePlatform
    ) -> List[MobileFinding]:
        """Get all findings for a specific platform.

        Args:
            platform: The platform to filter by.

        Returns:
            Filtered list of findings.
        """
        return [f for f in self._findings if f.platform == platform]

    def reset(self) -> None:
        """Reset all checklists and findings to initial state."""
        self._findings = []
        self._initialize_categories()

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _find_check_item(self, check_item_id: str) -> Optional[MobileCheckItem]:
        """Find a check item by its ID across all categories."""
        for test_cat in self._categories.values():
            for item in test_cat.check_items:
                if item.id == check_item_id:
                    return item
        return None

    def _compute_progress(self, items: List[MobileCheckItem]) -> Dict[str, int]:
        """Compute progress metrics for a list of check items."""
        total = len(items)
        completed = sum(1 for i in items if i.status in (CheckStatus.PASSED, CheckStatus.FAILED))
        not_started = sum(1 for i in items if i.status == CheckStatus.NOT_STARTED)
        passed = sum(1 for i in items if i.status == CheckStatus.PASSED)
        failed = sum(1 for i in items if i.status == CheckStatus.FAILED)
        skipped = sum(1 for i in items if i.status == CheckStatus.SKIPPED)
        return {
            "total": total,
            "completed": completed,
            "not_started": not_started,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
        }

    def _persist_finding(self, finding: MobileFinding) -> Optional[int]:
        """Persist a finding to the engagement database if available.

        Returns:
            The database row ID if persisted, None otherwise.
        """
        if self._database is None:
            return None

        try:
            import json

            conn = self._database.get_connection()
            cursor = conn.execute(
                """INSERT INTO findings
                   (title, severity, description, impact, remediation,
                    cwe_id, category, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
                (
                    finding.title,
                    finding.severity,
                    finding.description,
                    finding.impact,
                    finding.remediation,
                    finding.cwe_id,
                    finding.owasp_category.value,
                    finding.discovered_at,
                    finding.discovered_at,
                ),
            )
            conn.commit()
            return cursor.lastrowid
        except Exception:
            return None
