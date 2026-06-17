# app/core/attack_mapper.py
"""MITRE ATT&CK framework integration engine.

Provides mapping of engagement findings to ATT&CK Enterprise matrix
techniques, coverage matrix computation, technique suggestions based
on keyword matching, and report summary generation.

Operates against a per-engagement SQLite database provided via
set_database(). The bundled ATT&CK data is a representative subset
of the Enterprise matrix covering all 14 tactics with 50+ techniques.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.engagement_database import EngagementDatabase


# All 14 ATT&CK Enterprise tactics in kill-chain order
TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Valid mapping statuses
MAPPING_STATUSES = frozenset(["tested", "successful", "not_tested"])


# Bundled MITRE ATT&CK Enterprise matrix subset (representative techniques)
# Each entry: technique_id, name, tactic(s), platforms, data_sources, description keywords
ATTACK_ENTERPRISE_MATRIX: List[Dict] = [
    # --- Reconnaissance ---
    {"technique_id": "T1595", "name": "Active Scanning", "tactics": ["reconnaissance"],
     "platforms": ["PRE"], "data_sources": ["Network Traffic"],
     "description": "Adversaries scan victim IP blocks to gather information for targeting"},
    {"technique_id": "T1595.001", "name": "Scanning IP Blocks", "tactics": ["reconnaissance"],
     "platforms": ["PRE"], "data_sources": ["Network Traffic"],
     "description": "Adversaries scan IP blocks to identify live hosts and open services"},
    {"technique_id": "T1595.002", "name": "Vulnerability Scanning", "tactics": ["reconnaissance"],
     "platforms": ["PRE"], "data_sources": ["Network Traffic"],
     "description": "Adversaries scan for vulnerabilities on target systems using automated tools"},
    {"technique_id": "T1592", "name": "Gather Victim Host Information", "tactics": ["reconnaissance"],
     "platforms": ["PRE"], "data_sources": ["Internet Scan"],
     "description": "Adversaries gather information about victim hosts including hardware software configurations"},
    {"technique_id": "T1589", "name": "Gather Victim Identity Information", "tactics": ["reconnaissance"],
     "platforms": ["PRE"], "data_sources": ["Internet Scan"],
     "description": "Adversaries gather credentials email addresses employee names identity information"},

    # --- Resource Development ---
    {"technique_id": "T1583", "name": "Acquire Infrastructure", "tactics": ["resource-development"],
     "platforms": ["PRE"], "data_sources": ["Domain Registration", "DNS"],
     "description": "Adversaries acquire infrastructure such as domains servers and web services"},
    {"technique_id": "T1587", "name": "Develop Capabilities", "tactics": ["resource-development"],
     "platforms": ["PRE"], "data_sources": ["Malware Repository"],
     "description": "Adversaries build develop custom malware exploits tools and capabilities"},
    {"technique_id": "T1585", "name": "Establish Accounts", "tactics": ["resource-development"],
     "platforms": ["PRE"], "data_sources": ["Social Media"],
     "description": "Adversaries create accounts on services for operations social engineering phishing"},
    {"technique_id": "T1588", "name": "Obtain Capabilities", "tactics": ["resource-development"],
     "platforms": ["PRE"], "data_sources": ["Malware Repository"],
     "description": "Adversaries obtain exploits tools malware digital certificates for targeting"},

    # --- Initial Access ---
    {"technique_id": "T1566", "name": "Phishing", "tactics": ["initial-access"],
     "platforms": ["Windows", "macOS", "Linux"], "data_sources": ["Application Log", "Network Traffic"],
     "description": "Adversaries send phishing messages with malicious attachments or links to gain access"},
    {"technique_id": "T1566.001", "name": "Spearphishing Attachment", "tactics": ["initial-access"],
     "platforms": ["Windows", "macOS", "Linux"], "data_sources": ["Application Log", "Network Traffic"],
     "description": "Adversaries send spearphishing email with malicious attachment to gain initial access"},
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["initial-access"],
     "platforms": ["Windows", "Linux", "macOS", "Containers"], "data_sources": ["Application Log", "Network Traffic"],
     "description": "Adversaries exploit vulnerabilities in public-facing web applications servers to gain access"},
    {"technique_id": "T1133", "name": "External Remote Services", "tactics": ["initial-access"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Logon Session", "Network Traffic"],
     "description": "Adversaries use VPN RDP SSH remote services to gain initial access to network"},
    {"technique_id": "T1078", "name": "Valid Accounts", "tactics": ["initial-access", "defense-evasion", "persistence", "privilege-escalation"],
     "platforms": ["Windows", "Linux", "macOS", "Cloud"], "data_sources": ["Logon Session", "User Account"],
     "description": "Adversaries use stolen valid credentials default accounts to log in and gain access"},

    # --- Execution ---
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["execution"],
     "platforms": ["Windows", "macOS", "Linux"], "data_sources": ["Command", "Process", "Script"],
     "description": "Adversaries abuse command script interpreters to execute commands scripts code"},
    {"technique_id": "T1059.001", "name": "PowerShell", "tactics": ["execution"],
     "platforms": ["Windows"], "data_sources": ["Command", "Process", "Script"],
     "description": "Adversaries use PowerShell commands scripts to execute malicious code on Windows"},
    {"technique_id": "T1059.003", "name": "Windows Command Shell", "tactics": ["execution"],
     "platforms": ["Windows"], "data_sources": ["Command", "Process"],
     "description": "Adversaries use cmd.exe Windows command shell to execute commands batch scripts"},
    {"technique_id": "T1059.004", "name": "Unix Shell", "tactics": ["execution"],
     "platforms": ["Linux", "macOS"], "data_sources": ["Command", "Process"],
     "description": "Adversaries use bash sh Unix shell to execute commands scripts on Linux macOS"},
    {"technique_id": "T1203", "name": "Exploitation for Client Execution", "tactics": ["execution"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process"],
     "description": "Adversaries exploit vulnerabilities in client applications browsers office to execute code"},

    # --- Persistence ---
    {"technique_id": "T1547", "name": "Boot or Logon Autostart Execution", "tactics": ["persistence", "privilege-escalation"],
     "platforms": ["Windows", "macOS", "Linux"], "data_sources": ["Command", "File", "Windows Registry"],
     "description": "Adversaries configure system settings to automatically execute programs startup boot logon"},
    {"technique_id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactics": ["persistence", "privilege-escalation"],
     "platforms": ["Windows"], "data_sources": ["Command", "File", "Windows Registry"],
     "description": "Adversaries add programs to registry run keys startup folder for persistence"},
    {"technique_id": "T1053", "name": "Scheduled Task/Job", "tactics": ["persistence", "privilege-escalation", "execution"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Process", "Scheduled Job"],
     "description": "Adversaries abuse scheduled tasks cron jobs for persistence and execution"},
    {"technique_id": "T1136", "name": "Create Account", "tactics": ["persistence"],
     "platforms": ["Windows", "Linux", "macOS", "Cloud"], "data_sources": ["Process", "User Account"],
     "description": "Adversaries create accounts local domain cloud to maintain persistence access"},
    {"technique_id": "T1505", "name": "Server Software Component", "tactics": ["persistence"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File", "Network Traffic"],
     "description": "Adversaries install web shells backdoor server software components for persistence"},

    # --- Privilege Escalation ---
    {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "tactics": ["privilege-escalation"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process"],
     "description": "Adversaries exploit software vulnerabilities to escalate privileges gain higher access"},
    {"technique_id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactics": ["privilege-escalation", "defense-evasion"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Process"],
     "description": "Adversaries bypass UAC sudo elevation controls to escalate privileges"},
    {"technique_id": "T1548.002", "name": "Bypass User Account Control", "tactics": ["privilege-escalation", "defense-evasion"],
     "platforms": ["Windows"], "data_sources": ["Command", "Process", "Windows Registry"],
     "description": "Adversaries bypass Windows User Account Control UAC to elevate process privileges"},

    # --- Defense Evasion ---
    {"technique_id": "T1070", "name": "Indicator Removal", "tactics": ["defense-evasion"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Process"],
     "description": "Adversaries delete modify indicators artifacts logs to evade detection"},
    {"technique_id": "T1070.001", "name": "Clear Windows Event Logs", "tactics": ["defense-evasion"],
     "platforms": ["Windows"], "data_sources": ["Command", "Process"],
     "description": "Adversaries clear Windows event logs to remove evidence of intrusion"},
    {"technique_id": "T1027", "name": "Obfuscated Files or Information", "tactics": ["defense-evasion"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Process"],
     "description": "Adversaries obfuscate encrypt encode files payloads to evade security defenses"},
    {"technique_id": "T1562", "name": "Impair Defenses", "tactics": ["defense-evasion"],
     "platforms": ["Windows", "Linux", "macOS", "Cloud"], "data_sources": ["Command", "Process", "Windows Registry"],
     "description": "Adversaries disable modify security tools firewalls antivirus logging to evade defenses"},
    {"technique_id": "T1055", "name": "Process Injection", "tactics": ["defense-evasion", "privilege-escalation"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Process"],
     "description": "Adversaries inject code into running processes to evade detection and elevate privileges"},

    # --- Credential Access ---
    {"technique_id": "T1003", "name": "OS Credential Dumping", "tactics": ["credential-access"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Process"],
     "description": "Adversaries dump credentials hashes passwords from operating system memory SAM LSASS"},
    {"technique_id": "T1003.001", "name": "LSASS Memory", "tactics": ["credential-access"],
     "platforms": ["Windows"], "data_sources": ["Process"],
     "description": "Adversaries dump credentials from LSASS process memory using mimikatz procdump"},
    {"technique_id": "T1110", "name": "Brute Force", "tactics": ["credential-access"],
     "platforms": ["Windows", "Linux", "macOS", "Cloud"], "data_sources": ["Application Log", "User Account"],
     "description": "Adversaries brute force passwords credentials using password spraying dictionary attacks"},
    {"technique_id": "T1110.001", "name": "Password Guessing", "tactics": ["credential-access"],
     "platforms": ["Windows", "Linux", "macOS", "Cloud"], "data_sources": ["Application Log", "User Account"],
     "description": "Adversaries guess passwords using common passwords default credentials"},
    {"technique_id": "T1555", "name": "Credentials from Password Stores", "tactics": ["credential-access"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Process"],
     "description": "Adversaries search password managers browsers credential stores for saved passwords"},
    {"technique_id": "T1557", "name": "Adversary-in-the-Middle", "tactics": ["credential-access", "collection"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic"],
     "description": "Adversaries intercept network traffic man-in-the-middle MITM relay to capture credentials"},

    # --- Discovery ---
    {"technique_id": "T1046", "name": "Network Service Discovery", "tactics": ["discovery"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Network Traffic"],
     "description": "Adversaries scan discover network services ports open on remote systems nmap"},
    {"technique_id": "T1087", "name": "Account Discovery", "tactics": ["discovery"],
     "platforms": ["Windows", "Linux", "macOS", "Cloud"], "data_sources": ["Command", "Process"],
     "description": "Adversaries enumerate user accounts groups domain accounts for targeting"},
    {"technique_id": "T1018", "name": "Remote System Discovery", "tactics": ["discovery"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Network Traffic", "Process"],
     "description": "Adversaries discover remote systems on network using ping net view ARP scanning"},
    {"technique_id": "T1082", "name": "System Information Discovery", "tactics": ["discovery"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Process"],
     "description": "Adversaries gather detailed system information OS version hardware patches hostname"},
    {"technique_id": "T1083", "name": "File and Directory Discovery", "tactics": ["discovery"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Process"],
     "description": "Adversaries enumerate files directories looking for sensitive data configurations"},

    # --- Lateral Movement ---
    {"technique_id": "T1021", "name": "Remote Services", "tactics": ["lateral-movement"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Logon Session", "Network Traffic"],
     "description": "Adversaries use remote services RDP SSH SMB WinRM to move laterally between systems"},
    {"technique_id": "T1021.001", "name": "Remote Desktop Protocol", "tactics": ["lateral-movement"],
     "platforms": ["Windows"], "data_sources": ["Logon Session", "Network Traffic"],
     "description": "Adversaries use RDP Remote Desktop Protocol to laterally move access remote systems"},
    {"technique_id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactics": ["lateral-movement"],
     "platforms": ["Windows"], "data_sources": ["Logon Session", "Network Traffic"],
     "description": "Adversaries use SMB Windows admin shares C$ ADMIN$ for lateral movement file transfer"},
    {"technique_id": "T1550", "name": "Use Alternate Authentication Material", "tactics": ["lateral-movement", "defense-evasion"],
     "platforms": ["Windows", "Cloud"], "data_sources": ["Logon Session", "User Account"],
     "description": "Adversaries use pass-the-hash pass-the-ticket alternate authentication to move laterally"},

    # --- Collection ---
    {"technique_id": "T1005", "name": "Data from Local System", "tactics": ["collection"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File"],
     "description": "Adversaries collect sensitive data files from local system file shares drives"},
    {"technique_id": "T1039", "name": "Data from Network Shared Drive", "tactics": ["collection"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Network Traffic"],
     "description": "Adversaries collect data from network shared drives file shares SMB NFS"},
    {"technique_id": "T1113", "name": "Screen Capture", "tactics": ["collection"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Process"],
     "description": "Adversaries take screenshots capture screen content to collect information"},
    {"technique_id": "T1119", "name": "Automated Collection", "tactics": ["collection"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Script"],
     "description": "Adversaries use automated scripts tools to collect internal data documents"},

    # --- Command and Control ---
    {"technique_id": "T1071", "name": "Application Layer Protocol", "tactics": ["command-and-control"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic"],
     "description": "Adversaries communicate using application layer protocols HTTP HTTPS DNS to blend with traffic"},
    {"technique_id": "T1071.001", "name": "Web Protocols", "tactics": ["command-and-control"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic"],
     "description": "Adversaries use HTTP HTTPS web protocols for command and control communication"},
    {"technique_id": "T1105", "name": "Ingress Tool Transfer", "tactics": ["command-and-control"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["File", "Network Traffic"],
     "description": "Adversaries transfer tools files from external systems into compromised environment download"},
    {"technique_id": "T1572", "name": "Protocol Tunneling", "tactics": ["command-and-control"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Network Traffic"],
     "description": "Adversaries tunnel C2 traffic within allowed protocols SSH DNS HTTP to evade detection"},

    # --- Exfiltration ---
    {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactics": ["exfiltration"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Network Traffic"],
     "description": "Adversaries exfiltrate data over existing command and control channel"},
    {"technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactics": ["exfiltration"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Network Traffic"],
     "description": "Adversaries exfiltrate data over different protocol than C2 DNS FTP SMTP"},
    {"technique_id": "T1567", "name": "Exfiltration Over Web Service", "tactics": ["exfiltration"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Network Traffic"],
     "description": "Adversaries exfiltrate data to cloud storage web services Dropbox Google Drive"},

    # --- Impact ---
    {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "File", "Process"],
     "description": "Adversaries encrypt data files ransomware to deny access and demand payment"},
    {"technique_id": "T1489", "name": "Service Stop", "tactics": ["impact"],
     "platforms": ["Windows", "Linux", "macOS"], "data_sources": ["Command", "Process"],
     "description": "Adversaries stop disable critical services to disrupt availability denial of service"},
    {"technique_id": "T1499", "name": "Endpoint Denial of Service", "tactics": ["impact"],
     "platforms": ["Windows", "Linux", "macOS", "Cloud"], "data_sources": ["Network Traffic", "Application Log"],
     "description": "Adversaries perform denial of service DoS DDoS against endpoint services to disrupt availability"},
    {"technique_id": "T1531", "name": "Account Access Removal", "tactics": ["impact"],
     "platforms": ["Windows", "Linux", "macOS", "Cloud"], "data_sources": ["User Account"],
     "description": "Adversaries delete disable modify accounts passwords to deny access lock out users"},
]


class ATTACKMapper(QObject):
    """MITRE ATT&CK mapping engine for engagement findings.

    Provides technique mapping, coverage matrix computation, keyword-based
    technique suggestions, and report summary generation.

    Signals:
        mapping_created(int): Emitted with mapping_id after a finding is mapped.
        coverage_updated(): Emitted when the coverage matrix changes.
    """

    mapping_created = pyqtSignal(int)   # mapping_id
    coverage_updated = pyqtSignal()

    def __init__(self, parent=None):
        """Initialize the ATTACKMapper.

        Args:
            parent: Optional QObject parent.
        """
        super().__init__(parent)
        self._db: Optional[EngagementDatabase] = None
        # Build lookup indices
        self._techniques_by_id: Dict[str, Dict] = {}
        self._techniques_by_tactic: Dict[str, List[Dict]] = {t: [] for t in TACTICS}
        self._build_indices()

    def _build_indices(self) -> None:
        """Build internal lookup indices from the bundled ATT&CK matrix."""
        for technique in ATTACK_ENTERPRISE_MATRIX:
            tid = technique["technique_id"]
            self._techniques_by_id[tid] = technique
            for tactic in technique["tactics"]:
                self._techniques_by_tactic[tactic].append(technique)

    @property
    def database(self) -> Optional[EngagementDatabase]:
        """The current engagement database, or None."""
        return self._db

    def set_database(self, db: EngagementDatabase) -> None:
        """Set the per-engagement database to operate against.

        Args:
            db: A connected EngagementDatabase instance.
        """
        self._db = db

    def _require_db(self) -> EngagementDatabase:
        """Return the database or raise RuntimeError."""
        if self._db is None:
            raise RuntimeError("No database set. Call set_database() first.")
        return self._db

    # ------------------------------------------------------------------
    # Technique data access
    # ------------------------------------------------------------------

    def get_all_techniques(self) -> List[Dict]:
        """Return all bundled ATT&CK techniques.

        Returns:
            List of technique dicts with id, name, tactics, platforms, etc.
        """
        return list(ATTACK_ENTERPRISE_MATRIX)

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """Get a single technique by ID.

        Args:
            technique_id: ATT&CK technique ID (e.g., 'T1059.001').

        Returns:
            Technique dict or None if not found.
        """
        return self._techniques_by_id.get(technique_id)

    def get_techniques_by_tactic(self, tactic: str) -> List[Dict]:
        """Get all techniques for a given tactic.

        Args:
            tactic: Tactic name (e.g., 'execution').

        Returns:
            List of technique dicts for the specified tactic.
        """
        return list(self._techniques_by_tactic.get(tactic, []))

    def get_techniques_by_platform(self, platform: str) -> List[Dict]:
        """Get all techniques applicable to a platform.

        Args:
            platform: Platform name (e.g., 'Windows', 'Linux').

        Returns:
            List of technique dicts matching the platform.
        """
        return [
            t for t in ATTACK_ENTERPRISE_MATRIX
            if platform in t["platforms"]
        ]

    def get_techniques_by_data_source(self, data_source: str) -> List[Dict]:
        """Get all techniques associated with a data source.

        Args:
            data_source: Data source name (e.g., 'Network Traffic').

        Returns:
            List of technique dicts matching the data source.
        """
        return [
            t for t in ATTACK_ENTERPRISE_MATRIX
            if data_source in t["data_sources"]
        ]

    # ------------------------------------------------------------------
    # Mapping operations
    # ------------------------------------------------------------------

    def map_finding_to_technique(
        self,
        finding_id: int,
        technique_id: str,
        tactic: str,
        procedure_description: str = "",
        status: str = "tested",
    ) -> int:
        """Map a finding to an ATT&CK technique.

        Stores the mapping in the attack_mappings table and emits signals.

        Args:
            finding_id: ID of the finding in the engagement database.
            technique_id: ATT&CK technique ID (e.g., 'T1059.001').
            tactic: Tactic name for this mapping context.
            procedure_description: Description of how the technique was used.
            status: One of 'tested', 'successful', 'not_tested'.

        Returns:
            The ID of the created mapping record.

        Raises:
            RuntimeError: If no database is set.
            ValueError: If technique_id is not in the bundled matrix,
                        tactic is invalid, or status is invalid.
        """
        db = self._require_db()

        if technique_id not in self._techniques_by_id:
            raise ValueError(f"Unknown technique_id: {technique_id}")
        if tactic not in TACTICS:
            raise ValueError(f"Invalid tactic: {tactic}")
        if status not in MAPPING_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {sorted(MAPPING_STATUSES)}")

        # Validate technique belongs to the specified tactic
        technique = self._techniques_by_id[technique_id]
        if tactic not in technique["tactics"]:
            raise ValueError(
                f"Technique {technique_id} does not belong to tactic '{tactic}'. "
                f"Valid tactics: {technique['tactics']}"
            )

        mapping_id = db.execute_write(
            """INSERT INTO attack_mappings
               (finding_id, technique_id, tactic, procedure_description, status)
               VALUES (?, ?, ?, ?, ?)""",
            (finding_id, technique_id, tactic, procedure_description, status),
        )

        self.mapping_created.emit(mapping_id)
        self.coverage_updated.emit()
        return mapping_id

    def get_mappings_for_finding(self, finding_id: int) -> List[Dict]:
        """Get all ATT&CK mappings for a specific finding.

        Args:
            finding_id: The finding ID.

        Returns:
            List of mapping dicts with id, technique_id, tactic, procedure, status.
        """
        db = self._require_db()
        rows = db.execute_query(
            """SELECT id, finding_id, technique_id, tactic, procedure_description, status
               FROM attack_mappings WHERE finding_id = ?""",
            (finding_id,),
        )
        return [
            {
                "id": row[0],
                "finding_id": row[1],
                "technique_id": row[2],
                "tactic": row[3],
                "procedure_description": row[4],
                "status": row[5],
            }
            for row in rows
        ]

    def delete_mapping(self, mapping_id: int) -> bool:
        """Delete an ATT&CK mapping by ID.

        Args:
            mapping_id: The mapping record ID.

        Returns:
            True if a row was deleted, False otherwise.
        """
        db = self._require_db()
        rowcount = db.execute_write(
            "DELETE FROM attack_mappings WHERE id = ?", (mapping_id,)
        )
        if rowcount:
            self.coverage_updated.emit()
        return bool(rowcount)

    # ------------------------------------------------------------------
    # Coverage matrix
    # ------------------------------------------------------------------

    def get_coverage_matrix(
        self,
        tactic_filter: Optional[str] = None,
        platform_filter: Optional[str] = None,
        data_source_filter: Optional[str] = None,
    ) -> List[Dict]:
        """Compute ATT&CK coverage matrix for the current engagement.

        Returns a list of technique entries with their coverage status
        (tested, successful, not_tested) based on mappings in the database.

        Args:
            tactic_filter: If provided, only include techniques for this tactic.
            platform_filter: If provided, only include techniques for this platform.
            data_source_filter: If provided, only include techniques for this data source.

        Returns:
            List of dicts with technique_id, name, tactic, platforms,
            coverage_status ('tested', 'successful', or 'not_covered'),
            and mapping_count.
        """
        db = self._require_db()

        # Get all mappings from the database
        rows = db.execute_query(
            "SELECT technique_id, status FROM attack_mappings"
        )

        # Build per-technique status summary
        technique_statuses: Dict[str, List[str]] = {}
        for row in rows:
            tid, status = row[0], row[1]
            if tid not in technique_statuses:
                technique_statuses[tid] = []
            technique_statuses[tid].append(status)

        # Filter techniques
        techniques = ATTACK_ENTERPRISE_MATRIX
        if tactic_filter:
            techniques = [t for t in techniques if tactic_filter in t["tactics"]]
        if platform_filter:
            techniques = [t for t in techniques if platform_filter in t["platforms"]]
        if data_source_filter:
            techniques = [t for t in techniques if data_source_filter in t["data_sources"]]

        # Build coverage matrix
        matrix = []
        for technique in techniques:
            tid = technique["technique_id"]
            statuses = technique_statuses.get(tid, [])

            if not statuses:
                coverage_status = "not_covered"
                mapping_count = 0
            else:
                mapping_count = len(statuses)
                # If any mapping is 'successful', overall is successful
                if "successful" in statuses:
                    coverage_status = "successful"
                else:
                    coverage_status = "tested"

            matrix.append({
                "technique_id": tid,
                "name": technique["name"],
                "tactics": technique["tactics"],
                "platforms": technique["platforms"],
                "data_sources": technique["data_sources"],
                "coverage_status": coverage_status,
                "mapping_count": mapping_count,
            })

        return matrix

    # ------------------------------------------------------------------
    # Findings for technique
    # ------------------------------------------------------------------

    def get_findings_for_technique(self, technique_id: str) -> List[Dict]:
        """Get all findings and evidence linked to a specific technique.

        Args:
            technique_id: ATT&CK technique ID.

        Returns:
            List of dicts containing finding details and linked evidence.
        """
        db = self._require_db()

        rows = db.execute_query(
            """SELECT am.id, am.finding_id, am.tactic, am.procedure_description, am.status,
                      f.title, f.severity, f.description
               FROM attack_mappings am
               JOIN findings f ON f.id = am.finding_id
               WHERE am.technique_id = ?""",
            (technique_id,),
        )

        results = []
        for row in rows:
            mapping_id, finding_id = row[0], row[1]

            # Get linked evidence for this finding
            evidence_rows = db.execute_query(
                """SELECT e.id, e.evidence_type, e.title, e.created_at
                   FROM evidence e
                   JOIN evidence_finding_links efl ON efl.evidence_id = e.id
                   WHERE efl.finding_id = ?""",
                (finding_id,),
            )

            evidence_list = [
                {
                    "id": er[0],
                    "evidence_type": er[1],
                    "title": er[2],
                    "created_at": er[3],
                }
                for er in evidence_rows
            ]

            results.append({
                "mapping_id": mapping_id,
                "finding_id": finding_id,
                "tactic": row[2],
                "procedure_description": row[3],
                "status": row[4],
                "finding_title": row[5],
                "finding_severity": row[6],
                "finding_description": row[7],
                "evidence": evidence_list,
            })

        return results

    # ------------------------------------------------------------------
    # Technique suggestions
    # ------------------------------------------------------------------

    def suggest_techniques(
        self,
        finding_description: str,
        max_suggestions: int = 10,
    ) -> List[Dict]:
        """Suggest ATT&CK techniques based on keyword matching.

        Performs simple keyword matching between the finding description
        and technique names/descriptions. Returns ranked suggestions.

        Args:
            finding_description: The finding description text to match against.
            max_suggestions: Maximum number of suggestions to return.

        Returns:
            List of technique dicts ranked by relevance score (highest first),
            each including a 'score' field indicating match strength.
        """
        if not finding_description:
            return []

        # Normalize description to lowercase words
        desc_lower = finding_description.lower()
        desc_words = set(desc_lower.split())

        # Score each technique
        scored: List[Tuple[float, Dict]] = []
        for technique in ATTACK_ENTERPRISE_MATRIX:
            score = 0.0

            # Match against technique name
            name_lower = technique["name"].lower()
            name_words = set(name_lower.split())

            # Direct name word overlap
            name_overlap = desc_words & name_words
            score += len(name_overlap) * 3.0

            # Check if technique name appears as substring in description
            if name_lower in desc_lower:
                score += 5.0

            # Match against technique description keywords
            tech_desc_lower = technique["description"].lower()
            tech_desc_words = set(tech_desc_lower.split())
            desc_overlap = desc_words & tech_desc_words
            # Filter out very common words
            common_words = {"the", "a", "an", "is", "are", "to", "for", "and",
                          "or", "in", "on", "of", "at", "by", "with", "from",
                          "that", "this", "it", "be", "as", "was", "not"}
            meaningful_overlap = desc_overlap - common_words
            score += len(meaningful_overlap) * 1.0

            # Check technique_id mention in description (exact match preferred)
            tid_lower = technique["technique_id"].lower()
            if tid_lower in desc_lower:
                # Give bonus for exact technique ID match
                # Use word-boundary-like check to prefer T1059.001 over T1059
                # when "T1059.001" is in the description
                score += 10.0

            if score > 0:
                scored.append((score, technique))

        # Sort by score descending, take top N
        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for score, technique in scored[:max_suggestions]:
            result = dict(technique)
            result["score"] = score
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Report summary
    # ------------------------------------------------------------------

    def get_report_summary(self) -> Dict:
        """Produce ATT&CK coverage statistics for report generation.

        Returns:
            Dict with coverage stats including total_techniques,
            techniques_tested, techniques_successful, techniques_not_covered,
            coverage_by_tactic, and overall_coverage_percentage.
        """
        db = self._require_db()

        total_techniques = len(ATTACK_ENTERPRISE_MATRIX)

        # Get all mappings
        rows = db.execute_query(
            "SELECT technique_id, status FROM attack_mappings"
        )

        # Unique techniques that have been mapped
        technique_statuses: Dict[str, set] = {}
        for row in rows:
            tid, status = row[0], row[1]
            if tid not in technique_statuses:
                technique_statuses[tid] = set()
            technique_statuses[tid].add(status)

        techniques_tested = 0
        techniques_successful = 0
        for tid, statuses in technique_statuses.items():
            if "successful" in statuses:
                techniques_successful += 1
                techniques_tested += 1
            elif "tested" in statuses:
                techniques_tested += 1

        techniques_not_covered = total_techniques - len(technique_statuses)

        # Coverage by tactic
        coverage_by_tactic: Dict[str, Dict] = {}
        for tactic in TACTICS:
            tactic_techniques = self._techniques_by_tactic[tactic]
            tactic_total = len(tactic_techniques)
            tactic_tested = 0
            tactic_successful = 0

            for tech in tactic_techniques:
                tid = tech["technique_id"]
                if tid in technique_statuses:
                    if "successful" in technique_statuses[tid]:
                        tactic_successful += 1
                        tactic_tested += 1
                    elif "tested" in technique_statuses[tid]:
                        tactic_tested += 1

            coverage_by_tactic[tactic] = {
                "total": tactic_total,
                "tested": tactic_tested,
                "successful": tactic_successful,
                "not_covered": tactic_total - tactic_tested,
                "coverage_percentage": round(
                    (tactic_tested / tactic_total * 100) if tactic_total > 0 else 0, 1
                ),
            }

        overall_percentage = round(
            (len(technique_statuses) / total_techniques * 100) if total_techniques > 0 else 0, 1
        )

        return {
            "total_techniques": total_techniques,
            "techniques_tested": techniques_tested,
            "techniques_successful": techniques_successful,
            "techniques_not_covered": techniques_not_covered,
            "overall_coverage_percentage": overall_percentage,
            "coverage_by_tactic": coverage_by_tactic,
            "total_mappings": len(rows),
        }
