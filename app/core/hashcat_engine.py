"""Hashcat subprocess integration engine.

Wraps the hashcat binary, builds command lines, runs attacks as subprocesses,
and parses real-time output for the UI.
"""

import os
import re
import subprocess
import shutil
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from app.core.logger import logger

# Default hashcat path — check tools directory first, then system PATH
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_BUNDLED_HASHCAT = _PROJECT_ROOT / "tools" / "hashcat-7.1.2" / "hashcat.exe"

# Hashcat attack modes
ATTACK_STRAIGHT = 0       # Dictionary
ATTACK_COMBINATION = 1    # Combination
ATTACK_BRUTE_FORCE = 3    # Brute-force / Mask
ATTACK_HYBRID_DICT = 6    # Hybrid dict + mask
ATTACK_HYBRID_MASK = 7    # Hybrid mask + dict

# Common hash types
HASH_TYPES = {
    "MD5": 0,
    "SHA1": 100,
    "SHA-256": 1400,
    "SHA-512": 1700,
    "NTLM": 1000,
    "NetNTLMv2": 5600,
    "bcrypt": 3200,
    "WPA/WPA2": 22000,
    "Kerberos TGS-REP (RC4)": 13100,
    "Kerberos AS-REP (RC4)": 18200,
    "SSH Key ($sshng$)": 22921,
    "MSSQL (2012+)": 1731,
    "MySQL 4.1+": 300,
    "PostgreSQL MD5": 12,
    "LM": 3000,
    "DPAPI masterkey v1": 15300,
    "DPAPI masterkey v2": 15900,
    "Office 2013": 9600,
    "PDF 1.4-1.6": 10500,
    "7-Zip": 11600,
    "RAR5": 13000,
    "KeePass": 13400,
    "Bitcoin wallet": 11300,
    "Ethereum wallet": 15600,
}


@dataclass
class HashcatConfig:
    """Configuration for a hashcat attack."""
    hash_file: str = ""
    hash_type: int = 0
    attack_mode: int = ATTACK_STRAIGHT
    wordlist: str = ""
    rules_file: str = ""
    mask: str = ""
    outfile: str = ""
    workload_profile: int = 2  # 1=low, 2=default, 3=high, 4=nightmare
    optimized_kernels: bool = True
    force: bool = False
    status_timer: int = 5
    extra_args: List[str] = field(default_factory=list)


@dataclass
class HashcatStatus:
    """Parsed status from hashcat output."""
    status: str = "Initializing"
    speed: str = "0 H/s"
    recovered: str = "0/0"
    progress: float = 0.0
    time_started: str = ""
    time_estimated: str = ""
    candidates: str = ""


def find_hashcat_binary() -> Optional[str]:
    """Locate the hashcat binary."""
    # Check bundled location
    if _BUNDLED_HASHCAT.exists():
        return str(_BUNDLED_HASHCAT)

    # Check system PATH
    found = shutil.which("hashcat")
    if found:
        return found

    # Check common Windows locations
    common_paths = [
        Path(os.environ.get("PROGRAMFILES", "")) / "hashcat" / "hashcat.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "hashcat" / "hashcat.exe",
        Path.home() / "hashcat" / "hashcat.exe",
    ]
    for p in common_paths:
        if p.exists():
            return str(p)

    return None


def get_hashcat_dir() -> Path:
    """Get the hashcat installation directory (for rules, charsets, etc.)."""
    binary = find_hashcat_binary()
    if binary:
        return Path(binary).parent
    # Fallback to bundled source tree (has rules, charsets, etc.)
    return _PROJECT_ROOT / "tools" / "hashcat-7.1.2"


def get_available_rules() -> List[str]:
    """List available rule files."""
    rules_dir = get_hashcat_dir() / "rules"
    if not rules_dir.exists():
        return []
    return sorted([f.name for f in rules_dir.glob("*.rule")])


def get_available_charsets() -> List[str]:
    """List available charset files."""
    charsets_dir = get_hashcat_dir() / "charsets"
    if not charsets_dir.exists():
        return []
    return sorted([f.name for f in charsets_dir.rglob("*.hcchr")])


def build_command(config: HashcatConfig, hashcat_path: Optional[str] = None) -> List[str]:
    """
    Build the hashcat command line from a config.

    Returns:
        List of command arguments suitable for subprocess.
    """
    binary = hashcat_path or find_hashcat_binary()
    if not binary:
        raise FileNotFoundError(
            "hashcat binary not found. Install hashcat or place hashcat.exe in tools/hashcat-7.1.2/"
        )

    cmd = [binary]

    # Hash type
    cmd.extend(["-m", str(config.hash_type)])

    # Attack mode
    cmd.extend(["-a", str(config.attack_mode)])

    # Workload profile
    cmd.extend(["-w", str(config.workload_profile)])

    # Status timer for machine-readable output
    cmd.extend(["--status", "--status-timer", str(config.status_timer)])

    # Machine-readable status output
    cmd.append("--machine-readable")

    # Optimized kernels
    if config.optimized_kernels:
        cmd.append("-O")

    # Force (skip warnings about hardware)
    if config.force:
        cmd.append("--force")

    # Output file
    if config.outfile:
        cmd.extend(["-o", config.outfile])

    # Extra args
    cmd.extend(config.extra_args)

    # Hash file (target)
    cmd.append(config.hash_file)

    # Attack-specific arguments
    if config.attack_mode == ATTACK_STRAIGHT:
        # Dictionary attack
        if config.wordlist:
            cmd.append(config.wordlist)
        if config.rules_file:
            cmd.extend(["-r", config.rules_file])

    elif config.attack_mode == ATTACK_BRUTE_FORCE:
        # Mask attack
        if config.mask:
            cmd.append(config.mask)

    elif config.attack_mode in (ATTACK_HYBRID_DICT, ATTACK_HYBRID_MASK):
        # Hybrid attacks
        if config.wordlist:
            cmd.append(config.wordlist)
        if config.mask:
            cmd.append(config.mask)

    return cmd


def parse_status_line(line: str) -> Optional[HashcatStatus]:
    """
    Parse a hashcat status output line.

    Hashcat with --machine-readable outputs STATUS lines like:
    STATUS\t<status_code>\tSPEED\t<speed>\tREC\t<recovered>/<total>\t...
    """
    status = HashcatStatus()

    # Try machine-readable format
    if line.startswith("STATUS"):
        parts = line.split("\t")
        field_map = {}
        i = 0
        while i < len(parts) - 1:
            field_map[parts[i]] = parts[i + 1] if i + 1 < len(parts) else ""
            i += 2

        status.status = _status_code_to_text(field_map.get("STATUS", "0"))
        status.speed = field_map.get("SPEED", "0 H/s")
        status.recovered = field_map.get("REC", "0/0")

        progress_str = field_map.get("PROGRESS", "0/1")
        try:
            done, total = progress_str.split("/")
            status.progress = (int(done) / max(int(total), 1)) * 100
        except (ValueError, ZeroDivisionError):
            status.progress = 0.0

        return status

    # Try human-readable status block parsing
    if "Speed.#" in line or "Speed." in line:
        match = re.search(r"Speed[^:]*:\s*(.+)", line)
        if match:
            status.speed = match.group(1).strip()
            return status

    if "Recovered" in line and "/" in line:
        match = re.search(r"Recovered[^:]*:\s*(\d+/\d+)", line)
        if match:
            status.recovered = match.group(1)
            return status

    if "Progress" in line:
        match = re.search(r"Progress[^:]*:\s*(\d+)/(\d+)", line)
        if match:
            done, total = int(match.group(1)), int(match.group(2))
            status.progress = (done / max(total, 1)) * 100
            return status

    return None


def parse_cracked_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parse a cracked hash from hashcat output.

    Hashcat outputs cracked hashes as: <hash>:<password>
    """
    # Skip status/info lines
    if line.startswith("[") or line.startswith("STATUS") or ":" not in line:
        return None

    # Basic hash:password format
    parts = line.strip().split(":", 1)
    if len(parts) == 2 and len(parts[0]) >= 16:
        return {"hash": parts[0], "password": parts[1]}

    return None


def _status_code_to_text(code: str) -> str:
    """Convert hashcat numeric status code to text."""
    codes = {
        "0": "Initializing",
        "1": "Autotuning",
        "2": "Self-testing",
        "3": "Running",
        "4": "Paused",
        "5": "Exhausted",
        "6": "Cracked",
        "7": "Aborted",
        "8": "Quit",
        "9": "Bypass",
    }
    return codes.get(code, f"Unknown ({code})")
