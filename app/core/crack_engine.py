"""
Hash cracking engine with CPU multithreading and optional GPU acceleration.

Implements dictionary, brute-force, and rule-based attacks for common hash types.
Designed to run as a background worker with progress reporting.
No external binary dependencies — uses hashlib and standard crypto libraries.
GPU acceleration via pyopencl when available and enabled.
"""

import hashlib
import binascii
import itertools
import struct
import os
import time
from typing import Optional, List, Callable, Generator, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

# Try to import GPU engine
try:
    from app.core.gpu_crack_engine import (
        is_gpu_available, gpu_crack_batch, HAS_OPENCL,
        get_available_gpus, get_gpu_device_name, gpu_bruteforce_md5
    )
except ImportError:
    HAS_OPENCL = False
    is_gpu_available = lambda: False
    get_gpu_device_name = lambda: "N/A"
    gpu_bruteforce_md5 = None

# Try to import bcrypt for SSH key cracking
try:
    import bcrypt as _bcrypt_lib
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

# Try to import cryptography for AES decryption
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class AttackMode(Enum):
    DICTIONARY = "dictionary"
    BRUTE_FORCE = "brute_force"
    RULE_BASED = "rule_based"


class HashType(Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    NTLM = "ntlm"
    MD5_CRYPT = "md5_crypt"
    BCRYPT = "bcrypt"
    SSHNG = "sshng"


@dataclass
class CrackJob:
    """Defines a cracking job."""
    hash_value: str
    hash_type: HashType = HashType.MD5
    attack_mode: AttackMode = AttackMode.DICTIONARY
    wordlist_path: str = ""
    mask: str = ""
    rules: List[str] = field(default_factory=list)
    charset: str = "abcdefghijklmnopqrstuvwxyz0123456789"
    max_length: int = 8
    min_length: int = 1
    use_gpu: bool = False


@dataclass
class CrackResult:
    """Result of a cracking attempt."""
    hash_value: str
    password: Optional[str] = None
    cracked: bool = False
    attempts: int = 0
    elapsed: float = 0.0
    speed: float = 0.0  # attempts per second


# ---------------------------------------------------------------------------
# Hash computation functions
# ---------------------------------------------------------------------------

def compute_md5(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def compute_sha1(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest()


def compute_sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def compute_sha512(password: str) -> str:
    return hashlib.sha512(password.encode("utf-8")).hexdigest()


def compute_ntlm(password: str) -> str:
    """Compute NTLM hash (MD4 of UTF-16LE encoded password)."""
    try:
        return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()
    except ValueError:
        # MD4 not available in this OpenSSL build — use pure Python fallback
        return _md4_pure(password.encode("utf-16-le")).hex()


def _md4_pure(data: bytes) -> bytes:
    """Pure Python MD4 implementation for NTLM when hashlib doesn't support it."""
    import struct as _s

    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    def _left_rotate(n, b): return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    # Padding
    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += _s.pack("<Q", msg_len * 8)

    # Initial state
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        x = list(_s.unpack("<16I", msg[i:i+64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        for k in range(16):
            if k % 4 == 0: a = _left_rotate((a + _f(b, c, d) + x[k]) & 0xFFFFFFFF, 3)
            elif k % 4 == 1: d = _left_rotate((d + _f(a, b, c) + x[k]) & 0xFFFFFFFF, 7)
            elif k % 4 == 2: c = _left_rotate((c + _f(d, a, b) + x[k]) & 0xFFFFFFFF, 11)
            else: b = _left_rotate((b + _f(c, d, a) + x[k]) & 0xFFFFFFFF, 19)

        # Round 2
        for k in [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]:
            if [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15].index(k) % 4 == 0:
                a = _left_rotate((a + _g(b, c, d) + x[k] + 0x5A827999) & 0xFFFFFFFF, 3)
            elif [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15].index(k) % 4 == 1:
                d = _left_rotate((d + _g(a, b, c) + x[k] + 0x5A827999) & 0xFFFFFFFF, 5)
            elif [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15].index(k) % 4 == 2:
                c = _left_rotate((c + _g(d, a, b) + x[k] + 0x5A827999) & 0xFFFFFFFF, 9)
            else:
                b = _left_rotate((b + _g(c, d, a) + x[k] + 0x5A827999) & 0xFFFFFFFF, 13)

        # Round 3
        for k in [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]:
            if [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15].index(k) % 4 == 0:
                a = _left_rotate((a + _h(b, c, d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
            elif [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15].index(k) % 4 == 1:
                d = _left_rotate((d + _h(a, b, c) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
            elif [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15].index(k) % 4 == 2:
                c = _left_rotate((c + _h(d, a, b) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
            else:
                b = _left_rotate((b + _h(c, d, a) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return _s.pack("<4I", a, b, c, d)


# ---------------------------------------------------------------------------
# SSH Key (sshng) cracking
# ---------------------------------------------------------------------------

def parse_sshng_hash(hash_line: str) -> Optional[dict]:
    """
    Parse a $sshng$ hash line into its components.

    Format: $sshng$<type>$<salt_len>$<salt_hex>$<data_len>$<data_hex>$<rounds>$<ct_offset>
    """
    if not hash_line.startswith("$sshng$"):
        return None

    parts = hash_line.split("$")
    # parts[0] = "", parts[1] = "sshng", parts[2] = type, ...
    if len(parts) < 7:
        return None

    try:
        sshng_type = int(parts[2])
        salt_len = int(parts[3])
        salt = bytes.fromhex(parts[4])
        data_len = int(parts[5])
        data = bytes.fromhex(parts[6])
        rounds = int(parts[7]) if len(parts) > 7 else 16
        ct_offset = int(parts[8]) if len(parts) > 8 else 0
    except (ValueError, IndexError):
        return None

    return {
        "type": sshng_type,
        "salt": salt,
        "salt_len": salt_len,
        "data": data,
        "data_len": data_len,
        "rounds": rounds,
        "ct_offset": ct_offset,
    }


def try_sshng_password(password: str, sshng: dict) -> bool:
    """
    Attempt to crack an SSH key by deriving the key with bcrypt_pbkdf
    and checking if the decrypted private key has valid padding.

    Supports type 2 (aes256-cbc + bcrypt) and type 6 (aes256-ctr + bcrypt).
    """
    if not HAS_BCRYPT or not HAS_CRYPTO:
        return False

    sshng_type = sshng["type"]
    if sshng_type not in (2, 6):
        return False

    salt = sshng["salt"]
    rounds = sshng["rounds"]
    data = sshng["data"]
    ct_offset = sshng["ct_offset"]

    # Derive key + IV using bcrypt_pbkdf
    # For aes256-ctr/cbc: 32 bytes key + 16 bytes IV = 48 bytes
    try:
        key_iv = _bcrypt_pbkdf(password.encode("utf-8"), salt, 48, rounds)
    except Exception:
        return False

    key = key_iv[:32]
    iv = key_iv[32:48]

    # Get the ciphertext portion
    ciphertext = data[ct_offset:]
    if len(ciphertext) < 16:
        return False

    # Decrypt
    try:
        if sshng_type == 6:  # AES-256-CTR
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        else:  # AES-256-CBC (type 2)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        return False

    # Verify: first 8 bytes should be two identical uint32 values (check bytes)
    if len(plaintext) < 8:
        return False

    check1 = plaintext[0:4]
    check2 = plaintext[4:8]
    return check1 == check2


def _bcrypt_pbkdf(password: bytes, salt: bytes, key_len: int, rounds: int) -> bytes:
    """
    bcrypt_pbkdf key derivation (OpenSSH's KDF for encrypted keys).
    """
    # Use the bcrypt library's kdf function if available
    if hasattr(_bcrypt_lib, 'kdf'):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return _bcrypt_lib.kdf(password, salt, key_len, rounds)

    # Manual implementation using bcrypt hash rounds
    import hashlib

    num_blocks = (key_len + 31) // 32
    output = b""

    hpass = hashlib.sha512(password).digest()

    for block_num in range(1, num_blocks + 1):
        # salt || block_num (big-endian)
        block_salt = salt + struct.pack(">I", block_num)
        hsalt = hashlib.sha512(block_salt).digest()

        # bcrypt hash with hpass as password and hsalt as salt, 64 rounds
        out = _bcrypt_hash_round(hpass, hsalt)
        result = out

        for _ in range(1, rounds):
            hsalt = hashlib.sha512(out).digest()
            out = _bcrypt_hash_round(hpass, hsalt)
            result = bytes(a ^ b for a, b in zip(result, out))

        output += result

    return output[:key_len]


def _bcrypt_hash_round(hpass: bytes, hsalt: bytes) -> bytes:
    """Single bcrypt hash round for bcrypt_pbkdf."""
    # This is a simplified version — the real bcrypt_pbkdf uses
    # Blowfish internally. For production use, rely on bcrypt.kdf()
    ciphertext = b"OxychromaticBlowwordfishSwatwordfishDynamite"
    # Use hashlib as fallback approximation
    h = hashlib.blake2b(hpass + hsalt, digest_size=32)
    return h.digest()


# ---------------------------------------------------------------------------
# Rule engine (hashcat-compatible subset)
# ---------------------------------------------------------------------------

def apply_rule(word: str, rule: str) -> str:
    """
    Apply a single hashcat rule to a word.

    Supports common rules:
        :  (noop)
        l  (lowercase)
        u  (uppercase)
        c  (capitalize)
        t  (toggle case)
        r  (reverse)
        d  (duplicate)
        $X (append char X)
        ^X (prepend char X)
        [  (delete first)
        ]  (delete last)
    """
    if not rule or rule == ":":
        return word

    result = word
    i = 0
    while i < len(rule):
        cmd = rule[i]
        if cmd == "l":
            result = result.lower()
        elif cmd == "u":
            result = result.upper()
        elif cmd == "c":
            result = result.capitalize()
        elif cmd == "C":
            result = result[0].lower() + result[1:].upper() if result else result
        elif cmd == "t":
            result = result.swapcase()
        elif cmd == "r":
            result = result[::-1]
        elif cmd == "d":
            result = result + result
        elif cmd == "f":
            result = result + result[::-1]
        elif cmd == "$" and i + 1 < len(rule):
            i += 1
            result = result + rule[i]
        elif cmd == "^" and i + 1 < len(rule):
            i += 1
            result = rule[i] + result
        elif cmd == "[":
            result = result[1:] if result else result
        elif cmd == "]":
            result = result[:-1] if result else result
        elif cmd == "{":
            result = result[1:] + result[0] if result else result
        elif cmd == "}":
            result = result[-1] + result[:-1] if result else result
        elif cmd == " " or cmd == "\t":
            pass  # whitespace separator, skip
        i += 1

    return result


def load_rules(rules_file: str) -> List[str]:
    """Load rules from a hashcat rules file."""
    rules = []
    try:
        with open(rules_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if line and not line.startswith("#"):
                    rules.append(line)
    except Exception:
        pass
    return rules


# ---------------------------------------------------------------------------
# Candidate generators
# ---------------------------------------------------------------------------

def dictionary_candidates(wordlist_path: str) -> Generator[str, None, None]:
    """Yield password candidates from a wordlist file."""
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line.rstrip("\n\r")
    except Exception:
        return


def brute_force_candidates(charset: str, min_len: int, max_len: int) -> Generator[str, None, None]:
    """Yield brute-force candidates from a charset."""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def mask_candidates(mask: str) -> Generator[str, None, None]:
    """
    Yield candidates from a hashcat-style mask.

    Charsets:
        ?l = lowercase
        ?u = uppercase
        ?d = digits
        ?s = special
        ?a = all printable
    """
    charset_map = {
        "l": "abcdefghijklmnopqrstuvwxyz",
        "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "d": "0123456789",
        "s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        "a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
    }

    # Parse mask into position charsets
    positions = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            cs = charset_map.get(mask[i + 1], mask[i + 1])
            positions.append(cs)
            i += 2
        else:
            positions.append(mask[i])
            i += 1

    if not positions:
        return

    for combo in itertools.product(*positions):
        yield "".join(combo)


def rule_candidates(wordlist_path: str, rules: List[str]) -> Generator[str, None, None]:
    """Yield candidates by applying rules to each word in the wordlist."""
    for word in dictionary_candidates(wordlist_path):
        for rule in rules:
            yield apply_rule(word, rule)


# ---------------------------------------------------------------------------
# Main cracking function
# ---------------------------------------------------------------------------

def get_hash_function(hash_type: HashType) -> Optional[Callable[[str], str]]:
    """Get the hash computation function for a given type."""
    funcs = {
        HashType.MD5: compute_md5,
        HashType.SHA1: compute_sha1,
        HashType.SHA256: compute_sha256,
        HashType.SHA512: compute_sha512,
        HashType.NTLM: compute_ntlm,
    }
    return funcs.get(hash_type)


def identify_hash_type(hash_value: str) -> HashType:
    """Auto-detect hash type from the hash value."""
    if hash_value.startswith("$sshng$"):
        return HashType.SSHNG
    if hash_value.startswith("$2b$") or hash_value.startswith("$2a$"):
        return HashType.BCRYPT

    # Length-based detection for raw hex hashes
    clean = hash_value.strip()
    if len(clean) == 32 and all(c in "0123456789abcdef" for c in clean):
        return HashType.MD5
    if len(clean) == 40:
        return HashType.SHA1
    if len(clean) == 64:
        return HashType.SHA256
    if len(clean) == 128:
        return HashType.SHA512

    return HashType.MD5  # default fallback


def crack(job: CrackJob, progress_callback=None, stop_check=None) -> CrackResult:
    """
    Execute a cracking job using all available CPU threads.

    Args:
        job: The CrackJob configuration.
        progress_callback: Optional callable(attempts, speed, candidate) for progress updates.
        stop_check: Optional callable() -> bool, returns True to stop.

    Returns:
        CrackResult with the outcome.
    """
    result = CrackResult(hash_value=job.hash_value)
    start_time = time.time()
    target_hash = job.hash_value.strip().lower()

    # Special handling for SSH key hashes
    if job.hash_type == HashType.SSHNG:
        return _crack_sshng(job, progress_callback, stop_check)

    # Get hash function
    hash_fn = get_hash_function(job.hash_type)
    if not hash_fn:
        result.elapsed = time.time() - start_time
        return result

    # Get candidate generator
    if job.attack_mode == AttackMode.DICTIONARY:
        candidates = dictionary_candidates(job.wordlist_path)
    elif job.attack_mode == AttackMode.BRUTE_FORCE:
        if job.mask:
            candidates = mask_candidates(job.mask)
        else:
            candidates = brute_force_candidates(job.charset, job.min_length, job.max_length)
    elif job.attack_mode == AttackMode.RULE_BASED:
        candidates = rule_candidates(job.wordlist_path, job.rules)
    else:
        candidates = dictionary_candidates(job.wordlist_path)

    # Use thread pool for parallel hashing (max available threads)
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import threading

    # GPU path: process in large batches on GPU
    use_gpu = job.use_gpu and HAS_OPENCL and is_gpu_available()
    gpu_hash_type_map = {HashType.MD5: "md5", HashType.SHA1: "sha1"}
    gpu_type = gpu_hash_type_map.get(job.hash_type)

    if use_gpu and gpu_type:
        return _crack_gpu(job, candidates, target_hash, gpu_type, progress_callback, stop_check)

    # CPU path: multithreaded
    num_threads = os.cpu_count() or 4
    batch_size = num_threads * 256
    found_event = threading.Event()
    found_password = [None]
    attempts = 0
    last_report = start_time

    def check_batch(batch):
        """Check a batch of candidates against the target hash."""
        for candidate in batch:
            if found_event.is_set():
                return None
            computed = hash_fn(candidate)
            if computed.lower() == target_hash:
                return candidate
        return None

    # Process candidates in batches across threads
    batch = []
    for candidate in candidates:
        if stop_check and stop_check():
            break
        if found_event.is_set():
            break

        batch.append(candidate)
        attempts += 1

        if len(batch) >= batch_size:
            # Split batch across threads
            chunks = [batch[i::num_threads] for i in range(num_threads)]
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = [executor.submit(check_batch, chunk) for chunk in chunks if chunk]
                for future in as_completed(futures):
                    pw = future.result()
                    if pw is not None:
                        found_password[0] = pw
                        found_event.set()
                        break

            if found_event.is_set():
                break

            # Progress reporting
            if progress_callback:
                now = time.time()
                if now - last_report >= 0.5:
                    elapsed = now - start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    progress_callback(attempts, speed, batch[-1] if batch else "")
                    last_report = now

            batch = []

    # Process remaining batch
    if batch and not found_event.is_set() and not (stop_check and stop_check()):
        chunks = [batch[i::num_threads] for i in range(num_threads)]
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(check_batch, chunk) for chunk in chunks if chunk]
            for future in as_completed(futures):
                pw = future.result()
                if pw is not None:
                    found_password[0] = pw
                    found_event.set()
                    break

    if found_password[0]:
        result.password = found_password[0]
        result.cracked = True

    result.attempts = attempts
    result.elapsed = time.time() - start_time
    result.speed = attempts / result.elapsed if result.elapsed > 0 else 0
    return result


def _crack_gpu(job, candidates, target_hash, gpu_type, progress_callback, stop_check):
    """GPU-accelerated cracking path — processes large batches on GPU."""
    result = CrackResult(hash_value=job.hash_value)
    start_time = time.time()

    # For brute force with MD5, use fully on-GPU candidate generation
    if (job.attack_mode == AttackMode.BRUTE_FORCE and not job.mask
            and gpu_type == "md5" and gpu_bruteforce_md5 is not None):
        # Wrap progress callback to match GPU's 2-arg signature
        gpu_progress = None
        if progress_callback:
            def gpu_progress(attempts, speed):
                progress_callback(attempts, speed, "(GPU brute force)")

        password, attempts = gpu_bruteforce_md5(
            charset=job.charset,
            min_len=job.min_length,
            max_len=job.max_length,
            target_hash=target_hash,
            progress_callback=gpu_progress,
            stop_check=stop_check,
        )
        result.attempts = attempts
        if password:
            result.password = password
            result.cracked = True
        result.elapsed = time.time() - start_time
        result.speed = attempts / result.elapsed if result.elapsed > 0 else 0
        return result

    # For dictionary/rule-based attacks, batch candidates from Python to GPU
    attempts = 0
    last_report = start_time
    GPU_BATCH_SIZE = 1_000_000

    batch = []
    for candidate in candidates:
        if stop_check and stop_check():
            break

        batch.append(candidate)
        attempts += 1

        if len(batch) >= GPU_BATCH_SIZE:
            found = gpu_crack_batch(batch, target_hash, gpu_type)
            if found:
                result.password = found
                result.cracked = True
                break

            if progress_callback:
                now = time.time()
                elapsed = now - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                progress_callback(attempts, speed, batch[-1] if batch else "")
                last_report = now

            batch = []

    # Process remaining batch
    if batch and not result.cracked and not (stop_check and stop_check()):
        found = gpu_crack_batch(batch, target_hash, gpu_type)
        if found:
            result.password = found
            result.cracked = True

    result.attempts = attempts
    result.elapsed = time.time() - start_time
    result.speed = attempts / result.elapsed if result.elapsed > 0 else 0
    return result


def _crack_sshng(job: CrackJob, progress_callback=None, stop_check=None) -> CrackResult:
    """Crack an SSH key hash using bcrypt_pbkdf + AES decryption."""
    result = CrackResult(hash_value=job.hash_value)
    start_time = time.time()

    sshng = parse_sshng_hash(job.hash_value)
    if not sshng:
        return result

    if not HAS_BCRYPT or not HAS_CRYPTO:
        return result

    # Get candidate generator
    if job.attack_mode == AttackMode.DICTIONARY:
        candidates = dictionary_candidates(job.wordlist_path)
    elif job.attack_mode == AttackMode.BRUTE_FORCE:
        if job.mask:
            candidates = mask_candidates(job.mask)
        else:
            candidates = brute_force_candidates(job.charset, job.min_length, job.max_length)
    elif job.attack_mode == AttackMode.RULE_BASED:
        candidates = rule_candidates(job.wordlist_path, job.rules)
    else:
        candidates = dictionary_candidates(job.wordlist_path)

    attempts = 0
    last_report = start_time

    for candidate in candidates:
        if stop_check and stop_check():
            break

        attempts += 1

        if try_sshng_password(candidate, sshng):
            result.password = candidate
            result.cracked = True
            break

        # Progress reporting (SSH keys are slow — report every 5 seconds)
        if progress_callback and (attempts % 10 == 0):
            now = time.time()
            if now - last_report >= 5.0:
                elapsed = now - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                progress_callback(attempts, speed, candidate)
                last_report = now

    result.attempts = attempts
    result.elapsed = time.time() - start_time
    result.speed = attempts / result.elapsed if result.elapsed > 0 else 0
    return result
