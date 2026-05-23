"""
GPU-accelerated hash cracking engine using OpenCL via pyopencl.

Supports MD5, SHA1 on GPU with persistent context and large batch processing.
Falls back to CPU if no GPU is available.
"""

import os
import time
import numpy as np
from typing import Optional, List
from dataclasses import dataclass

try:
    import pyopencl as cl
    HAS_OPENCL = True
except ImportError:
    HAS_OPENCL = False


# OpenCL kernel source for MD5 hashing
MD5_KERNEL = r"""
__constant uint K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
__constant uint S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

uint rotate_left(uint x, uint n) { return (x << n) | (x >> (32 - n)); }

__kernel void md5_crack(
    __global const uchar *passwords,
    __global const uint *pw_lengths,
    __global uint *results,
    const uint count,
    const uint max_pw_len
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;

    uint offset = gid * max_pw_len;
    uint len = pw_lengths[gid];

    uint M[16];
    for (int i = 0; i < 16; i++) M[i] = 0;

    for (uint i = 0; i < len; i++) {
        uint byte_val = passwords[offset + i];
        M[i / 4] |= byte_val << ((i % 4) * 8);
    }
    M[len / 4] |= 0x80u << ((len % 4) * 8);
    M[14] = len * 8;

    uint a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    uint a = a0, b = b0, c = c0, d = d0;

    for (int i = 0; i < 64; i++) {
        uint f, g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3*i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7*i) % 16; }

        uint temp = d;
        d = c; c = b;
        b = b + rotate_left(a + f + K[i] + M[g], S[i]);
        a = temp;
    }

    results[gid * 4 + 0] = a0 + a;
    results[gid * 4 + 1] = b0 + b;
    results[gid * 4 + 2] = c0 + c;
    results[gid * 4 + 3] = d0 + d;
}
"""

SHA1_KERNEL = r"""
uint sha1_rotate_left(uint x, uint n) { return (x << n) | (x >> (32 - n)); }

__kernel void sha1_crack(
    __global const uchar *passwords,
    __global const uint *pw_lengths,
    __global uint *results,
    const uint count,
    const uint max_pw_len
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;

    uint offset = gid * max_pw_len;
    uint len = pw_lengths[gid];

    uint W[80];
    for (int i = 0; i < 16; i++) W[i] = 0;

    for (uint i = 0; i < len; i++) {
        uint byte_val = passwords[offset + i];
        W[i / 4] |= byte_val << (24 - (i % 4) * 8);
    }
    W[len / 4] |= 0x80u << (24 - (len % 4) * 8);
    W[15] = len * 8;

    for (int i = 16; i < 80; i++)
        W[i] = sha1_rotate_left(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

    uint h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0;
    uint a=h0, b=h1, c=h2, d=h3, e=h4;

    for (int i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }

        uint temp = sha1_rotate_left(a, 5) + f + e + k + W[i];
        e = d; d = c; c = sha1_rotate_left(b, 30); b = a; a = temp;
    }

    results[gid * 5 + 0] = h0 + a;
    results[gid * 5 + 1] = h1 + b;
    results[gid * 5 + 2] = h2 + c;
    results[gid * 5 + 3] = h3 + d;
    results[gid * 5 + 4] = h4 + e;
}
"""

MAX_PW_LEN = 32

# Brute-force MD5 kernel — generates candidates ON GPU from a global index
# Each work item converts its global_id + offset into a password using the charset,
# then computes MD5 and compares against the target.
MD5_BRUTEFORCE_KERNEL = r"""
__constant uint K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
__constant uint S_arr[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

uint bf_rotate_left(uint x, uint n) { return (x << n) | (x >> (32 - n)); }

__kernel void md5_bruteforce(
    __global const uchar *charset,      // the charset bytes
    __global uint *found_idx,           // output: index of found password (-1 if not found)
    const uint charset_len,
    const uint pw_len,                  // fixed password length for this dispatch
    const ulong start_idx,             // starting index in keyspace
    const uint target_a,
    const uint target_b,
    const uint target_c,
    const uint target_d
) {
    uint gid = get_global_id(0);
    ulong idx = start_idx + (ulong)gid;

    // Convert index to password using charset (base-N encoding)
    uchar pw[16];  // max 16 chars for brute force
    ulong tmp = idx;
    for (int i = pw_len - 1; i >= 0; i--) {
        pw[i] = charset[tmp % charset_len];
        tmp /= charset_len;
    }
    // If tmp > 0, this index exceeds the keyspace for this length — skip
    if (tmp > 0) return;

    // MD5 of the password
    uint M[16];
    for (int i = 0; i < 16; i++) M[i] = 0;
    for (uint i = 0; i < pw_len; i++) {
        M[i / 4] |= (uint)pw[i] << ((i % 4) * 8);
    }
    M[pw_len / 4] |= 0x80u << ((pw_len % 4) * 8);
    M[14] = pw_len * 8;

    uint a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    uint a = a0, b = b0, c = c0, d = d0;

    for (int i = 0; i < 64; i++) {
        uint f, g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3*i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7*i) % 16; }
        uint temp = d;
        d = c; c = b;
        b = b + bf_rotate_left(a + f + K[i] + M[g], S_arr[i]);
        a = temp;
    }

    a = a0 + a; b = b0 + b; c = c0 + c; d = d0 + d;

    // Compare with target
    if (a == target_a && b == target_b && c == target_c && d == target_d) {
        atomic_xchg(found_idx, gid);
    }
}
"""


@dataclass
class GPUDevice:
    """Represents an available GPU device."""
    name: str
    platform: str
    device: object


class GPUContext:
    """
    Persistent GPU context — compiles kernels once and reuses them.
    Allocates large buffers for batch processing.
    """

    def __init__(self, device=None):
        if not HAS_OPENCL:
            raise RuntimeError("pyopencl not available")

        if device:
            self.ctx = cl.Context(devices=[device])
        else:
            # Pick the best GPU (prefer NVIDIA)
            gpus = get_available_gpus()
            if not gpus:
                raise RuntimeError("No GPU devices found")
            # Prefer NVIDIA over Intel
            nvidia = [g for g in gpus if "NVIDIA" in g.platform.upper()]
            chosen = nvidia[0] if nvidia else gpus[0]
            self.ctx = cl.Context(devices=[chosen.device])
            self._device_name = chosen.name

        self.queue = cl.CommandQueue(self.ctx)
        self._md5_program = None
        self._sha1_program = None

        # Pre-allocate large buffers for batch processing
        self._batch_size = 0
        self._pw_buf = None
        self._len_buf = None
        self._result_buf = None

    @property
    def device_name(self):
        return getattr(self, '_device_name', 'GPU')

    def _get_md5_program(self):
        if self._md5_program is None:
            self._md5_program = cl.Program(self.ctx, MD5_KERNEL).build()
        return self._md5_program

    def _get_sha1_program(self):
        if self._sha1_program is None:
            self._sha1_program = cl.Program(self.ctx, SHA1_KERNEL).build()
        return self._sha1_program

    def _get_bruteforce_program(self):
        if not hasattr(self, '_bf_program') or self._bf_program is None:
            self._bf_program = cl.Program(self.ctx, MD5_BRUTEFORCE_KERNEL).build()
        return self._bf_program

    def bruteforce_md5(self, charset: str, pw_len: int, target_hash: str,
                       batch_size: int = 67_108_864,
                       progress_callback=None, stop_check=None):
        """
        Full on-GPU brute force for MD5. Generates candidates on the GPU.

        Args:
            charset: Characters to use (e.g. "abcdefghijklmnopqrstuvwxyz0123456789")
            pw_len: Fixed password length to try
            target_hash: Target MD5 hash (32 hex chars)
            batch_size: Work items per GPU dispatch (default 16M)
            progress_callback: callable(attempts, speed) for progress
            stop_check: callable() -> bool to stop

        Returns:
            (password, total_attempts) or (None, total_attempts)
        """
        import struct

        target_bytes = bytes.fromhex(target_hash)
        ta, tb, tc, td = struct.unpack("<4I", target_bytes)

        charset_bytes = charset.encode("ascii")
        charset_len = len(charset_bytes)
        keyspace = charset_len ** pw_len

        # Upload charset to GPU
        mf = cl.mem_flags
        charset_buf = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
                                hostbuf=np.frombuffer(charset_bytes, dtype=np.uint8))

        # Found index buffer (initialized to 0xFFFFFFFF = not found)
        found_host = np.array([0xFFFFFFFF], dtype=np.uint32)
        found_buf = cl.Buffer(self.ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=found_host)

        program = self._get_bruteforce_program()
        kernel = cl.Kernel(program, "md5_bruteforce")

        start_time = time.time()
        total_attempts = 0
        start_idx = 0

        while start_idx < keyspace:
            if stop_check and stop_check():
                break

            # Reset found flag
            found_host[0] = 0xFFFFFFFF
            cl.enqueue_copy(self.queue, found_buf, found_host)

            # Dispatch batch
            count = min(batch_size, keyspace - start_idx)

            kernel.set_args(
                charset_buf, found_buf,
                np.uint32(charset_len), np.uint32(pw_len),
                np.uint64(start_idx),
                np.uint32(ta), np.uint32(tb), np.uint32(tc), np.uint32(td)
            )
            cl.enqueue_nd_range_kernel(self.queue, kernel, (count,), None)

            # Check if found
            cl.enqueue_copy(self.queue, found_host, found_buf).wait()
            total_attempts += count

            if found_host[0] != 0xFFFFFFFF:
                # Reconstruct the password from the found index
                found_global_idx = start_idx + int(found_host[0])
                password = self._index_to_password(found_global_idx, charset, pw_len)
                return password, total_attempts

            start_idx += count

            # Progress
            if progress_callback:
                elapsed = time.time() - start_time
                speed = total_attempts / elapsed if elapsed > 0 else 0
                progress_callback(total_attempts, speed)

        return None, total_attempts

    def _index_to_password(self, idx: int, charset: str, pw_len: int) -> str:
        """Convert a numeric index back to a password string."""
        charset_len = len(charset)
        chars = []
        tmp = idx
        for _ in range(pw_len):
            chars.append(charset[tmp % charset_len])
            tmp //= charset_len
        return "".join(reversed(chars))

    def _ensure_buffers(self, count, hash_ints_per_entry):
        """Allocate/reuse GPU buffers for the given batch size."""
        if count <= self._batch_size:
            return

        mf = cl.mem_flags
        # Allocate slightly larger to avoid frequent reallocation
        alloc_size = max(count, self._batch_size * 2) if self._batch_size > 0 else count

        self._pw_buf = cl.Buffer(self.ctx, mf.READ_ONLY, size=alloc_size * MAX_PW_LEN)
        self._len_buf = cl.Buffer(self.ctx, mf.READ_ONLY, size=alloc_size * 4)
        self._result_buf = cl.Buffer(self.ctx, mf.WRITE_ONLY, size=alloc_size * hash_ints_per_entry * 4)
        self._batch_size = alloc_size

    def crack_md5_batch(self, candidates: List[str], target_hash: str) -> Optional[str]:
        """Crack MD5 hash with a batch of candidates. Returns password or None."""
        import struct

        target_bytes = bytes.fromhex(target_hash)
        target_ints = struct.unpack("<4I", target_bytes)

        count = len(candidates)
        self._ensure_buffers(count, 4)

        # Fast batch packing using bytearray
        pw_data = bytearray(count * MAX_PW_LEN)
        pw_lens = np.zeros(count, dtype=np.uint32)

        for i, pw in enumerate(candidates):
            pw_bytes = pw.encode("utf-8")[:MAX_PW_LEN]
            pw_lens[i] = len(pw_bytes)
            offset = i * MAX_PW_LEN
            pw_data[offset:offset + len(pw_bytes)] = pw_bytes

        pw_np = np.frombuffer(pw_data, dtype=np.uint8)

        # Upload to GPU
        cl.enqueue_copy(self.queue, self._pw_buf, pw_np)
        cl.enqueue_copy(self.queue, self._len_buf, pw_lens)

        # Execute kernel
        program = self._get_md5_program()
        kernel = cl.Kernel(program, "md5_crack")
        kernel.set_args(self._pw_buf, self._len_buf, self._result_buf,
                       np.uint32(count), np.uint32(MAX_PW_LEN))
        cl.enqueue_nd_range_kernel(self.queue, kernel, (count,), None)

        # Read results
        results = np.zeros(count * 4, dtype=np.uint32)
        cl.enqueue_copy(self.queue, results, self._result_buf).wait()

        # Vectorized comparison using numpy
        r = results.reshape(count, 4)
        matches = np.where(
            (r[:, 0] == target_ints[0]) & (r[:, 1] == target_ints[1]) &
            (r[:, 2] == target_ints[2]) & (r[:, 3] == target_ints[3])
        )[0]

        if len(matches) > 0:
            return candidates[matches[0]]
        return None

    def crack_sha1_batch(self, candidates: List[str], target_hash: str) -> Optional[str]:
        """Crack SHA1 hash with a batch of candidates. Returns password or None."""
        import struct

        target_bytes = bytes.fromhex(target_hash)
        target_ints = struct.unpack(">5I", target_bytes)

        count = len(candidates)
        self._ensure_buffers(count, 5)

        pw_data = bytearray(count * MAX_PW_LEN)
        pw_lens = np.zeros(count, dtype=np.uint32)

        for i, pw in enumerate(candidates):
            pw_bytes = pw.encode("utf-8")[:MAX_PW_LEN]
            pw_lens[i] = len(pw_bytes)
            offset = i * MAX_PW_LEN
            pw_data[offset:offset + len(pw_bytes)] = pw_bytes

        pw_np = np.frombuffer(pw_data, dtype=np.uint8)

        cl.enqueue_copy(self.queue, self._pw_buf, pw_np)
        cl.enqueue_copy(self.queue, self._len_buf, pw_lens)

        program = self._get_sha1_program()
        kernel = cl.Kernel(program, "sha1_crack")
        kernel.set_args(self._pw_buf, self._len_buf, self._result_buf,
                       np.uint32(count), np.uint32(MAX_PW_LEN))
        cl.enqueue_nd_range_kernel(self.queue, kernel, (count,), None)

        results = np.zeros(count * 5, dtype=np.uint32)
        cl.enqueue_copy(self.queue, results, self._result_buf).wait()

        r = results.reshape(count, 5)
        matches = np.where(
            (r[:, 0] == target_ints[0]) & (r[:, 1] == target_ints[1]) &
            (r[:, 2] == target_ints[2]) & (r[:, 3] == target_ints[3]) &
            (r[:, 4] == target_ints[4])
        )[0]

        if len(matches) > 0:
            return candidates[matches[0]]
        return None


# Module-level singleton context (lazy init)
_gpu_context: Optional[GPUContext] = None


def _get_gpu_context() -> GPUContext:
    """Get or create the singleton GPU context."""
    global _gpu_context
    if _gpu_context is None:
        _gpu_context = GPUContext()
    return _gpu_context


def get_available_gpus() -> List[GPUDevice]:
    """Detect available GPU devices."""
    if not HAS_OPENCL:
        return []
    gpus = []
    try:
        for platform in cl.get_platforms():
            for device in platform.get_devices(device_type=cl.device_type.GPU):
                gpus.append(GPUDevice(
                    name=device.name.strip(),
                    platform=platform.name.strip(),
                    device=device,
                ))
    except Exception:
        pass
    return gpus


def is_gpu_available() -> bool:
    """Check if any GPU is available for cracking."""
    return len(get_available_gpus()) > 0


def gpu_crack_batch(candidates: List[str], target_hash: str, hash_type: str) -> Optional[str]:
    """
    Crack a hash using GPU with persistent context.

    Args:
        candidates: Password candidates (should be large batches for efficiency).
        target_hash: Target hash hex string.
        hash_type: One of "md5", "sha1".

    Returns:
        Cracked password or None.
    """
    try:
        ctx = _get_gpu_context()
        if hash_type == "md5":
            return ctx.crack_md5_batch(candidates, target_hash)
        elif hash_type == "sha1":
            return ctx.crack_sha1_batch(candidates, target_hash)
    except Exception:
        return None
    return None


def get_gpu_device_name() -> str:
    """Get the name of the GPU being used."""
    try:
        ctx = _get_gpu_context()
        return ctx.device_name
    except Exception:
        return "Unknown GPU"


def gpu_bruteforce_md5(charset: str, min_len: int, max_len: int, target_hash: str,
                       progress_callback=None, stop_check=None):
    """
    Full on-GPU brute force MD5 cracking. Generates all candidates on GPU.

    Args:
        charset: Character set string
        min_len: Minimum password length
        max_len: Maximum password length
        target_hash: Target MD5 hash (32 hex chars)
        progress_callback: callable(attempts, speed)
        stop_check: callable() -> bool

    Returns:
        (password, total_attempts) or (None, total_attempts)
    """
    try:
        ctx = _get_gpu_context()
        total = 0
        for pw_len in range(min_len, max_len + 1):
            if stop_check and stop_check():
                break
            result, attempts = ctx.bruteforce_md5(
                charset, pw_len, target_hash,
                progress_callback=progress_callback,
                stop_check=stop_check,
            )
            total += attempts
            if result:
                return result, total
        return None, total
    except Exception:
        return None, 0
