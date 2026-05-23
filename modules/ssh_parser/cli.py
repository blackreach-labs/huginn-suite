"""CLI interface for the SSH key parser module."""

import argparse
import json
import sys
from pathlib import Path

from .parser import SSHKeyParser
from .scanner import SSHKeyScanner
from .exceptions import SSHParserError, InvalidKeyError


def main(argv=None):
    """Entry point for the SSH key parser CLI."""
    args = parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)
    else:
        return _run_parse(args)


def _run_parse(args):
    """Parse individual key files."""
    parser = SSHKeyParser()
    results = []
    exit_code = 0

    for filepath in args.files:
        try:
            info = parser.parse_file(filepath)
            result = {
                "file": str(filepath),
                **info.to_dict(),
            }
            results.append(result)

            if not args.json:
                _print_result(filepath, info)

        except (SSHParserError, InvalidKeyError) as e:
            exit_code = 1
            error_entry = {"file": str(filepath), "error": str(e)}
            results.append(error_entry)

            if not args.json:
                print(f"[!] {filepath}: {e}", file=sys.stderr)

    if args.json:
        output = results[0] if len(results) == 1 else results
        print(json.dumps(output, indent=2))

    return exit_code


def _run_scan(args):
    """Recursively scan a directory for SSH keys."""
    scanner = SSHKeyScanner()
    results = scanner.scan(args.path, recursive=not args.no_recurse)

    if not results:
        if not args.json:
            print(f"[*] No SSH keys found in {args.path}")
        else:
            print(json.dumps([]))
        return 0

    if args.json:
        output = [r.to_dict() for r in results]
        print(json.dumps(output, indent=2))
    else:
        encrypted = [r for r in results if r.success and r.info.is_encrypted]
        unencrypted = [r for r in results if r.success and not r.info.is_encrypted]
        errors = [r for r in results if not r.success]

        print(f"\n{'='*60}")
        print(f"  SSH Key Scan: {args.path}")
        print(f"  Found: {len(results)} keys "
              f"({len(encrypted)} encrypted, {len(unencrypted)} unencrypted, {len(errors)} errors)")
        print(f"{'='*60}")

        if unencrypted:
            print(f"\n  [CRITICAL] Unencrypted keys:")
            for r in unencrypted:
                print(f"    - {r.filepath} ({r.info.key_type or 'unknown type'})")

        if encrypted:
            print(f"\n  [INFO] Encrypted keys:")
            for r in encrypted:
                detail = f"{r.info.cipher}"
                if r.info.rounds:
                    detail += f", {r.info.rounds} rounds"
                print(f"    - {r.filepath} ({detail})")

        if errors:
            print(f"\n  [WARN] Parse errors:")
            for r in errors:
                print(f"    - {r.filepath}: {r.error}")

        print()

    return 0


def parse_args(argv=None):
    """Parse command-line arguments."""
    ap = argparse.ArgumentParser(
        prog="ssh-parser",
        description="Parse SSH private keys and extract encryption metadata.",
    )
    sub = ap.add_subparsers(dest="command")

    # Parse subcommand (default behavior)
    parse_cmd = sub.add_parser("parse", help="Parse individual key files")
    parse_cmd.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="SSH private key file(s) to parse",
    )
    parse_cmd.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON",
    )

    # Scan subcommand
    scan_cmd = sub.add_parser("scan", help="Recursively scan directory for SSH keys")
    scan_cmd.add_argument(
        "path",
        type=Path,
        help="Directory to scan for SSH keys",
    )
    scan_cmd.add_argument(
        "--no-recurse",
        action="store_true",
        default=False,
        help="Do not recurse into subdirectories",
    )
    scan_cmd.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON",
    )

    args = ap.parse_args(argv)

    # If no subcommand given, treat positional args as files (backward compat)
    if args.command is None:
        # Re-parse with legacy behavior
        legacy = argparse.ArgumentParser(prog="ssh-parser")
        legacy.add_argument("files", nargs="+", type=Path)
        legacy.add_argument("--json", action="store_true", default=False)
        args = legacy.parse_args(argv)
        args.command = "parse"

    return args


def _print_result(filepath, info):
    """Print a human-readable summary of parsed key info."""
    print(f"\n{'='*60}")
    print(f"  File:       {filepath}")
    print(f"  Format:     {info.format.value}")
    print(f"  State:      {info.state.value}")
    if info.key_type:
        print(f"  Key Type:   {info.key_type}")
    if info.cipher:
        print(f"  Cipher:     {info.cipher}")
    if info.kdf:
        print(f"  KDF:        {info.kdf}")
    if info.salt_hex:
        print(f"  Salt:       {info.salt_hex}")
    if info.rounds:
        print(f"  Rounds:     {info.rounds}")
    if info.iv_hex:
        print(f"  IV:         {info.iv_hex}")
    if info.errors:
        print(f"  Warnings:   {'; '.join(info.errors)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    sys.exit(main())
