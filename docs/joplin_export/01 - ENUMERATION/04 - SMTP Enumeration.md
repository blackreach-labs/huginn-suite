---
title: 04 - SMTP Enumeration
updated: 2025-04-19 03:35:05Z
created: 2025-04-15 13:25:07Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

**VFRY** - Asks the mail server to verify an email address
**EXPAND** - Asks the mail server for the membership of a mailing list
* * *
1. Connect to the mail server using netcat
`nc -nv <target> 25`
`VRFY root`
`VRFY idontexist`
2. Check how the success and error messages differ.
3. This can be used to guess valid usernames in an automated fashion

* * *
## smtp_enum.py
✅ Connects to the SMTP server
✅ Sends EHLO or HELO
✅ Attempts VRFY
✅ Falls back to EXPN
✅ Falls back to RCPT TO
✅ Parses and prints results with success/failure messages

--target (IP or hostname)
--port (default is 25)
--wordlist (path to your username list)
--domain (used in RCPT TO for email addresses)
--helo (defaults to test.local)
--output (specify an output file)

Example: 
**python3 smtp_enum.py \\
  --target mail.example.com \\
  --wordlist users.txt \\
  --domain example.com \\
  --output results.log**


```
import socket
import time
import argparse

def log(message, file=None):
    print(message)
    if file:
        with open(file, 'a') as f:
            f.write(message + "\n")

def send_and_recv(sock, command, delay=0.5):
    """Send a command to the socket and return the response."""
    time.sleep(delay)
    sock.sendall((command + "\r\n").encode())
    return sock.recv(1024).decode()

def smtp_probe(target, port, wordlist_path, domain, helo_name, output_file=None):
    with open(wordlist_path, 'r') as f:
        usernames = [line.strip() for line in f if line.strip()]

    for user in usernames:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            banner = s.recv(1024).decode()
            log(f"\n[+] Connected to {target}:{port} - Banner: {banner.strip()}", output_file)

            # Try EHLO or fallback to HELO
            try:
                response = send_and_recv(s, f"EHLO {helo_name}")
                if not response.startswith("250"):
                    raise Exception("EHLO not accepted")
            except:
                response = send_and_recv(s, f"HELO {helo_name}")

            log(f"[>] EHLO/HELO Response:\n{response.strip()}", output_file)

            # Try VRFY
            response = send_and_recv(s, f"VRFY {user}")
            if "250" in response or "252" in response:
                log(f"[✔] VRFY success for '{user}': {response.strip()}", output_file)
                s.close()
                continue
            else:
                log(f"[-] VRFY failed for '{user}': {response.strip()}", output_file)

                # Try EXPN
                response = send_and_recv(s, f"EXPN {user}")
                if "250" in response:
                    log(f"[✔] EXPN success for '{user}': {response.strip()}", output_file)
                    s.close()
                    continue
                else:
                    log(f"[-] EXPN failed: {response.strip()}", output_file)

                    # Try RCPT TO
                    send_and_recv(s, "MAIL FROM:<test@local>")
                    rcpt_response = send_and_recv(s, f"RCPT TO:<{user}@{domain}>")
                    if "250" in rcpt_response or "252" in rcpt_response:
                        log(f"[✔] RCPT TO success (user might exist): {rcpt_response.strip()}", output_file)
                    else:
                        log(f"[-] RCPT TO failed: {rcpt_response.strip()}", output_file)

            s.close()

        except Exception as e:
            log(f"[!] Error verifying '{user}': {e}", output_file)
            try:
                s.close()
            except:
                pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SMTP User Enumeration Tool")
    parser.add_argument("--target", required=True, help="Target SMTP server IP or hostname")
    parser.add_argument("--port", type=int, default=25, help="SMTP port (default: 25)")
    parser.add_argument("--wordlist", required=True, help="Path to username wordlist")
    parser.add_argument("--domain", required=True, help="Target domain for RCPT TO fallback")
    parser.add_argument("--helo", default="test.local", help="HELO name (default: test.local)")
    parser.add_argument("--output", help="File to write output to (appends if exists)")

    args = parser.parse_args()
    smtp_probe(args.target, args.port, args.wordlist, args.domain, args.helo, args.output)


```

