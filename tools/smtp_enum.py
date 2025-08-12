#!/usr/bin/env python3
import socket
import time
import argparse
import sys

def smtp_enum(target, port, wordlist_path, domain, helo_name="test.local"):
    with open(wordlist_path, 'r') as f:
        usernames = [line.strip() for line in f if line.strip()]

    for user in usernames:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            banner = s.recv(1024).decode()
            print(f"[+] Connected to {target}:{port}")

            # EHLO/HELO
            s.sendall(f"EHLO {helo_name}\r\n".encode())
            time.sleep(0.5)
            response = s.recv(1024).decode()

            # VRFY
            s.sendall(f"VRFY {user}\r\n".encode())
            time.sleep(0.5)
            response = s.recv(1024).decode()
            
            if "250" in response or "252" in response:
                print(f"[✓] VRFY success for '{user}': {response.strip()}")
            else:
                # EXPN fallback
                s.sendall(f"EXPN {user}\r\n".encode())
                time.sleep(0.5)
                response = s.recv(1024).decode()
                
                if "250" in response:
                    print(f"[✓] EXPN success for '{user}': {response.strip()}")
                else:
                    # RCPT TO fallback
                    s.sendall("MAIL FROM:<test@local>\r\n".encode())
                    time.sleep(0.5)
                    s.recv(1024)
                    s.sendall(f"RCPT TO:<{user}@{domain}>\r\n".encode())
                    time.sleep(0.5)
                    response = s.recv(1024).decode()
                    
                    if "250" in response or "252" in response:
                        print(f"[✓] RCPT TO success for '{user}': {response.strip()}")
                    else:
                        print(f"[-] No methods worked for '{user}'")

            s.close()
        except Exception as e:
            print(f"[!] Error with '{user}': {e}")

def main():
    parser = argparse.ArgumentParser(description="SMTP User Enumeration")
    parser.add_argument("target", help="Target SMTP server")
    parser.add_argument("--port", type=int, default=25, help="SMTP port")
    parser.add_argument("--wordlist", default="resources/wordlists/subdomains-top1000.txt", help="Username wordlist")
    parser.add_argument("--domain", required=True, help="Target domain")
    
    args = parser.parse_args()
    smtp_enum(args.target, args.port, args.wordlist, args.domain)

if __name__ == "__main__":
    main()