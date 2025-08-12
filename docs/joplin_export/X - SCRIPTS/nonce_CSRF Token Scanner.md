---
title: nonce/CSRF Token Scanner
updated: 2025-04-17 08:27:14Z
created: 2025-04-17 08:01:14Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## nonce_scanner.py

✅ Fetches a URL
✅ Scans for nonce/CSRF tokens using multiple common patterns
✅ Displays all matches (labelled by possible framework)
✅ Uses requests + re for maximum portability

```
import re
import requests

# Common regex patterns mapped to frameworks
TOKEN_PATTERNS = {
    'wordpress': re.compile(r'name=["\']?_wpnonce(?:_create-user)?["\']?\s+value=["\']?([^"\'>\s]+)["\']?'),
    'laravel': re.compile(r'name=["\']?_token["\']?\s+value=["\']?([^"\'>\s]+)["\']?'),
    'django': re.compile(r'name=["\']?csrfmiddlewaretoken["\']?\s+value=["\']?([^"\'>\s]+)["\']?'),
    'generic': re.compile(r'name=["\']?csrf_token["\']?\s+value=["\']?([^"\'>\s]+)["\']?'),
    'meta_tag': re.compile(r'<meta\s+name=["\']?csrf-token["\']?\s+content=["\']?([^"\'>\s]+)["\']?'),
    'js_var': re.compile(r'var\s+[^=]*nonce[^=]*=\s*["\']([^"\']+)["\']')
}

def scan_tokens(url):
    print(f"Scanning {url} for CSRF/nonces...\n")
    try:
        # Perform the HTTP request
        response = requests.get(url)

        # Check for 'X-CSRF-Token' header
        csrf_token = response.headers.get('X-CSRF-Token')
        if csrf_token:
            print(f"Found CSRF token in header: X-CSRF-Token = {csrf_token}\n")
        
        html = response.text

        found = False
        # Search for nonce tokens in the page content using regex
        for label, pattern in TOKEN_PATTERNS.items():
            matches = pattern.findall(html)
            if matches:
                found = True
                print(f"Found {len(matches)} match(es) for '{label}':")
                for match in matches:
                    print(f"    -> {match}")
                print()

        if not found and not csrf_token:
            print("No tokens found in HTML or headers.")
    except Exception as e:
        print(f"Error: {e}")

# Example usage
if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ").strip()
    scan_tokens(target_url)
```
