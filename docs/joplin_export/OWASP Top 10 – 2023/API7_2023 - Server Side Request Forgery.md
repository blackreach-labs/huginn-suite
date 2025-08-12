---
title: API7:2023 - Server Side Request Forgery
updated: 2023-11-05 04:52:47Z
created: 2023-11-05 04:52:41Z
latitude: -33.85985000
longitude: 151.20901000
altitude: 0.0000
---

Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote resource without validating the user-supplied URI. This enables an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall or a VPN.