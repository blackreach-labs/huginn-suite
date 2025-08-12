---
title: mysql
updated: 2025-04-19 12:08:06Z
created: 2025-04-19 12:00:26Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

Connect to **mysql** as **root**
`mysql -u root -p'password' -h <target> -P 3306`

Show version:
`SELECT version();`

Show current user and hostname for the mysql connection:
`SELECT system_user();`

Database work:
`SHOW databases;`

Retrieve password of user 'offsec' in the mysql database:
`SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';`
Note: Passwords are store as SHA-256 hash
