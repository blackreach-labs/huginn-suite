---
title: 'List directories on target:'
updated: 2023-10-28 08:31:27Z
created: 2023-10-28 08:29:24Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

List directories on target:
`rsync --list-only <targetip>::` 

List contents of directory:
`rsync --list-only <targetip>::directory` 

Copy file from remote to local:
`rsync <targetip>::directory/file.txt /tmp/rsync`