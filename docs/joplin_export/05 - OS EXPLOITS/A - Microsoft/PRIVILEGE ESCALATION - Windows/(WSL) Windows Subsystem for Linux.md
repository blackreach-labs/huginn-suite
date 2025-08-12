---
title: ' (WSL) Windows Subsystem for Linux'
updated: 2023-10-05 09:54:00Z
created: 2023-10-03 02:12:48Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# (WSL) Windows Subsystem for Linux
1. locate **wsl.exe** and **bash.exe**
`where /R c:\ wsl.exe`
`where /R c:\ bash.exe`
Add to PATH
`set PATH=%PATH%;<wsl.exe path>;<bash.exe path;`

2. Run bash.exe
Import tty to get a prompt:
`python -c "import pty;pty.spawn('/bin/bash')"`
