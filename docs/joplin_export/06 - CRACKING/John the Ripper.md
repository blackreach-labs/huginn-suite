---
title: John the Ripper
updated: 2025-04-24 15:14:34Z
created: 2025-04-24 15:08:53Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

# Professional John the Ripper Integration

> **Note**: Enhanced with professional features. See [Professional Cracking Suite](Professional%20Cracking%20Suite.md) for advanced capabilities.

## Professional Features
- **Multi-processing**: Fork-based parallel attacks
- **Auto-format Detection**: Automatic hash format recognition
- **Advanced Rules**: Complex mutation patterns
- **Result Management**: Automated result extraction

1. Create a rule file (**ssh.rule**) to use:
- Use **c** for Capitalization of the first letter
- Use 1 3 7 for the numerical values
- Append different special characters (**!**, **@**, **#**)
```
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```

2. **Append** the ssh.rule file to johntheripper configuration file:
`sh -c 'cat ssh.rule >> /etc/john/john.conf'`

3. Run John the Ripper with wordlist
`john --wordlist=<password_list> --rules=sshRules ssh.hash`
