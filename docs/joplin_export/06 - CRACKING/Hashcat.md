---
title: Hashcat
updated: 2025-04-29 02:20:50Z
created: 2025-04-24 13:34:04Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

# Professional Hashcat Integration

> **Note**: This tool now includes advanced professional features. See [Professional Cracking Suite](Professional%20Cracking%20Suite.md) for complete capabilities.

## Advanced Features
- **Auto-detection**: Automatic hash type identification
- **GPU Acceleration**: CUDA/OpenCL optimization
- **Multi-threading**: Configurable thread counts
- **Real-time Stats**: Live progress monitoring
- **Advanced Rules**: 50+ mutation patterns

# Mutating wordlists

### Using Rule files with Hashcat

Create rules, or use predefined hashcat rule located at:  
`/usr/share/hashcat/rules`

![fe9f4816ab10e87cd068c6b5c2f6faac.png](../_resources/fe9f4816ab10e87cd068c6b5c2f6faac.png)![492d6adfe767ab43cf41246f32499fb8.png](../_resources/492d6adfe767ab43cf41246f32499fb8.png)![cbb5af218f82fa260664e3ae49443442.png](../_resources/cbb5af218f82fa260664e3ae49443442.png)

![a7ec0e6cbf1e27e8bc56761f1f50d5f2.png](../_resources/a7ec0e6cbf1e27e8bc56761f1f50d5f2.png)
* * *

Create rules that must match passwords in a wordlist.

**Example wordlist:**
Window
rickc137
dave
superdave
megadave
umbrella

**Password Policy:**
- 3 numbers
- A caplital letter
- A special character

**ssh.rule** file
- Use **c** for Capitalization of the first letter
- Use 1 3 7 for the numerical values
- Append different special characters (**!**, **@**, **#**)
```
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#
```
* * *
**Run hashcat with rule**
`hashcat -m 22921 <hash_file> <password_list> -r ssh.rule --force`

**Note**: If you get an error "**Token length exception**", it's becuase **22921** doesn't support **aes-256-ctr** -- Then use **JohntheRipper**

* * * 
### Cracking SAM NTLM hashes
1. Copy NTLM hash to file **sam.hash**
2. Check the cipher used `hashcat --help | grep -i "ntlm"`
3. Using 1000 for NTLM Operating System 
`hashcat -m 1000 sam.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### Cracking NetNTLMv2 hashes
1. Copy NetNTLMv2 has to **file.hash**
2. Check the cipher used `hashcat --help | grep -i "ntlm"`
3. Using 5600 for NetNTLMv2
`hashcat -m 5600 file.hash /usr/share/wordlists/rockyou.txt --force`