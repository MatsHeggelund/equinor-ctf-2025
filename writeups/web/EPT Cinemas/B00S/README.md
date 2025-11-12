# EPT Cinemas Writeup - Team B00S

`Author: Bludsoe`

Since the task description was `Sometimes you can still find one of the most classical errors in even the most modern applications.`, I assumed the exploit here would be something very simple within web-hacking. By looking around on the website and in the source code, I was quickly able to find a SQL injection vulnerability. 

<img src="./images/vulnerability.png" width="100%" height="75%">

Here we see that the movie-id that is put in the url is directly inserted into the SQL query, without any form of sanitazion (the most common form of SQL vulnerability). Since just changing around the actual URL parameter didn't do anything, I tried to scan for vulnerabilities with `sqlmap`. 

<img src="./images/sqlmap-scan.png" width="100%">
...
<img src="./images/scan-results.png" width="100%">

As you can see, by scanning the url and having the movie-id as the scanning parameter, sqlmap was able to find a vulnerability for it. The reason we use the flags `--level 5 --risk 3` is because we want to make sure that sqlmap tests all kinds of vulnerabilities, no matter how much we mess around with queries. This is because there might be a vulnerability, but if we don't test it good enough, sqlmap might not spot it. 

Since we also know the DBMS is SQLite, we can use the vulnerability technique to find the tables in the database. We first try using the boolean-based blind injection to see if sqlmap can find the tables using that.

<img src="./images/table-scan.png" width="100%">

<img src="./images/table-results.png" width="25%">

By scanning for the tables in the database using the boolean-based blind injection, we were able to find 4 tables, where one of them is named `flag`. This will most likely be the table that contains the flag for this task, so this is what we choose to dump.

<img src="./images/flag-dump.png" width="100%">
<img src="./images/flag.png" width="75%">

By dumping the flag table we were able to retrieve the flag: `EPT{sql_injection_4_the_Win!}`