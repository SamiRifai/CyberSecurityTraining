# What is [[dig]]?
The **`dig`** command in Linux is used to gather DNS information. It stands for Domain Information Groper, and it collects data about Domain Name Servers. The **`dig`** command is helpful for [troubleshooting DNS problems](https://phoenixnap.com/kb/dns-troubleshooting), but is also used to display DNS information.

# Enumartion
## nmap scan
```sh
sami@bt:~/Documents/THM/CTFs/Dig_Dug$ sudo nmap -A -p- -oN nmap_results.txt givemetheflag.com
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-04 23:14 EET
Nmap scan report for givemetheflag.com (10.10.247.127)
Host is up (0.055s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 081d28747ab7b2a7c3b94d1990ec2c07 (RSA)
|   256 8b03796f269b03d38ff75cb0ace49834 (ECDSA)
|_  256 d51f7feb082fcbec26edff2c4a27f9a0 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/4%OT=22%CT=1%CU=30585%PV=Y%DS=2%DC=T%G=Y%TM=638D0DE
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=2%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
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
1   54.77 ms 10.11.0.1
2   55.04 ms givemetheflag.com (10.10.247.127)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.41 seconds
```
### Notes
- `ssh` open on port 22
- " A regular Nmap scan does not revile the hidden secure DNS port on the host" from https://systemweakness.com/dig-dug-dns-enumeration-on-thm-2691c3699c7f
## xmas nmap scan
```sh
sami@bt:~/Documents/THM/CTFs/Dig_Dug$ sudo nmap -sX -sV -p- -oN nmap_xmas_results.txt givemetheflag.com
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-04 23:19 EET
Nmap scan report for givemetheflag.com (10.10.247.127)
Host is up (0.058s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE         SERVICE    VERSION
22/tcp    open          ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
53/tcp    open|filtered tcpwrapped
49153/tcp open|filtered tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.91 seconds
```
### Notes
- port 53 is open
- port 49153 is open 
## dig query
```sh
sami@bt:~/Documents/THM/CTFs/Dig_Dug$ dig @10.10.247.127 givemetheflag.com AA

; <<>> DiG 9.18.7-1-Debian <<>> @10.10.247.127 givemetheflag.com AA
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40198
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;givemetheflag.com.		IN	A

;; ANSWER SECTION:
givemetheflag.com.	0	IN	TXT	"flag{0767ccd06e79853318f25aeb08ff83e2}"

;; Query time: 55 msec
;; SERVER: 10.10.247.127#53(10.10.247.127) (UDP)
;; WHEN: Sun Dec 04 23:38:34 EET 2022
;; MSG SIZE  rcvd: 86

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9950
;; flags: qr aa; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;AA.				IN	A

;; Query time: 55 msec
;; SERVER: 10.10.247.127#53(10.10.247.127) (UDP)
;; WHEN: Sun Dec 04 23:38:34 EET 2022
;; MSG SIZE  rcvd: 20
```
## [[nslookup]]
```sh
sami@bt:~/Documents/THM/CTFs/Dig_Dug$ nslookup givemetheflag.com  10.10.247.127 
Server:		10.10.247.127
Address:	10.10.247.127#53

givemetheflag.com	text = "flag{0767ccd06e79853318f25aeb08ff83e2}"
givemetheflag.com	text = "flag{0767ccd06e79853318f25aeb08ff83e2}"
```
## [[dnsrecon]]