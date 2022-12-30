# Enumeration
## nmap scan
```sh
sami@bt:~/Documents/THM/CTFs/Biohazard$ sudo nmap -A -p- -oN nmap_results.txt biohazard.thm
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-05 00:25 EET
Nmap scan report for biohazard.thm (10.10.223.143)
Host is up (0.059s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c903aaaaeaa9f1f40979c0474116f19b (RSA)
|   256 2e1d83116503b478e96d94d13bdbf4d6 (ECDSA)
|_  256 913de44fabaae29e44afd3578670bc39 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Beginning of the end
|_http-server-header: Apache/2.4.29 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/5%OT=21%CT=1%CU=38991%PV=Y%DS=2%DC=T%G=Y%TM=638D1E7
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10A%TI=Z%CI=I%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   57.42 ms 10.11.0.1
2   57.77 ms biohazard.thm (10.10.223.143)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.10 seconds
```
### Notes
- `ssh` is open on port `21`
- `ftp` is open on port `22`
- `http` is open on port `80`
## visit the website
- Picture of the website:
![[Pasted image 20221205002953.png]]
- `html` source-code:
```html
<!doctype html>
	<head>
		<title>Beginning of the end</title>
		<h1 align="center">The nightmare begin</h1>
	</head>

	<body>
	<img alt="mansion_front" src="[images/Mansion_front.jpg](view-source:http://biohazard.thm/images/Mansion_front.jpg)" style="display: block;margin-left: auto;margin-right: auto; width: 50%;"/>
	
	<p>July 1998, Evening</p>
	<p>The STARS alpha team, Chris, Jill, Barry, Weasker and Joseph is in the operation on searching the STARS bravo team in the nortwest of Racoon city.</p>
	<p>Unfortunately, the team was attacked by a horde of infected zombie dog. Sadly, Joseph was eaten alive.</p>
	<p>The team decided to run for the nearby <a href="[/mansionmain](view-source:http://biohazard.thm/mansionmain)"> mansion </a> and the nightmare begin..........</p>   
	</body>

</html>/home/sami/Documents/THM/Rooms/Advent_of_Cyber/day5/home/sami/Documents/THM/Rooms/Advent_of_Cyber/day5
```
- `http://biohazard.thm/mansionmain/`:
![[Pasted image 20221205003205.png]]