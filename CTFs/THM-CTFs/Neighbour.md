# Enumeration
## ping
```sh
sami@bt:~/Documents/THM/CTFs/Neighbour$ ping 10.10.217.101
PING 10.10.217.101 (10.10.217.101) 56(84) bytes of data.
64 bytes from 10.10.217.101: icmp_seq=1 ttl=63 time=67.2 ms
64 bytes from 10.10.217.101: icmp_seq=2 ttl=63 time=67.1 ms
^C
--- 10.10.217.101 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 67.060/67.117/67.174/0.057 ms
```
## port scan with [[nmap]]
```sh
sami@bt:~/Documents/THM/CTFs/Neighbour$ sudo nmap -A -p- -oN nmap_results.txt 10.10.217.101
[sudo] password for sami: 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-11 22:39 EET
Nmap scan report for 10.10.217.101
Host is up (0.067s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ec9c5d1582d9b615e2ec9a5c05cb57c3 (RSA)
|   256 bb2410bbcc4b049c089772ec9946b069 (ECDSA)
|_  256 7784d4c78bb4f6540c8b4b38cf849b11 (ED25519)
80/tcp open  http    Apache httpd 2.4.53 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
|_http-server-header: Apache/2.4.53 (Debian)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=11/11%OT=22%CT=1%CU=32995%PV=Y%DS=2%DC=T%G=Y%TM=636EB3
OS:23%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OP
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

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   66.65 ms 10.11.0.1
2   67.10 ms 10.10.217.101

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.17 seconds
```
### Notes:
- ssh in on port 22
- http on port 80
# http://neighbour.thm/
```sh
sami@bt:~/Documents/THM/CTFs/Neighbour$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	bt
10.10.217.101	neighbour.thm
```
![[Pasted image 20221111224427.png]]
## ctrl+u
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="[https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css](view-source:https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css)">
    <style>
        body{ font: 14px sans-serif; }
        .wrapper{ width: 360px; padding: 20px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Login</h2>
        <p>Please fill in your credentials to login.</p>

        <div class="alert alert-danger">Invalid username or password.</div>
        <form action="[/index.php](view-source:http://neighbour.thm/index.php)" method="post">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control " value="test">
                <span class="invalid-feedback"></span>
            </div>    
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" class="form-control ">
                <span class="invalid-feedback"></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p>Don't have an account? Use the guest account! (<code>Ctrl+U</code>)</p>
            <!-- use guest:guest credentials until registration is fixed. "admin" user account is off limits!!!!! -->
        </form>
    </div>
</body>
</html>
```
### Notes:
`<!-- use guest:guest credentials until registration is fixed. "admin" user account is off limits!!!!! -->`
## guest account
![[Pasted image 20221111224749.png]]
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <!-- admin account could be vulnerable, need to update -->
    <link rel="stylesheet" href="[https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css](view-source:https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css)">
    <style>
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <h1 class="my-5">Hi, <b>guest</b>. Welcome to our site. Try not to peep your neighbor's profile.</h1>
    <p>
        <a href="[logout.php](view-source:http://neighbour.thm/logout.php)" class="btn btn-danger ml-3">Sign Out of Your Account</a>
    </p>
</body>
</html>
```
Notes:
`<!-- admin account could be vulnerable, need to update -->`
- URL: `http://neighbour.thm/profile.php?user=guest` Attention to `user=guest`
- Testing for IDOR vulnerability by changing from `guest` to `admin`
## admin account
![[Pasted image 20221111225256.png]]
# Done