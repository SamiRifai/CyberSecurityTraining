# Setting up
```sh
⚡sudo vim /etc/hosts
...
10.10.50.173	bio.thm
...
⚡ping -c 4 bio.thm
PING bio.thm (10.10.50.173) 56(84) bytes of data.
64 bytes from bio.thm (10.10.50.173): icmp_seq=1 ttl=63 time=88.0 ms
64 bytes from bio.thm (10.10.50.173): icmp_seq=2 ttl=63 time=84.1 ms
64 bytes from bio.thm (10.10.50.173): icmp_seq=3 ttl=63 time=76.2 ms
64 bytes from bio.thm (10.10.50.173): icmp_seq=4 ttl=63 time=54.4 ms

--- bio.thm ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 54.362/75.668/88.016/13.022 ms
```
# Enumeration
## nmap scan
```sh
⚡sudo nmap -A -p- -oN nmap_results.txt bio.thm
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-02 21:43 EET
Nmap scan report for bio.thm (10.10.50.173)
Host is up (0.055s latency).
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
OS:SCAN(V=7.93%E=4%D=1/2%OT=21%CT=1%CU=44162%PV=Y%DS=2%DC=T%G=Y%TM=63B33400
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=2%ISR=10D%TI=Z%CI=I%II=I%TS=A)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(
OS:R=Y%DF=Y%T=40%W=6903%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   53.94 ms 10.11.0.1
2   53.99 ms bio.thm (10.10.50.173)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.28 seconds
```
### Notes
- `ssh` is open on port `21`
- `ftp` is open on port `22`
- `http` is open on port `80`
## The website (The Mansion)
- Picture of the website:
![[Pasted image 20221205002953.png]]
- from the source-code we obtain:
	- `<a href="/mansionmain"> mansion` directory called `mansionmain`
- Visiting `http://biohazard.thm/mansionmain/`:
![[Pasted image 20221205003205.png]]
- Checking the source-code:
	- `<!-- It is in the /diningRoom/ -->`
![[Pasted image 20230102215137.png]]
- Clicking on `YES` shows us:
```txt
emblem{fec832623ea498e20bf4fe1821d58727}

Look like you can put something on the emblem slot, refresh /diningRoom/
```
- Refreshing the `/diningRoom/` page we see the following changes:
![[Pasted image 20230102215422.png]]
- A form to input the obtained emblem 
- Let's check the source-code of the `/diningRoom/`
```txt
line 13: <!-- SG93IGFib3V0IHRoZSAvdGVhUm9vbS8= -->
```
- Decoding the following line
```sh
⚡ echo "SG93IGFib3V0IHRoZSAvdGVhUm9vbS8=" | base64 -d
How about the /teaRoom/
```
- Checking the `/teaRoom/`
![[Pasted image 20230102215950.png]]
- Handsome... now let's check the Lockpick link
```txt
lock_pick{037b35e2ff90916a9abf99129c8e1837}
```
- Moving to `/artRoom/`
![[Pasted image 20230102220243.png]]
- Clicking on `YES`
```txt
Look like a map
Location:  
/diningRoom/  
/teaRoom/  
/artRoom/  
/barRoom/  
/diningRoom2F/  
/tigerStatusRoom/  
/galleryRoom/  
/studyRoom/  
/armorRoom/  
/attic/
```
- So far we've checked a few so let's remove them from the list
```txt
/barRoom/  
/diningRoom2F/  
/tigerStatusRoom/  
/galleryRoom/  
/studyRoom/  
/armorRoom/  
/attic/
```
- We start investigating from top to bottom
- Checking `/barRoom/`
![[Pasted image 20230102221121.png]]
- Entering the `lock_pick` that we've found
![[Pasted image 20230102221219.png]]
- Checking the `READ` link we get
```txt
<p>Look like a music note</p>

NV2XG2LDL5ZWQZLFOR5TGNRSMQ3TEZDFMFTDMNLGGVRGIYZWGNSGCZLDMU3GCMLGGY3TMZL5
```
- Not base64 encoded, let's see if base32 encoded
```sh
⚡ echo "NV2XG2LDL5ZWQZLFOR5TGNRSMQ3TEZDFMFTDMNLGGVRGIYZWGNSGCZLDMU3GCMLGGY3TMZL5" | base32 -d
music_sheet{362d72deaf65f5bdc63daece6a1f676e}⏎ 
```
- Let's put that `music_sheet` into the piano input form, we got transferred to:
![[Pasted image 20230102221846.png]]
- Clicking on `YES`
```html
<p>gold_emblem{58a8c41a9d08b8a4e38d02a4d7ff4843}</p>
<p>Look like you can put something on the emblem slot, refresh the previous page</p>
```
- Putting the `gold_emblem` in the input form we get
```txt
Nothing happen
```
- Putting the `emblem` taken from the `/diningRoom/` we get
```txt
rebecca
```
- Putting back the `gold_emblem` we get
```txt 
klfvg ks r wimgnd biz mpuiui ulg fiemok tqod. Xii jvmc tbkg ks tempgf tyi_hvgct_jljinf_kvc
```
- Let's set the key as `rebecca` and see the results
```txt
there is a shield key inside the dining room. The html page is called the_great_shield_key
```
- And we found the shield key 
```txt
shield_key{48a7a9227cd7eb89f0a062590798cbac}
```
- Let's move to the `/diningRoom2F/`
![[Pasted image 20230102222755.png]]
- Let's check the source-code
```txt
Lbh trg gur oyhr trz ol chfuvat gur fgnghf gb gur ybjre sybbe. Gur trz vf ba gur qvavatEbbz svefg sybbe. Ivfvg fnccuver.ugzy
```
- Looks like a cipher text, let's find out in Cyberchef
	- Rules: Vigenere Decode > Key: N        _I brute forced all alphabetic letters :D_
	- `You get the blue gem by pushing the status to the lower floor. The gem is on the diningRoom first floor. Visit sapphire.html`
- Let's check `http://10.10.50.173/diningRoom/sapphire.html`
```txt
blue_jewel{e1d457e96cac640f863ec7bc475d48aa}
```
- Moving on to `/tigerStatusRoom/`
![[Pasted image 20230102225342.png]]
- Let's input the `blue_jewel` in the input form
```txt
crest 1:  
S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9  
Hint 1: Crest 1 has been encoded twice  
Hint 2: Crest 1 contanis 14 letters  
Note: You need to collect all 4 crests, combine and decode to reavel another path  
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```
- Decoding `S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9`
	- Rules: Base64 > Base32 > Base64:
		- Results: `FTP user: `
- Let's find out the rest by visiting `/galleryRoom/`
![[Pasted image 20230102230546.png]]
- Checking the note in `EXAMIN`
```txt
crest 2:
GVFWK5KHK5WTGTCILE4DKY3DNN4GQQRTM5AVCTKE
Hint 1: Crest 2 has been encoded twice
Hint 2: Crest 2 contanis 18 letters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```
- Decoding `GVFWK5KHK5WTGTCILE4DKY3DNN4GQQRTM5AVCTKE`
	- Cyberchef rules: Base32 > Base58:
		- Results: `h1bnRlciwgRlRQIHBh`
- Let's investigate further in `/studyRoom/`
	- Source-code:
```html
<html>
        <head>
                <title>Study room entrance</title>
                <h1 align="center">Study room entrance</h1>
        </head>

        <body>
        <img alt="door" src="[../images/16-Image33-1.jpg](view-source:http://10.10.50.173/images/16-Image33-1.jpg)" style="display: block;margin-left: auto;margin-right: auto; width: 50%;"/>

        <p>Look like the door has been locked</p>
	<p>A <b>helmet symbol</b> is embedded on the door </p>
	<form action=[unlock_door.php](view-source:http://10.10.50.173/studyRoom/unlock_door.php) method="POST">
		<input type="text" col="100" name="door_flag" placeholder="Enter flag"/>
		<input type="submit" value="submit"/>
	</form>
        </body>

</html>
```
- Analyzed the image:
```sh
⚡ strings 16-Image33-1.jpg 
<?xpacket begin="
" id="W5M0MpCehiHzreSzNTczkc9d"?>
```
- I don't know if that ID has to do with anything
- Checking `/attic/` room
![[Pasted image 20230102235453.png]]
- Submitting the shield key we get transferred to 
![[Pasted image 20230102235812.png]]
- Reading the note that was inside the body
```txt
crest 4:
gSUERauVpvKzRpyPpuYz66JDmRTbJubaoArM6CAQsnVwte6zF9J4GGYyun3k5qM9ma4s
Hint 1: Crest 2 has been encoded twice
Hint 2: Crest 2 contanis 17 characters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```
- Okay let's make a list of visited places so far
```txt
/diningRoom/      # Done
/teaRoom/         # Done
/artRoom/         # Done
/barRoom/         # Done
/diningRoom2F/    # Done
/tigerStatusRoom/ # Done
/galleryRoom/     # Done
/studyRoom/       
/armorRoom/       
/attic/           # Done
```
- Checking the `/armorRoom/`
![[Pasted image 20230103000751.png]]
- Putting the shield key we get
![[Pasted image 20230103000842.png]]
- Clicking on `READ` to read the note
```txt
crest 3:
MDAxMTAxMTAgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAxMDAgMDExMDAxMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMTEgMDAxMDAwMDAgMDAxMTAxMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTAxMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMDEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTEwMDA=
Hint 1: Crest 3 has been encoded three times
Hint 2: Crest 3 contanis 19 letters
Note: You need to collect all 4 crests, combine and decode to reavel another path
The combination should be crest 1 + crest 2 + crest 3 + crest 4. Also, the combination is a type of encoded base and you need to decode it
```
- All crests notes combined
```txt
1 S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9

2 GVFWK5KHK5WTGTCILE4DKY3DNN4GQQRTM5AVCTKE

3 MDAxMTAxMTAgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTEgMDAxMDAwMDAgMDAxMTAxMDAgMDExMDAxMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDAgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMTEgMDAxMDAwMDAgMDAxMTAxMTEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTAxMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMTAgMDExMDAwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDEgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTAxMTEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAxMDEgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMDAgMDAxMDAwMDAgMDAxMTAxMDEgMDAxMTEwMDAgMDAxMDAwMDAgMDAxMTAwMTEgMDAxMTAwMTAgMDAxMDAwMDAgMDAxMTAxMTAgMDAxMTEwMDA=

4 gSUERauVpvKzRpyPpuYz66JDmRTbJubaoArM6CAQsnVwte6zF9J4GGYyun3k5qM9ma4s
```
- Crest 1 decoded Base64 > Base32
```txt
RlRQIHVzZXI6IG
```
- Crest 2 decoded Base32 > Base58
```txt
h1bnRlciwgRlRQIHBh
```
- Crest 3 decoded base64 > binary > hex
```txt
c3M6IHlvdV9jYW50X2h
```
- Crest 4 decode base58 > hex
```txt
pZGVfZm9yZXZlcg==
```
- The combined strings looks like
```txt
RlRQIHVzZXI6IGh1bnRlciwgRlRQIHBhc3M6IHlvdV9jYW50X2hpZGVfZm9yZXZlcg==
```
- Decoded from base64
```txt 
FTP user: hunter, FTP pass: you_cant_hide_forever
```
## FTP Login (The guard house)
```sh
⚡ ftp hunter@10.10.50.173
Connected to 10.10.50.173.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            7994 Sep 19  2019 001-key.jpg
-rw-r--r--    1 0        0            2210 Sep 19  2019 002-key.jpg
-rw-r--r--    1 0        0            2146 Sep 19  2019 003-key.jpg
-rw-r--r--    1 0        0             121 Sep 19  2019 helmet_key.txt.gpg
-rw-r--r--    1 0        0             170 Sep 20  2019 important.txt
226 Directory send OK.
ftp> get 001-key.jpg
⚡ cat important.txt 
Jill,

I think the helmet key is inside the text file, but I have no clue on decrypting stuff. Also, I come across a /hidden_closet/ door but it was locked.

From,
Barry
```
### exiftool
```sh
⚡ exiftool 001-key.jpg 
ExifTool Version Number         : 12.50
File Name                       : 001-key.jpg
Directory                       : .
File Size                       : 8.0 kB
File Modification Date/Time     : 2023:01:03 00:51:37+02:00
File Access Date/Time           : 2023:01:03 01:02:08+02:00
File Inode Change Date/Time     : 2023:01:03 00:51:37+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 400
Image Height                    : 320
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 400x320
Megapixels                      : 0.128
⚡ exiftool 002-key.jpg
ExifTool Version Number         : 12.50
File Name                       : 002-key.jpg
Directory                       : .
File Size                       : 2.2 kB
File Modification Date/Time     : 2023:01:03 00:52:33+02:00
File Access Date/Time           : 2023:01:03 01:02:12+02:00
File Inode Change Date/Time     : 2023:01:03 00:52:33+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Comment                         : 5fYmVfZGVzdHJveV9
Image Width                     : 100
Image Height                    : 80
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 100x80
Megapixels                      : 0.008
⚡ exiftool 003-key.jpg
ExifTool Version Number         : 12.50
File Name                       : 003-key.jpg
Directory                       : .
File Size                       : 2.1 kB
File Modification Date/Time     : 2023:01:03 00:52:11+02:00
File Access Date/Time           : 2023:01:03 01:02:14+02:00
File Inode Change Date/Time     : 2023:01:03 00:52:11+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Comment                         : Compressed by jpeg-recompress
Image Width                     : 100
Image Height                    : 80
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 100x80
Megapixels                      : 0.008
```
- Comment from the second image:
	- `5fYmVfZGVzdHJveV9`
- Looking at the hint, we see the word "Three picture, three hints: hide [Stehide], comment [Exiftool] and walk away [Binwalk]" and we have images.
### steghide
```sh
⚡ steghide extract -sf 001-key.jpg
Enter passphrase: 
wrote extracted data to "key-001.txt".
⚡ cat key-001.txt 
cGxhbnQ0Ml9jYW
```
### binwalk
```
⚡ binwalk -e 003-key.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
1930          0x78A           Zip archive data, at least v2.0 to extract, uncompressed size: 14, name: key-003.txt
2124          0x84C           End of Zip archive, footer length: 22

```
- Let's combine the two obtained codes
```txt
cGxhbnQ0Ml9jYW5fYmVfZGVzdHJveV93aXRoX3Zqb2x0
```
- Let's decode them from base64 
```sh 
⚡ echo "cGxhbnQ0Ml9jYW5fYmVfZGVzdHJveV93aXRoX3Zqb2x0" | base64 -d
plant42_can_be_destroy_with_vjolt 
```
- With that string, let'd extract the helmet gpg file
```sh
⚡ gpg helmet_key.txt.gpg
gpg: WARNING: no command supplied.  Trying to guess what you mean ...
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase
⚡cat helmet_key.txt
helmet_key{458493193501d2b94bbab2e727f8db4b}
```
## The Revisit
- Before we investigate further, let's revisit our list of rooms
```txt
/diningRoom/      # Done
/teaRoom/         # Done
/artRoom/         # Done
/barRoom/         # Done
/diningRoom2F/    # Done
/tigerStatusRoom/ # Done
/galleryRoom/     # Done
/studyRoom/       
/armorRoom/       # Done
/attic/           # Done
/hidden_closet/
```
- Let's access the `/hidden_closet/` with the obtained helmet key
![[Pasted image 20230103234808.png]]
- We see
![[Pasted image 20230103234851.png]]
- Reading the MO disk
```txt
wpbwbxr wpkzg pltwnhro, txrks_xfqsxrd_bvv_fy_rvmexa_ajk
```
- Examining the wolf medal
```txt
SSH password: T_virus_rules
```
- Now let's check the `/studyRoom/`
![[Pasted image 20230104001048.png]]
- Supplying the helmet key send us to 
![[Pasted image 20230104001124.png]]
- Examining the book gives us a download file 
```sh
⚡ ls
-rw-r--r-- 1 sami sami  149 Jan  4 00:11 doom.tar.gz
```
- Let's extract that file
```sh
⚡ tar -xzvf doom.tar.gz 
eagle_medal.txt
⚡ cat eagle_medal.txt 
SSH user: umbrella_guest
```
**Notes:**
- SSH login obtained: umbrella_guest:T_virus_rules
## SSH login (Underground laboratory)
```sh
⚡ ssh umbrella_guest@bio.thm
umbrella_guest@umbrella_corp:~$ id
uid=1001(umbrella_guest) gid=1001(umbrella) groups=1001(umbrella)
umbrella_guest@umbrella_corp:~$ ls -hla
total 64K
drwxr-xr-x  8 umbrella_guest umbrella 4.0K Sep 20  2019 .
drwxr-xr-x  5 root           root     4.0K Sep 20  2019 ..
-rw-r--r--  1 umbrella_guest umbrella  220 Sep 19  2019 .bash_logout
-rw-r--r--  1 umbrella_guest umbrella 3.7K Sep 19  2019 .bashrc
drwxrwxr-x  6 umbrella_guest umbrella 4.0K Sep 20  2019 .cache
drwxr-xr-x 11 umbrella_guest umbrella 4.0K Sep 19  2019 .config
-rw-r--r--  1 umbrella_guest umbrella   26 Sep 19  2019 .dmrc
drwx------  3 umbrella_guest umbrella 4.0K Sep 19  2019 .gnupg
-rw-------  1 umbrella_guest umbrella  346 Sep 19  2019 .ICEauthority
drwxr-xr-x  2 umbrella_guest umbrella 4.0K Sep 20  2019 .jailcell
drwxr-xr-x  3 umbrella_guest umbrella 4.0K Sep 19  2019 .local
-rw-r--r--  1 umbrella_guest umbrella  807 Sep 19  2019 .profile
drwx------  2 umbrella_guest umbrella 4.0K Sep 20  2019 .ssh
-rw-------  1 umbrella_guest umbrella  109 Sep 19  2019 .Xauthority
-rw-------  1 umbrella_guest umbrella 7.4K Sep 19  2019 .xsession-errors
umbrella_guest@umbrella_corp:~$ cd .jailcell/
umbrella_guest@umbrella_corp:~/.jailcell$ ls
chris.txt
umbrella_guest@umbrella_corp:~/.jailcell$ cat chris.txt 
Jill: Chris, is that you?
Chris: Jill, you finally come. I was locked in the Jail cell for a while. It seem that weasker is behind all this.
Jil, What? Weasker? He is the traitor?
Chris: Yes, Jill. Unfortunately, he play us like a damn fiddle.
Jill: Lets get out of here first, I have contact brad for helicopter support.
Chris: Thanks Jill, here, take this MO Disk 2 with you. It look like the key to decipher something.
Jill: Alright, I will deal with him later.
Chris: see ya.

MO disk 2: albert 

umbrella_guest@umbrella_corp:/home$ ls
hunter  umbrella_guest  weasker
umbrella_guest@umbrella_corp:/home$ cd weasker/
umbrella_guest@umbrella_corp:/home/weasker$ ls
Desktop  weasker_note.txt
umbrella_guest@umbrella_corp:/home/weasker$ cat weasker_note.txt 
Weaker: Finally, you are here, Jill.
Jill: Weasker! stop it, You are destroying the  mankind.
Weasker: Destroying the mankind? How about creating a 'new' mankind. A world, only the strong can survive.
Jill: This is insane.
Weasker: Let me show you the ultimate lifeform, the Tyrant.

(Tyrant jump out and kill Weasker instantly)
(Jill able to stun the tyrant will a few powerful magnum round)

Alarm: Warning! warning! Self-detruct sequence has been activated. All personal, please evacuate immediately. (Repeat)
Jill: Poor bastard

```
- Let's use `albert` as a key to decipher the `wpbwbxr wpkzg pltwnhro, txrks_xfqsxrd_bvv_fy_rvmexa_ajk` text. Vigenere Decode with albert key
```txt
weasker login password, stars_members_are_my_guinea_pig
```
- Time to switch user to `weasker:stars_members_are_my_guinea_pig`
```sh
weasker@umbrella_corp:/home$ whoami
weasker
weasker@umbrella_corp:/home$ sudo -l
[sudo] password for weasker: 
Matching Defaults entries for weasker on umbrella_corp:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User weasker may run the following commands on umbrella_corp:
    (ALL : ALL) ALL
weasker@umbrella_corp:/$ sudo cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:110::/run/uuidd:/usr/sbin/nologin
avahi-autoipd:x:106:111:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
rtkit:x:109:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
lightdm:x:110:115:Light Display Manager:/var/lib/lightdm:/bin/false
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
whoopsie:x:112:119::/nonexistent:/bin/false
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:114:121::/var/lib/saned:/usr/sbin/nologin
pulse:x:115:122:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
avahi:x:116:124:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
colord:x:117:125:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:118:7:HPLIP system user,,,:/var/run/hplip:/bin/false
weasker:x:1000:1000:Biohazard,,,:/home/weasker:/bin/bash
sshd:x:119:65534::/run/sshd:/usr/sbin/nologin
umbrella_guest:x:1001:1001:umbrella,1,0,0,0:/home/umbrella_guest:/bin/bash
ftp:x:120:127:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
hunter:x:1002:1002:hunter,1,1,1,1:/home/hunter/FTP:/bin/bash
postfix:x:121:128::/var/spool/postfix:/usr/sbin/nologin
weasker@umbrella_corp:/$ sudo cat /etc/shadow
root:!:18158:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
systemd-network:*:17647:0:99999:7:::
systemd-resolve:*:17647:0:99999:7:::
syslog:*:17647:0:99999:7:::
messagebus:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
uuidd:*:17647:0:99999:7:::
avahi-autoipd:*:17647:0:99999:7:::
usbmux:*:17647:0:99999:7:::
dnsmasq:*:17647:0:99999:7:::
rtkit:*:17647:0:99999:7:::
lightdm:*:17647:0:99999:7:::
speech-dispatcher:!:17647:0:99999:7:::
whoopsie:*:17647:0:99999:7:::
kernoops:*:17647:0:99999:7:::
saned:*:17647:0:99999:7:::
pulse:*:17647:0:99999:7:::
avahi:*:17647:0:99999:7:::
colord:*:17647:0:99999:7:::
hplip:*:17647:0:99999:7:::
weasker:$1$gRf8XKq1$kxVV7sAQTZ6oqEp/mgAx..:18158:0:99999:7:::
sshd:*:18158:0:99999:7:::
umbrella_guest:$6$tXklG.xM$O5656kUL1nCJ7rlEmEvB5/08PWIygj/hbYd2GynOZ3QqyQ5TAJaCqEdDcmkuaSsDo9fi.ZSrwbm6dYxSylcQM1:18158:0:99999:7:::
ftp:*:18158:0:99999:7:::
hunter:$6$I8Ka2yEL$a3FQlz6YxbDHM2mB83TveFYTShrZK8raxSGUmjqAC8veoxZpUsusz1WVl1dEvbP9OQqG.X0SbP5572zD3LSiM/:18158:0:99999:7:::
postfix:*:18159:0:99999:7:::
weasker@umbrella_corp:/$ sudo su
root@umbrella_corp:/# cat /root/root.txt 
In the state of emergency, Jill, Barry and Chris are reaching the helipad and awaiting for the helicopter support.

Suddenly, the Tyrant jump out from nowhere. After a tough fight, brad, throw a rocket launcher on the helipad. Without thinking twice, Jill pick up the launcher and fire at the Tyrant.

The Tyrant shredded into pieces and the Mansion was blowed. The survivor able to escape with the helicopter and prepare for their next fight.

The End

flag: 3c5794a00dc56c35f2bf096571edf3bf
root@umbrella_corp:/# 
```
# Thanks to God, finally... Thanks for reading :) 