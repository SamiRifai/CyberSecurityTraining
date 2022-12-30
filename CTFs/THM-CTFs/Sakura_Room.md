# TIP-OFF
## background 
The OSINT Dojo recently found themselves the victim of a cyber attack. It seems that there is no major damage, and there does not appear to be any other significant indicators of compromise on any of our systems. However during forensic analysis our admins found an image left behind by the cybercriminals. Perhaps it contains some clues that could allow us to determine who the attackers were? 
We've copied the image left by the attacker, you can view it in your browser here.![[sakurapwnedletter.svg]]
## Instructions
Images can contain a treasure trove of information, both on the surface as well as embedded within the file itself. You might find information such as when a photo was created, what software was used, author and copyright information, as well as other metadata significant to an investigation. In order to answer the following question, you will need to thoroughly analyze the image found by the OSINT Dojo administrators in order to obtain basic information on the attacker.
## Questions
### What username does the attacker go by? 
```sh
sami@bt:~/Documents/THM/CTFs/Sakura_Room$ exiftool sakurapwnedletter.svg 
ExifTool Version Number         : 12.49
File Name                       : sakurapwnedletter.svg
Directory                       : .
File Size                       : 850 kB
File Modification Date/Time     : 2022:11:05 18:47:29+02:00
File Access Date/Time           : 2022:11:05 18:48:09+02:00
File Inode Change Date/Time     : 2022:11:05 18:47:29+02:00
File Permissions                : -rw-r--r--
File Type                       : SVG
File Type Extension             : svg
MIME Type                       : image/svg+xml
Xmlns                           : http://www.w3.org/2000/svg
Image Width                     : 116.29175mm
Image Height                    : 174.61578mm
View Box                        : 0 0 116.29175 174.61578
SVG Version                     : 1.1
ID                              : svg8
Version                         : 0.92.5 (2060ec1f9f, 2020-04-08)
Docname                         : pwnedletter.svg
Export-filename                 : /home/SakuraSnowAngelAiko/Desktop/pwnedletter.png
Export-xdpi                     : 96
Export-ydpi                     : 96
Metadata ID                     : metadata5
Work Format                     : image/svg+xml
Work Type                       : http://purl.org/dc/dcmitype/StillImage
Work Title                      : 
sami@bt:~/Documents/THM/CTFs/Sakura_Room$ 
```
Notes: SakuraSnowAngelAiko
# RECONNAISSANCE
## Background
It appears that our attacker made a fatal mistake in their operational security. They seem to have reused their username across other social media platforms as well. This should make it far easier for us to gather additional information on them by locating their other social media accounts. 
## Instructions
Most digital platforms have some sort of username field. Many people become attached to their usernames, and may therefore use it across a number of platforms, making it easy to find other accounts owned by the same person when the username is unique enough. This can be especially helpful on platforms such as on job hunting sites where a user is more likely to provide real information about themselves, such as their full name or location information.

A quick search on a reputable search engine can help find matching usernames on other platforms, and there are also a large number of specialty tools that exist for that very same purpose. Keep in mind, that sometimes a platform will not show up in either the search engine results or in the specialized username searches due to false negatives. In some cases you need to manually check the site yourself to be 100% positive if the account exists or not. In order to answer the following questions, use the attacker's username found in Task 2 to expand the OSINT investigation onto other platforms in order to gather additional identifying information on the attacker. Be wary of any false positives!
## Questions
### What is the full email address used by the attacker?
![[Pasted image 20221105215749.png]]
SakuraSnowAngel83@protonmail.com
###  What is the attacker's full real name? 
AiKO ABE
# UNVEIL
## Background
It seems the cybercriminal is aware that we are on to them. As we were investigating into their Github account we observed indicators that the account owner had already begun editing and deleting information in order to throw us off their trail. It is likely that they were removing this information because it contained some sort of data that would add to our investigation. Perhaps there is a way to retrieve the original information that they provided? 
## Instructions
On some platforms, the edited or removed content may be unrecoverable unless the page was cached or archived on another platform. However, other platforms may possess built-in functionality to view the history of edits, deletions, or insertions. When available this audit history allows investigators to locate information that was once included, possibly by mistake or oversight, and then removed by the user. Such content is often quite valuable in the course of an investigation. In order to answer the below questions, you will need to perform a deeper dive into the attacker's Github account for any additional information that may have been altered or removed. You will then utilize this information to trace some of the attacker's cryptocurrency transactions.
## Questions
###  What cryptocurrency does the attacker own a cryptocurrency wallet for? 
Ethereum https://github.com/sakurasnowangelaiko/ETH/commit/5d83f7bb37c2048bb5b9eb29bb95ec1603c40135
### What is the attacker's cryptocurrency wallet address?
0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef https://github.com/sakurasnowangelaiko/ETH/commit/5d83f7bb37c2048bb5b9eb29bb95ec1603c40135
### What mining pool did the attacker receive payments from on January 23, 2021 UTC?
ethermine https://etherscan.io/txs?a=0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef
### What other cryptocurrency did the attacker exchange with using their cryptocurrency wallet?
tether from https://etherscan.io/txs?a=0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef
# TAUNT
## Background
Just as we thought, the cybercriminal is fully aware that we are gathering information about them after their attack. They were even so brazen as to message the OSINT Dojo on Twitter and taunt us for our efforts. The Twitter account which they used appears to use a different username than what we were previously tracking, maybe there is some additional information we can locate to get an idea of where they are heading to next?

We've taken a screenshot of the message sent to us by the attacker, you can view it in your browser here.
## Instructions
Although many users share their username across different platforms, it isn't uncommon for users to also have alternative accounts that they keep entirely separate, such as for investigations, trolling, or just as a way to separate their personal and public lives. These alternative accounts might contain information not seen in their other accounts, and should also be investigated thoroughly. In order to answer the following questions, you will need to view the screenshot of the message sent by the attacker to the OSINT Dojo on Twitter and use it to locate additional information on the attacker's Twitter account. You will then need to follow the leads from the Twitter account to the Dark Web and other platforms in order to discover additional information.
## Questions
### What is the attacker's current Twitter handle?

### What is the URL for the location where the attacker saved their WiFi  SSIDs and passwords?
http://deepv2w7p33xa4pwxzwi2ps4j62gfxpyp44ezjbmpttxz3owlsp4ljid.onion/show.php?md5=b2b37b3c106eb3f86e2340a3050968e2
### What is the BSSID for the attacker's Home WiFi?
Home WiFi: DKIF-G pass: Fsdf324T@@
# HOMEBOUND