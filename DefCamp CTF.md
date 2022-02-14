# DefCamp CTF
- https://ctftime.org/event/1560
- Feb 11 to Feb 13
- Ranking: 73/1035 with 736 points

## Solves
| Challenge Name | Category | Difficulty | Points | Solver |
|---|---|---|---|---|
| cant-touch-this | Misc | Medium | 250/300 | wyl3waK |
| catch-me-if-you-can | Code Review/Mobile | Medium | 186/772 | Xenonminer |
| Ok! | Forensics | Medium | 100/415 | wyl3waK |
| para-code | Web | Easy | 50 | Xenonminer | 
| this-file-hides-something | Forensics | Medium | 50 | Xenonminer |
| web-intro | Web | Entry Level | 50 | drpain365 |
| zebra-lib | Misc | Easy | 50 | wyl3waK |

## cant-touch-this
The Nesteaz company suffered from a security breach. We are low on personnel and we require your help in investigating the events collected from the compromised machine.

Credentials: elastic/k8jTYMCoAqppB

1. Please provide the user account on which malicious actions were executed. (Points: 50)
2.  We need the IP of the compromised machine (Points: 50)
3.  The attackers managed to execute some malicious scripts without being detected by our security systems. Can you determine which program was executed? (Points: 50)
4.  What system management tool did the attacker use in order to launch its program with full privileges? (Points: 50)
5.  We know that the attacker managed to download an infected executable using a Windows utility. We need that name, please. (Points: 50) (Not solved)
6.  The attacker managed to give full privileges to his account. We need the code of the event triggered by this action. (Points: 50)

Attachments: 34.141.93.151:32729

### Solution

The website/IP address is Elastic, a multipurpose website used by companies for monitoring, management, etc. We are interested in Elastic Security. We navigate to that dashboard and can choose to show reports/logs of activity. While there is no information available in the last 24 hours, extending the search dates to February 1 shows us numerous events and processes that occured within the past month. We see there is a single host named DESKTOP-IHO95MC. We can access information about it such as its operating system (Windows 10) and its IP address, **192.168.0.108**. It was accessed by multiple users, however one username stands out: **malware_attacker**. Examining the processes and events, we see that **NSudo.exe** was run by malware_attacker several times. Googling it shows that it allows users to run programs with full privileges. We also see that NSudo.exe was used for a file in C:\Users\plant\OneDrive\Desktop\stuff-i-want\ named **Defeat-Defender.bat**. For the last part of the challenge, we notice multiple events that state "Special privileges assigned to new logon." The event code is **4672**. 

This challenge tests one's ability to analyze computer logs. Utilizing filters and identifying suspicious details helps.

Flags: 
1. malware_attacker
2. 192.168.0.108
3. Defeat-Defender.bat
4. NSudo.exe
5. Not solved
6. 4672

## para-code
I do not think that this API needs any sort of security testing as it only executes and retrieves the output of ID and PS commands.

Flag format: CTF{sha256}

Attachments: 34.159.7.96:32210

### Solution
Taking a look at the website given, we see some php code

```php
<?php
require __DIR__ . '/flag.php';
if (!isset($_GET['start'])){
    show_source(__FILE__);
    exit;
} 

$blackList = array(
  'ss','sc','aa','od','pr','pw','pf','ps','pa','pd','pp','po','pc','pz','pq','pt','pu','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','pf','pz','pv','pw','px','py','pq','pk','pj','pl','pm','pn','pq','ls','dd','nl','nk','df','wc', 'du'
);

$valid = true;
foreach($blackList as $blackItem)
{
    if(strpos($_GET['start'], $blackItem) !== false)
    {
         $valid = false;
         break;
    }
}

if(!$valid)
{
  show_source(__FILE__);
  exit;
}

// This will return output only for id and ps. 
if (strlen($_GET['start']) < 5){
  echo shell_exec($_GET['start']);
} else {
  echo "Please enter a valid command";
}

if (False) {
  echo $flag;
}

?>
```
Reading through this php code, we can see that this is a command injection challenge where we can put commands into the the start query.
Also we can see that if we somehow trigger False, the flag variable will appear in the source code.

Reading the input part of the code, we see that there is a blacklist preventing us from typing any of those letters inside our commands and that our command must be less that 5 characters long.

With this knowledge, I tried out some basic command injection stuff like l\s or l's' and it printed out that there was a flag.php and a index.php.
With only 4 letters to type for our command, I knew that opening the flag.php file was an impossibility.

Next, I went to try to exploit the if (False) part to get the $flag variable to show in the source code.
I knew that the input could only be 4 characters max, so I would have to have at max a 2 character command followed by a space and an asterisk after.

This part wasn't very fun for me, because I had to "bruteforce" through all the 2 characters commands until I found a correct one.

Eventually I got to the command m4 which when doing ```?start=m4 *``` showed the $flag variable in the source code.

Note: Sadly I didn't know what m4 actually did to trigger the if statement to a False and print the flag in the source code, but the m4 command processes macros in files.
Read more at: https://www.commandlinux.com/man-page/man1/m4.1.html

Wrapping the flag with CTF{} we get:
```CTF{791b21ee6421993a8e25564227a816ee52e48edb437909cba7e1e80c0579b6be}```

## this-file-hides-something
There is an emergency regarding this file. We need to extract the password ASAP. It's a crash dump, but our tools are not working. Please help us, time is not on our side.

PS: Flag format is not standard.

Attachments: https://api.cyberedu.ro/v1/contest/dctf21/challenge/bf7cde20-89b7-11ec-b6ba-fdc8d6daa06e/download/2001

### Solution
We are given a crashdump.zip file that we can extract into a crashdump.elf.

From the description, it is hinting us that this challenge is something to do with memory and memory that gets rid of itself or deletes itself.
Also, the name of the file is crashdump, so the tool we need for this challenge stands out.

We will be using the tool ```volatility```, which is a tool that is good for memory forensics challenges.
The download to the tool can be found at https://github.com/volatilityfoundation/volatility

After the tool is setup, we can run the vo.py file using any version of python2 and use the -f option to supply our memory file.

First, we want to use the ```imageinfo``` option to find the correct profile.
![imageinfo](https://user-images.githubusercontent.com/46347858/153773080-2e1d1268-14b4-4ce7-80af-e2cd67aded5d.PNG)

We will choose the first profile in the list and use that for our next tests. (Win7SP1x64)

We can extract the lsa secrets now using the ```lsadump``` option.
![password](https://user-images.githubusercontent.com/46347858/153773086-cd374023-2f2b-4e74-941b-84dca2e931e0.PNG)

We get the password:
```Str0ngAsAR0ck!```


## zebra-lib
All these years of technological developments and I still haven’t seen a color photo of a zebra. Change my mind.

Flag format: CTF{sha256}

Attachments: 34.159.7.96:30441

### Solution

This challenge is just another pwntools scripting challenge. We must connect to an IP address and decode texts using Base64 and zlib. The decoded text must be sent within a time period and there are five hundred encoded texts. Therefore, doing this manually is not ideal.  

Steps:
1. Connect to IP address using pwntools
2. Receive data using recvuntil
3. Isolate the encoded text using split()
4. Decode using Base64 and inflate using zlib
5. Send plaintext using sendline()
6. Repeat until flag

CyberChef is helpful in identifying the encodings used. Also, the text was encoded using **url safe Base64** instead of standard Base64. If the text was decoded using standard Base64, zlib will not work. This minor detail caused me some trouble. 

Script
```python
from pwn import *
import base64
import zlib

def decode_base64_and_inflate(b64string):
	decoded_data = base64.urlsafe_b64decode(b64string)
	return zlib.decompress(decoded_data)

connection = remote('34.159.7.96', 32358)

data = connection.recvuntil(b':')
data2 = str(data).split('\\r\\n')
print(f'ciphertext for 1: {data2[1]}')
workproof = decode_base64_and_inflate(data2[1])
connection.sendline(workproof)

counter = 2
while counter != 500: # 500 texts to decode
	data = connection.recvuntil(b':')
	data2 = str(data).split('\\r\\n')
	print(f'ciphertext for {counter}: {data2[2]}')
	workproof = decode_base64_and_inflate(data2[2])
	connection.sendline(workproof)
	counter += 1

while True: # for reading flag
	data = connection.read()
	print(data)
```

Flag: ```CTF{a7550246d72f8c7946a9248b3b9eee93461ac30f53ac8ca9749c9590b4ed1a2b}```
