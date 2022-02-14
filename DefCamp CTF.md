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

## catch-me-if-you-can
We need your technical expertise to analyze this Android project. We tried to compile it, no success, we tried to open it, no success, but we know for sure that the final product had to scope to deliver hidden messages to different attackers worldwide in a form of a mobile game. 

Flag format: not standard

Attachments: https://api.cyberedu.ro/v1/contest/dctf21/challenge/bd772bd0-8a4c-11ec-84f7-4917e4d507f7/download/2006

### Solution

I just went straight to the 4th question, since the competition was almost over and it seemed the most understandable and easiest to do.

The question was ```Something is wrong with the SharedPreferences file. We didn't manage to understand the string value. Please share it with us.```

The question asks us to look at the SharedPreferences file and taking a look at the options, it was clear it was talking about the SharedPreferences.java file.
![stringthing](https://user-images.githubusercontent.com/46347858/153781418-66be7fdc-b7f5-491e-8a21-497a2ea8ab16.PNG)

Looking at the file we see the string value that looks cryptic and not understandable that the question was talking about.
I knew that we had to somehow decrypt this into a normal string, so I started looking for options.

I couldn't think of any ciphers that looked like this, so I took a look at the SharedPreferences.java file again.

Right about the cryptic string, I saw that it said '1337'.
I thought about this for a while and got nothing, but then I searched 1337 code on google and it brought me to ```Leet Speak```

I found a decoder for it by dcode.fr: https://www.dcode.fr/leet-speak-1337

Putting the text in and decrypting, we get a more recognizable word, but some parts of it are still not as understable.

But looking at the text, we can deduce the rest of the words and make the decoded string.

Flags: 
1. Not solved
2. Not solved
3. Not solved
4. DOYOUTHINKYOUHAVEIT

## Ok!
Our computer performance was altered by a malicious individual. We have managed to make a copy of the altered computer and we need immediately to obtain some answers regarding this file. Due to the stressful situation, one of our colleagues managed to write just a single word in his notebook: 

Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook. Ook? Ook. Ook. Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook. Ook? Ook. Ook? Ook. Ook! Ook! Ook? Ook! Ook. Ook? Ook. Ook? Ook. Ook? Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook! Ook! Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook. Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. 

Your input is needed on the following aspects and you should remember that wecracktheworlds is an important key in this process.

Files are available at the following links:
-   https://storage.googleapis.com/cyberedu-production/dctf22-ok-chall/unintended.zip.000
-   https://storage.googleapis.com/cyberedu-production/dctf22-ok-chall/unintended.zip.001
-   https://storage.googleapis.com/cyberedu-production/dctf22-ok-chall/unintended.zip.002

1.  A message is received when the first task is completed. Please share it with us: (Points: 229)
2. We know that the attacker attempted to download an infected image from one of his servers before launching the attack. Can you provide the file name? (Points: 50)
3. We know that the attacker used a password to unrar the malicious scripts downloaded from his server. Can you provide its value? (Points: 50)
4. We suspect that the Sample 5 script contains another malicious download link. Can you determine the address? (Points: 86)

## Solution
First, we start off with the Ook text in the challenge description. We see that Ook! is a joke programming language. Using a translator, the text ouputs "autopsy" which is a reference to the digital forensics tool. 

Then, we download the three files. We try to extract the first zip file, but notice that it is an incomplete zip file. Using cat, we can combine or concatenate the three files. Unzipping the completed zip file gives us a .vmdk file. It is a virtual machine disk file developed by VMware. I tried to make an image with the .vmdk file, however the windows machine was broken and I could not access the files. 

So, we resort to using autopsy.  We find that there are two drives: C:/ and D:/. The D:/ drive was more comprehensive and contained more valuable information. Using the File Analysis mode, we have access to all the files and folders in the drive. Inside the Users folder, there is a user named sunflower. Inside its Downloads folder, there is a suspicious folder named *Malicious-Powershell-Samples-master* with multiple subfolders. 

In the README.txt file of the *Malicious-Powershell-Samples-master*, we see 
```
# Malicious-Powershell-Samples

rarpass=infect

```
This looks like a password. 

Inside Powershell Samples - Part 1/Sample 1 subfolder, we find a suspicious .jpg file named **p_1372hc5v1.jpg**. It is actually contains numbers and text.

While part 4 of the challenge was not solved during the competition, we see a file named Powershell Samples - Part2.7z. Downloading and attempting to extract it with 7zip shows that Sample 5 is in this zip file. Unfortunately, the zip file was password protected and we could not crack it. 

Flags:
1. Not solved
2. p_1372hc5v1.jpg
3. infect
4. Not solved

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
By bruteforce, I meant go through the commands that seemed valid in https://www.davekb.com/browse_computer_tips:linux_two_letter_commands:txt

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
