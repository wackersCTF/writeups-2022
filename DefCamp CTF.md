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

Wrapping the flag with CTF{} we get:
```CTF{791b21ee6421993a8e25564227a816ee52e48edb437909cba7e1e80c0579b6be}```

## Notes


## this-file-hides-something
Description: There is an emergency regarding this file. We need to extract the password ASAP. It's a crash dump, but our tools are not working. Please help us, time is not on our side.

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
