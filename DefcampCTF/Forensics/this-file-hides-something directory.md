#### Challenge
There is an emergency regarding this file. We need to extract the password ASAP. It's a crash dump, but our tools are not working. Please help us, time is not on our side.
PS: Flag format is not standard.

Attachments: https://api.cyberedu.ro/v1/contest/dctf21/challenge/bf7cde20-89b7-11ec-b6ba-fdc8d6daa06e/download/2001
#### Solution
We are given a crashdump.zip file that we can extract into a crashdump.elf.

From the description, it is hinting us that this challenge is something to do with memory and memory that gets rid of itself or deletes itself.
Also, the name of the file is crashdump, so the tool we need for this challenge stands out.

We will be using the tool ```volatility```, which is a tool that is good for memory forensics challenges.
The download to the tool can be found at https://github.com/volatilityfoundation/volatility

After the tool is setup, we can run the vo.py file using any version of python2 and use the -f option to supply our memory file.

First, we want to use the ```imageinfo``` option to find the correct profile.


We get the password:
```Str0ngAsAR0ck!```

