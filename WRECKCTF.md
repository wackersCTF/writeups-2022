# WRECKCTF

## crypto/mtp
- 73 solves / 428 points
- BrownieInMotion
- I encrypt all my secrets with the unbreakable Multi-Time Pad ```nc challs.wreckctf.com 31239```

Challenge file: server.py
```python
#!/usr/local/bin/python -u

import os
import random

LETTERS = set('abcdefghijklmnopqrstuvwxyz')

def encrypt(plaintext, key):
    return ''.join(
        chr(permutation[ord(letter) - ord('a')] + ord('a'))
        if letter in LETTERS
        else letter
        for letter, permutation in zip(plaintext, key)
    )


key = [list(range(26)) for _ in range(256)]
for permutation in key:
    random.shuffle(permutation) 

print('Welcome to the Multi-Time Pad!')
while True:
    print('1. Encrypt message')
    print('2. Get flag')
    choice = input('> ')
    match choice:
        case '1':
            plaintext = input('What\'s your message? ')
        case '2':
            plaintext = os.environ.get('FLAG', 'no flag provided!')
        case _:
            print('Invalid choice!')
            continue
    print(f'Result: {encrypt(plaintext, key)}')
```

To solve, brute force flag by trying letters until they match.

Solve script:
```python
from pwn import *

letters = list('abcdefghijklmnopqrstuvwxyz')

conn = remote('challs.wreckctf.com', 31239)

# gets ciphertext
data = conn.recvuntil(b'> ')
conn.send(b'2\n')
data = conn.recvuntilS(b'}')
ct = data[data.index(' ') + 1:]
print(ct)

# brute force
flag = 'flag{' # update as necessary since there's a timeout

for i in range(len(flag), len(ct)): # start index is next letter
    if ct[i] not in letters: # underscore
        flag += ct[i]
    else: 
        for letter in letters: # tries a letter
            conn.send(b'1\n')
            conn.recvuntil(b'What\'s your message? ')
            flag = flag + letter + '}'
            conn.send(flag.encode() + b'\n') # sends attempt

            data = conn.recvuntilS(b'}')
            attempt = data[data.index(' ')+1:data.index('}') + 1]
            print(f'attempt: {flag} -> {attempt}')

            if attempt[i] == ct[i]: # compares attempt and ct
                print(f'flag: {flag}')
                flag = flag[:len(flag) - 1] # remove } 
                break # move onto next character
            else:
                flag = flag[:len(flag) - 2] # remove last letter and }

conn.close()

# flag{oops_key_reuse_bwcjpqdweoclkwlbkoc}
```


