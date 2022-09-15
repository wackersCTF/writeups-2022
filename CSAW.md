# CSAW
- https://ctftime.org/event/1613
- 9/9 - 9/11

Does not include all challenge writeups. 

## Gotta Crack Them All - whilehak
As an intern in the security department, you want to show the admin what a major security issue there is by having all passwords being from a wordlist (even if it is one the admin created) as well as potential issues with stream ciphers. Here's the list of encrypted passwords (including the admin's), the encryption algorithm and your password. Can you crack them all and get the admin's password? Here is the web service that the admin made to encrypt a password: nc crypto.chal.csaw.io 5002

NOTE: The flag is just the admin's password.

The challenge files were a leaked password (Cacturne-Grass-Dark), list of encrypted passwords, and the cipher code below.

```python
with open('key.txt','rb') as f:
    key = f.read()

def encrypt(plain):
    return b''.join((ord(x) ^ y).to_bytes(1,'big') for (x,y) in zip(plain,key))
```
This basically XOR the passwords with a key.

Solve script:

```python
encrypted_passwords = open('encrypted_passwords.txt', 'rb')
encrypted_passwords = encrypted_passwords.read()
encrypted_passwords = encrypted_passwords.split(b'\n')

leaked = 'Cacturne-Grass-Dark'
passwds = []
for passwd in encrypted_passwords:
    if len(passwd) == len(leaked):
        passwds.append(passwd)

passwds = [b'kz\xc6\xb9\xd9Du\xcb\x8a\x9e\xe0\x9d\xbeo\xee\x03\xcf\xddd', b'`t\xca\xbd\xcd\x1bK\xdd\xde\xba\xfa\x95\xae1\x84/\xc1\xdc{', b'xn\xd5\xa4\xd8Wi\x83\xf5\xb6\xf1\x97\xe0[\xb1(\xdb\xc1k']

keys = []
for passwd in passwds:
    key = b''
    for i in range(len(leaked)):
        key += (ord(leaked[i]) ^ passwd[i]).to_bytes(1,'big')
    keys.append(key)

keys = [b'(\x1b\xa5\xcd\xac6\x1b\xae\xa7\xd9\x92\xfc\xcd\x1c\xc3G\xae\xaf\x0f', b'#\x15\xa9\xc9\xb8i%\xb8\xf3\xfd\x88\xf4\xddB\xa9k\xa0\xae\x10', b';\x0f\xb6\xd0\xad%\x07\xe6\xd8\xf1\x83\xf6\x93(\x9cl\xba\xb3\x00']

def decrypt(plain, key):
    return b''.join((x ^ y).to_bytes(1,'big') for (x,y) in zip(plain,key))

for key in keys:
    print('----------')
    for passwd in encrypted_passwords:
        print(decrypt(passwd, key))

key1 = b'(\x1b\xa5\xcd\xac6\x1b\xae\xa7\xd9\x92\xfc\xcd\x1c\xc3G\xae\xaf\x0f'
# key 1 works but incomplete

key = b'(\x1b\xa5\xcd\xac6\x1b\xae\xa7\xd9\x92\xfc\xcd\x1c\xc3G\xae\xaf\x0f\x95\x8c\xbb\xc9\xfb'
# Use incomplete passwords to complete the key.

for passwd in encrypted_passwords:
    print(decrypt(passwd, key))

flag = '1n53cu2357234mc1ph32'
```
