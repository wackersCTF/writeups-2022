# UMDCTF
- https://ctftime.org/event/1593
- March 4 to March 6
- Ranking: 223/552

## MTP - Crypto

One-time pad? More like multiple-time pad ;)

NOTE: You can assume that the plaintexts are grammatically-correct English sentences

FLAG FORMAT: Concatenate all 8 plaintext sentences together like so: `"[pt1][pt2][pt3][pt4][pt5][pt6][pt7][pt8]"` and take the MD5 hash of this string. Wrap the MD5 hash in the flag format to submit.

```python
import hashlib
plaintexts = [...]

pt_str = ''
for pt in plaintexts:
    pt_str += pt

print('UMDCTF{' + hashlib.md5(pt_str.encode()).hexdigest() + '}')
```

**Author:** itsecgary

encrypt.py:
```python
import random
from binascii import unhexlify, hexlify

KEY_LEN = 30

keybytes = []
for _ in range(KEY_LEN):
    keybytes.append(random.randrange(0,255))
print(f'key = {bytes(keybytes)}')

key = keybytes

with open('plaintexts.txt', 'r') as f:
    pts = f.read().strip().split('\n')

cts = []
for pt in pts:
    ct_bytes = []
    for i in range(len(pt)):
        ct_bytes.append(ord(pt[i]) ^ key[i])
    cts.append(bytes(ct_bytes))

print(' ')
with open('ciphertexts.txt', 'w') as f:
    for ct in cts:
        print(hexlify(ct).decode())
        f.write(hexlify(ct).decode() + '\n')
```
ciphertexts.txt:
```
c909eb881127081823ecf53b383e8b6cd1a8b65e0b0c3bacef53d83f80fb
cf00ec8a5635095d33bfa12a317bc2789eabf95e090c29abe81dd4339ffb
c700ec851e72124b6afef52c3f37cf2bcda9f74202426fa2f54f9c3797fb
cd0ebe8718365b4f2bebb6277039c469dfecf05419586fb4f658dd2997fb
c341ff8b562114552ff0bb2a702cc3649ea0ff5a085f6fb0f51dd93b86f4
da13f1801321085738bf9e2e24218b7fdfb9f159190c22a1ba49d43381fb
cb0df2c63f721c573ebfba21702fc36e9ea9ee50000c38a5e91ddd7ab0fb
c913e796023d1c4a2befbd367032d82bdfecf55e02406fa7f548ce2997f4
```

### Solution by wyl3waK
#### Part 1
Looking at encrypt.py, we see that the first couple lines create a key with a length of 30. Each "byte" of the key is a random integer between 0 and 254. Then, it encrypts each letter in the plaintexts by XORing the ASCII values of the letter with a number from the key. Finally, it changes the value to bytes and encodes the combined bytes using hexadecimal. 

So what's our plan? To start off, we should reverse engineer the encrypt script as much as possible. Decode the ciphertexts from hexadecimal and change the bytes to their ASCII values. 

The first part of decoding from hexadecimal is pretty simple. 
```python
import random
from binascii import unhexlify, hexlify

pts = []
with open('ciphertexts.txt', 'r') as f:
    cts = f.read().split('\n')
    for ct in cts:
        pts.append(str(unhexlify(ct)))

for i in range(len(pts)):
    pts[i] = pts[i][2:-1] # remove b''
```
In this code, we convert from hex and remove the ```b''``` in our strings. An example result is 
```
\\xc9\\t\\xeb\\x88\\x11'\\x08\\x18#\\xec\\xf5;8>\\x8bl\\xd1\\xa8\\xb6^\\x0b\\x0c;\\xac\\xefS\\xd8?\\x80\\xfb
```
Now we want to change this to a list of 30 numbers, the encrypted plaintext. How do we do that? 

The ASCII table covers numerous characters and noncharacters. For values that are not charcters, they are represented like `\\xc9` (209 in hexadecimal). Well, which values of the ASCII table are like this? 

Looking at an ASCII table, we see that the first 32 ASCII numbers (0-31) are not characters. These would be represented in hexadecimal form rather than a character. In addition to this, we also need to cover values that are greater than 127. The maximum number you can get from XOR any two number between 0 and 255 is 255. Therefore, the range of values of noncharacters are from 0 to 31 and 128 to 255. 

To change these special noncharacters in hexadecimal to their decimal value, I used replace(). After replacing all of them, I can use ord() to revert each of the characters to their ASCII values. If I did not deal with the noncharacters first, ord() will not work properly. 

The following code might be complicated and hard to understand, but it essentially does what I explained above. 
```python
temp = [] # temporary list
list1 = [] # 0 - 31
for i in range(32):
    temp.append(i)
    list1.append(bytes(temp))
    temp = []
list1 = str(list1)
list1 = list1.replace("[b'", '')
list1 = list1.replace("']", '')
list1 = list1.split("', b'")

list2 = [] # 127 - 255
for i in range(127, 256):
    temp.append(i)
    list2.append(bytes(temp))
    temp = []
list2 = str(list2)
list2 = list2.replace("[b'", '')
list2 = list2.replace("']", '')
list2 = list2.split("', b'")

list3 = [] # list of all noncharacters
for i in range(32):
    list3.append(str(i))
for i in range(127, 256):
    list3.append(str(i))

for pt in pts: 
    pt2 = pt
    # --- noncharacters ---
    for i in range(len(list1)):
        weplace = '-!' + str(i) + '-!' # -! is an arbitrary choice. must be unique
        pt2 = pt2.replace(list1[i], weplace)
    
    for i in range(len(list2)):
        weplace = '-!' + str(i+127) + '-!' 
        pt2 = pt2.replace(list2[i], weplace)
        
    pt3 = pt2.split('-!') # -! was used to signify where the start/end
    
    for i in range(len(pt3)-1, -1, -1): # if empty, remove
        if pt3[i] == '':
            pt3.pop(i)
    # --- characters ---
    pt4 = []
    for i in pt3:
        pt4.append(i)
    
    for i in range(len(pt3)):
        bad = pt3[i]
        if bad not in list3: # this is in case the characters are clumped together
            j = pt4.index(bad)
            bad = bad[::-1]
            pt4.pop(j)
            for character in bad:
                pt4.insert(j, str(ord(character)))
    print(f'{pt4}')

```

Running this script, we should get our lists of decimal values like shown below. We have a list of 30 values for each sentence. 
```python
a = [201, 9,  235, 136, 17, 39,  8,  24, 35,  236, 245, 59, 56,  62,  139, 108, 209, 168, 182, 94, 11, 12, 59,  172, 239, 83, 216, 63,  128, 251]
b = [207, 0,  236, 138, 86, 53,  9,  93, 51,  191, 161, 42, 49,  123, 194, 120, 158, 171, 249, 94, 9,  12, 41,  171, 232, 29, 212, 3,   159, 251]
c = [199, 0,  236, 133, 30, 114, 18, 75, 106, 254, 245, 44, 63,  55,  207, 43,  205, 169, 247, 66, 2,  66, 111, 162, 245, 79, 156, 7,   151, 251]
d = [205, 14, 190, 135, 24, 54,  91, 79, 43,  235, 182, 39, 112, 57,  196, 105, 223, 236, 240, 84, 25, 88, 111, 180, 246, 88, 221, 41,  151, 251]
e = [195, 65, 255, 139, 86, 33,  20, 85, 47,  240, 187, 42, 112, 44,  195, 100, 158, 160, 255, 90, 8,  95, 111, 176, 245, 29, 217, 59,  134, 244]
f = [218, 19, 241, 128, 19, 33,  8,  87, 56,  191, 158, 46, 36,  33,  139, 127, 223, 185, 241, 89, 25, 12, 34,  161, 186, 73, 212, 3,   129, 251]
g = [203, 13, 242, 198, 63, 114, 28, 87, 62,  191, 186, 33, 112, 47,  195, 110, 158, 169, 238, 80, 0,  12, 8,   165, 233, 29, 221, 122, 176, 251]
h = [201, 19, 231, 150, 2,  61,  28, 74, 43,  239, 189, 54, 112, 50,  216, 43,  223, 236, 245, 94, 2,  64, 111, 167, 245, 72, 206, 41,  151, 244]
```

#### Part 2
My initial try was to XOR values in the same position in the lists together to cancel out the key. Long story short, it did not work. So, I decided on bruteforcing the key.

Since there's only 256 values for each part of the key, it was definitely doable. To brute force, a key value is XORed with each number in the same index in the lists, giving us a new number (the plaintext if the key is correct). For example, XOR the key value 23 with each of the first numbers in the lists. When the resulting numbers of all 8 lists are all ASCII values for letters, we know that we got the right key. 

Sometimes, several keys can give you all letters. To know which one is the correct key from the multiple valid ones, we need to handle them manually by seeing which key gives letters that fit our sentences. For my script, I had to run it several times and update it with the correct keys. See lists special and specialkeys below. 

Script: 
```python

king = []
king.append(a)
king.append(b)
king.append(c)
king.append(d)
king.append(e)
king.append(f)
king.append(g)
king.append(h)

pts = [] # list of plaintexts
for i in range(8):
	pts.append('')

key = 0
good = 0 # counts if a key gives a letter/space
letters = '' # holds possible decrypted letters
correctLetters = '' # holds correct decrypted letters

# when multiple valid keys exist
special = [0, 11, 19, 20, 23, 27, 28, 29] # index of special
specialkeys = [138, 79, 49, 109, 196, 90, 242, 213] # the keys at those indexes

for j in range(30):
	if j not in special:
		acceptable = 0 # number of valid keys
		for key in range(256): # brute force key values
			good = 0
			letters = ''

			for i in range(8):
				c = king[i][j] # "ciphertext"
				p = c ^ key # "plaintext"
				# 32 = space, 65-90 are uppercase, 97-122 are lowercase
				if (p == 32) or (p >= 65 and p <= 90) or (p >= 97 and p <= 122):
					good += 1 # if letter or space, good increases
					letters += chr(king[i][j] ^ key)
				else:
					break

			if good == 8: # if all the values are letters/spaces
				print(f'key for {j} is {key}')
				print(f'letters: {letters}')
				correctLetters = letters
				acceptable += 1 # increases for each valid key

		if acceptable == 1: # if only 1 valid key, add it 
			for x in range(8):
				pts[x] += correctLetters[x] # add letter to sentence
		else: # if multiple valid keys, add ?
			for x in range(8):
				pts[x] += '?'
	else: # ik the key already
		temp = '' # stores all 8 letters
		ind = special.index(j)
		key = specialkeys[ind]
		for i in range(8):
			temp += chr(king[i][j] ^ key)
		for x in range(8):
			pts[x] += temp[x] # add letter to sentence
print(pts)
```
Note: The last characters were period and exclamation marks, so the script ignores them. Do them manually.

Running our code and manually adding keys for some, we get the text below. 
```
['Chungus is the god of thunder.', 'Earl grey tea is good for hYm.', 'March is a cold season for ]e.', 'Go and watch boba fett please.', 'I am someone who likes to eat!', 'Professor Katz taught me thYs.', 'All I got on the exam Gas a B.', 'Cryptography is a cool course!']
```

It looks like our script in Part 1 made some mistakes resulting in incorrect values. However, we can easily fix the incorrect letters and get the correct text.
```
['Chungus is the god of thunder.', 'Earl grey tea is good for him.', 'March is a cold season for me.', 'Go and watch boba fett please.', 'I am someone who likes to eat!', 'Professor Katz taught me this.', 'All I got on the exam was a B.', 'Cryptography is a cool course!']
```

To get our flag, we just run the md5 code in the description. 

```python
import hashlib
plaintexts = ['Chungus is the god of thunder.', 'Earl grey tea is good for him.', 'March is a cold season for me.', 'Go and watch boba fett please.', 'I am someone who likes to eat!', 'Professor Katz taught me this.', 'All I got on the exam was a B.', 'Cryptography is a cool course!']
print(plaintexts)
pt_str = ''
for pt in plaintexts:
	pt_str += pt

print('UMDCTF{' + hashlib.md5(pt_str.encode()).hexdigest() + '}')
```

Flag: ```UMDCTF{0a46e0b2b19dc21b5c15435653ffed67}```

Challenge thoughts:
Although the encryption method was simple, the challenge was unique and clever in my opinion. The challenge required a lot of programming and brute forcing the key seemed an unlikely solution. While it was frustrating most of the time, seeing the plaintext appear was very satisfying. 
