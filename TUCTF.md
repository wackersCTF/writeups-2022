# TUCTF
Writeups by whilehak for:
- Crypto/That One RSA Challenge
- Misc/Inverse Shell
- Programming/Leisurely Math
- Web/Hyper Maze

## Crypto/That One RSA Challenge
Every CTF needs an RSA challenge, right? This one is pretty easy, but it's a good warmup for the harder ones.

nc chals.tuctf.com 30003

### Writeup
We are given a server where we can encrypt the flag. Each time the flag is encrypted by different primes but the same encryption key (e=5). 
Since we can encrypt the same plaintext e times, we can apply [Hastad's attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack). 
Using Chinese Remainder Theorem to find a number that is equivalent to all the ciphertexts in their corresponding mod N, we can take the nth root of that number to calculate the message. 

```python
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
import libnum

ns = [9441645341246877190551252105007943067253047329596047187094604411500767490646270769301704634672966112566053238513961572556122637351007962690592690007404506698188196683595759468916470769972465617685842341577812134539110827936800893939936550524133810480683727665154132210756985166124068441821804521683069592926454774724051176153615870426873452826466735732479570889649, 7194251211506414666056233709018849302218634549876983281157691016333323790770050927840861259753838795675047884581824718180644684847114800695033045287071282610953052732255503589254300181438423448232234460018310465452254905174250611121635810542403681763002933724334251331570248104535678858925341946140601451293580929161437649413751108003546693189784208536063148130241, 5331314902743243118671923961448048325175861054848606398188200865612862054394494294381241357510457259678279147364815848573172797018798825838540087709388846719889780396231200276594464023062984349760701097034416927658377409999779519347386145584155542241558608993060054528846551715143943457202291952666672646610245252173745212131227168183655658783337268172925846686983, 10566205463904448220894249566353548511114132880313235767240509687787236050263751111588798869623201072800324516537848836917141115838623917045244597740728258457272309102684248849179493702508491400493136343625676646245750211418323128163033667465303332640776812299400796917048247976211043197933498677719086231114765688279641839211006900661152636213490246334138207001393, 11050467663162231617880308689126730713021626478225311049777614783543244791031044202058065190828241517600665632712283978035239051926902545414070336820590045753721576826320480911871003715613152058928432432929969264802634751882398959844103682189695105789146749064958065349327302109661784112024058091429083323194270144682513551820828052963508931881577359643897132818413]
cs = [6695134867923010709731389482468962057412603767456612510664303340331123232520544403808104845691047264481918043470581843684944166809620150801770480847107597746312849902538989411454614289178910448367797809262749027915185042424611105875356250453484097126954594696256801517390683283076606079494327126777146692710821248081377769450339300639933605278622579240328971036100, 4014693399513458235820928637101913410134317599358285012628229648403657422645305937415610718358738504465458287343694436550089691460787635539527408675032416384122320540880589040188383523085055246515194846768110340111461725488111447252159781927684125892858551666898050160271598620157136995573950985279604262047942198334647906685455921815506907043209753040314339782847, 1776242176378903308963162083943952859382716938519004206889347899009495560287779312717240209973276037662877884515145371172092202256019966583114852403515824338835440086581372638265266228525542328673687537256167219133328109886106607399519301102278872966904776889588669611248705957990184111302464923446436161825030858582657769776559976098877967411233781389734365843456, 5759150001593394332079619104621330661574518147171827622763309676740360409627647136471937676475135261780004048708217851361361004550231857717576369420093167592022560851100500165257299009395758464975331140430513945078763106909464491626528139149291517036169537680608097628982804560406876542285565940937297851077802381529195176188512236195481556850892770392203736640906, 10877797554054839677096916200668762746720672488144145753145404421977281150051902601579628592389181314953304652183970000882088699509485082803902062778397471272273517489476836441965743460985959458399665021211404491650964540253131518295551760802866415445453957305685398418134024414738479704868655255728404211644408768932873060525106464925835434760805091601158433464371]
e = 5

assert len(ns) == e
assert len(cs) == e

c6 = libnum.solve_crt(cs, ns) # 73448690174896106135676773887969898376313644525180577635638534667360398313545968245865457044768650498073919986296816184849746808491061728181876720693332170726810820658795124493571143780153343023652595257458464865059042345641702358771008787607355295320693998300553350404027525319624789400937306774517103831179992855723955092191381869960795275997575970901077630183000778125
print(f'c6: {c6}')

m = libnum.nroot(c6, e)
assert m**5 == c6

print(f'm: {m}')
print(long_to_bytes(m))
```

Flag: ```TUCTF{0bl1g4t0ry_RSA_chall_l0l}```

## Misc/Inverse Shell
You arent a real hacker until you get an inverse shell.

nc chals.tuctf.com 30100

Writeup:
You are given access to a shell but the text is reversed and ascii shifted by its version number. 

```python
from pwn import *

def encrypt(data, shift):
	data = data[::-1]
	ct = ''
	for i in data:
		ct += chr(ord(i) + shift)
	return ct.encode()

def decrypt(data, shift):
	data = data.replace(b'\n', b'')
	data = data.replace(b'\xc2', b'')
	data = data[::-1]
	pt = ''
	for i in data:
		pt += chr(i - shift)
	return pt

conn = remote('chals.tuctf.com', 30100)
data = conn.recvuntil(b'version ')
data = conn.read()
shift = [int(i) for i in data.split() if i.isdigit()]
shift = shift[0]
print(f'shift: {shift}')
print(data)
print(decrypt(data, shift))

conn.sendline(encrypt('help', shift))

data = conn.recvlines(7)
for i in data:
	print(decrypt(i, shift))

conn.sendline(encrypt('ls', shift))
data = conn.recvlines(2)
for i in data:
	print(decrypt(i, shift))

conn.sendline(encrypt('cd secret', shift))
data = conn.recvlines(2)
for i in data:
	print(decrypt(i, shift))

conn.sendline(encrypt('cat .flag.txt', shift))
data = conn.recvlines(2)
for i in data:
	print(decrypt(i, shift))
```

Flag: ```TUCTF{my_5up3r_dup3r_53cr37_1337_5h3ll}```

## Programming/Leisurely Math
Too slow for rapid arithmetic? Want to take things a little more leisurely? Try this challenge!

nc chals.tuctf.com 30202

### Writeup
Just a standard netcat programming challenge. One thing to note is the code injection for some problems. Sanitize inputs!

```python
from pwn import *
import re

p = remote('chals.tuctf.com', 30202)
pattern = '\d.+\d'

counter = 0

while True:
	try:
		data = str(p.recvuntil(b'Answer: '))
	except Exception as e:
		print('----------ERROR----------')
		data = str(p.read())
		print(data)
		print('-------------------------')
	equations = re.findall(pattern, data)
	equation = equations[0]
	print(equation)
	if 'else' in equation: # injecting malicious code
		print('----------WARNING----------')
		equations = equation.split('\\n')
		equation = equations[-1]
		print(equation)
		print('---------------------------')
	ans = 0
	exec('ans = ' + equation)
	print(ans)
	p.sendline(str(ans).encode())
	counter += 1
	print(f'---{counter}---')
```

Flag: ```TUCTF{7h4nk5_f0r_74k1n6_7h1n65_4_l177l3_5l0w_4268285}```

## Web/Hyper Maze

Welcome to my }HYPER{}MAZE{!

Try to find out way out of my evil maze! There is a gift waiting for you at the end!

https://hyper-maze.tuctf.com

### Writeup
Create a web crawler that finds the next page by sending a request and using regex to identify.

```python
import requests
import re
pattern = 'href="page_\w{1,50}\d{1,2}\.html'

nextPage = 'page_aesthetician100.html' # starting page
while True:
	url = 'https://hyper-maze.tuctf.com/pages/' + nextPage
	req = requests.get(url)
	nextPages = re.findall(pattern, req.text)
	if len(nextPages) == 1:
		nextPage = nextPages[0]
		nextPage = nextPage[6:]
		print(nextPage)
	else:
		print('WARNING: more than 1 possible pages')
		print(nextPages)
```
At the last page (/page_lagenaria1.html), there was one more page (/3xtr4_s3cr3t_fl4g_429850252068.html) hidden in the source code.

Flag: ```TUCTF{y0u_50lv3d_my_hyp3r73x7_m4z3_38157}```