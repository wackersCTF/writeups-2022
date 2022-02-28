# MHSCTF 2022
- https://ctftime.org/event/1564
- Feb 18 to Feb 25
Ranking: 106/739 with 630 points

Does not include all challenge writeups. Only two writeups from wyl3waK. Cloudy was done by prince-of-tennis.

## Euler's Method - wyl3waK
Naturally, your favorite class of the day is AP Calculus BC and you've recently been learning Euler's Method. Your teacher has had a lot on their plate, so they've just been using the same curve for your homework problems every day, y'(x) = x^2 - 6y^2, y(5) = 2. To simplify matters, you're going to write a program to automate this trivial task for you.

For each input, you will receive a space-separated set of two numbers (each between -10 and 10). The first is your step size and the second is the x-value of the point you need the estimated y-value for (to the nearest tenth and incuding trailing zero if necessary). Your output will be between -1,000 and 1,000.

Sample Input 1:  
`0.8 5.8`  
Sample Output 1:  
`2.8`

Sample Input 2:  
`0.9 7.7`  
Sample Output 2:  
`-645.1`

Notes:
-   the inputs will be passed in (through stdin) separated by newlines; make sure your output is also separated by newlines
-   the first line of input will contain only one integer representing the number of additional lines of input you will receive

### Solution
Although this challenge does involved a calculus topic, the math needed to solve it is only limited to algebra. One can solve this challenge by only learning the formula and plugging in values without knowing any of the math concepts. However, I will still attempt to explain Euler's method in this writeup.

#### What is Euler's Method?
Euler's Method is a procedure used to approximate the coordinates of a point of a curve and solutions of differential equations. 

#### So, how does it work?
Let a curve defined by the function f(x) and the point (x, f(x)) is on that curve. We want to approximate a point (red) that is h units right to (x, f(x)). The x coordinate of that point is x+h, but we don't know its y coordinate.

To find that, we draw a tangent line to the curve at (x, f(x)). The slope of that line is the derivative of f(x) or f'(x). Drawing a right triangle (green), we see that want to know the vertical leg or Y. Since slope = rise/run, we have f'(x) = Y/h. Solving for Y, we have Y = h \* f'(x). We add this to our original y coordinate to get **(x+h, f(x) + h \* f'(x))**. 

<img width="695" alt="image" src="https://user-images.githubusercontent.com/82113302/155904848-78963cf2-9b86-4707-81e6-f5e0ea96a0b1.png">

As we can see, this approximation becomes less accurate when h is larger. By having a smaller h, our approximated points will be closer to the curve. However, if we decrease h, our points will be far from our desired point. To fix this, we can do multiple approximations as shown in the image below.

![](https://ds055uzetaobb.cloudfront.net/brioche/uploads/rKeFJmU5ZM-euler2-1.png?width=2500)

Euler's Method is particularly useful when a differential equation cannot be easily solved by breaking apart the x's and y's. 

#### Enough of the concepts. What do I need to do?
To do Euler's Method, we require a couple things. First, we need to know our starting point. We also need to know the x coordinate of the point we want. We need to know h which is called the step size. Finally, we need to know the slope or f'(x). If the problem does not gives us f'(x), we can take the derivative of f(x) to find it. 

After we have all those numbers, we can use the "formula" of the coordinates we derived above. It is **(x + h, f(x) + h \* f'(x))**.

It can also be written as **(x + h, y + h \* y')** . 

#### Actual challenge solution 

For this challenge, the starting point and y'(x) are constant. However, we get different step sizes and x coordinates of our target point. 

Let's do an example calculation with our sample input. 
Starting point: y(5) = 2
Slope: y'(x) = x^2 - 6y^2
Step size: 0.8
x coordinate of target point: 5.8

Calculations: 
```
(x1, y1) = (x + h, y + h * y')
	   = (5 + h, 2 + h * y')
	   = (5 + 0.8, 2 + 0.8 * y')
	   = (5 + 0.8, 2 + 0.8 * (x^2 - 6y^2))
	   = (5 + 0.8, 2 + 0.8 * (5^2 - 6*2^2))
	   = (5 + 0.8, 2 + 0.8 * (5^2 - 6*2^2))
	   = (5.8, 2.8)
```
Our answer is 2.8. 

While this problem only required one approximation, others will require multiple. To do those, consider the last approximation to be the new "starting point" and repeat the same procedure. 

Steps to solving
1. As mentioned in the notes, the first input will inform us how many problems we will receive. Store this value first.
2. After we stored our first input, store our h and x coordinate into separate float variables.
3. While our x coordinate is not close enough to our target x coordinate, perform Euler's Method.
4. Round the y coordinate and if it is an integer, append a ".0". The challenge requests the y coordinates to be rounded to the nearest tenth and add a trailing zero if necessary. 
5. Output the answer and reset the necessary variables. 
6. Repeat until the program has solved the number of problems (told by the first input). 

```python
from sys import stdin, stdout
def main():
  inputt = stdin
  outputt = stdout

  numbers = '' # number of problems that will be given
  counter = 0 # tracks how many problems were solved
  x = 5 # starting x coordinate
  y = 2 # starting y coordinate
  h = '' # step size
  target_x = '' # target x coordinate

  for i in inputt: 
    if numbers == '': # if numbers is empty, it is the first input
      numbers = int(i)

    else: # input is a problem

      j = i.split(' ') # split the two numbers
      h = float(j[0]) # first number is step size
      target_x = float(j[1]) # second number is target x

      while round(x, 2) != target_x: # while the approximated x value is not near the target x
        x += h # increase x by step size
        y += h * ( pow(x, 2) - 6 * pow(y, 2) ) # increase y by h * y'

      y = str(round(y, 1)) # round to nearest tenth
      if '.' not in y: # if y is an integer, add trailing zero
        y += '.0'

      outputt.write(y+"\n") # output

      x = 5 # reset starting x
      y = 2 # # reset starting y

      counter += 1 # one problem has been solved

      if counter == numbers: # all the problems have been solved
        break # break out of the loop
main()
```

## Python Bytecode Rev Challenge - wyl3waK
<details>
  <summary>Click to reveal challenge file</summary>
  
```python
  1           0 LOAD_CONST               0 (<code object main at 0x564456b6b9c0, file "example.py", line 1>)
              2 LOAD_CONST               1 ('main')
              4 MAKE_FUNCTION            0
              6 STORE_NAME               0 (main)

 15           8 LOAD_NAME                0 (main)
             10 CALL_FUNCTION            0
             12 POP_TOP
             14 LOAD_CONST               2 (None)
             16 RETURN_VALUE

Disassembly of <code object main at 0x564456b6b9c0, file "example.py", line 1>:
  2           0 LOAD_GLOBAL              0 (input)
              2 LOAD_CONST               1 ("What's the password? ")
              4 CALL_FUNCTION            1
              6 STORE_FAST               0 (inp)

  3           8 LOAD_CONST               2 ('')
             10 STORE_FAST               1 (pwd)

  4          12 SETUP_LOOP              52 (to 66)
             14 LOAD_GLOBAL              1 (range)
             16 LOAD_GLOBAL              2 (len)
             18 LOAD_FAST                0 (inp)
             20 CALL_FUNCTION            1
             22 CALL_FUNCTION            1
             24 GET_ITER
        >>   26 FOR_ITER                36 (to 64)
             28 STORE_FAST               2 (i)

  5          30 LOAD_FAST                1 (pwd)
             32 LOAD_GLOBAL              3 (chr)
             34 LOAD_GLOBAL              4 (ord)
             36 LOAD_FAST                0 (inp)
             38 LOAD_FAST                2 (i)
             40 BINARY_SUBSCR
             42 CALL_FUNCTION            1
             44 LOAD_FAST                2 (i)
             46 LOAD_GLOBAL              5 (int)
             48 LOAD_CONST               3 (7)
             50 CALL_FUNCTION            1
             52 BINARY_MODULO
             54 BINARY_ADD
             56 CALL_FUNCTION            1
             58 INPLACE_ADD
             60 STORE_FAST               1 (pwd)
             62 JUMP_ABSOLUTE           26
        >>   64 POP_BLOCK

  6     >>   66 LOAD_CONST               4 (102)
             68 LOAD_CONST               5 (109)
             70 LOAD_CONST               6 (99)
             72 LOAD_CONST               7 (106)
             74 LOAD_CONST               8 (127)
             76 LOAD_CONST               9 (53)
             78 LOAD_CONST              10 (116)
             80 LOAD_CONST              11 (95)
             82 LOAD_CONST              12 (122)
             84 LOAD_CONST              13 (113)
             86 LOAD_CONST              14 (120)
             88 LOAD_CONST              15 (118)
             90 LOAD_CONST              16 (100)
             92 LOAD_CONST              17 (55)
             94 LOAD_CONST              18 (51)
             96 LOAD_CONST              19 (103)
             98 LOAD_CONST              20 (57)
            100 LOAD_CONST              21 (128)
            102 BUILD_LIST              18
            104 STORE_FAST               3 (comp)

  7         106 LOAD_CONST              22 (False)
            108 STORE_FAST               4 (incor)

  8         110 SETUP_LOOP              58 (to 170)
            112 LOAD_GLOBAL              1 (range)
            114 LOAD_GLOBAL              2 (len)
            116 LOAD_FAST                1 (pwd)
            118 CALL_FUNCTION            1
            120 CALL_FUNCTION            1
            122 GET_ITER
        >>  124 FOR_ITER                42 (to 168)
            126 STORE_FAST               2 (i)

  9         128 LOAD_FAST                1 (pwd)
            130 LOAD_FAST                2 (i)
            132 BINARY_SUBSCR
            134 LOAD_GLOBAL              3 (chr)
            136 LOAD_FAST                3 (comp)
            138 LOAD_FAST                2 (i)
            140 BINARY_SUBSCR
            142 CALL_FUNCTION            1
            144 COMPARE_OP               3 (!=)
            146 POP_JUMP_IF_FALSE      160

 10         148 LOAD_GLOBAL              6 (print)
            150 LOAD_CONST              23 ('Incorrect password...')
            152 CALL_FUNCTION            1
            154 POP_TOP

 11         156 LOAD_CONST              24 (True)
            158 STORE_FAST               4 (incor)

 12     >>  160 LOAD_FAST                4 (incor)
            162 POP_JUMP_IF_FALSE      124
            164 BREAK_LOOP
            166 JUMP_ABSOLUTE          124
        >>  168 POP_BLOCK

 13     >>  170 LOAD_FAST                4 (incor)
            172 POP_JUMP_IF_TRUE       182
            174 LOAD_GLOBAL              6 (print)
            176 LOAD_CONST              25 ('Welcome!')
            178 CALL_FUNCTION            1
            180 POP_TOP
        >>  182 LOAD_CONST               0 (None)
            184 RETURN_VALUE
```
</details>

### Introduction
Programming languages usually fall into two main categories: compiled languages or interpreted languages. In compiled languages, the source code is directly translated to machine code for the computer to execute. In interpreted languages, the source code is translated to an intermediary code which is executed by an interpreter. 

Python is an interpreted programming language. Its intermediary code is referred to as byte code. The most common implementation for Python is CPython. It compiles source code into byte code and then interprets it. 

Python virtual machine (PVM) converts bytecode to machine code. PVM is stack based and uses three stacks: call stack, evaluation/data stack, and block stack. An important feature of these stacks is the Last-In-First-Out (LIFO) method. The first item that enters is put at the very bottom and the last item that enters is at the top. Think of a stack of plates at a buffet. 


### Challenge Solution
First, let's talk about the structure of the bytecode. The leftmost numbers are line numbers. To the right, we have a column of instructions such as "LOAD_CONST" and another column with data like "inp."

Looking at the instructions, we can infer what these do. LOAD_CONST deals with constants. LOAD_GLOBAL appears to deal with built-in Python functions like range(). STORE_FAST saves data into variables. There are a couple more instructions, but these three are the most important.

Moving onto analyzing the bytecode. The strategy I used is analyzing the code line by line and attempting to convert it back to normal Python code. Afterwards, I can check it using the Python module dis which dissambles Python code. 

Looking at line 1 and 15, it seeems like line 1 makes the main() function and line 15 calls it. We can ignore these lines because they're not helpful. 

We start with line 2. Since PVM uses stacks, we should start from the bottom and work our way up. Seeing STORE_FAST and inp, it seems like we are storing some input into the variable inp. Above it, we see the input() function and a question. Converting this to Python code, it is 
```python
inp = input("What's the password? ")
```
We can check this by running the dis module on it.

Looking at line 3, we see its pretty simple. It just sets the variable pwd to an empty string. 
```python
pwd = ''
```

From line 4, it gets a bit complicated. We see a FOR_ITER and the variable i. Since i is commonly used for index, we can assume there is a for loop. In addition, we see range, len, and inp. We get this code:
```python
for i in range(len(inp)):
```

For line 5, it is harder to convert. It will take more trial and error for this one. We write our guess, run dis on it, and compare the two results. Tweak our code a bit and try again. 

I would like to point out how Python experience and thinking (rather than randomly guessing) really helps in solving this challenge. Since line 5 is inside a loop and we have addition, we can infer that the string pwd is being added to like ```pwd += [something]```. We also see chr() followed by ord(). Having ```chr(ord())``` achieves nothing. Instead, it is more logical to have ```chr(ord() + something)```. Last but not least, we see inp followed by i. We see from line 4 that i is the index for the variable inp which leads us to infer ```inp[i]```. By noticing these hints and thinking about the code, we can quickly convert the byte code to something like this: 

```python
pwd += chr(ord(inp[i]) + i % int(7))
```

With the BUILD_LIST and the numerous LOAD_CONST, we see that line 6 stores a bunch of values into a list named comp. 
```python
comp = [102, 109, 99, 106, 127, 53, 116, 95, 122, 113, 120, 118, 100, 55, 51, 103, 57, 128]
```

The lines below appear to compare some strings. It looks like we figured out the most important part of our code: the encoding method and the ciphertext.

The encoding method is taking the ASCII value of a character from inp and adding a remainder of 7. The ciphertext seems to be the comp list. 

We write our decoding script: 
```python
comp = [102, 109, 99, 106, 127, 53, 116, 95, 122, 113, 120, 118, 100, 55, 51, 103, 57, 128]
flag = ''
for i in range(len(comp)):
    flag += chr(comp[i] - (i % 7))
print(flag)
```

Flag: ```flag{0n_your_13f7}```


Challenge thoughts:
I found this challenge very enjoyable and interesting. Learning about and reverse engineering python bytecode was a new and insightful experience.
    
Websites I found helpful: 
- https://docs.python.org/3/library/dis.html
- https://opensource.com/article/18/4/introduction-python-bytecode
- https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d
	
	
## Cloudy with a chance of probability - prince-of-tennis
To help out your local meteorologist, you decide to write a sophisticated program that can determine the chance of rain for any given six hours. Hint: think about or's and and's in probability!

For each input, you will receive a space-separated array of integers (each between 0 and 100) that represent the percent chance of rain for each hour in a six hour period. Your program should return the percent chance (rounded down to the nearest integer) that it rains during any of those six hours.

Sample Input 1:
```5 93 83 28 100 8```
Sample Output 1:
```100```

Sample Input 2:
```26 13 4 16 28 30```
	
Sample Output 2:
```73```

Notes:
- the inputs will be passed in (through stdin) separated by newlines; make sure your output (returned on stdout) is also separated by newlines
- the first line of input will contain only one integer representing the number of additional lines of input you will receive

### Solution

The math/logic part of this problem is just simple probabilities. To find the probability that it rains in any of the 6 hours, you first find the probability that it doesn't rain on any of the 6 days then subtract that from 1.

What is harder is working with stdin. stdin is essentially constant terminal output, which means that you can't take a single line of input or just stop taking input sometime like ```input()```. The problem is we need the first line of input for the number of line inputs that we will receive. A solution is to use an if-else every iteration.

```python
from sys import stdin, stdout
import math
def main():
    inputt = stdin
    out = stdout
    counter = 0
    numbers = ''
    for i in inputt:
        if numbers == '':
            numbers = int(i)
        else:
            j = i.split(' ')
            out.write(str(calc_p(j))+"\n")
            counter += 1
            if counter == numbers:
                break
def calc_p(a):
    p=1
    for i in range(len(a)):
        a[i] = float(a[i])*0.01
    for i in a:
        p*=(1-i)
    return(int(math.floor((1-p)*100)))
main()
```
