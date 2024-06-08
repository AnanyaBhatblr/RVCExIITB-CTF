# Doors of Death

we check all properties by doing exiftool, eog, there is nothing visible directly. The next step would be to check if something is hidden in the image. We do binwalk for this.

`binwalk -e tartarus.jpg`

On extracting we see an image `lost.jpg`
Nothing is visible on the image. So something must be hidden in it. Binwalk doesn't reveal anything so it's definitely steghide.

`steghide extract -sf lost.jpg`

this says could not extract any data with that passphrase!
we need a passphrase
The challenge says the greek gods are your key. So now we need a wordlist of greek gods so that we can bruteforce using stegcracker

we browse greek gods wordlist github on google and get a csv file from any repo
we need to convert that to a wordlist. we use a python script for the same.

```python
import csv

def extract_column(csv_file, column_index, output_file):
    with open(csv_file, 'r') as csvfile, open(output_file, 'w') as txtfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) > column_index:
                txtfile.write(row[column_index] + '\n')

# Example usage:
csv_file = 'greek_gods.csv'
column_index = 0  # Change this to the index of the column you want to extract (0-based index)
output_file = 'wordlistgreek.txt'

extract_column(csv_file, column_index, output_file)

```

Now we use this wordlist to bruteforce and get the password
```bash
stegcracker lost.jpg /home/ananya/Downloads/wordlistgreek.txt        
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2024 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

Counting lines in wordlist..
Attacking file 'lost.jpg' with wordlist '/home/ananya/Downloads/outpu.txt'..
Successfully cracked file with password: Nyx
Tried 157 passwords
Your file has been written to: lost.jpg.out
Nyx
```

now the passphrase is Nyx and the contents of lost.jpg.out are `/folders/1ecvI1N8mLoKCsJXQd462crf_7BnTCrEe`. This is clearly a drive link.

open a folder in your drive and paste this after /drive

we get a gates.pdf but it is locked.
We use pdfcrack to get the password and use the same wordlist.

```bash
$ pdfcrack gates.pdf outpu.txt        
PDF version 1.4
Security Handler: Standard
V: 2
R: 3
P: -4
Length: 128
Encrypted Metadata: True
FileID: 594de6527e4bb7d236db0fa49a8cac3a
U: dd819f0778cab16acafe30a2ad8be4ab28bf4e5e4e758a4164004e56fffa0108
O: e2d87be5dba283a83508a5e2982f97d95e90fe44e4da082ecb0250dd458db63a
found user-password: 'Thanatos
```
Thanatos is the password

we see some text  on decrypting it in cyberchef we get `flag{_seemedtohave_reachedthedo0rs_0f_D34th_Annabeth&Percy}`. This doesn't work.

Now we look at the question again. It says `The mist may create illusions and conceal the real door.` 
so obviously it's not visible to us. We do control A and see that there is some text in white
`Here’s the real treat - flag{Annabeth_reach%the&do0rs_0f_D34th#Percy}`

and we see the real flag.

# Labyrinth
it's a disc image. so we view the contents using fls
```bash
$ fls chall.iso            
d/d 1:	dir1
d/d 2:	dir2
d/d 3:	dir3
d/d 4:	dir4
d/d 5:	dir5
V/V 60:	$OrphanFiles
```

The question says 4!5!4!, so we go to the specific directories
```bash
$ fls chall.iso 4
d/d 24:	dir1
d/d 25:	dir2
d/d 26:	dir3
d/d 27:	dir4
d/d 28:	dir5
d/d 29:	dir6
```

```bash
$ fls chall.iso 28
d/d 36:	dir1
d/d 37:	dir2
d/d 38:	dir3
d/d 39:	dir4
d/d 40:	dir5
```

```bash
$ fls chall.iso 39
d/d 41:	dir1
d/d 42:	dir2
d/d 43:	dir3
d/d 44:	dir4
d/d 45:	dir5
r/r 46:	dirr3
d/d 47:	john
```

we see that r/r is there only for dirr3 which means it's not a directory, we view the contents using icat. we get this
```bash
$icat chall.iso 46               
Ao(mgHXnjO1LkM\EbT*+?["5HBPD?kA8
'q@oRAEBgm)MF>RcEFD*CMAo(mgFDk`3@ps=f<+oiZ@:FM&Bl8$+I/

```

On putting this in magic cyberchef we get the flag
`flag{d1r3ct0ries_w1thin_direcToRiEs_t4keth1sflagtoescapeThelabyrinth}`


# Le Café des Secrets
The crypticmessage.txt definitely looks like an esolang. We see that the challenge hints to louis pasteur (associated with acetic acid) and nail polish remover (acetone).
we go to https://esolangs.org/wiki/Language_list and look at the language list. We find aceto, that's the closest to the above.

We click on it. Click on official implementation, that takes you to the github repo.
do `pip install acetolang` then do
```bash
$ aceto crypticmessage.txt
Ac3t0L@NG#83 
```
then you get the message, wrap it with flag{} and submit
`flag{Ac3t0L@NG#83}`


# XOR enigma
we use a python script to solve this challenge
```python
k1 = "b3c8d73e3a9b23df7cc1253277a4878ef65bcfe9735f29d84424"
k2_k1 = "fb3514ac2e94885e9d5ec915821650572d5e0b842e9630f32b1b"
k2_k3 = "d2656867798e8584ec34ab2d4562b1a9c82b8fcf1feeeddf70e2"
flag_k1_k3_k2 = "07c1de3e3867c32fe29cbd6957a2695f0e021f4b58c2b03446bb"

k1_ord = [o for o in bytes.fromhex(k1)]
k2_k3_ord = [o for o in bytes.fromhex(k2_k3)]
flag_k1_k3_k2_ord = [o for o in bytes.fromhex(flag_k1_k3_k2)]

flag_k1_ord = [
    o_f132 ^ o23 for (o_f132, o23) in zip(flag_k1_k3_k2_ord, k2_k3_ord)
]
flag_ord = [o_f1 ^ o1 for (o_f1, o1) in zip(flag_k1_ord, k1_ord)]
flag = "".join(chr(o) for o in flag_ord)

print(flag)
```

first we convert from hex to bytes and then xor
`flag{retri3ved_x0r_m4st3r}`

# Builder Bob and Alice
on observation we see that the modulo are the same. So this is a classic modulo attack challenge.
we use a python script to solve this too.
```python                             
from libnum import xgcd, invmod, n2s

def common_modulus(e1, e2, c1, c2, N):
	a,b,d = xgcd(e1,e2)
	if b<0:
		c2 = invmod(c2, N)
		b = -b
	if a<0:
		c1 = invmod(c1,N)
		a = -a
	
	m = (pow(c1,a,N) * pow(c2,b,N))%N
	return m

N = 429121770631378567901343966601594638005200015410084049877005074706242144998835920068635924092327155154777724260920698564074246047428058702591438336354875385912113367812170140583119952718402254809563407665546757040976089024031265008069827573661895233187750822966323913745243562262084682435720233192587715830559

c1 = 87502995845613296640748517793461033238581559539831264070261405010457509045073974678421603483424284030953936003665163387882484477968792761078988595610302455403388677294958433069302896533782914177156060718958383452389999702278314396059598387560745347823772156262268912853464875822933280715397288456397500467082

c2 = 136066714893268542026804519389494696977338362492232911025630528665249367078493449633065764703691698428341934584595699819793588312946103371760765032815931350400960037961574476205220355485393336049341594068050222109820636564284034763886026894874140832144968716951111868453836181469982554783322713071884032213425

e1 = 386032633976106490452762780248103046765080671002988892055330641519564235852922762822642402279578918838636246752652910094048142722891896247145254930177193887644017516737007121616205743252470102524562046452022844285592502850136557110998891279346966111674327705149116034487327385428052869529026582167188809884767
e2 = 163750396495935852923904966204815324377529736034694345075646930507887571607611362069683718460469444053908143551023118580605176614326477189584938691146244409712347416452049032774643069943984015216081063830861336324570672997063592368707183334828352359237101478758418750499394554746092209859925767816955766723283

m = common_modulus(e1,e2,c1,c2,N)

flag = n2s(m)
print(flag)
plaintext = flag.decode('utf-8')

print("Decoded plaintext:", plaintext)

```

# Robot Uprising
We go to the site, it tells a lot about robots which indicates we much look into the robots.txt file.

`curl https://robot-uprising.rvcechalls.xyz/robots.txt`

```
		User-agent: *

      	YOU HAVE ENTERED THE ROBOTS BASE!
      	BUT NOT THROUGH THE RIGHT DOOR,
      	NOT WITH THE RIGHT ID!
        MAYBE WALL-E HAS THE SECRET!

```

this indicates that the User-agent must be WALL-E

`$ curl https://robot-uprising.rvcechalls.xyz/robots.txt -H 'User-agent: WALL-E'
```

        User-agent: *

        THE ROBOT UPRISING IS ON THE WAY!
        HERE'S THE SECRET KEY: flag{wallE_m1Ght_b3_4n_Ally}
                                                                  
```

you have your flag

